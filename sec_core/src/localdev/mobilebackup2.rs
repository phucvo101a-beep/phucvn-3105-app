//! Apple DeviceLink (`DL*`) Backup2 Client over RSD / Lockdown
//! Extracts unencrypted device backup snapshots so target `AppDomain-<bundle_id>` files
//! can be recovered cleanly into app Sandbox storage even when `house_arrest` is locked.

use super::plist_util::PlistValue;
use super::tunnel::{read_plist, send_plist_value, LockdownStream};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufWriter, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

const DL_CODE_SUCCESS: u8 = 0x00;
const DL_CODE_ERROR_REMOTE: u8 = 0x0B;
const DL_CODE_FILE_DATA: u8 = 0x0C;
const MB2_MAX_PATH_BYTES: usize = 4096;
const MB2_CHUNK_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mb2ProgressSnapshot {
    pub running: bool,
    pub phase: String,
    pub files_received: u64,
    pub bytes_received: u64,
    pub last_path: String,
    pub error: Option<String>,
}

impl Default for Mb2ProgressSnapshot {
    fn default() -> Self {
        Self {
            running: false,
            phase: "idle".to_string(),
            files_received: 0,
            bytes_received: 0,
            last_path: String::new(),
            error: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mb2ExtractReport {
    pub udid: String,
    pub bundle_id: String,
    pub staging_udid_dir: String,
    pub manifest_db_path: Option<String>,
    pub files_received: u64,
    pub bytes_received: u64,
}

static MB2_CANCEL: AtomicBool = AtomicBool::new(false);
static MB2_PROGRESS: Mutex<Option<Mb2ProgressSnapshot>> = Mutex::new(None);

fn update_progress(f: impl FnOnce(&mut Mb2ProgressSnapshot)) {
    let mut guard = match MB2_PROGRESS.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    let snap = guard.get_or_insert_with(Mb2ProgressSnapshot::default);
    f(snap);
}

pub fn get_progress_snapshot() -> Mb2ProgressSnapshot {
    let guard = match MB2_PROGRESS.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    guard.clone().unwrap_or_default()
}

pub fn request_cancel() {
    MB2_CANCEL.store(true, Ordering::SeqCst);
    update_progress(|s| {
        if s.running {
            s.phase = "Đang hủy trích xuất...".to_string();
        }
    });
}

fn check_cancelled() -> Result<(), String> {
    if MB2_CANCEL.load(Ordering::SeqCst) {
        Err("Người dùng đã hủy trích xuất Backup.".to_string())
    } else {
        Ok(())
    }
}

pub struct MobileBackup2Client {
    stream: LockdownStream,
}

impl MobileBackup2Client {
    pub fn new(stream: LockdownStream) -> Self {
        // Backup transfers over utun/CDTunnel need generous read timeouts
        stream.set_timeouts(120, 30);
        Self { stream }
    }

    pub fn run_backup_into_staging(
        mut self,
        udid: &str,
        bundle_id: &str,
        staging_dir: &Path,
        free_bytes: u64,
    ) -> Result<Mb2ExtractReport, String> {
        let clean_udid = sanitize_single_segment(udid, "UDID")?;
        let clean_bundle = bundle_id.trim();
        if clean_bundle.is_empty() {
            return Err("Thiếu bundle_id mục tiêu".to_string());
        }

        MB2_CANCEL.store(false, Ordering::SeqCst);
        update_progress(|s| {
            s.running = true;
            s.phase = "Đang bắt tay DeviceLink (mobilebackup2)...".to_string();
            s.files_received = 0;
            s.bytes_received = 0;
            s.last_path.clear();
            s.error = None;
        });

        let result = self.run_backup_inner(&clean_udid, clean_bundle, staging_dir, free_bytes);
        update_progress(|s| {
            s.running = false;
            match &result {
                Ok(rep) => {
                    s.phase = format!("Hoàn tất nhận {} tệp", rep.files_received);
                    s.error = None;
                }
                Err(err) => {
                    s.phase = "Thất bại".to_string();
                    s.error = Some(err.clone());
                }
            }
        });
        result
    }

    fn run_backup_inner(
        &mut self,
        udid: &str,
        bundle_id: &str,
        staging_dir: &Path,
        free_bytes: u64,
    ) -> Result<Mb2ExtractReport, String> {
        fs::create_dir_all(staging_dir)
            .map_err(|e| format!("Không tạo được thư mục tạm backup: {}", e))?;
        let target_root = staging_dir.join(udid);
        fs::create_dir_all(&target_root)
            .map_err(|e| format!("Không tạo được thư mục UDID backup: {}", e))?;

        // 1. DeviceLink version exchange & ready signal
        self.perform_dl_version_exchange()?;
        check_cancelled()?;

        // 2. MobileBackup2 Hello
        update_progress(|s| {
            s.phase = "Đang thương lượng giao thức mobilebackup2...".to_string();
        });
        self.send_hello()?;
        check_cancelled()?;

        // 3. Issue Backup request for target UDID
        update_progress(|s| {
            s.phase = format!("Đang yêu cầu dữ liệu backup cho {}...", bundle_id);
        });
        let mut opts = HashMap::new();
        opts.insert("ForceFullBackup".to_string(), PlistValue::Boolean(false));
        let mut req = HashMap::new();
        req.insert("MessageName".to_string(), PlistValue::String("Backup".to_string()));
        req.insert("TargetIdentifier".to_string(), PlistValue::String(udid.to_string()));
        req.insert("SourceIdentifier".to_string(), PlistValue::String(udid.to_string()));
        req.insert("Options".to_string(), PlistValue::Dictionary(opts));
        self.send_process_message(req)?;

        let mut files_received: u64 = 0;
        let mut bytes_received: u64 = 0;

        loop {
            check_cancelled()?;
            let msg = read_plist(&mut self.stream)?;
            let arr = msg
                .as_array()
                .ok_or_else(|| "DeviceLink trả về gói không phải mảng".to_string())?;
            let Some(cmd) = arr.first().and_then(|v| v.as_str()) else {
                return Err("DeviceLink thiếu mã lệnh".to_string());
            };

            match cmd {
                "DLMessageGetFreeDiskSpace" => {
                    let avail = i64::try_from(free_bytes.min(i64::MAX as u64)).unwrap_or(i64::MAX);
                    self.send_dl_status_value(0, PlistValue::Integer(avail))?;
                }
                "DLMessagePurgeDiskSpace" => {
                    self.send_dl_status_empty(0)?;
                }
                "DLMessageContentsOfDirectory" => {
                    let rel = arr.get(1).and_then(|v| v.as_str()).unwrap_or("");
                    let listing = list_staging_directory(staging_dir, rel)?;
                    self.send_dl_status_value(0, listing)?;
                }
                "DLMessageCreateDirectory" => {
                    let rel = arr.get(1).and_then(|v| v.as_str()).unwrap_or("");
                    let dir = resolve_safe_subpath(staging_dir, rel)?;
                    fs::create_dir_all(&dir)
                        .map_err(|e| format!("DLMessageCreateDirectory failed: {}", e))?;
                    self.send_dl_status_empty(0)?;
                }
                "DLMessageCopyItem" => {
                    let src_rel = arr.get(1).and_then(|v| v.as_str()).unwrap_or("");
                    let dst_rel = arr.get(2).and_then(|v| v.as_str()).unwrap_or("");
                    let src = resolve_safe_subpath(staging_dir, src_rel)?;
                    let dst = resolve_safe_subpath(staging_dir, dst_rel)?;
                    copy_item_recursive(&src, &dst)?;
                    self.send_dl_status_empty(0)?;
                }
                "DLMessageMoveItems" | "DLMessageMoveFiles" => {
                    if let Some(map) = arr.get(1).and_then(|v| v.as_dict()) {
                        for (src_rel, dst_val) in map {
                            if let Some(dst_rel) = dst_val.as_str() {
                                let src = resolve_safe_subpath(staging_dir, src_rel)?;
                                let dst = resolve_safe_subpath(staging_dir, dst_rel)?;
                                if let Some(parent) = dst.parent() {
                                    let _ = fs::create_dir_all(parent);
                                }
                                if src.exists() {
                                    let _ = fs::rename(&src, &dst);
                                }
                            }
                        }
                    }
                    self.send_dl_status_empty(0)?;
                }
                "DLMessageRemoveItems" | "DLMessageRemoveFiles" => {
                    if let Some(list) = arr.get(1).and_then(|v| v.as_array()) {
                        for item in list {
                            if let Some(rel) = item.as_str() {
                                if let Ok(path) = resolve_safe_subpath(staging_dir, rel) {
                                    if path.is_dir() {
                                        let _ = fs::remove_dir_all(&path);
                                    } else if path.exists() {
                                        let _ = fs::remove_file(&path);
                                    }
                                }
                            }
                        }
                    }
                    self.send_dl_status_empty(0)?;
                }
                "DLMessageDownloadFiles" => {
                    let req_paths = arr.get(1).and_then(|v| v.as_array()).unwrap_or(&[]);
                    self.handle_download_files(staging_dir, req_paths)?;
                }
                "DLMessageUploadFiles" => {
                    self.handle_upload_files(
                        staging_dir,
                        &mut files_received,
                        &mut bytes_received,
                    )?;
                }
                "DLMessageDisconnect" => {
                    break;
                }
                "DLMessageProcessMessage" => {
                    if let Some(dict) = arr.get(1).and_then(|v| v.as_dict()) {
                        let mname = dict
                            .get("MessageName")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        if mname.eq_ignore_ascii_case("Response") {
                            let err_code = dict
                                .get("ErrorCode")
                                .and_then(|v| match v {
                                    PlistValue::Integer(n) => Some(*n),
                                    _ => None,
                                })
                                .unwrap_or(0);
                            if err_code != 0 {
                                let desc = dict
                                    .get("ErrorDescription")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("mobilebackup2 từ chối yêu cầu sao lưu");
                                return Err(format_mb2_error(err_code, desc));
                            }
                            break;
                        }
                    }
                }
                other => {
                    eprintln!("localdev: mobilebackup2 unhandled DL cmd={}", other);
                    self.send_dl_status_empty(0)?;
                }
            }
        }

        let manifest_candidate = target_root.join("Manifest.db");
        let manifest_db_path = if manifest_candidate.is_file() {
            Some(manifest_candidate.to_string_lossy().to_string())
        } else {
            None
        };

        Ok(Mb2ExtractReport {
            udid: udid.to_string(),
            bundle_id: bundle_id.to_string(),
            staging_udid_dir: target_root.to_string_lossy().to_string(),
            manifest_db_path,
            files_received,
            bytes_received,
        })
    }

    fn perform_dl_version_exchange(&mut self) -> Result<(), String> {
        let msg = read_plist(&mut self.stream)?;
        let arr = msg
            .as_array()
            .ok_or_else(|| "DeviceLink VersionExchange không hợp lệ".to_string())?;
        if arr.first().and_then(|v| v.as_str()) != Some("DLMessageVersionExchange") {
            return Err("Không nhận được DLMessageVersionExchange từ thiết bị".to_string());
        }
        let major = match arr.get(1) {
            Some(PlistValue::Integer(v)) => *v,
            _ => 300,
        };
        let ack = PlistValue::Array(vec![
            PlistValue::String("DLMessageVersionExchange".to_string()),
            PlistValue::String("DLVersionsOk".to_string()),
            PlistValue::Integer(major),
        ]);
        send_plist_value(&mut self.stream, &ack)?;

        let ready = read_plist(&mut self.stream)?;
        let ready_arr = ready
            .as_array()
            .ok_or_else(|| "DeviceLink thiếu DLMessageDeviceReady".to_string())?;
        if ready_arr.first().and_then(|v| v.as_str()) != Some("DLMessageDeviceReady") {
            return Err("Thiết bị không gửi DLMessageDeviceReady".to_string());
        }
        Ok(())
    }

    fn send_hello(&mut self) -> Result<(), String> {
        let mut req = HashMap::new();
        req.insert("MessageName".to_string(), PlistValue::String("Hello".to_string()));
        req.insert(
            "SupportedProtocolVersions".to_string(),
            PlistValue::Array(vec![PlistValue::Real(2.0), PlistValue::Real(2.1)]),
        );
        self.send_process_message(req)?;

        let resp = read_plist(&mut self.stream)?;
        let arr = resp
            .as_array()
            .ok_or_else(|| "mobilebackup2 Hello response không hợp lệ".to_string())?;
        if arr.first().and_then(|v| v.as_str()) != Some("DLMessageProcessMessage") {
            return Err("mobilebackup2 Hello thiếu DLMessageProcessMessage".to_string());
        }
        let dict = arr
            .get(1)
            .and_then(|v| v.as_dict())
            .ok_or_else(|| "mobilebackup2 Hello thiếu payload dict".to_string())?;
        let err_code = dict
            .get("ErrorCode")
            .and_then(|v| match v {
                PlistValue::Integer(n) => Some(*n),
                _ => None,
            })
            .unwrap_or(0);
        if err_code != 0 {
            let desc = dict
                .get("ErrorDescription")
                .and_then(|v| v.as_str())
                .unwrap_or("Hello thất bại");
            return Err(format_mb2_error(err_code, desc));
        }
        Ok(())
    }

    fn send_process_message(&mut self, dict: HashMap<String, PlistValue>) -> Result<(), String> {
        let val = PlistValue::Array(vec![
            PlistValue::String("DLMessageProcessMessage".to_string()),
            PlistValue::Dictionary(dict),
        ]);
        send_plist_value(&mut self.stream, &val)
    }

    fn send_dl_status_empty(&mut self, code: i64) -> Result<(), String> {
        self.send_dl_status_value(code, PlistValue::Dictionary(HashMap::new()))
    }

    fn send_dl_status_value(&mut self, code: i64, val: PlistValue) -> Result<(), String> {
        let reply = PlistValue::Array(vec![
            PlistValue::String("DLMessageStatusResponse".to_string()),
            PlistValue::Integer(code),
            val,
            PlistValue::String(String::new()),
        ]);
        send_plist_value(&mut self.stream, &reply)
    }

    fn handle_download_files(
        &mut self,
        staging_dir: &Path,
        req_paths: &[PlistValue],
    ) -> Result<(), String> {
        let mut errs: HashMap<String, PlistValue> = HashMap::new();
        let mut buf = vec![0u8; MB2_CHUNK_BYTES];

        for item in req_paths {
            check_cancelled()?;
            let Some(rel) = item.as_str() else {
                continue;
            };
            let local = match resolve_safe_subpath(staging_dir, rel) {
                Ok(p) if p.is_file() => p,
                _ => {
                    let mut err_entry = HashMap::new();
                    err_entry.insert("DLFileErrorCode".to_string(), PlistValue::Integer(-6));
                    err_entry.insert(
                        "DLFileErrorString".to_string(),
                        PlistValue::String("No such file or directory".to_string()),
                    );
                    errs.insert(rel.to_string(), PlistValue::Dictionary(err_entry));
                    continue;
                }
            };

            let name_bytes = rel.as_bytes();
            let nlen = (name_bytes.len() as u32).to_be_bytes();
            self.stream
                .write_all(&nlen)
                .and_then(|_| self.stream.write_all(name_bytes))
                .map_err(|e| format!("DLMessageDownloadFiles write name failed: {}", e))?;

            let mut f = File::open(&local)
                .map_err(|e| format!("Mở file staging thất bại: {}", e))?;
            loop {
                let n = f
                    .read(&mut buf)
                    .map_err(|e| format!("Đọc file staging thất bại: {}", e))?;
                if n == 0 {
                    break;
                }
                let hdr = ((n + 1) as u32).to_be_bytes();
                self.stream
                    .write_all(&hdr)
                    .and_then(|_| self.stream.write_all(&[DL_CODE_FILE_DATA]))
                    .and_then(|_| self.stream.write_all(&buf[..n]))
                    .map_err(|e| format!("DLMessageDownloadFiles write chunk failed: {}", e))?;
            }
            let eof_hdr = 1u32.to_be_bytes();
            self.stream
                .write_all(&eof_hdr)
                .and_then(|_| self.stream.write_all(&[DL_CODE_SUCCESS]))
                .map_err(|e| format!("DLMessageDownloadFiles write EOF failed: {}", e))?;
        }

        // Batch terminator (zero-length filename)
        self.stream
            .write_all(&0u32.to_be_bytes())
            .and_then(|_| self.stream.flush())
            .map_err(|e| format!("DLMessageDownloadFiles terminator failed: {}", e))?;

        if errs.is_empty() {
            self.send_dl_status_empty(0)
        } else {
            self.send_dl_status_value(-6, PlistValue::Dictionary(errs))
        }
    }

    fn handle_upload_files(
        &mut self,
        staging_dir: &Path,
        files_received: &mut u64,
        bytes_received: &mut u64,
    ) -> Result<(), String> {
        let mut scratch = vec![0u8; MB2_CHUNK_BYTES];

        loop {
            check_cancelled()?;
            let dir_name = read_dl_string(&mut self.stream)?;
            if dir_name.is_empty() {
                break;
            }
            let backup_name = read_dl_string(&mut self.stream)?;
            if backup_name.is_empty() {
                break;
            }

            let target_path = resolve_safe_subpath(staging_dir, &backup_name)?;
            if let Some(parent) = target_path.parent() {
                fs::create_dir_all(parent)
                    .map_err(|e| format!("Không tạo được thư mục {}: {}", parent.display(), e))?;
            }
            let file = File::create(&target_path)
                .map_err(|e| format!("Không ghi được file backup {}: {}", target_path.display(), e))?;
            let mut writer = BufWriter::new(file);
            let mut file_failed = false;

            loop {
                check_cancelled()?;
                let mut len_buf = [0u8; 4];
                self.stream
                    .read_exact(&mut len_buf)
                    .map_err(|e| format!("Đọc kích thước chunk backup thất bại: {}", e))?;
                let chunk_len = u32::from_be_bytes(len_buf) as usize;
                if chunk_len == 0 {
                    break;
                }

                let mut code_buf = [0u8; 1];
                self.stream
                    .read_exact(&mut code_buf)
                    .map_err(|e| format!("Đọc mã chunk backup thất bại: {}", e))?;
                let code = code_buf[0];
                let payload_len = chunk_len - 1;

                let mut rem = payload_len;
                while rem > 0 {
                    let to_read = rem.min(scratch.len());
                    self.stream
                        .read_exact(&mut scratch[..to_read])
                        .map_err(|e| format!("Đọc dữ liệu tệp backup thất bại: {}", e))?;
                    if !file_failed && code != DL_CODE_ERROR_REMOTE {
                        writer
                            .write_all(&scratch[..to_read])
                            .map_err(|e| format!("Ghi tệp backup thất bại: {}", e))?;
                        *bytes_received = bytes_received.saturating_add(to_read as u64);
                    }
                    rem -= to_read;
                }

                if code == DL_CODE_ERROR_REMOTE {
                    file_failed = true;
                    break;
                }
                if code == DL_CODE_SUCCESS {
                    break;
                }
                if code != DL_CODE_FILE_DATA {
                    // Other terminal status marker
                    break;
                }
            }

            let _ = writer.flush();
            drop(writer);
            if file_failed {
                let _ = fs::remove_file(&target_path);
            } else {
                *files_received = files_received.saturating_add(1);
                let fc = *files_received;
                let bc = *bytes_received;
                update_progress(|s| {
                    s.phase = format!("Đang tải dữ liệu backup ({} tệp)...", fc);
                    s.files_received = fc;
                    s.bytes_received = bc;
                    s.last_path = backup_name.clone();
                });
            }
        }

        self.send_dl_status_empty(0)
    }
}

fn read_dl_string(stream: &mut LockdownStream) -> Result<String, String> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .map_err(|e| format!("DeviceLink read string len failed: {}", e))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 {
        return Ok(String::new());
    }
    if len > MB2_MAX_PATH_BYTES {
        return Err(format!("DeviceLink string quá dài: {} bytes", len));
    }
    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .map_err(|e| format!("DeviceLink read string payload failed: {}", e))?;
    Ok(String::from_utf8_lossy(&buf).to_string())
}

fn sanitize_single_segment(raw: &str, label: &str) -> Result<String, String> {
    let clean = raw.trim();
    if clean.is_empty()
        || clean.contains('/')
        || clean.contains('\\')
        || clean.contains("..")
        || clean.contains('\0')
    {
        return Err(format!("{} không hợp lệ: {}", label, clean));
    }
    Ok(clean.to_string())
}

fn resolve_safe_subpath(root: &Path, rel: &str) -> Result<PathBuf, String> {
    let normalized = rel.replace('\\', "/");
    let mut out = root.to_path_buf();
    for comp in Path::new(normalized.trim_start_matches('/')).components() {
        match comp {
            Component::Normal(seg) => out.push(seg),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(format!("Đường dẫn không an toàn trong backup: {}", rel));
            }
        }
    }
    Ok(out)
}

fn list_staging_directory(staging_dir: &Path, rel: &str) -> Result<PlistValue, String> {
    let dir_path = resolve_safe_subpath(staging_dir, rel)?;
    let mut out: HashMap<String, PlistValue> = HashMap::new();
    if !dir_path.is_dir() {
        return Ok(PlistValue::Dictionary(out));
    }

    let entries = fs::read_dir(&dir_path)
        .map_err(|e| format!("Đọc thư mục backup thất bại: {}", e))?;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with('.') {
            continue;
        }
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        let ftype = if meta.is_dir() {
            "DLFileTypeDirectory"
        } else {
            "DLFileTypeRegular"
        };
        let mut info = HashMap::new();
        info.insert("DLFileType".to_string(), PlistValue::String(ftype.to_string()));
        info.insert("DLFileSize".to_string(), PlistValue::Integer(meta.len() as i64));
        out.insert(name, PlistValue::Dictionary(info));
    }
    Ok(PlistValue::Dictionary(out))
}

fn copy_item_recursive(src: &Path, dst: &Path) -> Result<(), String> {
    if !src.exists() {
        return Ok(());
    }
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Tạo thư mục đích copy thất bại: {}", e))?;
    }
    if src.is_file() {
        fs::copy(src, dst)
            .map_err(|e| format!("Copy tệp backup thất bại: {}", e))?;
        return Ok(());
    }
    if src.is_dir() {
        fs::create_dir_all(dst)
            .map_err(|e| format!("Tạo thư mục copy thất bại: {}", e))?;
        for entry in fs::read_dir(src).map_err(|e| e.to_string())?.flatten() {
            let child_src = entry.path();
            let child_dst = dst.join(entry.file_name());
            copy_item_recursive(&child_src, &child_dst)?;
        }
    }
    Ok(())
}

fn format_mb2_error(code: i64, desc: &str) -> String {
    let lower = desc.to_ascii_lowercase();
    if lower.contains("encrypt") {
        format!(
            "iPhone đang bật mã hóa bản sao lưu cục bộ (code {}): {}. Hãy tắt 'Encrypt local backup' rồi thử lại.",
            code, desc
        )
    } else if code == -205 || code == 205 || lower.contains("passcode") || lower.contains("locked") {
        format!(
            "Thiết bị yêu cầu mở khóa / nhập mật mã trên màn hình iPhone để sao lưu (code {}): {}",
            code, desc
        )
    } else {
        format!("mobilebackup2 lỗi (code {}): {}", code, desc)
    }
}
