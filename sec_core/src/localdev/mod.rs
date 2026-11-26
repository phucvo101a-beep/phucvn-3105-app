//! LocalDev Core Module for iOS 15.0 - iOS 27.2.1
//! Dual-Stack Lockdown + CoreDevice/RSD, AFC & House Arrest File Management

pub mod afc_client;
pub mod apps;
pub mod ffi;
pub mod heartbeat;
pub mod house_arrest;
pub mod pairing;
pub mod plist_util;
pub mod tunnel;

use heartbeat::HeartbeatService;
use pairing::PairingFile;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Mutex;
use tunnel::{
    LockdownClient, LockdownError, LockdownErrorKind, LockdownStage, DEFAULT_LOCALDEV_IP,
    DEFAULT_LOCKDOWN_PORT, MAX_HANDSHAKE_ATTEMPTS,
};

/// Status Codes: distinguishes Pairing file validity, VPN/socket resets, and Remote Pairing format
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LocalDevStatusCode {
    Live = 1,
    MissingPairing = 2,
    VpnDisconnected = 3,
    LocalNetworkDenied = 4,
    PairingExpiredOrCorrupt = 5,
    TunnelReset = 6,
    RemotePairingUnsupported = 7,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalDevStatusReport {
    pub code: i32,
    pub status: String,
    pub message: String,
    pub host: String,
    pub port: u16,
    pub udid: Option<String>,
    pub is_heartbeat_alive: bool,
}

pub struct LocalDevManager {
    pub host: String,
    pub port: u16,
    pub storage_dir: Option<PathBuf>,
    pub active_pairing: Option<PairingFile>,
    pub heartbeat: HeartbeatService,
}

impl Default for LocalDevManager {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalDevManager {
    pub fn new() -> Self {
        Self {
            host: DEFAULT_LOCALDEV_IP.to_string(),
            port: DEFAULT_LOCKDOWN_PORT,
            storage_dir: None,
            active_pairing: None,
            heartbeat: HeartbeatService::new(),
        }
    }

    /// Initializes storage directory and loads saved pairing file
    pub fn init(&mut self, storage_path: Option<&str>, host: Option<&str>, port: Option<u16>) {
        if let Some(h) = host {
            if !h.trim().is_empty() {
                self.host = h.to_string();
            }
        }
        if let Some(p) = port {
            if p > 0 {
                self.port = p;
            }
        }
        if let Some(sp) = storage_path {
            let path = PathBuf::from(sp);
            self.storage_dir = Some(path.clone());
            if let Ok(loaded) = PairingFile::load_from_dir(&path) {
                self.active_pairing = Some(loaded);
            }
        }
    }

    /// Imports a new pairing file from raw data and persists it
    pub fn import_pairing(&mut self, data: &[u8]) -> Result<LocalDevStatusReport, String> {
        match PairingFile::parse(data) {
            Ok(parsed) => {
                if let Some(ref dir) = self.storage_dir {
                    let _ = std::fs::remove_file(dir.join("remote_pairing.plist"));
                    let _ = parsed.save_to_dir(dir);
                }
                self.active_pairing = Some(parsed);
                self.check_status_report()
            }
            Err(err) if err.starts_with("REMOTE_PAIRING_UNSUPPORTED:") => {
                self.active_pairing = None;
                self.heartbeat.stop();
                if let Some(ref dir) = self.storage_dir {
                    if !dir.exists() {
                        let _ = std::fs::create_dir_all(dir);
                    }
                    let _ = std::fs::remove_file(dir.join("pairing.mobiledevicepairing"));
                    let _ = std::fs::remove_file(dir.join("pairing.plist"));
                    let _ = std::fs::write(dir.join("remote_pairing.plist"), data);
                }
                Ok(remote_pairing_unsupported_report(self.host.clone(), self.port))
            }
            Err(err) => Err(err),
        }
    }

    fn candidate_ips(&self) -> Vec<String> {
        let mut ips = vec![self.host.clone()];
        for fallback in ["10.7.0.1", "10.7.1.1", "127.0.0.1"] {
            if !ips.iter().any(|existing| existing == fallback) {
                ips.push(fallback.to_string());
            }
        }
        ips
    }

    /// Evaluates current LocalDev status and returns structured report (`code` 1..7)
    pub fn check_status_report(&mut self) -> Result<LocalDevStatusReport, String> {
        // Sync with disk in case user cleared `.localdev/pairing.*` or saved a Remote Pairing plist
        if let Some(ref dir) = self.storage_dir {
            let remote_path = dir.join("remote_pairing.plist");
            let has_saved = dir.join("pairing.mobiledevicepairing").exists()
                || dir.join("pairing.plist").exists();
            if remote_path.exists() && !has_saved {
                self.active_pairing = None;
                self.heartbeat.stop();
                return Ok(remote_pairing_unsupported_report(self.host.clone(), self.port));
            }
            if !has_saved {
                self.active_pairing = None;
                self.heartbeat.stop();
            } else if self.active_pairing.is_none() {
                if let Some(load_res) = PairingFile::load_any_from_dir(dir) {
                    match load_res {
                        Ok(loaded) => self.active_pairing = Some(loaded),
                        Err(err) if err.starts_with("REMOTE_PAIRING_UNSUPPORTED:") => {
                            self.heartbeat.stop();
                            return Ok(remote_pairing_unsupported_report(self.host.clone(), self.port));
                        }
                        Err(err) => {
                            self.heartbeat.stop();
                            return Ok(LocalDevStatusReport {
                                code: LocalDevStatusCode::PairingExpiredOrCorrupt as i32,
                                status: "PAIRING FILE HẾT HẠN / LỖI".to_string(),
                                message: format!("Không thể phân tích tệp pairing đã lưu: {}", err),
                                host: self.host.clone(),
                                port: self.port,
                                udid: None,
                                is_heartbeat_alive: false,
                            });
                        }
                    }
                }
            }
        }

        // 1. Check if pairing file exists
        let pairing = match &self.active_pairing {
            Some(p) => p.clone(),
            None => {
                return Ok(LocalDevStatusReport {
                    code: LocalDevStatusCode::MissingPairing as i32,
                    status: "CHƯA CÓ PAIRING FILE".to_string(),
                    message: "Vui lòng nhập tệp .mobiledevicepairing để kết nối LocalDev (Sandbox & Nhật ký USB vẫn dùng bình thường).".to_string(),
                    host: self.host.clone(),
                    port: self.port,
                    udid: None,
                    is_heartbeat_alive: false,
                });
            }
        };

        // 2. Connect directly once per candidate IP (avoid opening a throwaway pre-probe socket that causes RST)
        let mut last_failure: Option<(String, LockdownError)> = None;

        for ip in self.candidate_ips() {
            match LockdownClient::connect_with_retry(&ip, self.port, &pairing, MAX_HANDSHAKE_ATTEMPTS)
            {
                Ok(client) => {
                    self.host = ip.clone();
                    let verified_udid = client
                        .device_udid
                        .filter(|u| !u.is_empty())
                        .unwrap_or_else(|| pairing.udid.clone());

                    if !self.heartbeat.is_active() {
                        self.heartbeat
                            .start(pairing.clone(), self.host.clone(), self.port);
                    }

                    return Ok(LocalDevStatusReport {
                        code: LocalDevStatusCode::Live as i32,
                        status: "LOCALDEV LIVE".to_string(),
                        message: format!("Kết nối LocalDev thành công (UDID: {})", verified_udid),
                        host: self.host.clone(),
                        port: self.port,
                        udid: Some(verified_udid),
                        is_heartbeat_alive: true,
                    });
                }
                Err(err) => {
                    let priority = error_priority(&err);
                    let replace = last_failure
                        .as_ref()
                        .map(|(_, prev)| priority > error_priority(prev))
                        .unwrap_or(true);
                    if replace {
                        last_failure = Some((ip.clone(), err));
                    }
                    // Permission denied applies app-wide; no need to probe remaining IPs
                    if priority == 4 {
                        break;
                    }
                }
            }
        }

        let (failed_ip, err) = last_failure.unwrap_or_else(|| {
            (
                self.host.clone(),
                LockdownError::new(
                    LockdownErrorKind::TunnelUnreachable,
                    LockdownStage::TcpConnect,
                    "Không có phản hồi từ tunnel LocalDev",
                ),
            )
        });

        Ok(build_failure_report(failed_ip, self.port, &pairing.udid, &err))
    }

    /// Scans installed applications over `installation_proxy`
    pub fn scan_apps(&mut self) -> Result<Vec<apps::LocalDevAppInfo>, String> {
        let pairing = self
            .active_pairing
            .as_ref()
            .ok_or_else(|| "Chưa có pairing file".to_string())?;
        apps::AppScanner::scan_user_apps(&self.host, self.port, pairing)
    }
}

fn error_priority(err: &LockdownError) -> u8 {
    match err.kind {
        LockdownErrorKind::PermissionDenied => 4,
        LockdownErrorKind::PairingRejected => 3,
        LockdownErrorKind::SocketReset | LockdownErrorKind::ProtocolError => 2,
        LockdownErrorKind::Timeout | LockdownErrorKind::TunnelUnreachable => 1,
    }
}

fn build_failure_report(
    host: String,
    port: u16,
    udid: &str,
    err: &LockdownError,
) -> LocalDevStatusReport {
    match err.kind {
        LockdownErrorKind::PermissionDenied => {
            let (bundle_id, _, _) = crate::integrity::read_bundle_identity();
            if bundle_id.starts_with("com.apple.") {
                LocalDevStatusReport {
                    code: LocalDevStatusCode::LocalNetworkDenied as i32,
                    status: "BỊ CHẶN DO BUNDLE ID HỆ THỐNG".to_string(),
                    message: format!(
                        "Bundle ID '{}' có tiền tố 'com.apple.' khiến iOS 26/27 chặn EPERM tới {}:{} và ẩn công tắc Mạng cục bộ trong Cài đặt. Cần build lại bằng Bundle ID riêng (ví dụ: com.phucvn.threeoneosfive). Chi tiết: {}",
                        bundle_id, host, port, err.detail
                    ),
                    host,
                    port,
                    udid: Some(udid.to_string()),
                    is_heartbeat_alive: false,
                }
            } else {
                LocalDevStatusReport {
                    code: LocalDevStatusCode::LocalNetworkDenied as i32,
                    status: "CHƯA CẤP QUYỀN MẠNG CỤC BỘ".to_string(),
                    message: format!(
                        "iOS đang chặn kết nối tới tunnel {}:{} (EPERM — {}). Hãy bấm 'Kích hoạt quyền Mạng cục bộ' -> Cho phép, hoặc bật công tắc 'Mạng cục bộ' trong Cài đặt -> 3105 x PHUCVN rồi quay lại app.",
                        host, port, err.detail
                    ),
                    host,
                    port,
                    udid: Some(udid.to_string()),
                    is_heartbeat_alive: false,
                }
            }
        }
        LockdownErrorKind::PairingRejected => LocalDevStatusReport {
            code: LocalDevStatusCode::PairingExpiredOrCorrupt as i32,
            status: "PAIRING FILE HẾT HẠN / LỖI".to_string(),
            message: format!(
                "Thiết bị từ chối tệp pairing tại bước [{}]: {}. Hãy tạo lại hoặc nhập tệp .mobiledevicepairing mới.",
                err.stage, err.detail
            ),
            host,
            port,
            udid: Some(udid.to_string()),
            is_heartbeat_alive: false,
        },
        LockdownErrorKind::SocketReset | LockdownErrorKind::ProtocolError => LocalDevStatusReport {
            code: LocalDevStatusCode::TunnelReset as i32,
            status: "SOCKET/DAEMON RESET KHI BẮT TAY".to_string(),
            message: format!(
                "Socket {}:{} bị ngắt/reset ở bước [{}] ({}). Đây là lỗi tunnel LocalDevVPN hoặc daemon iOS ngắt kết nối cổng 62078 (không mặc định là file pairing hỏng). Hãy tắt/bật lại LocalDevVPN; Sandbox & Nhật ký USB vẫn hoạt động bình thường.",
                host, port, err.stage, err.detail
            ),
            host,
            port,
            udid: Some(udid.to_string()),
            is_heartbeat_alive: false,
        },
        LockdownErrorKind::Timeout | LockdownErrorKind::TunnelUnreachable => LocalDevStatusReport {
            code: LocalDevStatusCode::VpnDisconnected as i32,
            status: "CHƯA BẬT LOCALDEV VPN".to_string(),
            message: format!(
                "Không thể kết nối {}:{}. Hãy bật LocalDevVPN hoặc StosVPN.",
                host, port
            ),
            host,
            port,
            udid: Some(udid.to_string()),
            is_heartbeat_alive: false,
        },
    }
}

fn remote_pairing_unsupported_report(host: String, port: u16) -> LocalDevStatusReport {
    LocalDevStatusReport {
        code: LocalDevStatusCode::RemotePairingUnsupported as i32,
        status: "CHƯA HỖ TRỢ REMOTE PAIRING".to_string(),
        message: "File pairing này thuộc chuẩn Remote Pairing (idevice pair v1.2.0: public_key / private_key / identifier / alt_irk). Core libsec_core.dylib hiện chỉ hỗ trợ USB Lockdown X.509 cổ điển (HostCertificate & HostID) qua cổng 62078. Hãy tạo/nhập tệp .mobiledevicepairing chuẩn Lockdown, hoặc tắt LocalDev để dùng thẳng Sandbox & Nhật ký USB.".to_string(),
        host,
        port,
        udid: None,
        is_heartbeat_alive: false,
    }
}

static LOCALDEV_INSTANCE: Mutex<Option<LocalDevManager>> = Mutex::new(None);

pub fn with_manager<F, R>(f: F) -> R
where
    F: FnOnce(&mut LocalDevManager) -> R,
{
    let mut guard = LOCALDEV_INSTANCE.lock().unwrap();
    if guard.is_none() {
        *guard = Some(LocalDevManager::new());
    }
    f(guard.as_mut().unwrap())
}
