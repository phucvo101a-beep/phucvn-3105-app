use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Formats UTC+7 timestamp string matching existing PHP admin/log conventions (`YYYY-MM-DD HH:MM:SS`).
pub fn format_vn_time(unix_ts: i64) -> String {
    let vn = unix_ts + 7 * 3600;
    let days = vn.div_euclid(86400);
    let rem = vn.rem_euclid(86400);
    let hour = rem / 3600;
    let minute = (rem % 3600) / 60;
    let second = rem % 60;

    // Howard Hinnant civil-from-days algorithm
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if m <= 2 { 1 } else { 0 };
    format!("{year:04}-{m:02}-{d:02} {hour:02}:{minute:02}:{second:02}")
}

#[cfg(unix)]
mod file_lock {
    use std::fs::File;
    use std::os::unix::io::AsRawFd;

    extern "C" {
        fn flock(fd: i32, operation: i32) -> i32;
    }

    pub struct LockGuard(File);

    impl LockGuard {
        pub fn lock_exclusive(file: File) -> std::io::Result<Self> {
            const LOCK_EX: i32 = 2;
            let rc = unsafe { flock(file.as_raw_fd(), LOCK_EX) };
            if rc != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(Self(file))
        }
    }

    impl Drop for LockGuard {
        fn drop(&mut self) {
            const LOCK_UN: i32 = 8;
            unsafe {
                let _ = flock(self.0.as_raw_fd(), LOCK_UN);
            }
        }
    }
}

#[cfg(not(unix))]
mod file_lock {
    use std::fs::File;

    pub struct LockGuard(File);

    impl LockGuard {
        pub fn lock_exclusive(file: File) -> std::io::Result<Self> {
            Ok(Self(file))
        }
    }
}

use file_lock::LockGuard;

fn with_locked_file<T, F>(data_dir: &Path, name: &str, op: F) -> Result<T, String>
where
    F: FnOnce(&Path) -> Result<T, String>,
{
    fs::create_dir_all(data_dir).map_err(|e| format!("Failed creating data dir: {e}"))?;
    let lock_path = data_dir.join(format!(".{name}.lock"));
    let lock_file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(&lock_path)
        .map_err(|e| format!("Lock open error for {name}: {e}"))?;
    let _guard = LockGuard::lock_exclusive(lock_file)
        .map_err(|e| format!("Lock acquire error for {name}: {e}"))?;
    let target = data_dir.join(name);
    op(&target)
}

fn read_json_or_default<T: for<'de> Deserialize<'de> + Default>(path: &Path) -> Result<T, String> {
    if !path.exists() {
        return Ok(T::default());
    }
    let mut f = File::open(path).map_err(|e| format!("Read open failed: {e}"))?;
    let mut buf = String::new();
    f.read_to_string(&mut buf)
        .map_err(|e| format!("Read failed: {e}"))?;
    if buf.trim().is_empty() {
        return Ok(T::default());
    }
    serde_json::from_str(&buf).map_err(|e| format!("Invalid JSON in {}: {e}", path.display()))
}

fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let tmp_path = path.with_extension("tmp");
    let data = serde_json::to_vec_pretty(value).map_err(|e| format!("Serialize error: {e}"))?;
    let mut f = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&tmp_path)
        .map_err(|e| format!("Temp write open failed: {e}"))?;
    f.write_all(&data)
        .and_then(|_| f.sync_all())
        .map_err(|e| format!("Temp write failed: {e}"))?;
    drop(f);
    fs::rename(&tmp_path, path).map_err(|e| format!("Atomic rename failed: {e}"))
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PresetPolicy {
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackagePolicy {
    pub server_open: Option<bool>,
    pub server_closed_message: Option<String>,
    pub force_update: Option<bool>,
    pub min_required_version: Option<String>,
    pub latest_version: Option<String>,
    pub download_url: Option<String>,
    pub update_message: Option<String>,
    pub enforce_binary_hash: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerSettings {
    #[serde(default = "default_true")]
    pub server_open: bool,
    #[serde(default)]
    pub system_paused: bool,
    #[serde(default = "default_closed_msg")]
    pub server_closed_message: String,
    #[serde(default)]
    pub notice_text: String,
    #[serde(default)]
    pub force_update: bool,
    #[serde(default = "default_version")]
    pub min_required_version: String,
    #[serde(default = "default_version")]
    pub latest_version: String,
    #[serde(default)]
    pub download_url: String,
    #[serde(default = "default_update_msg")]
    pub update_message: String,
    #[serde(default)]
    pub enforce_binary_hash: bool,
    #[serde(default)]
    pub preset_policies: BTreeMap<String, PresetPolicy>,
    #[serde(default)]
    pub packages: BTreeMap<String, PackagePolicy>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

fn default_true() -> bool {
    true
}
fn default_closed_msg() -> String {
    "Hệ thống máy chủ đang bảo trì / tạm đóng. Vui lòng quay lại sau.".to_string()
}
fn default_version() -> String {
    "2.1.0".to_string()
}
fn default_update_msg() -> String {
    "Đã có phiên bản ứng dụng mới bắt buộc. Vui lòng cập nhật để tiếp tục sử dụng.".to_string()
}

impl Default for ServerSettings {
    fn default() -> Self {
        Self {
            server_open: true,
            system_paused: false,
            server_closed_message: default_closed_msg(),
            notice_text: String::new(),
            force_update: false,
            min_required_version: default_version(),
            latest_version: default_version(),
            download_url: String::new(),
            update_message: default_update_msg(),
            enforce_binary_hash: false,
            preset_policies: BTreeMap::new(),
            packages: BTreeMap::new(),
            extra: Map::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct EffectivePolicy {
    pub server_open: bool,
    pub closed_message: String,
    pub force_update: bool,
    pub min_required_version: String,
    pub latest_version: String,
    pub download_url: String,
    pub update_message: String,
    pub enforce_binary_hash: bool,
}

impl ServerSettings {
    /// Resolves effective policy combining global kill-switch & per-package overrides.
    pub fn resolve_policy(&self, package_id: &str) -> EffectivePolicy {
        let global_open = self.server_open && !self.system_paused;
        let pkg = self.packages.get(package_id);
        let pkg_open = pkg.and_then(|p| p.server_open).unwrap_or(true);
        let server_open = global_open && pkg_open;

        let closed_message = if !global_open {
            if !self.server_closed_message.trim().is_empty() {
                self.server_closed_message.clone()
            } else if !self.notice_text.trim().is_empty() {
                self.notice_text.clone()
            } else {
                default_closed_msg()
            }
        } else if let Some(msg) = pkg
            .and_then(|p| p.server_closed_message.as_ref())
            .filter(|m| !m.trim().is_empty())
        {
            msg.clone()
        } else if !self.server_closed_message.trim().is_empty() {
            self.server_closed_message.clone()
        } else {
            default_closed_msg()
        };

        let force_update = pkg.and_then(|p| p.force_update).unwrap_or(self.force_update);
        let min_required_version = pkg
            .and_then(|p| p.min_required_version.clone())
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| self.min_required_version.clone());
        let latest_version = pkg
            .and_then(|p| p.latest_version.clone())
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| self.latest_version.clone());
        let download_url = pkg
            .and_then(|p| p.download_url.clone())
            .filter(|u| !u.trim().is_empty())
            .unwrap_or_else(|| self.download_url.clone());
        let update_message = pkg
            .and_then(|p| p.update_message.clone())
            .filter(|m| !m.trim().is_empty())
            .unwrap_or_else(|| self.update_message.clone());
        let enforce_binary_hash = pkg
            .and_then(|p| p.enforce_binary_hash)
            .unwrap_or(self.enforce_binary_hash);

        EffectivePolicy {
            server_open,
            closed_message,
            force_update,
            min_required_version,
            latest_version,
            download_url,
            update_message,
            enforce_binary_hash,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceObject {
    pub hwid: String,
    #[serde(default)]
    pub activated_at: String,
    #[serde(default)]
    pub last_seen: String,
    #[serde(default)]
    pub ip: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DeviceEntry {
    Obj(DeviceObject),
    Str(String),
}

impl DeviceEntry {
    pub fn hwid(&self) -> &str {
        match self {
            DeviceEntry::Obj(o) => &o.hwid,
            DeviceEntry::Str(s) => s,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LicenseKeyRecord {
    pub key: String,
    #[serde(default = "default_duration")]
    pub duration: String,
    #[serde(default)]
    pub expiry_date: Option<String>,
    #[serde(default)]
    pub expiry_ts: Option<i64>,
    #[serde(default = "default_one")]
    pub max_devices: u32,
    #[serde(default)]
    pub devices: Vec<DeviceEntry>,
    #[serde(default)]
    pub used_by: Option<Value>,
    #[serde(default)]
    pub is_used: bool,
    #[serde(default = "default_role")]
    pub role: String,
    #[serde(default = "default_status")]
    pub status: String,
    #[serde(default)]
    pub ban_reason: String,
    #[serde(default)]
    pub bound_packages: Vec<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

fn default_duration() -> String {
    "30d".to_string()
}
fn default_one() -> u32 {
    1
}
fn default_role() -> String {
    "member".to_string()
}
fn default_status() -> String {
    "active".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildManifest {
    pub package_id: String,
    pub version: String,
    #[serde(default)]
    pub build: String,
    pub app_hash: String,
    pub sec_hash: String,
    #[serde(default = "default_true")]
    pub active: bool,
    #[serde(default)]
    pub revoked: bool,
    #[serde(default)]
    pub registered_at: String,
    #[serde(default)]
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BannedDevice {
    pub hwid: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub banned_by: String,
    #[serde(default)]
    pub banned_at: String,
    #[serde(default = "default_true")]
    pub active: bool,
    #[serde(default)]
    pub source_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RateBucket {
    pub window_start: i64,
    pub count: u32,
    pub blocked_until: i64,
}

pub struct Storage {
    pub data_dir: PathBuf,
}

impl Storage {
    pub fn new(data_dir: PathBuf) -> Self {
        Self { data_dir }
    }

    pub fn load_settings(&self) -> Result<ServerSettings, String> {
        with_locked_file(&self.data_dir, "settings.json", read_json_or_default)
    }

    pub fn save_settings_with<F>(&self, mutator: F) -> Result<ServerSettings, String>
    where
        F: FnOnce(&mut ServerSettings),
    {
        with_locked_file(&self.data_dir, "settings.json", |p| {
            let mut s: ServerSettings = read_json_or_default(p)?;
            mutator(&mut s);
            write_json_atomic(p, &s)?;
            Ok(s)
        })
    }

    /// Atomically checks whether nonce was already seen and inserts it with TTL = 600s.
    pub fn check_and_record_nonce(&self, nonce_hex: &str, now: i64) -> Result<bool, String> {
        with_locked_file(&self.data_dir, "api_nonces.json", |p| {
            let mut nonces: HashMap<String, i64> = read_json_or_default(p)?;
            nonces.retain(|_, &mut exp| exp > now - 600);
            if nonces.contains_key(nonce_hex) {
                return Ok(false);
            }
            nonces.insert(nonce_hex.to_string(), now + 600);
            write_json_atomic(p, &nonces)?;
            Ok(true)
        })
    }

    /// Checks whether a bucket is currently blocked without mutating counters.
    pub fn is_rate_limited(&self, bucket_key: &str, now: i64) -> bool {
        with_locked_file(&self.data_dir, "rate_limits.json", |p| {
            let map: HashMap<String, RateBucket> = read_json_or_default(p)?;
            Ok(map
                .get(bucket_key)
                .map(|b| b.blocked_until > now)
                .unwrap_or(false))
        })
        .unwrap_or(false)
    }

    /// Atomically checks and increments rate limit counter for a bucket.
    pub fn check_rate_limit(
        &self,
        bucket_key: &str,
        window_secs: i64,
        max_hits: u32,
        block_secs: i64,
        now: i64,
    ) -> Result<bool, String> {
        with_locked_file(&self.data_dir, "rate_limits.json", |p| {
            let mut map: HashMap<String, RateBucket> = read_json_or_default(p)?;
            map.retain(|_, b| b.window_start + window_secs > now || b.blocked_until > now);
            let entry = map.entry(bucket_key.to_string()).or_default();
            if entry.blocked_until > now {
                write_json_atomic(p, &map)?;
                return Ok(false);
            }
            if now - entry.window_start >= window_secs {
                entry.window_start = now;
                entry.count = 1;
            } else {
                entry.count = entry.count.saturating_add(1);
                if entry.count > max_hits {
                    entry.blocked_until = now + block_secs;
                    write_json_atomic(p, &map)?;
                    return Ok(false);
                }
            }
            write_json_atomic(p, &map)?;
            Ok(true)
        })
    }

    pub fn load_manifests(&self) -> Result<Vec<BuildManifest>, String> {
        with_locked_file(&self.data_dir, "build_manifests.json", read_json_or_default)
    }

    pub fn find_active_ban(&self, hwid: &str) -> Result<Option<BannedDevice>, String> {
        let needle = hwid.trim();
        if needle.is_empty() {
            return Ok(None);
        }
        with_locked_file(&self.data_dir, "banned_devices.json", |p| {
            let list: Vec<BannedDevice> = read_json_or_default(p)?;
            Ok(list
                .into_iter()
                .find(|b| b.active && b.hwid.trim().eq_ignore_ascii_case(needle)))
        })
    }

    pub fn register_manifest(&self, manifest: BuildManifest) -> Result<(), String> {
        with_locked_file(&self.data_dir, "build_manifests.json", |p| {
            let mut list: Vec<BuildManifest> = read_json_or_default(p)?;
            let app_l = manifest.app_hash.to_lowercase();
            let sec_l = manifest.sec_hash.to_lowercase();
            if let Some(existing) = list.iter_mut().find(|m| {
                m.package_id == manifest.package_id
                    && m.app_hash.eq_ignore_ascii_case(&app_l)
                    && m.sec_hash.eq_ignore_ascii_case(&sec_l)
            }) {
                existing.version = manifest.version;
                existing.build = manifest.build;
                existing.active = manifest.active;
                existing.revoked = manifest.revoked;
                existing.registered_at = manifest.registered_at;
                existing.note = manifest.note;
            } else {
                list.push(BuildManifest {
                    app_hash: app_l,
                    sec_hash: sec_l,
                    ..manifest
                });
            }
            write_json_atomic(p, &list)
        })
    }

    pub fn mutate_keys<T, F>(&self, mutator: F) -> Result<T, String>
    where
        F: FnOnce(&mut Vec<LicenseKeyRecord>) -> Result<T, String>,
    {
        with_locked_file(&self.data_dir, "keys.json", |p| {
            let mut keys: Vec<LicenseKeyRecord> = read_json_or_default(p)?;
            let res = mutator(&mut keys)?;
            write_json_atomic(p, &keys)?;
            Ok(res)
        })
    }

    pub fn append_log(&self, action: &str, key: &str, hwid: &str, ip: &str, details: &str) {
        let now = now_unix();
        let entry = serde_json::json!({
            "time": format_vn_time(now),
            "ts": now,
            "action": action,
            "key": key,
            "hwid": hwid,
            "ip": ip,
            "details": details,
        });
        let _ = with_locked_file(&self.data_dir, "logs.json", |p| {
            let mut logs: Vec<Value> = read_json_or_default(p)?;
            logs.push(entry);
            if logs.len() > 2000 {
                let drop_n = logs.len() - 2000;
                logs.drain(0..drop_n);
            }
            write_json_atomic(p, &logs)
        });
    }
}
