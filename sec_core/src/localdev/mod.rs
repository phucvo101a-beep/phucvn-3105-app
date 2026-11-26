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

/// Status Codes: distinguishes Pairing file validity from VPN tunnel / socket resets
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LocalDevStatusCode {
    Live = 1,
    MissingPairing = 2,
    VpnDisconnected = 3,
    LocalNetworkDenied = 4,
    PairingExpiredOrCorrupt = 5,
    TunnelReset = 6,
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
        let parsed = PairingFile::parse(data)?;
        if let Some(ref dir) = self.storage_dir {
            let _ = parsed.save_to_dir(dir);
        }
        self.active_pairing = Some(parsed);

        // Verify connectivity over tunnel without crashing or blocking indefinitely
        self.check_status_report()
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

    /// Evaluates current LocalDev status and returns structured report (`code` 1..6)
    pub fn check_status_report(&mut self) -> Result<LocalDevStatusReport, String> {
        // Sync with disk in case user cleared `.localdev/pairing.*` from Sandbox UI
        if let Some(ref dir) = self.storage_dir {
            let has_saved = dir.join("pairing.mobiledevicepairing").exists()
                || dir.join("pairing.plist").exists();
            if !has_saved {
                self.active_pairing = None;
                self.heartbeat.stop();
            } else if self.active_pairing.is_none() {
                if let Ok(loaded) = PairingFile::load_from_dir(dir) {
                    self.active_pairing = Some(loaded);
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
        LockdownErrorKind::PermissionDenied => LocalDevStatusReport {
            code: LocalDevStatusCode::LocalNetworkDenied as i32,
            status: "CHƯA CẤP QUYỀN MẠNG CỤC BỘ".to_string(),
            message: "iOS đang chặn kết nối tới tunnel 10.7.0.1:62078 (EPERM). Hãy bấm 'Kích hoạt quyền Mạng cục bộ' rồi chọn Cho phép (hoặc tắt/bỏ qua LocalDev để dùng thẳng Sandbox & Nhật ký USB).".to_string(),
            host,
            port,
            udid: Some(udid.to_string()),
            is_heartbeat_alive: false,
        },
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
