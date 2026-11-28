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

use apps::{AppScanner, LocalDevAppInfo};
use heartbeat::HeartbeatService;
use pairing::PairingFile;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Mutex;
use tunnel::{LockdownClient, DEFAULT_LOCALDEV_IP, DEFAULT_LOCKDOWN_PORT};

/// Exact 5 Status Codes
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LocalDevStatusCode {
    Live = 1,
    MissingPairing = 2,
    VpnDisconnected = 3,
    LocalNetworkDenied = 4,
    PairingExpiredOrCorrupt = 5,
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
        let _udid = parsed.udid.clone();
        self.active_pairing = Some(parsed);

        // Check if tunnel is reachable and start heartbeat
        self.check_status_report()
    }

    /// Evaluates current status and returns one of the 5 exact status reports
    pub fn check_status_report(&mut self) -> Result<LocalDevStatusReport, String> {
        // 1. Check if pairing file exists
        let pairing = match &self.active_pairing {
            Some(p) => p.clone(),
            None => {
                // Try reloading from storage_dir if available
                if let Some(ref dir) = self.storage_dir {
                    if let Ok(loaded) = PairingFile::load_from_dir(dir) {
                        self.active_pairing = Some(loaded.clone());
                        loaded
                    } else {
                        return Ok(LocalDevStatusReport {
                            code: LocalDevStatusCode::MissingPairing as i32,
                            status: "CHƯA CÓ PAIRING FILE".to_string(),
                            message: "Vui lòng nhập tệp .mobiledevicepairing để kết nối LocalDev.".to_string(),
                            host: self.host.clone(),
                            port: self.port,
                            udid: None,
                            is_heartbeat_alive: false,
                        });
                    }
                } else {
                    return Ok(LocalDevStatusReport {
                        code: LocalDevStatusCode::MissingPairing as i32,
                        status: "CHƯA CÓ PAIRING FILE".to_string(),
                        message: "Vui lòng nhập tệp .mobiledevicepairing để kết nối LocalDev.".to_string(),
                        host: self.host.clone(),
                        port: self.port,
                        udid: None,
                        is_heartbeat_alive: false,
                    });
                }
            }
        };

        // 2. Check candidate IPs for loopback tunnel reachability
        let candidate_ips = [self.host.as_str(), "10.7.1.1", "10.7.0.1", "127.0.0.1"];
        let mut active_ip = None;
        for &ip in &candidate_ips {
            if LockdownClient::test_tunnel_reachability(ip, self.port) {
                active_ip = Some(ip.to_string());
                break;
            }
        }

        if let Some(ref ip) = active_ip {
            self.host = ip.clone();
        } else if !LockdownClient::test_tunnel_reachability(&self.host, self.port) {
            return Ok(LocalDevStatusReport {
                code: LocalDevStatusCode::VpnDisconnected as i32,
                status: "CHƯA BẬT LOCALDEV VPN".to_string(),
                message: format!("Không thể kết nối {}:{}. Hãy bật LocalDevVPN hoặc StosVPN.", self.host, self.port),
                host: self.host.clone(),
                port: self.port,
                udid: Some(pairing.udid.clone()),
                is_heartbeat_alive: false,
            });
        }

        // 3. Try lockdown TLS connection with pairing credentials
        match LockdownClient::connect(&self.host, self.port, &pairing) {
            Ok(_client) => {
                // Ensure heartbeat worker is running in the background
                if !self.heartbeat.is_active() {
                    self.heartbeat.start(pairing.clone(), self.host.clone(), self.port);
                }

                Ok(LocalDevStatusReport {
                    code: LocalDevStatusCode::Live as i32,
                    status: "LOCALDEV LIVE".to_string(),
                    message: format!("Kết nối LocalDev thành công (UDID: {})", pairing.udid),
                    host: self.host.clone(),
                    port: self.port,
                    udid: Some(pairing.udid.clone()),
                    is_heartbeat_alive: true,
                })
            }
            Err(e) => {
                if e.contains("Permission denied") || e.contains("Operation not permitted") {
                    Ok(LocalDevStatusReport {
                        code: LocalDevStatusCode::LocalNetworkDenied as i32,
                        status: "CHƯA CẤP QUYỀN MẠNG CỤC BỘ".to_string(),
                        message: "Ứng dụng chưa được cấp quyền Mạng cục bộ trong Cài đặt iPhone.".to_string(),
                        host: self.host.clone(),
                        port: self.port,
                        udid: Some(pairing.udid.clone()),
                        is_heartbeat_alive: false,
                    })
                } else {
                    Ok(LocalDevStatusReport {
                        code: LocalDevStatusCode::PairingExpiredOrCorrupt as i32,
                        status: "PAIRING FILE HẾT HẠN / LỖI".to_string(),
                        message: format!("Xác thực thất bại: {}. Hãy tạo lại file pairing mới.", e),
                        host: self.host.clone(),
                        port: self.port,
                        udid: Some(pairing.udid.clone()),
                        is_heartbeat_alive: false,
                    })
                }
            }
        }
    }

    /// Scans installed applications over installation_proxy
    pub fn scan_apps(&mut self) -> Result<Vec<LocalDevAppInfo>, String> {
        let pairing = self.active_pairing.as_ref().ok_or_else(|| "Chưa có pairing file".to_string())?;
        AppScanner::scan_user_apps(&self.host, self.port, pairing)
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
