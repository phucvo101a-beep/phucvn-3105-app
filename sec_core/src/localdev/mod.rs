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
pub struct TunnelCandidate {
    pub host: String,
    #[serde(default = "default_tunnel_port")]
    pub port: u16,
    #[serde(default)]
    pub iface: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
}

fn default_tunnel_port() -> u16 {
    DEFAULT_LOCKDOWN_PORT
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalDevStatusReport {
    pub code: i32,
    pub status: String,
    pub message: String,
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub interface_name: Option<String>,
    pub udid: Option<String>,
    pub is_heartbeat_alive: bool,
}

pub struct LocalDevManager {
    pub host: String,
    pub port: u16,
    pub active_iface: Option<String>,
    pub candidates: Vec<TunnelCandidate>,
    pub local_network_state: i32,
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
            active_iface: None,
            candidates: Vec::new(),
            local_network_state: 0,
            storage_dir: None,
            active_pairing: None,
            heartbeat: HeartbeatService::new(),
        }
    }

    /// Updates dynamic tunnel candidate endpoints discovered via Swift `getifaddrs()` (`utun`)
    pub fn set_candidates(&mut self, candidates: Vec<TunnelCandidate>, local_network_state: i32) {
        let mut cleaned = Vec::new();
        for mut c in candidates {
            let trimmed = c.host.trim().to_string();
            if trimmed.is_empty() {
                continue;
            }
            c.host = trimmed;
            if c.port == 0 {
                c.port = self.port;
            }
            if !cleaned.iter().any(|e: &TunnelCandidate| e.host == c.host && e.port == c.port) {
                cleaned.push(c);
            }
        }
        if let Some(first) = cleaned.first() {
            if self.active_iface.is_none() || self.host == "127.0.0.1" {
                self.host = first.host.clone();
                self.port = first.port;
                self.active_iface = first.iface.clone();
            }
        }
        self.candidates = cleaned;
        self.local_network_state = local_network_state;
    }

    pub fn effective_candidates(&self) -> Vec<TunnelCandidate> {
        let mut ordered: Vec<TunnelCandidate> = Vec::new();
        let mut push_unique = |cand: TunnelCandidate| {
            let trimmed = cand.host.trim();
            if trimmed.is_empty() {
                return;
            }
            let port = if cand.port > 0 { cand.port } else { DEFAULT_LOCKDOWN_PORT };
            if !ordered.iter().any(|e| e.host == trimmed && e.port == port) {
                ordered.push(TunnelCandidate {
                    host: trimmed.to_string(),
                    port,
                    iface: cand.iface,
                    source: cand.source,
                });
            }
        };

        // Keep previously verified working non-loopback endpoint first only if still listed or live
        if self.active_iface.is_some() && self.host != "127.0.0.1" {
            let present = self
                .candidates
                .iter()
                .find(|c| c.host == self.host && c.port == self.port)
                .cloned();
            if let Some(c) = present {
                push_unique(c);
            }
        }

        for c in &self.candidates {
            push_unique(c.clone());
        }

        if self.host != "127.0.0.1" && !self.host.trim().is_empty() {
            push_unique(TunnelCandidate {
                host: self.host.clone(),
                port: self.port,
                iface: self.active_iface.clone(),
                source: Some("configured-host".to_string()),
            });
        }

        for (ip, src) in [
            ("10.7.0.1", "standard-localdev"),
            ("10.7.0.0", "standard-localdev"),
            ("127.0.0.1", "loopback-fallback"),
        ] {
            push_unique(TunnelCandidate {
                host: ip.to_string(),
                port: DEFAULT_LOCKDOWN_PORT,
                iface: if ip == "127.0.0.1" { Some("lo0".to_string()) } else { None },
                source: Some(src.to_string()),
            });
        }

        ordered
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
                let probe_hosts: Vec<String> = self
                    .effective_candidates()
                    .into_iter()
                    .filter(|c| c.host != "127.0.0.1")
                    .map(|c| c.host)
                    .collect();
                let rsd_notes = tunnel::probe_rsd_and_remotepairing(&probe_hosts);
                Ok(remote_pairing_unsupported_report(
                    self.host.clone(),
                    self.port,
                    self.active_iface.clone(),
                    &rsd_notes,
                ))
            }
            Err(err) => Err(err),
        }
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
                let probe_hosts: Vec<String> = self
                    .effective_candidates()
                    .into_iter()
                    .filter(|c| c.host != "127.0.0.1")
                    .map(|c| c.host)
                    .collect();
                let rsd_notes = tunnel::probe_rsd_and_remotepairing(&probe_hosts);
                return Ok(remote_pairing_unsupported_report(
                    self.host.clone(),
                    self.port,
                    self.active_iface.clone(),
                    &rsd_notes,
                ));
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
                            let probe_hosts: Vec<String> = self
                                .effective_candidates()
                                .into_iter()
                                .filter(|c| c.host != "127.0.0.1")
                                .map(|c| c.host)
                                .collect();
                            let rsd_notes = tunnel::probe_rsd_and_remotepairing(&probe_hosts);
                            return Ok(remote_pairing_unsupported_report(
                                self.host.clone(),
                                self.port,
                                self.active_iface.clone(),
                                &rsd_notes,
                            ));
                        }
                        Err(err) => {
                            self.heartbeat.stop();
                            return Ok(LocalDevStatusReport {
                                code: LocalDevStatusCode::PairingExpiredOrCorrupt as i32,
                                status: "PAIRING FILE HẾT HẠN / LỖI".to_string(),
                                message: format!("Không thể phân tích tệp pairing đã lưu: {}", err),
                                host: self.host.clone(),
                                port: self.port,
                                interface_name: self.active_iface.clone(),
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
                    interface_name: self.active_iface.clone(),
                    udid: None,
                    is_heartbeat_alive: false,
                });
            }
        };

        // 2. Probe all dynamic candidates sequentially (`utun dstaddr` -> `10.7.0.1` -> `10.7.0.0` -> `127.0.0.1`)
        let candidates = self.effective_candidates();
        let mut attempts: Vec<EndpointAttempt> = Vec::with_capacity(candidates.len());

        for cand in candidates {
            match LockdownClient::connect_with_retry(
                &cand.host,
                cand.port,
                &pairing,
                MAX_HANDSHAKE_ATTEMPTS,
            ) {
                Ok(client) => {
                    self.host = cand.host.clone();
                    self.port = cand.port;
                    self.active_iface = cand.iface.clone();

                    let verified_udid = client
                        .device_udid
                        .filter(|u| !u.is_empty())
                        .unwrap_or_else(|| pairing.udid.clone());

                    if !self.heartbeat.is_active() {
                        self.heartbeat
                            .start(pairing.clone(), self.host.clone(), self.port);
                    }

                    let via_str = cand
                        .iface
                        .as_deref()
                        .map(|i| format!(" qua {}", i))
                        .unwrap_or_default();

                    return Ok(LocalDevStatusReport {
                        code: LocalDevStatusCode::Live as i32,
                        status: "LOCALDEV LIVE".to_string(),
                        message: format!(
                            "Kết nối LocalDev thành công tại {}:{}{} (UDID: {})",
                            self.host, self.port, via_str, verified_udid
                        ),
                        host: self.host.clone(),
                        port: self.port,
                        interface_name: self.active_iface.clone(),
                        udid: Some(verified_udid),
                        is_heartbeat_alive: true,
                    });
                }
                Err(err) => {
                    attempts.push(EndpointAttempt { cand, err });
                }
            }
        }

        let probe_hosts: Vec<String> = self
            .effective_candidates()
            .into_iter()
            .filter(|c| c.host != "127.0.0.1")
            .map(|c| c.host)
            .collect();
        let rsd_notes = if attempts
            .iter()
            .any(|a| matches!(a.err.kind, LockdownErrorKind::SocketReset | LockdownErrorKind::ProtocolError))
        {
            tunnel::probe_rsd_and_remotepairing(&probe_hosts)
        } else {
            Vec::new()
        };

        Ok(build_multi_failure_report(
            &attempts,
            self.local_network_state,
            &pairing.udid,
            &rsd_notes,
        ))
    }

    /// Scans installed applications over `installation_proxy`
    pub fn scan_apps(&mut self) -> Result<Vec<apps::LocalDevAppInfo>, String> {
        let pairing = self
            .active_pairing
            .as_ref()
            .ok_or_else(|| "Chưa có pairing file".to_string())?;
        let candidate_pairs: Vec<(String, u16)> = self
            .effective_candidates()
            .into_iter()
            .map(|c| (c.host, c.port))
            .collect();
        let (apps, connected_host, connected_port) =
            apps::AppScanner::scan_user_apps_with_candidates(&candidate_pairs, pairing)?;
        self.host = connected_host;
        self.port = connected_port;
        Ok(apps)
    }
}

struct EndpointAttempt {
    cand: TunnelCandidate,
    err: LockdownError,
}

fn format_attempts_summary(attempts: &[EndpointAttempt]) -> String {
    attempts
        .iter()
        .map(|a| {
            let via = a
                .cand
                .iface
                .as_deref()
                .map(|i| format!(" [{}]", i))
                .unwrap_or_default();
            format!("{}:{}{} -> {}", a.cand.host, a.cand.port, via, a.err.errno_label())
        })
        .collect::<Vec<_>>()
        .join(" | ")
}

fn build_multi_failure_report(
    attempts: &[EndpointAttempt],
    local_network_state: i32,
    udid: &str,
    rsd_notes: &[String],
) -> LocalDevStatusReport {
    let summary = format_attempts_summary(attempts);
    let fallback = EndpointAttempt {
        cand: TunnelCandidate {
            host: DEFAULT_LOCALDEV_IP.to_string(),
            port: DEFAULT_LOCKDOWN_PORT,
            iface: None,
            source: None,
        },
        err: LockdownError::new(
            LockdownErrorKind::TunnelUnreachable,
            LockdownStage::TcpConnect,
            "Không có phản hồi từ tunnel LocalDev",
        ),
    };

    // 1. Pairing rejected on any endpoint takes highest diagnostic precedence
    if let Some(a) = attempts
        .iter()
        .find(|a| a.err.kind == LockdownErrorKind::PairingRejected)
    {
        return LocalDevStatusReport {
            code: LocalDevStatusCode::PairingExpiredOrCorrupt as i32,
            status: "PAIRING FILE HẾT HẠN / LỖI".to_string(),
            message: format!(
                "Thiết bị tại {}:{} từ chối tệp pairing ở bước [{}]: {}. Thử: [{}]",
                a.cand.host, a.cand.port, a.err.stage, a.err.detail, summary
            ),
            host: a.cand.host.clone(),
            port: a.cand.port,
            interface_name: a.cand.iface.clone(),
            udid: Some(udid.to_string()),
            is_heartbeat_alive: false,
        };
    }

    // 2. TCP connected then reset/protocol mismatch
    if let Some(a) = attempts.iter().find(|a| {
        matches!(
            a.err.kind,
            LockdownErrorKind::SocketReset | LockdownErrorKind::ProtocolError
        )
    }) {
        let via = a
            .cand
            .iface
            .as_deref()
            .map(|i| format!(" ({})", i))
            .unwrap_or_default();
        let rsd_suffix = if rsd_notes.is_empty() {
            String::new()
        } else {
            format!(" | Dò RSD/RP: [{}]", rsd_notes.join(", "))
        };
        return LocalDevStatusReport {
            code: LocalDevStatusCode::TunnelReset as i32,
            status: "SOCKET/DAEMON RESET KHI BẮT TAY".to_string(),
            message: format!(
                "Socket {}:{}{} bị ngắt ở bước [{}] ({}). Thử: [{}]{}. Trên iOS 27.2.1 hãy kiểm tra tệp pairing Lockdown (HostCertificate/HostID còn hiệu lực) hoặc cấu hình LocalDevVPN; Sandbox & Nhật ký USB vẫn hoạt động bình thường.",
                a.cand.host, a.cand.port, via, a.err.stage, a.err.detail, summary, rsd_suffix
            ),
            host: a.cand.host.clone(),
            port: a.cand.port,
            interface_name: a.cand.iface.clone(),
            udid: Some(udid.to_string()),
            is_heartbeat_alive: false,
        };
    }

    // Prefer reporting real `utun` / non-loopback endpoint before loopback fallback
    let primary = attempts
        .iter()
        .find(|a| a.cand.host != "127.0.0.1")
        .or_else(|| attempts.first())
        .unwrap_or(&fallback);
    let primary_via = primary
        .cand
        .iface
        .as_deref()
        .map(|i| format!(" qua {}", i))
        .unwrap_or_default();

    let (bundle_id, _, _) = crate::integrity::read_bundle_identity();
    if bundle_id.starts_with("com.apple.")
        && attempts
            .iter()
            .any(|a| a.err.kind == LockdownErrorKind::PermissionDenied)
    {
        return LocalDevStatusReport {
            code: LocalDevStatusCode::LocalNetworkDenied as i32,
            status: "BỊ CHẶN DO BUNDLE ID HỆ THỐNG".to_string(),
            message: format!(
                "Bundle ID '{}' có tiền tố 'com.apple.' khiến iOS 26/27 ẩn công tắc Mạng cục bộ. Endpoint thử: [{}]",
                bundle_id, summary
            ),
            host: primary.cand.host.clone(),
            port: primary.cand.port,
            interface_name: primary.cand.iface.clone(),
            udid: Some(udid.to_string()),
            is_heartbeat_alive: false,
        };
    }

    // 3. Do NOT lump every EPERM into "CHƯA CẤP QUYỀN MẠNG CỤC BỘ" when Local Network is already confirmed OK
    // or when `utun` timed out / refused while only loopback `127.0.0.1` hit `EPERM`.
    let has_utun_network_failure = attempts
        .iter()
        .any(|a| a.cand.host != "127.0.0.1" && a.err.kind != LockdownErrorKind::PermissionDenied);

    if local_network_state == -1
        || (local_network_state == 0
            && !has_utun_network_failure
            && attempts
                .iter()
                .any(|a| a.cand.host != "127.0.0.1" && a.err.kind == LockdownErrorKind::PermissionDenied))
    {
        return LocalDevStatusReport {
            code: LocalDevStatusCode::LocalNetworkDenied as i32,
            status: "CHƯA CẤP QUYỀN MẠNG CỤC BỘ".to_string(),
            message: format!(
                "Kết nối tới {}:{}{} bị từ chối ({}). Hãy bật 'Mạng cục bộ' trong Cài đặt -> 3105 x PHUCVN hoặc bấm 'Kích hoạt quyền Mạng cục bộ'. Chi tiết thử: [{}]",
                primary.cand.host,
                primary.cand.port,
                primary_via,
                primary.err.errno_label(),
                summary
            ),
            host: primary.cand.host.clone(),
            port: primary.cand.port,
            interface_name: primary.cand.iface.clone(),
            udid: Some(udid.to_string()),
            is_heartbeat_alive: false,
        };
    }

    let status_title = if primary.err.kind == LockdownErrorKind::PermissionDenied {
        "MẠNG CỤC BỘ ĐÃ BẬT — LỖI POLICY TUNNEL"
    } else {
        "CHƯA BẬT / KHÔNG TỚI ĐƯỢC LOCALDEV VPN"
    };

    LocalDevStatusReport {
        code: LocalDevStatusCode::VpnDisconnected as i32,
        status: status_title.to_string(),
        message: format!(
            "Đã kiểm tra Mạng cục bộ OK nhưng không kết nối được tunnel (ưu tiên {}:{}{}: {}). Kết quả từng endpoint: [{}]. Hãy mở app LocalDevVPN đảm bảo VPN Connected (utun đang chạy).",
            primary.cand.host,
            primary.cand.port,
            primary_via,
            primary.err.errno_label(),
            summary
        ),
        host: primary.cand.host.clone(),
        port: primary.cand.port,
        interface_name: primary.cand.iface.clone(),
        udid: Some(udid.to_string()),
        is_heartbeat_alive: false,
    }
}

fn remote_pairing_unsupported_report(
    host: String,
    port: u16,
    iface: Option<String>,
    rsd_notes: &[String],
) -> LocalDevStatusReport {
    let rsd_info = if rsd_notes.is_empty() {
        "Chưa phát hiện cổng RSD:58783/RP:49152 mở sẵn trên utun".to_string()
    } else {
        format!("Dò tunnel: [{}]", rsd_notes.join(", "))
    };
    LocalDevStatusReport {
        code: LocalDevStatusCode::RemotePairingUnsupported as i32,
        status: "REMOTE PAIRING / CHƯA CÓ X.509 LOCKDOWN".to_string(),
        message: format!(
            "Đã nhận diện file Remote Pairing (public_key/private_key/identifier/alt_irk). {} — Core libsec_core.dylib hiện kết nối AFC/HouseArrest qua Direct Lockdown X.509 (`HostCertificate` + `HostPrivateKey` trên cổng 62078), chưa bao gồm đầy đủ ngăn xếp TLS-PSK/CDTunnel/RemoteXPC HTTP2 cho RPPairing. Hãy xuất pairing chuẩn Lockdown X.509 hoặc tắt LocalDev để dùng thẳng Sandbox & Nhật ký USB.",
            rsd_info
        ),
        host,
        port,
        interface_name: iface,
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
