//! LocalDev Core Module for iOS 15.0 - iOS 27.2.1
//! Dual-Stack RemotePairing/RSD (`10.7.0.1:49152` priority) + Lockdown (`62078` fallback),
//! AFC & House Arrest File Management

pub mod afc_client;
pub mod apps;
pub mod ffi;
pub mod heartbeat;
pub mod house_arrest;
pub mod mobilebackup2;
pub mod pairing;
pub mod plist_util;
pub mod rsd;
pub mod tls_psk;
pub mod tunnel;

use afc_client::AfcClient;
use heartbeat::HeartbeatService;
use house_arrest::{HouseArrestClient, HouseArrestDirItem, ERR_SANDBOX_LOCKED_APPSTORE};
use mobilebackup2::{Mb2ExtractReport, MobileBackup2Client};
use obfstr::obfstr;
use pairing::UnifiedPairing;
use rsd::RsdTunnelSession;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;
use tunnel::{
    LockdownClient, LockdownError, LockdownErrorKind, LockdownStage, LockdownStream,
    DEFAULT_LOCALDEV_IP, DEFAULT_LOCKDOWN_PORT, DEFAULT_REMOTE_PAIRING_PORT, MAX_HANDSHAKE_ATTEMPTS,
};

/// Status Codes: distinguishes Pairing file validity, VPN/socket resets, and Remote Pairing state
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
    DEFAULT_REMOTE_PAIRING_PORT
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
    pub active_pairing: Option<UnifiedPairing>,
    pub active_rsd: Option<RsdTunnelSession>,
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
            port: DEFAULT_REMOTE_PAIRING_PORT,
            active_iface: None,
            candidates: Vec::new(),
            local_network_state: 0,
            storage_dir: None,
            active_pairing: None,
            active_rsd: None,
            heartbeat: HeartbeatService::new(),
        }
    }

    fn reset_active_connections(&mut self) {
        self.heartbeat.stop();
        if let Some(sess) = self.active_rsd.take() {
            sess.close();
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

    /// Ordered non-loopback `utun` hosts (`10.7.0.1` / `dstaddr` / peer -> IPv6 -> `127.0.0.1` last) paired with `target_port`.
    pub fn effective_candidates_for_port(&self, target_port: u16) -> Vec<TunnelCandidate> {
        let mut ordered: Vec<TunnelCandidate> = Vec::new();
        let mut push_host = |host: &str, port: u16, iface: Option<String>, source: Option<String>| {
            let trimmed = host.trim();
            if trimmed.is_empty() {
                return;
            }
            if !ordered.iter().any(|e| e.host == trimmed && e.port == port) {
                ordered.push(TunnelCandidate {
                    host: trimmed.to_string(),
                    port,
                    iface,
                    source,
                });
            }
        };

        if self.active_iface.is_some() && self.host != "127.0.0.1" {
            if let Some(c) = self.candidates.iter().find(|c| c.host == self.host) {
                push_host(&c.host, target_port, c.iface.clone(), c.source.clone());
            }
        }

        // First pass: non-loopback `utun` addresses
        for c in &self.candidates {
            if c.host != "127.0.0.1" {
                push_host(&c.host, target_port, c.iface.clone(), c.source.clone());
            }
        }

        if self.host != "127.0.0.1" && !self.host.trim().is_empty() {
            push_host(&self.host, target_port, self.active_iface.clone(), Some("configured-host".to_string()));
        }

        for (ip, src) in [("10.7.0.1", "standard-localdev"), ("10.7.0.0", "standard-localdev")] {
            push_host(ip, target_port, None, Some(src.to_string()));
        }

        // Loopback strictly last fallback
        for c in &self.candidates {
            if c.host == "127.0.0.1" {
                push_host(&c.host, target_port, c.iface.clone(), c.source.clone());
            }
        }
        push_host("127.0.0.1", target_port, Some("lo0".to_string()), Some("loopback-fallback".to_string()));

        ordered
    }

    pub fn effective_candidates(&self) -> Vec<TunnelCandidate> {
        let preferred_port = self
            .active_pairing
            .as_ref()
            .and_then(|p| p.tunnel_port)
            .unwrap_or(DEFAULT_REMOTE_PAIRING_PORT);
        let mut combined = self.effective_candidates_for_port(preferred_port);
        for c in &self.candidates {
            if c.port > 0 && !combined.iter().any(|e| e.host == c.host && e.port == c.port) {
                combined.push(c.clone());
            }
        }
        combined
    }

    /// Initializes storage directory and loads saved pairing file (RemotePairing and/or Lockdown)
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
            if let Some(Ok(loaded)) = UnifiedPairing::load_any_from_dir(&path) {
                self.active_pairing = Some(loaded);
            }
        }
    }

    /// Imports a new pairing file (Remote Pairing `idevice_pair v1.2.0`, Lockdown X.509, or composite)
    pub fn import_pairing(&mut self, data: &[u8]) -> Result<LocalDevStatusReport, String> {
        let parsed = UnifiedPairing::parse(data)?;
        self.reset_active_connections();
        if let Some(ref dir) = self.storage_dir {
            parsed.save_to_dir(dir)?;
        }
        if let Some(custom_port) = parsed.tunnel_port {
            self.port = custom_port;
        } else if parsed.remote.is_some() {
            self.port = DEFAULT_REMOTE_PAIRING_PORT;
        }
        self.active_pairing = Some(parsed);
        self.check_status_report()
    }

    /// Evaluates current LocalDev status prioritizing `10.7.0.1:49152` RemotePairing/RSD over `62078` Lockdown.
    pub fn check_status_report(&mut self) -> Result<LocalDevStatusReport, String> {
        if let Some(ref dir) = self.storage_dir {
            match UnifiedPairing::load_any_from_dir(dir) {
                None => {
                    self.active_pairing = None;
                    self.reset_active_connections();
                }
                Some(Ok(loaded)) => {
                    let changed = self.active_pairing.as_ref().is_none_or(|cur| {
                        cur.udid != loaded.udid
                            || cur.remote.is_some() != loaded.remote.is_some()
                            || cur.lockdown.is_some() != loaded.lockdown.is_some()
                            || cur.tunnel_port != loaded.tunnel_port
                    });
                    if changed {
                        self.reset_active_connections();
                        self.active_pairing = Some(loaded);
                    }
                }
                Some(Err(err)) => {
                    self.active_pairing = None;
                    self.reset_active_connections();
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

        let pairing = match &self.active_pairing {
            Some(p) => p.clone(),
            None => {
                return Ok(LocalDevStatusReport {
                    code: LocalDevStatusCode::MissingPairing as i32,
                    status: "CHƯA CÓ PAIRING FILE".to_string(),
                    message: "Vui lòng nhập tệp pairing (Remote Pairing hoặc .mobiledevicepairing) để kết nối LocalDev (Sandbox & Nhật ký USB vẫn dùng bình thường).".to_string(),
                    host: self.host.clone(),
                    port: self.port,
                    interface_name: self.active_iface.clone(),
                    udid: None,
                    is_heartbeat_alive: false,
                });
            }
        };

        // Reuse active verified RSD tunnel if healthy
        if let Some(ref sess) = self.active_rsd {
            if sess.verify_alive().is_ok() {
                let iface_label = sess.endpoint_iface_label();
                self.host = sess.endpoint_host.clone();
                self.port = sess.endpoint_port;
                self.active_iface = sess.iface.clone();
                let verified_udid = if sess.udid.is_empty() {
                    pairing.udid.clone()
                } else {
                    sess.udid.clone()
                };
                return Ok(LocalDevStatusReport {
                    code: LocalDevStatusCode::Live as i32,
                    status: "LOCALDEV LIVE".to_string(),
                    message: format_live_rsd_message(
                        &self.host,
                        self.port,
                        &iface_label,
                        &verified_udid,
                        sess.product_type.as_deref(),
                        sess.os_version.as_deref(),
                        sess.services.len(),
                    ),
                    host: self.host.clone(),
                    port: self.port,
                    interface_name: Some(iface_label),
                    udid: Some(verified_udid),
                    is_heartbeat_alive: true,
                });
            }
            if let Some(stale) = self.active_rsd.take() {
                stale.close();
            }
        }

        // Priority #1: Probe RemotePairing / RSD port (`tunnel_port` or `49152`) across active `utun` hosts
        let rp_port = pairing.tunnel_port.unwrap_or(DEFAULT_REMOTE_PAIRING_PORT);
        let rp_candidates = self.effective_candidates_for_port(rp_port);
        let mut rp_attempts: Vec<EndpointAttempt> = Vec::new();
        let mut open_rp_endpoints: Vec<TunnelCandidate> = Vec::new();

        for cand in &rp_candidates {
            if cand.host == "127.0.0.1" && !open_rp_endpoints.is_empty() {
                continue;
            }
            match tunnel::probe_tcp_open(&cand.host, cand.port, Duration::from_millis(800)) {
                Ok(()) => open_rp_endpoints.push(cand.clone()),
                Err(err) => rp_attempts.push(EndpointAttempt {
                    cand: cand.clone(),
                    err,
                }),
            }
        }

        // If `49152` (or custom RemotePairing port) is OPEN on `utun`, commit exclusively to RemotePairing/RSD
        // and NEVER fall back to legacy `62078` LockdownClient (`ECONNRESET / os error 54` on iOS 27.2.1).
        if !open_rp_endpoints.is_empty() {
            let mut rsd_connect_attempts: Vec<EndpointAttempt> = Vec::new();
            let mut saw_not_rp_and_no_lockdown = false;

            for cand in open_rp_endpoints {
                if let Some(ref rp_file) = pairing.remote {
                    match RsdTunnelSession::connect_remote_pairing(
                        &cand.host,
                        cand.port,
                        cand.iface.clone(),
                        rp_file,
                    ) {
                        Ok(session) => {
                            return Ok(self.activate_rsd_session(session, &pairing.udid));
                        }
                        Err(err) => {
                            rsd_connect_attempts.push(EndpointAttempt { cand, err });
                        }
                    }
                } else {
                    // Only classic Lockdown file present while `49152` is OPEN: try Direct HTTP/2 RSD just in case
                    match RsdTunnelSession::connect_direct_rsd(
                        &cand.host,
                        cand.port,
                        cand.iface.clone(),
                    ) {
                        Ok(session) => {
                            return Ok(self.activate_rsd_session(session, &pairing.udid));
                        }
                        Err(err) => {
                            saw_not_rp_and_no_lockdown = true;
                            self.host = cand.host.clone();
                            self.port = cand.port;
                            self.active_iface = cand.iface.clone();
                            rsd_connect_attempts.push(EndpointAttempt { cand, err });
                        }
                    }
                }
            }

            if saw_not_rp_and_no_lockdown && pairing.remote.is_none() {
                let first = rsd_connect_attempts.first();
                let ep_host = first.map(|a| a.cand.host.clone()).unwrap_or_else(|| self.host.clone());
                let ep_port = first.map(|a| a.cand.port).unwrap_or(rp_port);
                let ep_iface = first
                    .and_then(|a| a.cand.iface.clone())
                    .map(|i| format!("{} · RSD", i))
                    .or_else(|| Some("RSD".to_string()));
                return Ok(LocalDevStatusReport {
                    code: LocalDevStatusCode::RemotePairingUnsupported as i32,
                    status: "CẦN FILE REMOTE PAIRING CHO CỔNG 49152".to_string(),
                    message: format!(
                        "Phát hiện cổng RemotePairing/RSD {}:{} đang OPEN (iOS 27.2.1 không dùng cổng Lockdown 62078). Tệp hiện tại là Lockdown X.509 cũ (chỉ có HostCertificate/HostID) — hãy chọn đúng file Remote Pairing từ idevice_pair (Plist/JSON có public_key, private_key, identifier, alt_irk) cho cổng {}.",
                        ep_host, ep_port, ep_port
                    ),
                    host: ep_host,
                    port: ep_port,
                    interface_name: ep_iface,
                    udid: Some(pairing.udid),
                    is_heartbeat_alive: false,
                });
            }

            return Ok(build_multi_failure_report(
                &rsd_connect_attempts,
                self.local_network_state,
                &pairing.udid,
                &[],
            ));
        }

        // Priority #2 (Fallback): Check Direct HTTP/2 RSD on `58783` if open, or classic `62078` Lockdown (older iOS)
        let rsd_58783_candidates = self.effective_candidates_for_port(58783);
        for cand in rsd_58783_candidates.iter().take(2) {
            if cand.host != "127.0.0.1"
                && tunnel::probe_tcp_open(&cand.host, 58783, Duration::from_millis(500)).is_ok()
            {
                if let Ok(session) = RsdTunnelSession::connect_direct_rsd(&cand.host, 58783, cand.iface.clone()) {
                    return Ok(self.activate_rsd_session(session, &pairing.udid));
                }
            }
        }

        let mut all_attempts = Vec::new();
        if let Some(ref lockdown_pairing) = pairing.lockdown {
            let lockdown_candidates = self.effective_candidates_for_port(DEFAULT_LOCKDOWN_PORT);
            for cand in lockdown_candidates {
                match LockdownClient::connect_with_retry(
                    &cand.host,
                    cand.port,
                    lockdown_pairing,
                    MAX_HANDSHAKE_ATTEMPTS,
                ) {
                    Ok(client) => {
                        self.host = cand.host.clone();
                        self.port = cand.port;
                        self.active_iface = cand.iface.clone();
                        let verified_udid = client
                            .device_udid
                            .filter(|u| !u.is_empty())
                            .unwrap_or_else(|| lockdown_pairing.udid.clone());

                        if !self.heartbeat.is_active() {
                            self.heartbeat
                                .start(lockdown_pairing.clone(), self.host.clone(), self.port);
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
                                "Kết nối Lockdown thành công tại {}:{}{} (UDID: {})",
                                self.host, self.port, via_str, verified_udid
                            ),
                            host: self.host.clone(),
                            port: self.port,
                            interface_name: self.active_iface.clone(),
                            udid: Some(verified_udid),
                            is_heartbeat_alive: true,
                        });
                    }
                    Err(err) => all_attempts.push(EndpointAttempt { cand, err }),
                }
            }
        } else {
            all_attempts.extend(rp_attempts);
        }

        let probe_hosts: Vec<String> = rp_candidates
            .iter()
            .filter(|c| c.host != "127.0.0.1")
            .map(|c| c.host.clone())
            .collect();
        let rsd_notes = if all_attempts
            .iter()
            .any(|a| matches!(a.err.kind, LockdownErrorKind::SocketReset | LockdownErrorKind::ProtocolError))
        {
            tunnel::probe_rsd_and_remotepairing(&probe_hosts)
        } else {
            Vec::new()
        };

        Ok(build_multi_failure_report(
            &all_attempts,
            self.local_network_state,
            &pairing.udid,
            &rsd_notes,
        ))
    }

    fn activate_rsd_session(
        &mut self,
        session: RsdTunnelSession,
        fallback_udid: &str,
    ) -> LocalDevStatusReport {
        self.heartbeat.stop();
        if let Some(old) = self.active_rsd.take() {
            old.close();
        }
        let host = session.endpoint_host.clone();
        let port = session.endpoint_port;
        let iface_label = session.endpoint_iface_label();
        let udid = if session.udid.is_empty() {
            fallback_udid.to_string()
        } else {
            session.udid.clone()
        };
        let msg = format_live_rsd_message(
            &host,
            port,
            &iface_label,
            &udid,
            session.product_type.as_deref(),
            session.os_version.as_deref(),
            session.services.len(),
        );
        self.host = host.clone();
        self.port = port;
        self.active_iface = session.iface.clone();
        self.active_rsd = Some(session);

        LocalDevStatusReport {
            code: LocalDevStatusCode::Live as i32,
            status: "LOCALDEV LIVE".to_string(),
            message: msg,
            host,
            port,
            interface_name: Some(iface_label),
            udid: Some(udid),
            is_heartbeat_alive: true,
        }
    }

    fn ensure_backend(&mut self) -> Result<bool, String> {
        if self.active_rsd.is_some() {
            return Ok(true);
        }
        let report = self.check_status_report()?;
        if self.active_rsd.is_some() {
            return Ok(true);
        }
        if report.code == LocalDevStatusCode::Live as i32 {
            return Ok(false);
        }
        Err(report.message)
    }

    fn reconnect_rsd_once(&mut self) -> Result<(), String> {
        if let Some(stale) = self.active_rsd.take() {
            stale.close();
        }
        let report = self.check_status_report()?;
        if self.active_rsd.is_some() {
            Ok(())
        } else {
            Err(report.message)
        }
    }

    /// Scans installed user apps via active RSD (`installation_proxy.shim.remote` / `coredevice.appservice`)
    /// or classic `62078` Lockdown fallback.
    pub fn scan_apps(&mut self) -> Result<Vec<apps::LocalDevAppInfo>, String> {
        if self.ensure_backend()? {
            let first = self
                .active_rsd
                .as_ref()
                .ok_or_else(|| "RSD session unavailable".to_string())?
                .scan_apps();
            if let Ok(apps) = first {
                return Ok(apps);
            }
            if self.reconnect_rsd_once().is_ok() {
                if let Some(ref sess) = self.active_rsd {
                    return sess.scan_apps();
                }
            }
            return first;
        }

        let lockdown_pairing = self
            .active_pairing
            .as_ref()
            .and_then(|p| p.lockdown.as_ref())
            .ok_or_else(|| "Chưa có pairing file Lockdown hợp lệ".to_string())?;
        let candidate_pairs: Vec<(String, u16)> = self
            .effective_candidates_for_port(DEFAULT_LOCKDOWN_PORT)
            .into_iter()
            .map(|c| (c.host, c.port))
            .collect();
        let (apps, connected_host, connected_port) =
            apps::AppScanner::scan_user_apps_with_candidates(&candidate_pairs, lockdown_pairing)?;
        self.host = connected_host;
        self.port = connected_port;
        Ok(apps)
    }

    fn with_afc_client<T>(
        &mut self,
        service_type: i32,
        bundle_id: &str,
        op: impl Fn(AfcClient, String) -> Result<T, String>,
    ) -> Result<T, String> {
        let is_rsd = self.ensure_backend()?;
        let ha_rsd = obfstr!("com.apple.mobile.house_arrest.shim.remote").to_string();
        let ha_classic = obfstr!("com.apple.mobile.house_arrest").to_string();
        let afc2_svc = obfstr!("com.apple.afc2").to_string();
        let afc_rsd = obfstr!("com.apple.afc.shim.remote").to_string();
        let afc_classic = obfstr!("com.apple.afc").to_string();

        if is_rsd {
            let open_pair = |sess: &RsdTunnelSession| -> Result<(AfcClient, String), String> {
                if service_type == ffi::SERVICE_TYPE_HOUSE_ARREST {
                    HouseArrestClient::connect_app_container_with_opener(
                        || {
                            let s = sess.open_checked_in_service(&[ha_rsd.as_str(), ha_classic.as_str()])?;
                            Ok(LockdownStream::RsdTunnel(s))
                        },
                        bundle_id,
                    )
                } else {
                    for (svc, mode) in [
                        (afc2_svc.as_str(), "afc2"),
                        (afc_rsd.as_str(), "afc"),
                        (afc_classic.as_str(), "afc"),
                    ] {
                        if let Ok(s) = sess.open_checked_in_service(&[svc]) {
                            return Ok((AfcClient::new(LockdownStream::RsdTunnel(s)), mode.to_string()));
                        }
                    }
                    Err("RSD không hỗ trợ dịch vụ AFC".to_string())
                }
            };

            let sess = self
                .active_rsd
                .as_ref()
                .ok_or_else(|| "RSD session unavailable".to_string())?;
            let first = open_pair(sess).and_then(|(afc, mode)| op(afc, mode));
            match first {
                Ok(v) => return Ok(v),
                Err(err) if err.contains(ERR_SANDBOX_LOCKED_APPSTORE) => return Err(err),
                Err(err) => {
                    if self.reconnect_rsd_once().is_ok() {
                        if let Some(ref new_sess) = self.active_rsd {
                            if let Ok((afc, mode)) = open_pair(new_sess) {
                                return op(afc, mode);
                            }
                        }
                    }
                    return Err(err);
                }
            }
        }

        let lockdown_pairing = self
            .active_pairing
            .as_ref()
            .and_then(|p| p.lockdown.as_ref())
            .ok_or_else(|| "Chưa có pairing file".to_string())?;
        if service_type == ffi::SERVICE_TYPE_HOUSE_ARREST {
            let (afc, mode) = HouseArrestClient::connect_app_container(
                &self.host,
                self.port,
                lockdown_pairing,
                bundle_id,
            )?;
            op(afc, mode)
        } else {
            let (afc, mode) = AfcClient::connect_device_afc(&self.host, self.port, lockdown_pairing)?;
            op(afc, mode)
        }
    }

    pub fn list_dir_detailed(
        &mut self,
        service_type: i32,
        bundle_id: &str,
        path: &str,
    ) -> Result<(Vec<String>, Vec<HouseArrestDirItem>, String), String> {
        let path_owned = path.to_string();
        self.with_afc_client(service_type, bundle_id, move |mut afc, mode| {
            if service_type == ffi::SERVICE_TYPE_HOUSE_ARREST {
                HouseArrestClient::list_dir_detailed_with_afc(afc, mode, &path_owned)
            } else {
                let entries = afc.list_dir(&path_owned)?;
                let prefix = path_owned.trim_end_matches('/');
                let mut items = Vec::with_capacity(entries.len());
                for name in &entries {
                    let full = if prefix.is_empty() {
                        format!("/{}", name)
                    } else {
                        format!("{}/{}", prefix, name)
                    };
                    let info = afc.get_file_info(&full).unwrap_or_default();
                    let is_dir = info.get("st_ifmt").map(|v| v == "S_IFDIR").unwrap_or(false);
                    let size = if is_dir {
                        -1
                    } else {
                        info.get("st_size")
                            .and_then(|s| s.parse::<i64>().ok())
                            .unwrap_or(0)
                    };
                    items.push(HouseArrestDirItem {
                        name: name.clone(),
                        is_dir,
                        size,
                    });
                }
                Ok((entries, items, mode))
            }
        })
    }

    pub fn read_file(
        &mut self,
        service_type: i32,
        bundle_id: &str,
        path: &str,
    ) -> Result<Vec<u8>, String> {
        let path_owned = path.to_string();
        self.with_afc_client(service_type, bundle_id, move |mut afc, mode| {
            if service_type == ffi::SERVICE_TYPE_HOUSE_ARREST {
                HouseArrestClient::read_file_with_afc(afc, &mode, &path_owned)
            } else {
                afc.read_file_full(&path_owned)
            }
        })
    }

    pub fn write_file(
        &mut self,
        service_type: i32,
        bundle_id: &str,
        path: &str,
        data: &[u8],
    ) -> Result<(), String> {
        let path_owned = path.to_string();
        let data_owned = data.to_vec();
        self.with_afc_client(service_type, bundle_id, move |mut afc, mode| {
            if service_type == ffi::SERVICE_TYPE_HOUSE_ARREST {
                HouseArrestClient::write_file_safe_with_afc(afc, &mode, &path_owned, &data_owned)
            } else {
                if let Ok(existing) = afc.read_file_full(&path_owned) {
                    let backup_path = format!("{}.bak", path_owned);
                    let _ = afc.write_file_full(&backup_path, &existing);
                }
                afc.write_file_full(&path_owned, &data_owned)
            }
        })
    }

    /// Extracts unencrypted `com.apple.mobilebackup2` snapshot over RSD (`10.7.0.1:49152`) or Lockdown
    /// so target `AppDomain-<bundle_id>` files can be recovered into local Sandbox storage.
    pub fn extract_backup_app(
        &mut self,
        bundle_id: &str,
        staging_dir: &str,
        free_bytes: u64,
    ) -> Result<Mb2ExtractReport, String> {
        let clean_bundle = bundle_id.trim();
        let clean_staging = staging_dir.trim();
        if clean_bundle.is_empty() || clean_staging.is_empty() {
            return Err("Thiếu bundle_id hoặc đường dẫn thư mục tạm backup".to_string());
        }

        let mb2_rsd = obfstr!("com.apple.mobilebackup2.shim.remote").to_string();
        let mb2_classic = obfstr!("com.apple.mobilebackup2").to_string();
        let default_udid = self
            .active_pairing
            .as_ref()
            .map(|p| p.udid.clone())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "default-device".to_string());

        let is_rsd = self.ensure_backend()?;
        if is_rsd {
            let mut resolved_udid = default_udid.clone();
            let stream = {
                let sess = self
                    .active_rsd
                    .as_ref()
                    .ok_or_else(|| "RSD session unavailable".to_string())?;
                if !sess.udid.trim().is_empty() {
                    resolved_udid = sess.udid.clone();
                }
                match sess.open_checked_in_service(&[mb2_rsd.as_str(), mb2_classic.as_str()]) {
                    Ok(s) => Ok(s),
                    Err(first_err) => {
                        if self.reconnect_rsd_once().is_ok() {
                            if let Some(ref new_sess) = self.active_rsd {
                                if !new_sess.udid.trim().is_empty() {
                                    resolved_udid = new_sess.udid.clone();
                                }
                                new_sess.open_checked_in_service(&[mb2_rsd.as_str(), mb2_classic.as_str()])
                            } else {
                                Err(first_err)
                            }
                        } else {
                            Err(first_err)
                        }
                    }
                }
            }?;

            let client = MobileBackup2Client::new(LockdownStream::RsdTunnel(stream));
            return client.run_backup_into_staging(
                &resolved_udid,
                clean_bundle,
                std::path::Path::new(clean_staging),
                free_bytes,
            );
        }

        let lockdown_pairing = self
            .active_pairing
            .as_ref()
            .and_then(|p| p.lockdown.as_ref())
            .ok_or_else(|| "Chưa có pairing file hợp lệ để kết nối mobilebackup2".to_string())?;
        let mut lockdown = LockdownClient::connect(&self.host, self.port, lockdown_pairing)?;
        let udid = lockdown
            .device_udid
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or(default_udid);
        let (sock, _, _) = lockdown.start_service(mb2_classic.as_str())?;
        let client = MobileBackup2Client::new(sock);
        client.run_backup_into_staging(
            &udid,
            clean_bundle,
            std::path::Path::new(clean_staging),
            free_bytes,
        )
    }
}

fn format_live_rsd_message(
    host: &str,
    port: u16,
    iface_label: &str,
    udid: &str,
    product_type: Option<&str>,
    os_version: Option<&str>,
    svc_count: usize,
) -> String {
    let hw = match (product_type, os_version) {
        (Some(p), Some(v)) => format!(" · {} iOS {}", p, v),
        (Some(p), None) => format!(" · {}", p),
        _ => String::new(),
    };
    format!(
        "Kết nối RemotePairing/RSD thành công tại {}:{} ({}){} — {} services, UDID: {}",
        host, port, iface_label, hw, svc_count, udid
    )
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
            port: DEFAULT_REMOTE_PAIRING_PORT,
            iface: None,
            source: None,
        },
        err: LockdownError::new(
            LockdownErrorKind::TunnelUnreachable,
            LockdownStage::TcpConnect,
            "Không có phản hồi từ tunnel LocalDev",
        ),
    };

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
                "Socket {}:{}{} bị ngắt ở bước [{}] ({}). Thử: [{}]{}. Hãy kiểm tra tệp Remote Pairing (`idevice_pair`) hoặc khởi động lại LocalDevVPN; Sandbox & Nhật ký USB vẫn hoạt động bình thường.",
                a.cand.host, a.cand.port, via, a.err.stage, a.err.detail, summary, rsd_suffix
            ),
            host: a.cand.host.clone(),
            port: a.cand.port,
            interface_name: a.cand.iface.clone(),
            udid: Some(udid.to_string()),
            is_heartbeat_alive: false,
        };
    }

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

static LOCALDEV_INSTANCE: Mutex<Option<LocalDevManager>> = Mutex::new(None);

pub fn with_manager<F, R>(f: F) -> R
where
    F: FnOnce(&mut LocalDevManager) -> R,
{
    let mut guard = match LOCALDEV_INSTANCE.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    let manager = guard.get_or_insert_with(LocalDevManager::new);
    f(manager)
}
