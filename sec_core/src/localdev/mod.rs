//! LocalDev Core Module for iOS 15.0 - iOS 27.2.1
//! Dual-Stack RemotePairing/RSD (`10.7.0.1:49152` priority) + Lockdown (`62078` fallback),
//! AFC & House Arrest File Management

pub mod afc_client;
pub mod apps;
pub mod ffi;
pub mod fileservice;
pub mod heartbeat;
pub mod house_arrest;
pub mod mobilebackup2;
pub mod pairing;
pub mod plist_util;
pub mod rsd;
pub mod tls_psk;
pub mod tunnel;

use afc_client::AfcClient;
use apps::{app_group_container_path, container_path_from_url, LocalDevAppInfo};
use fileservice::{
    normalize_control_capacity, probe_capabilities, CoreDeviceFileServiceClient,
    CoreDeviceFileServiceError, FileServiceCapabilityReport, FileServiceTargetContext,
    DEFAULT_CONTROL_CAPACITY,
};
use heartbeat::HeartbeatService;
use house_arrest::{HouseArrestClient, HouseArrestDirItem, ERR_SANDBOX_LOCKED_APPSTORE};
use mobilebackup2::{Mb2ExtractReport, MobileBackup2Client};
use obfstr::obfstr;
use pairing::UnifiedPairing;
use rsd::RsdTunnelSession;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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
    #[serde(default)]
    pub trusted_services_count: Option<usize>,
    #[serde(default)]
    pub coredevice_proxy_active: Option<bool>,
    #[serde(default)]
    pub coredevice_tunnel_status: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AirLiftRouteInfo {
    pub attempt: bool,
    pub fallback: bool,
    pub reason: Option<String>,
    pub backend: String,
    pub bundle_id: String,
    pub path: String,
    pub data_container_url: Option<String>,
    pub app_group_identifiers: Vec<String>,
    pub app_group_paths: Vec<String>,
    pub control_capacity: u64,
    pub detail: Option<String>,
    #[serde(default)]
    pub direct_known_path_mode: bool,
    #[serde(default)]
    pub bulk_directory_disabled: bool,
    #[serde(default)]
    pub direct_read_disabled: bool,
    #[serde(default)]
    pub strategy: Option<String>,
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
    pub cached_apps: HashMap<String, LocalDevAppInfo>,
    pub did_scan_for_cache: bool,
    pub last_airlift_route: Option<AirLiftRouteInfo>,
}

impl Default for LocalDevManager {
    fn default() -> Self {
        Self::new()
    }
}

enum ContainerOpenOutcome<T> {
    SessionOpenedOpOk(T, String),
    SessionOpenedOpErr(String, String),
    ContainerRejected(String),
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
            cached_apps: HashMap::new(),
            did_scan_for_cache: false,
            last_airlift_route: None,
        }
    }

    fn reset_active_connections(&mut self) {
        self.heartbeat.stop();
        if let Some(sess) = self.active_rsd.take() {
            sess.close();
        }
        self.did_scan_for_cache = false;
        self.last_airlift_route = None;
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

    /// Ordered candidates prioritizing IPv6 ULA (`fd00::/8`, e.g. `utun5` `fd2b:...::2`/`::1`)
    /// ahead of `10.7.0.1` (`utun4`), with `127.0.0.1` strictly last.
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

        // Pass 1a: Strict IPv6 ULA (`fd00::/8`, Trusted CDTunnel) + derived `::2` & `::1` peers FIRST
        for c in &self.candidates {
            if tunnel::is_strict_ipv6_ula_fd00(&c.host) {
                for ula_host in tunnel::derive_ula_peer_candidates(&c.host) {
                    push_host(&ula_host, target_port, c.iface.clone(), c.source.clone());
                }
            }
        }
        if tunnel::is_strict_ipv6_ula_fd00(&self.host) {
            for ula_host in tunnel::derive_ula_peer_candidates(&self.host) {
                push_host(&ula_host, target_port, self.active_iface.clone(), Some("configured-ula".to_string()));
            }
        }

        // Pass 1b: Other `fc00::/7` ULA candidates
        for c in &self.candidates {
            if tunnel::is_ipv6_ula(&c.host) && !tunnel::is_strict_ipv6_ula_fd00(&c.host) {
                push_host(&c.host, target_port, c.iface.clone(), c.source.clone());
            }
        }

        // Pass 2: Active non-loopback non-ULA interface (if already selected) + remaining `utun` candidates
        if self.active_iface.is_some()
            && self.host != "127.0.0.1"
            && !tunnel::is_ipv6_ula(&self.host)
        {
            if let Some(c) = self.candidates.iter().find(|c| c.host == self.host) {
                push_host(&c.host, target_port, c.iface.clone(), c.source.clone());
            }
        }

        for c in &self.candidates {
            if c.host != "127.0.0.1" && !tunnel::is_ipv6_ula(&c.host) {
                push_host(&c.host, target_port, c.iface.clone(), c.source.clone());
            }
        }

        if self.host != "127.0.0.1"
            && !self.host.trim().is_empty()
            && !tunnel::is_ipv6_ula(&self.host)
        {
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
                        ..Default::default()
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
                    ..Default::default()
                });
            }
        };

        // Reuse active verified RSD tunnel if healthy — unless we only had an untrusted session
        // and a direct fd00::/8 IPv6 ULA Trusted CDTunnel interface just became available.
        let has_fd00_candidate = self
            .candidates
            .iter()
            .any(|c| tunnel::is_strict_ipv6_ula_fd00(&c.host));
        if let Some(ref sess) = self.active_rsd {
            let has_lan_lockdown_upgrade = pairing.lockdown.is_some()
                && !sess.is_trusted_tunnel()
                && self.candidates.iter().any(|c| {
                    c.host != "127.0.0.1"
                        && (c.iface.as_deref().is_some_and(|i| i.starts_with("en"))
                            || c.source.as_deref() == Some("wifi-en0-lockdown"))
                        && tunnel::is_lan_ipv4(&c.host)
                });
            let should_upgrade_to_ula = has_fd00_candidate
                && !sess.is_trusted_tunnel()
                && !tunnel::is_strict_ipv6_ula_fd00(&sess.endpoint_host);
            if !has_lan_lockdown_upgrade && !should_upgrade_to_ula && sess.verify_alive().is_ok() {
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
                        sess.coredevice_tunnel_status.as_deref(),
                    ),
                    host: self.host.clone(),
                    port: self.port,
                    interface_name: Some(iface_label),
                    udid: Some(verified_udid),
                    is_heartbeat_alive: true,
                    trusted_services_count: Some(sess.trusted_services.len()),
                    coredevice_proxy_active: Some(sess.coredevice_proxy_active),
                    coredevice_tunnel_status: sess.coredevice_tunnel_status.clone(),
                });
            }
            if let Some(stale) = self.active_rsd.take() {
                stale.close();
            }
        }

        let rp_port = pairing.tunnel_port.unwrap_or(DEFAULT_REMOTE_PAIRING_PORT);

        // Priority -1 (`strategy=lockdown_first`): Wi-Fi LAN `en0:62078` Lockdown -> CoreDeviceProxy::create_software_tunnel()
        // when valid Lockdown X.509 pairing exists in app sandbox and `127.0.0.1` is excluded.
        if let Some(lan_lockdown_session) = self.probe_and_connect_en0_lockdown_strategy4(&pairing) {
            return Ok(self.activate_rsd_session(lan_lockdown_session, &pairing.udid));
        }

        // Priority #0: Direct connection to Trusted CDTunnel IPv6 ULA (`fd00::/8`, e.g. utun5 `fd2b:...::2`/`::1`)
        // across ports `49152`, `58783`, and mDNS (`_remotepairing._tcp` / `_remoted._tcp`) ahead of `10.7.0.1:49152`.
        if has_fd00_candidate {
            if let Some(ula_session) = self.probe_and_connect_ipv6_ula(&pairing, rp_port) {
                return Ok(self.activate_rsd_session(ula_session, &pairing.udid));
            }
        }

        // Priority #1: Probe RemotePairing / RSD port (`tunnel_port` or `49152`) across active `utun` hosts
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
                    match RsdTunnelSession::connect_remote_pairing_with_options(
                        &cand.host,
                        cand.port,
                        cand.iface.clone(),
                        rp_file,
                        pairing.lockdown.as_ref(),
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
                    match RsdTunnelSession::connect_direct_rsd_with_options(
                        &cand.host,
                        cand.port,
                        cand.iface.clone(),
                        pairing.remote.as_ref(),
                        pairing.lockdown.as_ref(),
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
                    ..Default::default()
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
                if let Ok(session) = RsdTunnelSession::connect_direct_rsd_with_options(
                    &cand.host,
                    58783,
                    cand.iface.clone(),
                    pairing.remote.as_ref(),
                    pairing.lockdown.as_ref(),
                ) {
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
                            ..Default::default()
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


fn expand_ula_peer_candidates(candidates: &[TunnelCandidate], fallback_port: u16) -> Vec<(String, u16, Option<String>)> {
    let mut out: Vec<(String, u16, Option<String>)> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for c in candidates {
        if tunnel::is_strict_ipv6_ula_fd00(&c.host) {
            let ports = if c.port > 0 { vec![c.port, 49152, 58783] } else { vec![fallback_port, 49152, 58783] };
            for p in ports {
                let key = format!("{}|{}", c.host, p);
                if seen.insert(key) {
                    out.push((c.host.clone(), p, c.iface.clone()));
                }
            }
            if c.host.ends_with("::1") {
                let peer = format!("{}::2", &c.host[..c.host.len() - 3]);
                for p in [49152_u16, 58783_u16] {
                    let key = format!("{}|{}", peer, p);
                    if seen.insert(key) {
                        out.push((peer.clone(), p, c.iface.clone()));
                    }
                }
            }
        }
    }
    out
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
        let trusted_count = session.trusted_services.len();
        let proxy_active = session.coredevice_proxy_active;
        let tunnel_status = session.coredevice_tunnel_status.clone();
        let msg = format_live_rsd_message(
            &host,
            port,
            &iface_label,
            &udid,
            session.product_type.as_deref(),
            session.os_version.as_deref(),
            session.services.len(),
            tunnel_status.as_deref(),
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
            trusted_services_count: Some(trusted_count),
            coredevice_proxy_active: Some(proxy_active),
            coredevice_tunnel_status: tunnel_status,
        }
    }

    fn ensure_backend(&mut self) -> Result<bool, String> {
        let has_fd00_upgrade = self
            .candidates
            .iter()
            .any(|c| tunnel::is_strict_ipv6_ula_fd00(&c.host))
            && self.active_rsd.as_ref().is_some_and(|s| {
                !s.is_trusted_tunnel() && !tunnel::is_strict_ipv6_ula_fd00(&s.endpoint_host)
            });
        if self.active_rsd.is_some() && !has_fd00_upgrade {
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

    fn probe_and_connect_en0_lockdown_strategy4(
        &self,
        pairing: &UnifiedPairing,
    ) -> Option<RsdTunnelSession> {
        let lockdown_pairing = pairing.lockdown.as_ref()?;
        let mut en_hosts: Vec<(String, Option<String>)> = Vec::new();
        for c in &self.candidates {
            let trimmed = c.host.trim();
            if trimmed.is_empty() || trimmed == "127.0.0.1" || trimmed == "::1" {
                continue;
            }
            let is_en_iface = c
                .iface
                .as_deref()
                .map(|i| i.starts_with("en"))
                .unwrap_or(false)
                || c.source.as_deref() == Some("wifi-en0-lockdown");
            if (is_en_iface || tunnel::is_lan_ipv4(trimmed)) && tunnel::is_lan_ipv4(trimmed) {
                if !en_hosts.iter().any(|(h, _)| h == trimmed) {
                    en_hosts.push((trimmed.to_string(), c.iface.clone()));
                }
            }
        }
        if tunnel::is_lan_ipv4(&self.host)
            && self.host != "127.0.0.1"
            && !en_hosts.iter().any(|(h, _)| h == &self.host)
        {
            en_hosts.push((self.host.clone(), self.active_iface.clone()));
        }

        for (host, iface) in en_hosts {
            if tunnel::probe_tcp_open(&host, DEFAULT_LOCKDOWN_PORT, Duration::from_millis(450)).is_err() {
                continue;
            }
            eprintln!(
                "localdev: strategy=lockdown_first probing {}:{} ({}) -> CoreDeviceProxy::create_software_tunnel()",
                host,
                DEFAULT_LOCKDOWN_PORT,
                iface.as_deref().unwrap_or("en0")
            );
            match RsdTunnelSession::connect_lockdown_coredevice_proxy(
                &host,
                DEFAULT_LOCKDOWN_PORT,
                iface.clone(),
                lockdown_pairing,
            ) {
                Ok(sess) => return Some(sess),
                Err(err) => {
                    eprintln!(
                        "localdev: strategy=lockdown_first {}:{} CoreDeviceProxy fallback: {}",
                        host, DEFAULT_LOCKDOWN_PORT, err
                    );
                }
            }
        }
        None
    }

    fn probe_and_connect_ipv6_ula(
        &self,
        pairing: &UnifiedPairing,
        rp_port: u16,
    ) -> Option<RsdTunnelSession> {
        let mut ula_pairs: Vec<(String, u16, Option<String>)> = Vec::new();
        let mut push_pair = |host: String, port: u16, iface: Option<String>| {
            if port > 0 && !ula_pairs.iter().any(|(h, p, _)| h == &host && *p == port) {
                ula_pairs.push((host, port, iface));
            }
        };

        let mut ula_ports: Vec<u16> = Vec::new();
        for p in [49152u16, 58783u16, rp_port] {
            if p > 0 && !ula_ports.contains(&p) {
                ula_ports.push(p);
            }
        }
        for c in &self.candidates {
            if tunnel::is_strict_ipv6_ula_fd00(&c.host) && c.port > 0 && !ula_ports.contains(&c.port) {
                ula_ports.push(c.port);
            }
        }

        // First try exact candidate host:port pairs (e.g. mDNS-resolved ports on IPv6 ULA)
        for c in &self.candidates {
            if tunnel::is_strict_ipv6_ula_fd00(&c.host) {
                for derived_host in tunnel::derive_ula_peer_candidates(&c.host) {
                    push_pair(derived_host, c.port, c.iface.clone());
                }
            }
        }
        // Then try standard RSD/RP ports (49152, 58783, mdns ports) across all derived ::2 / ::1 ULA hosts
        for port in &ula_ports {
            for c in &self.candidates {
                if tunnel::is_strict_ipv6_ula_fd00(&c.host) {
                    for derived_host in tunnel::derive_ula_peer_candidates(&c.host) {
                        push_pair(derived_host, *port, c.iface.clone());
                    }
                }
            }
        }

        let mut fallback_session: Option<RsdTunnelSession> = None;
        for (host, port, iface) in ula_pairs {
            if tunnel::probe_tcp_open(&host, port, Duration::from_millis(650)).is_err() {
                continue;
            }
            eprintln!(
                "localdev: IPv6 ULA endpoint OPEN at [{}]:{} ({})",
                host,
                port,
                iface.as_deref().unwrap_or("utun")
            );
            if let Ok(sess) = RsdTunnelSession::connect_direct_rsd_with_options(
                &host,
                port,
                iface.clone(),
                pairing.remote.as_ref(),
                pairing.lockdown.as_ref(),
            ) {
                if sess.is_trusted_tunnel() {
                    if let Some(old_fb) = fallback_session.take() {
                        old_fb.close();
                    }
                    return Some(sess);
                }
                if fallback_session.is_none() {
                    fallback_session = Some(sess);
                } else {
                    sess.close();
                }
            }
            if let Some(ref rp_file) = pairing.remote {
                if let Ok(sess) = RsdTunnelSession::connect_remote_pairing_with_options(
                    &host,
                    port,
                    iface.clone(),
                    rp_file,
                    pairing.lockdown.as_ref(),
                ) {
                    if sess.is_trusted_tunnel() {
                        if let Some(old_fb) = fallback_session.take() {
                            old_fb.close();
                        }
                        return Some(sess);
                    }
                    if fallback_session.is_none() {
                        fallback_session = Some(sess);
                    } else {
                        sess.close();
                    }
                }
            }
        }
        fallback_session
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
    pub fn scan_apps(&mut self) -> Result<Vec<LocalDevAppInfo>, String> {
        let result = if self.ensure_backend()? {
            let first = self
                .active_rsd
                .as_ref()
                .ok_or_else(|| "RSD session unavailable".to_string())?
                .scan_apps();
            if first.is_ok() {
                first
            } else if self.reconnect_rsd_once().is_ok() {
                if let Some(ref sess) = self.active_rsd {
                    sess.scan_apps()
                } else {
                    first
                }
            } else {
                first
            }
        } else {
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
        }?;

        self.cache_scanned_apps(&result);
        Ok(result)
    }

    fn cache_scanned_apps(&mut self, apps: &[LocalDevAppInfo]) {
        self.cached_apps.clear();
        for app in apps {
            self.cached_apps.insert(app.bundle_id.clone(), app.clone());
        }
        self.did_scan_for_cache = true;
    }

    fn resolve_target_context(&mut self, bundle_id: &str) -> FileServiceTargetContext {
        let clean_bundle = bundle_id.trim();
        if !clean_bundle.is_empty()
            && !self.cached_apps.contains_key(clean_bundle)
            && !self.did_scan_for_cache
        {
            self.did_scan_for_cache = true;
            if let Ok(apps) = self.scan_apps() {
                self.cache_scanned_apps(&apps);
            }
        }
        if let Some(info) = self.cached_apps.get(clean_bundle) {
            let durl = info
                .data_container_url
                .as_deref()
                .or(info.container_path.as_deref());
            FileServiceTargetContext::from_app_info(
                clean_bundle,
                durl,
                &info.app_group_identifiers,
                &info.app_group_containers,
            )
        } else {
            FileServiceTargetContext::from_app_info(clean_bundle, None, &[], &HashMap::new())
        }
    }

    pub fn probe_fileservice_status(
        &mut self,
        bundle_id: Option<&str>,
        control_capacity: u64,
    ) -> FileServiceCapabilityReport {
        let _ = self.ensure_backend();
        let ctx = bundle_id
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|bid| self.resolve_target_context(bid));
        probe_capabilities(self.active_rsd.as_ref(), ctx.as_ref(), control_capacity)
    }

    fn resolve_local_container_root(&self, ctx: &FileServiceTargetContext) -> Option<PathBuf> {
        let raw_root = ctx.data_container_url.as_deref()?;
        let container_root = container_path_from_url(raw_root);
        let clean = container_root.trim().trim_end_matches('/');
        if clean.is_empty() {
            return None;
        }
        let stripped = clean.strip_prefix("/private").unwrap_or(clean);
        for candidate in [clean, stripped] {
            if candidate.is_empty() {
                continue;
            }
            let p = PathBuf::from(candidate);
            if std::fs::read_dir(&p).is_ok() {
                return Some(p);
            }
        }
        None
    }

    fn record_airlift_route(
        &mut self,
        attempt: bool,
        fallback: bool,
        reason: Option<String>,
        backend: String,
        ctx: &FileServiceTargetContext,
        path: &str,
        cap: u64,
        detail: Option<String>,
        direct_mode: bool,
    ) -> AirLiftRouteInfo {
        let app_group_paths = ctx
            .system_app_group_identifiers
            .iter()
            .map(|gid| {
                ctx.app_group_containers
                    .get(gid)
                    .cloned()
                    .unwrap_or_else(|| app_group_container_path(gid))
            })
            .collect();
        let strategy = self
            .active_rsd
            .as_ref()
            .and_then(|s| s.coredevice_tunnel_status.as_deref())
            .and_then(|st| {
                st.contains("strategy=lockdown_first")
                    .then(|| "lockdown_first".to_string())
            });
        let info = AirLiftRouteInfo {
            attempt,
            fallback,
            reason,
            backend,
            bundle_id: ctx.bundle_id.clone(),
            path: path.to_string(),
            data_container_url: ctx.data_container_url.clone(),
            app_group_identifiers: ctx.system_app_group_identifiers.clone(),
            app_group_paths,
            control_capacity: cap,
            detail,
            direct_known_path_mode: direct_mode,
            bulk_directory_disabled: direct_mode,
            direct_read_disabled: direct_mode,
            strategy,
        };
        eprintln!(
            "patch.airlift attempt={} fallback={} reason={} backend={} bundle={} path={} direct_known_path={} strategy={} detail={}",
            info.attempt,
            info.fallback,
            info.reason.as_deref().unwrap_or("none"),
            info.backend,
            info.bundle_id,
            info.path,
            info.direct_known_path_mode,
            info.strategy.as_deref().unwrap_or("rsd"),
            info.detail.as_deref().unwrap_or("ok")
        );
        self.last_airlift_route = Some(info.clone());
        info
    }

    /// Routes app container file operations strictly across:
    /// 1) `com.apple.coredevice.fileservice.data` (`DataContainerURL` / `AppGroup`)
    /// 2) `HouseArrest` (`VendContainer` -> `VendDocuments`)
    /// 3) Local TrollStore / Jailbreak container path `/var/mobile/Containers/Data/Application/<UUID>` (when directly readable)
    /// Never falls back to `com.apple.afc.shim.remote` (`/var/mobile/Media`) for an app bundle ID.
    fn execute_airlift_app_op<T>(
        &mut self,
        bundle_id: &str,
        path: &str,
        control_capacity: u64,
        fs_op: impl Fn(&mut CoreDeviceFileServiceClient, &FileServiceTargetContext, &str) -> Result<T, CoreDeviceFileServiceError>,
        afc_op: impl Fn(AfcClient, String, &str) -> Result<T, String>,
        local_op: impl Fn(&std::path::Path, &str) -> Result<T, String>,
    ) -> Result<(T, AirLiftRouteInfo), String> {
        self.execute_airlift_app_op_with_mode(
            bundle_id,
            path,
            control_capacity,
            false,
            fs_op,
            afc_op,
            local_op,
        )
    }

    fn execute_airlift_app_op_with_mode<T>(
        &mut self,
        bundle_id: &str,
        path: &str,
        control_capacity: u64,
        direct_mode: bool,
        fs_op: impl Fn(&mut CoreDeviceFileServiceClient, &FileServiceTargetContext, &str) -> Result<T, CoreDeviceFileServiceError>,
        afc_op: impl Fn(AfcClient, String, &str) -> Result<T, String>,
        local_op: impl Fn(&std::path::Path, &str) -> Result<T, String>,
    ) -> Result<(T, AirLiftRouteInfo), String> {
        let cap = normalize_control_capacity(control_capacity);
        let ctx = self.resolve_target_context(bundle_id);
        let is_rsd = self.ensure_backend()?;

        let mut fs_reason = "unavailable".to_string();
        let mut fs_detail = "Lockdown mode (RSD FileService unavailable)".to_string();

        // Step 1 (attempt=true): Try `com.apple.coredevice.fileservice.controlcapacity` + `.data` first
        if is_rsd {
            let fs_res = {
                let sess = self
                    .active_rsd
                    .as_ref()
                    .ok_or_else(|| "RSD session unavailable".to_string())?;
                CoreDeviceFileServiceClient::connect_blocking(sess, cap).and_then(|mut client| {
                    if direct_mode {
                        client.set_direct_known_path_mode(true);
                    }
                    fs_op(&mut client, &ctx, path)
                })
            };
            match fs_res {
                Ok(val) => {
                    let route = self.record_airlift_route(
                        true,
                        false,
                        None,
                        "coredevice.fileservice.data".to_string(),
                        &ctx,
                        path,
                        cap,
                        ctx.data_container_url.clone(),
                        direct_mode,
                    );
                    return Ok((val, route));
                }
                Err(err) => {
                    fs_reason = err.reason.as_str().to_string();
                    fs_detail = err.detail;
                }
            }
        }

        // Step 2 (fallback=true): Downgrade sequentially to HouseArrest (`VendContainer` -> `VendDocuments`).
        // Distinguish container-level refusal (`SANDBOX_LOCKED_APPSTORE`) from post-open AFC file errors.
        let ha_outcome = self.try_house_arrest_only(bundle_id, |afc, mode| {
            let backend_label = format!("house_arrest.{}", mode);
            (afc_op(afc, mode, path), backend_label)
        });

        match ha_outcome {
            ContainerOpenOutcome::SessionOpenedOpOk(val, backend_label) => {
                let route = self.record_airlift_route(
                    true,
                    true,
                    Some(fs_reason),
                    backend_label,
                    &ctx,
                    path,
                    cap,
                    Some(fs_detail),
                    direct_mode,
                );
                Ok((val, route))
            }
            ContainerOpenOutcome::SessionOpenedOpErr(afc_err, backend_label) => {
                self.record_airlift_route(
                    true,
                    true,
                    Some(fs_reason),
                    backend_label,
                    &ctx,
                    path,
                    cap,
                    Some(afc_err.clone()),
                    direct_mode,
                );
                Err(afc_err)
            }
            ContainerOpenOutcome::ContainerRejected(ha_err) => {
                // Step 3: Local `/var/mobile/Containers/Data/Application/<UUID>` ONLY on TrollStore / Jailbreak
                if let Some(local_root) = self.resolve_local_container_root(&ctx) {
                    let target = safe_join_local_container(&local_root, path)?;
                    match local_op(&target, path) {
                        Ok(val) => {
                            let route = self.record_airlift_route(
                                true,
                                true,
                                Some(fs_reason),
                                "local_container_fs".to_string(),
                                &ctx,
                                path,
                                cap,
                                Some(local_root.display().to_string()),
                                direct_mode,
                            );
                            return Ok((val, route));
                        }
                        Err(local_err) => {
                            self.record_airlift_route(
                                true,
                                true,
                                Some(fs_reason),
                                "local_container_fs".to_string(),
                                &ctx,
                                path,
                                cap,
                                Some(local_err.clone()),
                                direct_mode,
                            );
                            return Err(local_err);
                        }
                    }
                }

                // Step 4: Container rejected by CoreDevice FileService, HouseArrest, and local Sandbox FS.
                // Strictly return SANDBOX_LOCKED_APPSTORE (never fall back to `com.apple.afc.shim.remote`).
                let combined_err = format!(
                    "{} [patch.airlift attempt=true fallback=true reason={} | fileservice: {}]",
                    ha_err, fs_reason, fs_detail
                );
                self.record_airlift_route(
                    true,
                    true,
                    Some(fs_reason),
                    "sandbox_locked".to_string(),
                    &ctx,
                    path,
                    cap,
                    Some(combined_err.clone()),
                    direct_mode,
                );
                Err(combined_err)
            }
        }
    }

    fn try_house_arrest_only<T>(
        &mut self,
        bundle_id: &str,
        op: impl Fn(AfcClient, String) -> (Result<T, String>, String),
    ) -> ContainerOpenOutcome<T> {
        let is_rsd = match self.ensure_backend() {
            Ok(v) => v,
            Err(e) => return ContainerOpenOutcome::ContainerRejected(e),
        };
        let ha_rsd = obfstr!("com.apple.mobile.house_arrest.shim.remote").to_string();
        let ha_classic = obfstr!("com.apple.mobile.house_arrest").to_string();

        if is_rsd {
            let open_pair = |sess: &RsdTunnelSession| -> Result<(AfcClient, String), String> {
                HouseArrestClient::connect_app_container_with_opener(
                    || {
                        let s = sess.open_checked_in_service(&[ha_rsd.as_str(), ha_classic.as_str()])?;
                        Ok(LockdownStream::RsdTunnel(s))
                    },
                    bundle_id,
                )
            };

            let opened = {
                let Some(ref sess) = self.active_rsd else {
                    return ContainerOpenOutcome::ContainerRejected(
                        "RSD session unavailable".to_string(),
                    );
                };
                open_pair(sess)
            };

            match opened {
                Ok((afc, mode)) => {
                    let (res, backend) = op(afc, mode);
                    return match res {
                        Ok(v) => ContainerOpenOutcome::SessionOpenedOpOk(v, backend),
                        Err(e) => ContainerOpenOutcome::SessionOpenedOpErr(e, backend),
                    };
                }
                Err(err) if err.contains(ERR_SANDBOX_LOCKED_APPSTORE) => {
                    return ContainerOpenOutcome::ContainerRejected(err);
                }
                Err(err) => {
                    if self.reconnect_rsd_once().is_ok() {
                        if let Some(ref new_sess) = self.active_rsd {
                            if let Ok((afc, mode)) = open_pair(new_sess) {
                                let (res, backend) = op(afc, mode);
                                return match res {
                                    Ok(v) => ContainerOpenOutcome::SessionOpenedOpOk(v, backend),
                                    Err(e) => ContainerOpenOutcome::SessionOpenedOpErr(e, backend),
                                };
                            }
                        }
                    }
                    return ContainerOpenOutcome::ContainerRejected(err);
                }
            }
        }

        let Some(lockdown_pairing) = self
            .active_pairing
            .as_ref()
            .and_then(|p| p.lockdown.as_ref())
        else {
            return ContainerOpenOutcome::ContainerRejected("Chưa có pairing file".to_string());
        };
        match HouseArrestClient::connect_app_container(
            &self.host,
            self.port,
            lockdown_pairing,
            bundle_id,
        ) {
            Ok((afc, mode)) => {
                let (res, backend) = op(afc, mode);
                match res {
                    Ok(v) => ContainerOpenOutcome::SessionOpenedOpOk(v, backend),
                    Err(e) => ContainerOpenOutcome::SessionOpenedOpErr(e, backend),
                }
            }
            Err(err) => ContainerOpenOutcome::ContainerRejected(err),
        }
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
                        (afc_rsd.as_str(), "afc.shim.remote"),
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
        if service_type == ffi::SERVICE_TYPE_HOUSE_ARREST {
            let ((entries, items, mode), _route) =
                self.airlift_list_dir(bundle_id, path, DEFAULT_CONTROL_CAPACITY)?;
            return Ok((entries, items, mode));
        }
        let path_owned = path.to_string();
        self.with_afc_client(service_type, bundle_id, move |mut afc, mode| {
            let entries = afc.list_dir(&path_owned)?;
            let items = build_afc_dir_items(&mut afc, &path_owned, &entries);
            Ok((entries, items, mode))
        })
    }

    pub fn airlift_list_dir(
        &mut self,
        bundle_id: &str,
        path: &str,
        control_capacity: u64,
    ) -> Result<((Vec<String>, Vec<HouseArrestDirItem>, String), AirLiftRouteInfo), String> {
        let ((entries, items, mode), route) = self.execute_airlift_app_op(
            bundle_id,
            path,
            control_capacity,
            |client, ctx, p| {
                let items = client.list_blocking(ctx, p)?;
                let entries = items.iter().map(|i| i.name.clone()).collect();
                Ok((entries, items, "coredevice.fileservice.data".to_string()))
            },
            |afc, mode, p| HouseArrestClient::list_dir_detailed_with_afc(afc, mode, p),
            |local_target, _| list_local_dir_items(local_target),
        )?;
        Ok(((entries, items, mode), route))
    }

    pub fn read_file(
        &mut self,
        service_type: i32,
        bundle_id: &str,
        path: &str,
    ) -> Result<Vec<u8>, String> {
        if service_type == ffi::SERVICE_TYPE_HOUSE_ARREST {
            let (bytes, _route) =
                self.airlift_read_file(bundle_id, path, DEFAULT_CONTROL_CAPACITY)?;
            return Ok(bytes);
        }
        let path_owned = path.to_string();
        self.with_afc_client(service_type, bundle_id, move |mut afc, _mode| {
            afc.read_file_full(&path_owned)
        })
    }

    pub fn airlift_read_file(
        &mut self,
        bundle_id: &str,
        path: &str,
        control_capacity: u64,
    ) -> Result<(Vec<u8>, AirLiftRouteInfo), String> {
        self.execute_airlift_app_op(
            bundle_id,
            path,
            control_capacity,
            |client, ctx, p| client.fileservice_read(ctx, p),
            |afc, mode, p| HouseArrestClient::read_file_with_afc(afc, &mode, p),
            |local_target, _| {
                std::fs::read(local_target).map_err(|e| format!("LocalFS read failed: {}", e))
            },
        )
    }

    pub fn write_file(
        &mut self,
        service_type: i32,
        bundle_id: &str,
        path: &str,
        data: &[u8],
    ) -> Result<(), String> {
        if service_type == ffi::SERVICE_TYPE_HOUSE_ARREST {
            let (_route, _) =
                self.airlift_write_file(bundle_id, path, data, DEFAULT_CONTROL_CAPACITY)?;
            return Ok(());
        }
        let path_owned = path.to_string();
        let data_owned = data.to_vec();
        self.with_afc_client(service_type, bundle_id, move |mut afc, _mode| {
            if let Ok(existing) = afc.read_file_full(&path_owned) {
                let backup_path = format!("{}.bak", path_owned);
                let _ = afc.write_file_full(&backup_path, &existing);
            }
            afc.write_file_full(&path_owned, &data_owned)
        })
    }

    pub fn airlift_write_file(
        &mut self,
        bundle_id: &str,
        path: &str,
        data: &[u8],
        control_capacity: u64,
    ) -> Result<(AirLiftRouteInfo, usize), String> {
        self.airlift_write_file_opts(bundle_id, path, data, control_capacity, false)
    }

    pub fn airlift_write_file_opts(
        &mut self,
        bundle_id: &str,
        path: &str,
        data: &[u8],
        control_capacity: u64,
        direct_known_path: bool,
    ) -> Result<(AirLiftRouteInfo, usize), String> {
        let len = data.len();
        let (_, route) = self.execute_airlift_app_op_with_mode(
            bundle_id,
            path,
            control_capacity,
            direct_known_path,
            |client, ctx, p| client.fileservice_write_with_options(ctx, p, data, direct_known_path),
            |afc, mode, p| {
                if direct_known_path {
                    HouseArrestClient::write_file_direct_known_path_with_afc(afc, &mode, p, data)
                } else {
                    HouseArrestClient::write_file_safe_with_afc(afc, &mode, p, data)
                }
            },
            |local_target, _| {
                if !direct_known_path {
                    if let Some(parent) = local_target.parent() {
                        std::fs::create_dir_all(parent)
                            .map_err(|e| format!("LocalFS mkdir parent failed: {}", e))?;
                    }
                }
                std::fs::write(local_target, data)
                    .map_err(|e| format!("LocalFS write failed: {}", e))
            },
        )?;
        Ok((route, len))
    }

    pub fn make_dir(
        &mut self,
        service_type: i32,
        bundle_id: &str,
        path: &str,
    ) -> Result<String, String> {
        if service_type == ffi::SERVICE_TYPE_HOUSE_ARREST {
            let route = self.airlift_mkdir(bundle_id, path, DEFAULT_CONTROL_CAPACITY)?;
            return Ok(route.backend);
        }
        let path_owned = path.to_string();
        self.with_afc_client(service_type, bundle_id, move |mut afc, mode| {
            afc.make_dir_recursive(&path_owned)?;
            Ok(mode)
        })
    }

    pub fn remove_path(
        &mut self,
        service_type: i32,
        bundle_id: &str,
        path: &str,
    ) -> Result<String, String> {
        if service_type == ffi::SERVICE_TYPE_HOUSE_ARREST {
            let route = self.airlift_remove(bundle_id, path, DEFAULT_CONTROL_CAPACITY)?;
            return Ok(route.backend);
        }
        let path_owned = path.to_string();
        self.with_afc_client(service_type, bundle_id, move |mut afc, mode| {
            afc.remove_path_recursive(&path_owned)?;
            Ok(mode)
        })
    }

    pub fn airlift_mkdir(
        &mut self,
        bundle_id: &str,
        path: &str,
        control_capacity: u64,
    ) -> Result<AirLiftRouteInfo, String> {
        let (_, route) = self.execute_airlift_app_op(
            bundle_id,
            path,
            control_capacity,
            |client, ctx, p| client.fileservice_mkdir(ctx, p),
            |afc, mode, p| HouseArrestClient::make_dir_with_afc(afc, &mode, p),
            |local_target, _| {
                std::fs::create_dir_all(local_target)
                    .map_err(|e| format!("LocalFS mkdir failed: {}", e))
            },
        )?;
        Ok(route)
    }

    pub fn airlift_remove(
        &mut self,
        bundle_id: &str,
        path: &str,
        control_capacity: u64,
    ) -> Result<AirLiftRouteInfo, String> {
        let (_, route) = self.execute_airlift_app_op(
            bundle_id,
            path,
            control_capacity,
            |client, ctx, p| client.fileservice_remove(ctx, p),
            |afc, mode, p| HouseArrestClient::remove_path_with_afc(afc, &mode, p),
            |local_target, _| {
                if local_target.is_dir() {
                    std::fs::remove_dir_all(local_target)
                } else {
                    std::fs::remove_file(local_target)
                }
                .map_err(|e| format!("LocalFS remove failed: {}", e))
            },
        )?;
        Ok(route)
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

fn safe_join_local_container(root: &std::path::Path, rel_path: &str) -> Result<PathBuf, String> {
    let mut out = root.to_path_buf();
    for seg in rel_path.trim().trim_start_matches('/').split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            return Err("Đường dẫn LocalContainer không hợp lệ".to_string());
        }
        out.push(seg);
    }
    Ok(out)
}

fn list_local_dir_items(dir: &std::path::Path) -> Result<(Vec<String>, Vec<HouseArrestDirItem>, String), String> {
    let rd = std::fs::read_dir(dir).map_err(|e| format!("LocalFS read_dir failed: {}", e))?;
    let mut pairs: Vec<(String, HouseArrestDirItem)> = Vec::new();
    for entry_res in rd {
        let Ok(entry) = entry_res else { continue };
        let name = entry.file_name().to_string_lossy().to_string();
        if name == "." || name == ".." {
            continue;
        }
        let meta = entry.metadata().ok();
        let is_dir = meta.as_ref().map(|m| m.is_dir()).unwrap_or(false);
        let size = if is_dir {
            -1
        } else {
            meta.as_ref().map(|m| m.len() as i64).unwrap_or(0)
        };
        pairs.push((
            name.clone(),
            HouseArrestDirItem {
                name,
                is_dir,
                size,
            },
        ));
    }
    pairs.sort_by(|a, b| a.0.cmp(&b.0));
    let entries = pairs.iter().map(|(n, _)| n.clone()).collect();
    let items = pairs.into_iter().map(|(_, i)| i).collect();
    Ok((entries, items, "local_container_fs".to_string()))
}

fn build_afc_dir_items(afc: &mut AfcClient, dir_path: &str, entries: &[String]) -> Vec<HouseArrestDirItem> {
    let prefix = dir_path.trim_end_matches('/');
    let mut items = Vec::with_capacity(entries.len());
    for name in entries {
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
    items
}

fn format_live_rsd_message(
    host: &str,
    port: u16,
    iface_label: &str,
    udid: &str,
    product_type: Option<&str>,
    os_version: Option<&str>,
    svc_count: usize,
    coredevice_tunnel_status: Option<&str>,
) -> String {
    let hw = match (product_type, os_version) {
        (Some(p), Some(v)) => format!(" · {} iOS {}", p, v),
        (Some(p), None) => format!(" · {}", p),
        _ => String::new(),
    };
    let mut base = format!(
        "Kết nối RemotePairing/RSD thành công tại {}:{} ({}){} — {} services, UDID: {}",
        host, port, iface_label, hw, svc_count, udid
    );
    if let Some(status_line) = coredevice_tunnel_status.map(str::trim).filter(|s| !s.is_empty()) {
        base.push('\n');
        base.push_str(status_line);
    }
    base
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
        ..Default::default()
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
