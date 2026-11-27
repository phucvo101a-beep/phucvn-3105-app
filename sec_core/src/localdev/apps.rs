//! App Scanner via `com.apple.mobile.installation_proxy`
//! Queries all installed applications over the LocalDev loopback connection
//! Supports iOS 15.0 - iOS 27.2.1

use super::pairing::PairingFile;
use super::plist_util::PlistValue;
use super::tunnel::{read_plist, send_plist, LockdownClient, LockdownStream};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalDevAppInfo {
    pub bundle_id: String,
    pub display_name: String,
    pub version: String,
    pub access_type: String, // "FullContainer" | "DocumentsOnly" | "SandboxLocked"
    pub file_sharing_enabled: bool,
    pub container_path: Option<String>,
    pub bundle_path: Option<String>,
    pub is_developer_signed: bool,
}

pub struct AppScanReport {
    pub apps: Vec<LocalDevAppInfo>,
    pub saw_complete: bool,
    pub chunks: usize,
    pub error: Option<String>,
}

pub fn merge_app_lists(dst: &mut Vec<LocalDevAppInfo>, extra: Vec<LocalDevAppInfo>) {
    let mut idx_by_bundle: HashMap<String, usize> = dst
        .iter()
        .enumerate()
        .map(|(i, a)| (a.bundle_id.clone(), i))
        .collect();

    for app in extra {
        if let Some(&idx) = idx_by_bundle.get(&app.bundle_id) {
            if dst[idx].display_name == dst[idx].bundle_id && app.display_name != app.bundle_id {
                dst[idx].display_name = app.display_name;
            }
            if dst[idx].version == "1.0" && app.version != "1.0" && !app.version.is_empty() {
                dst[idx].version = app.version;
            }
            if dst[idx].bundle_path.is_none() {
                dst[idx].bundle_path = app.bundle_path;
            }
            if dst[idx].container_path.is_none() {
                dst[idx].container_path = app.container_path;
            }
            if dst[idx].access_type == "SandboxLocked" && app.access_type != "SandboxLocked" {
                dst[idx].access_type = app.access_type;
                dst[idx].file_sharing_enabled = app.file_sharing_enabled;
                dst[idx].is_developer_signed = app.is_developer_signed;
            }
        } else {
            idx_by_bundle.insert(app.bundle_id.clone(), dst.len());
            dst.push(app);
        }
    }
    dst.sort_by(|a, b| a.display_name.to_lowercase().cmp(&b.display_name.to_lowercase()));
}

pub struct AppScanner;

impl AppScanner {
    /// Scans installed user applications via `com.apple.mobile.installation_proxy`
    pub fn scan_user_apps_with_candidates(
        candidates: &[(String, u16)],
        pairing: &PairingFile,
    ) -> Result<(Vec<LocalDevAppInfo>, String, u16), String> {
        let mut candidate_endpoints: Vec<(String, u16)> = Vec::new();
        for (h, p) in candidates {
            if !candidate_endpoints.iter().any(|(eh, ep)| eh == h && *ep == *p) {
                candidate_endpoints.push((h.clone(), *p));
            }
        }
        for fallback in ["10.7.0.1", "10.7.0.0", "127.0.0.1"] {
            if !candidate_endpoints.iter().any(|(eh, ep)| eh == fallback && *ep == 62078) {
                candidate_endpoints.push((fallback.to_string(), 62078));
            }
        }

        let mut lockdown_client = None;
        let mut connected_host = String::new();
        let mut connected_port = 62078u16;
        let mut errors = Vec::new();

        for (target_ip, target_port) in candidate_endpoints {
            match LockdownClient::connect(&target_ip, target_port, pairing) {
                Ok(client) => {
                    connected_host = target_ip;
                    connected_port = target_port;
                    lockdown_client = Some(client);
                    break;
                }
                Err(e) => errors.push(format!("{}:{} -> {}", target_ip, target_port, e)),
            }
        }

        let mut lockdown = lockdown_client.ok_or_else(|| {
            if errors.is_empty() {
                "Failed to connect to LocalDev on any tunnel endpoint".to_string()
            } else {
                errors.join(" | ")
            }
        })?;

        let (sock, _service_port, _ssl) = lockdown.start_service("com.apple.mobile.installation_proxy")?;
        let report = Self::scan_user_apps_report(sock);
        let mut discovered_apps = report.apps;

        if !report.saw_complete || discovered_apps.is_empty() {
            if let Ok((lookup_sock, _, _)) = lockdown.start_service("com.apple.mobile.installation_proxy") {
                let lookup_rep = Self::lookup_user_apps_report(lookup_sock);
                merge_app_lists(&mut discovered_apps, lookup_rep.apps);
            }
        }
        if !report.saw_complete || discovered_apps.is_empty() {
            if let Ok((min_sock, _, _)) = lockdown.start_service("com.apple.mobile.installation_proxy") {
                let min_rep = Self::scan_user_apps_minimal_report(min_sock);
                merge_app_lists(&mut discovered_apps, min_rep.apps);
            }
        }
        if discovered_apps.is_empty() {
            if let Some(err) = report.error {
                return Err(err);
            }
        }
        Ok((discovered_apps, connected_host, connected_port))
    }

    /// Streams all installed `User` apps & games over any started `installation_proxy` stream (Lockdown or RSD),
    /// retaining `FullContainer`, `DocumentsOnly`, and `SandboxLocked` items alike.
    pub fn scan_user_apps_over_stream(sock: LockdownStream) -> Result<Vec<LocalDevAppInfo>, String> {
        let rep = Self::scan_user_apps_report(sock);
        if rep.apps.is_empty() {
            if let Some(err) = rep.error {
                return Err(err);
            }
        }
        Ok(rep.apps)
    }

    /// Single-shot or streamed `Lookup` fallback for firmwares/proxies that prefer `Lookup` over `Browse`.
    pub fn lookup_user_apps_over_stream(sock: LockdownStream) -> Result<Vec<LocalDevAppInfo>, String> {
        let rep = Self::lookup_user_apps_report(sock);
        if rep.apps.is_empty() {
            if let Some(err) = rep.error {
                return Err(err);
            }
        }
        Ok(rep.apps)
    }

    pub fn scan_user_apps_report(sock: LockdownStream) -> AppScanReport {
        run_apps_command(sock, "Browse", user_app_client_options())
    }

    pub fn scan_user_apps_minimal_report(sock: LockdownStream) -> AppScanReport {
        run_apps_command(sock, "Browse", user_app_client_options_minimal())
    }

    pub fn lookup_user_apps_report(sock: LockdownStream) -> AppScanReport {
        run_apps_command(sock, "Lookup", user_app_client_options())
    }
}

fn run_apps_command(
    mut sock: LockdownStream,
    command: &str,
    client_options: HashMap<String, PlistValue>,
) -> AppScanReport {
    sock.set_timeouts(30, 10);

    let mut req = HashMap::new();
    req.insert("Command".to_string(), PlistValue::String(command.to_string()));
    req.insert("ClientOptions".to_string(), PlistValue::Dictionary(client_options));
    if let Err(e) = send_plist(&mut sock, &req) {
        return AppScanReport {
            apps: Vec::new(),
            saw_complete: false,
            chunks: 0,
            error: Some(e),
        };
    }

    let mut discovered_apps = Vec::new();
    let mut seen_bundles = HashSet::new();
    let mut saw_complete = false;
    let mut chunks = 0usize;
    let mut trailing_err = None;

    loop {
        let resp = match read_plist(&mut sock) {
            Ok(r) => r,
            Err(e) => {
                trailing_err = Some(e);
                break;
            }
        };
        chunks += 1;
        if let Some(err) = resp.get_string("Error") {
            trailing_err = Some(format!("installation_proxy {} error: {}", command, err));
            break;
        }
        let status = resp.get_string("Status").unwrap_or_default();

        if let Some(PlistValue::Array(list)) = resp.get("CurrentList") {
            for item in list {
                if let Some(app_dict) = item.as_dict() {
                    if let Some(app) = parse_app_record(None, app_dict) {
                        if seen_bundles.insert(app.bundle_id.clone()) {
                            discovered_apps.push(app);
                        }
                    }
                }
            }
        }

        if let Some(lookup_map) = resp.get("LookupResult").and_then(|v| v.as_dict()) {
            for (bid, item) in lookup_map {
                if let Some(app_dict) = item.as_dict() {
                    if let Some(app) = parse_app_record(Some(bid), app_dict) {
                        if seen_bundles.insert(app.bundle_id.clone()) {
                            discovered_apps.push(app);
                        }
                    }
                }
            }
        }

        if status.eq_ignore_ascii_case("Complete") {
            saw_complete = true;
            break;
        }
    }

    discovered_apps.sort_by(|a, b| a.display_name.to_lowercase().cmp(&b.display_name.to_lowercase()));
    AppScanReport {
        apps: discovered_apps,
        saw_complete,
        chunks,
        error: trailing_err,
    }
}

fn user_app_client_options() -> HashMap<String, PlistValue> {
    let mut client_options = HashMap::new();
    client_options.insert("ApplicationType".to_string(), PlistValue::String("User".to_string()));

    let return_attrs = vec![
        PlistValue::String("CFBundleIdentifier".to_string()),
        PlistValue::String("CFBundleDisplayName".to_string()),
        PlistValue::String("CFBundleName".to_string()),
        PlistValue::String("CFBundleExecutable".to_string()),
        PlistValue::String("CFBundleShortVersionString".to_string()),
        PlistValue::String("CFBundleVersion".to_string()),
        PlistValue::String("ApplicationType".to_string()),
        PlistValue::String("UIFileSharingEnabled".to_string()),
        PlistValue::String("LSSupportsOpeningDocumentsInPlace".to_string()),
        PlistValue::String("Entitlements".to_string()),
        PlistValue::String("Path".to_string()),
        PlistValue::String("Container".to_string()),
    ];
    client_options.insert("ReturnAttributes".to_string(), PlistValue::Array(return_attrs));
    client_options
}

fn user_app_client_options_minimal() -> HashMap<String, PlistValue> {
    let mut client_options = HashMap::new();
    client_options.insert("ApplicationType".to_string(), PlistValue::String("User".to_string()));

    let return_attrs = vec![
        PlistValue::String("CFBundleIdentifier".to_string()),
        PlistValue::String("CFBundleDisplayName".to_string()),
        PlistValue::String("CFBundleName".to_string()),
        PlistValue::String("CFBundleShortVersionString".to_string()),
        PlistValue::String("CFBundleVersion".to_string()),
        PlistValue::String("UIFileSharingEnabled".to_string()),
        PlistValue::String("Entitlements".to_string()),
        PlistValue::String("Path".to_string()),
        PlistValue::String("Container".to_string()),
    ];
    client_options.insert("ReturnAttributes".to_string(), PlistValue::Array(return_attrs));
    client_options
}

fn plist_truthy(val: Option<&PlistValue>) -> bool {
    match val {
        Some(PlistValue::Boolean(b)) => *b,
        Some(PlistValue::Integer(n)) => *n != 0,
        Some(PlistValue::String(s)) => {
            let clean = s.trim();
            clean.eq_ignore_ascii_case("true")
                || clean.eq_ignore_ascii_case("yes")
                || clean == "1"
        }
        _ => false,
    }
}

fn non_empty_str<'a>(dict: &'a HashMap<String, PlistValue>, key: &str) -> Option<&'a str> {
    dict.get(key)
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

fn parse_app_record(fallback_bundle_id: Option<&str>, dict: &HashMap<String, PlistValue>) -> Option<LocalDevAppInfo> {
    let bundle_id = non_empty_str(dict, "CFBundleIdentifier")
        .or_else(|| fallback_bundle_id.map(str::trim).filter(|s| !s.is_empty()))?
        .to_string();

    // Only exclude internal/background daemons and extensions; keep all apps returned for the User query
    // (including iOS 27.2.1 shim removable/user apps even if `ApplicationType` casing or label varies).
    if let Some(app_type) = non_empty_str(dict, "ApplicationType") {
        let lower = app_type.to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "internal" | "hidden" | "pluginkitplugin" | "vpnplugin" | "systemappplaceholder"
        ) {
            return None;
        }
    }

    let display_name = non_empty_str(dict, "CFBundleDisplayName")
        .or_else(|| non_empty_str(dict, "CFBundleName"))
        .or_else(|| non_empty_str(dict, "CFBundleExecutable"))
        .unwrap_or(&bundle_id)
        .to_string();

    let version = non_empty_str(dict, "CFBundleShortVersionString")
        .or_else(|| non_empty_str(dict, "CFBundleVersion"))
        .unwrap_or("1.0")
        .to_string();

    let ui_file_sharing = plist_truthy(dict.get("UIFileSharingEnabled"));
    let open_in_place = plist_truthy(dict.get("LSSupportsOpeningDocumentsInPlace"));
    let file_sharing_enabled = ui_file_sharing || open_in_place;

    let container_path = non_empty_str(dict, "Container").map(|s| s.to_string());
    let bundle_path = non_empty_str(dict, "Path").map(|s| s.to_string());

    // Check entitlements for get-task-allow (developer signed)
    let is_developer_signed = plist_truthy(
        dict.get("Entitlements")
            .and_then(|e| e.as_dict())
            .and_then(|ent| ent.get("get-task-allow")),
    );

    // Categorize access level without hiding locked App Store apps/games:
    // 1. Sideloaded / Dev apps with get-task-allow -> FullContainer
    // 2. Apps with UIFileSharingEnabled or LSSupportsOpeningDocumentsInPlace -> DocumentsOnly
    // 3. Locked App Store apps & games -> SandboxLocked (retained in list)
    let access_type = if is_developer_signed {
        "FullContainer".to_string()
    } else if file_sharing_enabled {
        "DocumentsOnly".to_string()
    } else {
        "SandboxLocked".to_string()
    };

    Some(LocalDevAppInfo {
        bundle_id,
        display_name,
        version,
        access_type,
        file_sharing_enabled,
        container_path,
        bundle_path,
        is_developer_signed,
    })
}
