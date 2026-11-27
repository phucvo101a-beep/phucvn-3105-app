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
        let discovered_apps = Self::scan_user_apps_over_stream(sock)?;
        Ok((discovered_apps, connected_host, connected_port))
    }

    /// Streams all installed `User` apps & games over any started `installation_proxy` stream (Lockdown or RSD),
    /// retaining `FullContainer`, `DocumentsOnly`, and `SandboxLocked` items alike.
    pub fn scan_user_apps_over_stream(mut sock: LockdownStream) -> Result<Vec<LocalDevAppInfo>, String> {
        sock.set_timeouts(25, 10);

        let mut req = HashMap::new();
        req.insert("Command".to_string(), PlistValue::String("Browse".to_string()));
        req.insert("ClientOptions".to_string(), PlistValue::Dictionary(user_app_client_options()));
        send_plist(&mut sock, &req)?;

        let mut discovered_apps = Vec::new();
        let mut seen_bundles = HashSet::new();

        // Stream responses until Status == "Complete"
        loop {
            let resp = match read_plist(&mut sock) {
                Ok(r) => r,
                Err(_) if !discovered_apps.is_empty() => break,
                Err(e) => return Err(e),
            };
            if let Some(err) = resp.get_string("Error") {
                return Err(format!("installation_proxy error: {}", err));
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
                break;
            }
        }

        // Sort apps & games alphabetically by display name
        discovered_apps.sort_by(|a, b| a.display_name.to_lowercase().cmp(&b.display_name.to_lowercase()));
        Ok(discovered_apps)
    }

    /// Single-shot `Lookup` fallback for firmwares/proxies that prefer `Lookup` over `Browse`.
    pub fn lookup_user_apps_over_stream(mut sock: LockdownStream) -> Result<Vec<LocalDevAppInfo>, String> {
        sock.set_timeouts(25, 10);

        let mut req = HashMap::new();
        req.insert("Command".to_string(), PlistValue::String("Lookup".to_string()));
        req.insert("ClientOptions".to_string(), PlistValue::Dictionary(user_app_client_options()));
        send_plist(&mut sock, &req)?;

        let resp = read_plist(&mut sock)?;
        if let Some(err) = resp.get_string("Error") {
            return Err(format!("installation_proxy lookup error: {}", err));
        }

        let mut discovered_apps = Vec::new();
        let mut seen_bundles = HashSet::new();

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

        discovered_apps.sort_by(|a, b| a.display_name.to_lowercase().cmp(&b.display_name.to_lowercase()));
        Ok(discovered_apps)
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

    if let Some(app_type) = non_empty_str(dict, "ApplicationType") {
        if !app_type.eq_ignore_ascii_case("User") {
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
