//! App Scanner via `com.apple.mobile.installation_proxy`
//! Queries all installed applications over the LocalDev loopback connection
//! Supports iOS 15.0 - iOS 27.2.1

use super::pairing::PairingFile;
use super::plist_util::PlistValue;
use super::tunnel::{read_plist, send_plist, LockdownClient};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

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
    pub fn scan_user_apps(
        ip: &str,
        port: u16,
        pairing: &PairingFile,
    ) -> Result<Vec<LocalDevAppInfo>, String> {
        let candidate_ips = [ip, "10.7.1.1", "10.7.0.1", "127.0.0.1"];
        let mut lockdown_client = None;
        let mut last_err = String::new();

        for &target_ip in &candidate_ips {
            match LockdownClient::connect(target_ip, port, pairing) {
                Ok(client) => {
                    lockdown_client = Some(client);
                    break;
                }
                Err(e) => last_err = e,
            }
        }

        let mut lockdown = lockdown_client.ok_or_else(|| {
            if last_err.is_empty() {
                format!("Failed to connect to LocalDev on candidate IPs at port {}", port)
            } else {
                last_err
            }
        })?;

        let (mut sock, _service_port, _ssl) = lockdown.start_service("com.apple.mobile.installation_proxy")?;

        sock.set_read_timeout(Some(Duration::from_secs(12))).ok();
        sock.set_write_timeout(Some(Duration::from_secs(10))).ok();

        // Send Browse request
        let mut req = HashMap::new();
        req.insert("Command".to_string(), PlistValue::String("Browse".to_string()));

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

        req.insert("ClientOptions".to_string(), PlistValue::Dictionary(client_options));
        send_plist(&mut sock, &req)?;

        let mut discovered_apps = Vec::new();

        // Stream responses until Status == "Complete"
        loop {
            let resp = read_plist(&mut sock)?;
            let status = resp.get_string("Status").unwrap_or_default();

            if let Some(PlistValue::Array(list)) = resp.get("CurrentList") {
                for item in list {
                    if let Some(app_dict) = item.as_dict() {
                        if let Some(app) = parse_app_record(app_dict) {
                            discovered_apps.push(app);
                        }
                    }
                }
            }

            if status == "Complete" {
                break;
            }
        }

        // Sort apps alphabetically by display name
        discovered_apps.sort_by(|a, b| a.display_name.to_lowercase().cmp(&b.display_name.to_lowercase()));
        Ok(discovered_apps)
    }
}

fn parse_app_record(dict: &HashMap<String, PlistValue>) -> Option<LocalDevAppInfo> {
    let bundle_id = dict.get("CFBundleIdentifier")?.as_str()?.to_string();

    let display_name = dict.get("CFBundleDisplayName")
        .and_then(|v| v.as_str())
        .or_else(|| dict.get("CFBundleName").and_then(|v| v.as_str()))
        .unwrap_or(&bundle_id)
        .to_string();

    let version = dict.get("CFBundleShortVersionString")
        .and_then(|v| v.as_str())
        .or_else(|| dict.get("CFBundleVersion").and_then(|v| v.as_str()))
        .unwrap_or("1.0")
        .to_string();

    let file_sharing_enabled = dict.get("UIFileSharingEnabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let container_path = dict.get("Container")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let bundle_path = dict.get("Path")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Check entitlements for get-task-allow (developer signed)
    let is_developer_signed = dict.get("Entitlements")
        .and_then(|e| e.as_dict())
        .and_then(|ent| ent.get("get-task-allow"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // Categorize access level:
    // 1. Sideloaded / Dev apps with get-task-allow -> FullContainer
    // 2. Apps with UIFileSharingEnabled -> DocumentsOnly
    // 3. Locked App Store apps -> SandboxLocked
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
