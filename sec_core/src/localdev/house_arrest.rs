//! House Arrest Protocol Client (`com.apple.mobile.house_arrest`)
//! Vends access to application sandboxes (`VendContainer` & `VendDocuments`)
//! Provides chunked AFC file streaming and automatic `.bak` backup protection
//! Supports iOS 15.0 - iOS 27.2.1

use super::afc_client::AfcClient;
use super::pairing::PairingFile;
use super::plist_util::PlistValue;
use super::tunnel::{read_plist, send_plist, LockdownClient, LockdownStream};
use serde::Serialize;
use std::collections::HashMap;

pub const ERR_SANDBOX_LOCKED_APPSTORE: &str = "SANDBOX_LOCKED_APPSTORE";

#[derive(Debug, Clone, Serialize)]
pub struct HouseArrestDirItem {
    pub name: String,
    pub is_dir: bool,
    pub size: i64,
}

pub struct HouseArrestClient;

impl HouseArrestClient {
    /// Vends container access using an arbitrary service stream opener (`RSDCheckin` or Lockdown).
    pub fn connect_app_container_with_opener(
        mut open_service: impl FnMut() -> Result<LockdownStream, String>,
        bundle_id: &str,
    ) -> Result<(AfcClient, String), String> {
        let mut sock = open_service()?;

        // 1. First Tier: Try VendContainer (gives full Documents, Library, tmp for sideloaded/dev apps)
        let mut req = HashMap::new();
        req.insert("Command".to_string(), PlistValue::String("VendContainer".to_string()));
        req.insert("Identifier".to_string(), PlistValue::String(bundle_id.to_string()));
        send_plist(&mut sock, &req)?;

        let resp = read_plist(&mut sock)?;
        let status = resp.get_string("Status").unwrap_or_default();

        if status == "Complete" {
            return Ok((AfcClient::new(sock), "VendContainer".to_string()));
        }

        let err1 = resp.get_string("Error").unwrap_or_default();

        // 2. Second Tier Fallback: Try VendDocuments (accessible if UIFileSharingEnabled == true)
        let mut fallback_sock = open_service()?;
        let mut req2 = HashMap::new();
        req2.insert("Command".to_string(), PlistValue::String("VendDocuments".to_string()));
        req2.insert("Identifier".to_string(), PlistValue::String(bundle_id.to_string()));
        send_plist(&mut fallback_sock, &req2)?;

        let resp2 = read_plist(&mut fallback_sock)?;
        let status2 = resp2.get_string("Status").unwrap_or_default();

        if status2 == "Complete" {
            return Ok((AfcClient::new(fallback_sock), "VendDocuments".to_string()));
        }

        // 3. Both failed: this is a locked App Store application without file sharing
        let err2 = resp2.get_string("Error").unwrap_or_default();
        Err(format!(
            "{}: App '{}' denied container access (VendContainer: '{}', VendDocuments: '{}')",
            ERR_SANDBOX_LOCKED_APPSTORE, bundle_id, err1, err2
        ))
    }

    /// Connects to `com.apple.mobile.house_arrest` and vends container access for target app
    pub fn connect_app_container(
        ip: &str,
        port: u16,
        pairing: &PairingFile,
        bundle_id: &str,
    ) -> Result<(AfcClient, String), String> {
        let mut lockdown = LockdownClient::connect(ip, port, pairing)?;
        Self::connect_app_container_with_opener(
            || {
                let (sock, _p, _ssl) = lockdown.start_service("com.apple.mobile.house_arrest")?;
                Ok(sock)
            },
            bundle_id,
        )
    }

    /// Lists directory inside target application sandbox
    #[allow(dead_code)]
    pub fn list_dir(
        ip: &str,
        port: u16,
        pairing: &PairingFile,
        bundle_id: &str,
        path: &str,
    ) -> Result<Vec<String>, String> {
        let (mut afc, mode) = Self::connect_app_container(ip, port, pairing, bundle_id)?;
        let effective_path = normalize_house_arrest_path(&mode, path);
        afc.list_dir(&effective_path)
    }

    /// Lists directory entries with metadata using an already-started `(AfcClient, mode)` session.
    pub fn list_dir_detailed_with_afc(
        mut afc: AfcClient,
        mode: String,
        path: &str,
    ) -> Result<(Vec<String>, Vec<HouseArrestDirItem>, String), String> {
        let effective_path = normalize_house_arrest_path(&mode, path);
        let entries = afc.list_dir(&effective_path)?;
        let mut items = Vec::with_capacity(entries.len());
        let prefix = effective_path.trim_end_matches('/');

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

    /// Lists directory entries with metadata (directory flag & size) and granted mode
    pub fn list_dir_detailed(
        ip: &str,
        port: u16,
        pairing: &PairingFile,
        bundle_id: &str,
        path: &str,
    ) -> Result<(Vec<String>, Vec<HouseArrestDirItem>, String), String> {
        let (afc, mode) = Self::connect_app_container(ip, port, pairing, bundle_id)?;
        Self::list_dir_detailed_with_afc(afc, mode, path)
    }

    /// Reads file bytes from an already-started HouseArrest `(AfcClient, mode)` session.
    pub fn read_file_with_afc(mut afc: AfcClient, mode: &str, path: &str) -> Result<Vec<u8>, String> {
        let effective_path = normalize_house_arrest_path(mode, path);
        afc.read_file_full(&effective_path)
    }

    /// Reads file bytes from target application sandbox
    pub fn read_file(
        ip: &str,
        port: u16,
        pairing: &PairingFile,
        bundle_id: &str,
        path: &str,
    ) -> Result<Vec<u8>, String> {
        let (afc, mode) = Self::connect_app_container(ip, port, pairing, bundle_id)?;
        Self::read_file_with_afc(afc, &mode, path)
    }

    /// Creates directory inside an already-started HouseArrest `(AfcClient, mode)` session.
    pub fn make_dir_with_afc(mut afc: AfcClient, mode: &str, path: &str) -> Result<(), String> {
        let effective_path = normalize_house_arrest_path(mode, path);
        afc.make_dir(&effective_path)
    }

    /// Removes a path inside an already-started HouseArrest `(AfcClient, mode)` session.
    pub fn remove_path_with_afc(mut afc: AfcClient, mode: &str, path: &str) -> Result<(), String> {
        let effective_path = normalize_house_arrest_path(mode, path);
        afc.remove_path(&effective_path)
    }

    /// Writes file bytes into an already-started HouseArrest `(AfcClient, mode)` session with `.bak` backup.
    pub fn write_file_safe_with_afc(
        mut afc: AfcClient,
        mode: &str,
        path: &str,
        data: &[u8],
    ) -> Result<(), String> {
        let effective_path = normalize_house_arrest_path(mode, path);

        // Safety backup: if file already exists, create `<path>.bak` before overwriting
        if let Ok(existing_bytes) = afc.read_file_full(&effective_path) {
            let backup_path = format!("{}.bak", effective_path);
            let _ = afc.write_file_full(&backup_path, &existing_bytes);
        }

        // Write new file bytes in 128KB chunks
        afc.write_file_full(&effective_path, data)
    }

    /// Writes file bytes into target application sandbox with automatic `.bak` backup
    pub fn write_file_safe(
        ip: &str,
        port: u16,
        pairing: &PairingFile,
        bundle_id: &str,
        path: &str,
        data: &[u8],
    ) -> Result<(), String> {
        let (afc, mode) = Self::connect_app_container(ip, port, pairing, bundle_id)?;
        Self::write_file_safe_with_afc(afc, &mode, path, data)
    }
}

fn normalize_house_arrest_path(mode: &str, path: &str) -> String {
    let clean = path.trim();
    if mode != "VendDocuments" {
        return if clean.is_empty() { "/".to_string() } else { clean.to_string() };
    }
    let trimmed = clean.trim_start_matches('/');
    if trimmed.is_empty() || trimmed == "Documents" {
        "/Documents".to_string()
    } else if trimmed.starts_with("Documents/") {
        format!("/{}", trimmed)
    } else {
        format!("/Documents/{}", trimmed)
    }
}
