//! House Arrest Protocol Client (`com.apple.mobile.house_arrest`)
//! Vends access to application sandboxes (`VendContainer` & `VendDocuments`)
//! Provides chunked AFC file streaming and automatic `.bak` backup protection
//! Supports iOS 15.0 - iOS 27.2.1

use super::afc_client::AfcClient;
use super::pairing::PairingFile;
use super::plist_util::PlistValue;
use super::tunnel::{read_plist, send_plist, LockdownClient};
use std::collections::HashMap;

pub const ERR_SANDBOX_LOCKED_APPSTORE: &str = "SANDBOX_LOCKED_APPSTORE";

pub struct HouseArrestClient;

impl HouseArrestClient {
    /// Connects to `com.apple.mobile.house_arrest` and vends container access for target app
    pub fn connect_app_container(
        ip: &str,
        port: u16,
        pairing: &PairingFile,
        bundle_id: &str,
    ) -> Result<(AfcClient, String), String> {
        let mut lockdown = LockdownClient::connect(ip, port, pairing)?;
        let (mut sock, _service_port, _ssl) = lockdown.start_service("com.apple.mobile.house_arrest")?;

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
        // Need fresh service connection for the fallback command
        let (mut fallback_sock, _sp, _ssl) = lockdown.start_service("com.apple.mobile.house_arrest")?;
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

    /// Lists directory inside target application sandbox
    pub fn list_dir(
        ip: &str,
        port: u16,
        pairing: &PairingFile,
        bundle_id: &str,
        path: &str,
    ) -> Result<Vec<String>, String> {
        let (mut afc, _mode) = Self::connect_app_container(ip, port, pairing, bundle_id)?;
        afc.list_dir(path)
    }

    /// Reads file bytes from target application sandbox
    pub fn read_file(
        ip: &str,
        port: u16,
        pairing: &PairingFile,
        bundle_id: &str,
        path: &str,
    ) -> Result<Vec<u8>, String> {
        let (mut afc, _mode) = Self::connect_app_container(ip, port, pairing, bundle_id)?;
        afc.read_file_full(path)
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
        let (mut afc, _mode) = Self::connect_app_container(ip, port, pairing, bundle_id)?;

        // Safety backup: if file already exists, create `<path>.bak` before overwriting
        if let Ok(existing_bytes) = afc.read_file_full(path) {
            let backup_path = format!("{}.bak", path);
            let _ = afc.write_file_full(&backup_path, &existing_bytes);
        }

        // Write new file bytes in 128KB chunks
        afc.write_file_full(path, data)
    }
}
