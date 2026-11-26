//! iOS Pairing File (.mobiledevicepairing / pair.plist) Parser & Storage Manager
//! Fully compatible with iOS 15.0 - iOS 27.2.1

use super::plist_util::{base64_decode, parse_plist, PlistValue};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct PairingFile {
    pub host_id: String,
    pub system_buid: String,
    pub host_certificate_der: Vec<u8>,
    pub host_private_key_der: Vec<u8>,
    pub root_certificate_der: Vec<u8>,
    pub device_certificate_der: Vec<u8>,
    pub udid: String,
    pub raw_data: Vec<u8>,
}

impl PairingFile {
    /// Parses raw bytes of a .mobiledevicepairing or .plist file (XML or bplist00)
    pub fn parse(raw_data: &[u8]) -> Result<Self, String> {
        let root = parse_plist(raw_data)?;
        let dict = root.as_dict().ok_or_else(|| "Pairing file root must be a Dictionary".to_string())?;

        // Detect `idevice pair v1.2.0` Remote Pairing plist (`public_key`, `private_key`, `identifier`, `alt_irk`)
        if dict.contains_key("public_key")
            && dict.contains_key("private_key")
            && !dict.contains_key("HostCertificate")
            && !dict.contains_key("HostID")
        {
            return Err("REMOTE_PAIRING_UNSUPPORTED: Đã nhận diện tệp Remote Pairing (public_key / private_key / identifier / alt_irk), nhưng libsec_core.dylib hiện tại chỉ hỗ trợ Lockdown X.509 TLS (HostCertificate / HostID trên cổng 62078).".to_string());
        }

        // 1. HostID
        let host_id = dict.get("HostID")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing required 'HostID' in pairing file".to_string())?
            .to_string();

        // 2. SystemBUID
        let system_buid = dict.get("SystemBUID")
            .and_then(|v| v.as_str())
            .unwrap_or("00000000-0000-0000-0000-000000000000")
            .to_string();

        // 3. UDID
        let udid = dict.get("UDID")
            .and_then(|v| v.as_str())
            .or_else(|| dict.get("DeviceUDID").and_then(|v| v.as_str()))
            .unwrap_or("unknown-udid")
            .to_string();

        // 4. HostCertificate
        let host_cert_raw = extract_bytes(dict, "HostCertificate")
            .ok_or_else(|| "Missing required 'HostCertificate' in pairing file".to_string())?;
        let host_certificate_der = normalize_to_der(&host_cert_raw)?;

        // 5. HostPrivateKey
        let host_key_raw = extract_bytes(dict, "HostPrivateKey")
            .ok_or_else(|| "Missing required 'HostPrivateKey' in pairing file".to_string())?;
        let host_private_key_der = normalize_to_der(&host_key_raw)?;

        // 6. RootCertificate
        let root_cert_raw = extract_bytes(dict, "RootCertificate")
            .ok_or_else(|| "Missing required 'RootCertificate' in pairing file".to_string())?;
        let root_certificate_der = normalize_to_der(&root_cert_raw)?;

        // 7. DeviceCertificate
        let device_cert_raw = extract_bytes(dict, "DeviceCertificate")
            .ok_or_else(|| "Missing required 'DeviceCertificate' in pairing file".to_string())?;
        let device_certificate_der = normalize_to_der(&device_cert_raw)?;

        // Validate that key and certificates are non-empty
        if host_id.is_empty() || host_certificate_der.is_empty() || host_private_key_der.is_empty() {
            return Err("Invalid pairing file: empty cryptographic credentials".to_string());
        }

        Ok(Self {
            host_id,
            system_buid,
            host_certificate_der,
            host_private_key_der,
            root_certificate_der,
            device_certificate_der,
            udid,
            raw_data: raw_data.to_vec(),
        })
    }

    /// Saves this pairing file to persistent storage path
    pub fn save_to_dir(&self, dir: &Path) -> Result<PathBuf, String> {
        if !dir.exists() {
            fs::create_dir_all(dir).map_err(|e| format!("Failed to create storage dir: {}", e))?;
        }
        let file_path = dir.join("pairing.mobiledevicepairing");
        fs::write(&file_path, &self.raw_data)
            .map_err(|e| format!("Failed to write pairing file: {}", e))?;
        Ok(file_path)
    }

    /// Loads pairing file from persistent storage directory
    pub fn load_from_dir(dir: &Path) -> Result<Self, String> {
        let candidate1 = dir.join("pairing.mobiledevicepairing");
        let candidate2 = dir.join("pairing.plist");

        let target = if candidate1.exists() {
            candidate1
        } else if candidate2.exists() {
            candidate2
        } else {
            return Err("No pairing file found in directory".to_string());
        };

        let data = fs::read(&target).map_err(|e| format!("Failed to read stored pairing: {}", e))?;
        Self::parse(&data)
    }
}

fn extract_bytes(dict: &std::collections::HashMap<String, PlistValue>, key: &str) -> Option<Vec<u8>> {
    match dict.get(key)? {
        PlistValue::Data(d) => Some(d.clone()),
        PlistValue::String(s) => {
            // Might be PEM formatted or Base64 encoded string
            if s.contains("BEGIN ") {
                Some(s.as_bytes().to_vec())
            } else {
                base64_decode(s).ok()
            }
        }
        _ => None,
    }
}

/// Normalizes PEM certificates or keys to pure DER binary
pub fn normalize_to_der(input: &[u8]) -> Result<Vec<u8>, String> {
    // If it starts with ASN.1 sequence (0x30), it's already DER
    if !input.is_empty() && input[0] == 0x30 {
        return Ok(input.to_vec());
    }

    let text = std::str::from_utf8(input)
        .map_err(|_| "Invalid non-DER binary data".to_string())?;

    // Extract between -----BEGIN ...----- and -----END ...-----
    if let Some(start_idx) = text.find("-----BEGIN") {
        if let Some(header_end) = text[start_idx..].find("-----") {
            let actual_header_end = start_idx + header_end + 5;
            if let Some(second_header_end) = text[actual_header_end..].find("-----") {
                let body_start = actual_header_end + second_header_end + 5;
                if let Some(footer_start) = text[body_start..].find("-----END") {
                    let b64_body = &text[body_start..body_start + footer_start];
                    return base64_decode(b64_body);
                }
            }
        }
    }

    // Attempt direct base64 decode if stripped of headers
    base64_decode(text).map_err(|e| format!("Failed to parse PEM/DER bytes: {}", e))
}
