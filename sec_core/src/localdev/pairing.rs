//! iOS Pairing File (.mobiledevicepairing / pair.plist) Parser & Storage Manager
//! Fully compatible with iOS 15.0 - iOS 27.2.1

use super::plist_util::{base64_decode, dict_key_names, parse_plist, PlistValue};
use std::collections::HashMap;
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
        let root_dict = root
            .as_dict()
            .ok_or_else(|| "Pairing file root must be a Dictionary".to_string())?;
        let dict = unwrap_pairing_dict(root_dict);
        let keys_summary = dict_key_names(dict).join(", ");

        // Detect `idevice pair v1.2.0` Remote Pairing plist (XML or bplist00)
        // Keys typically: `public_key`, `private_key`, `identifier`, `alt_irk`
        if is_remote_pairing_dict(dict) {
            return Err("REMOTE_PAIRING_UNSUPPORTED: Đã nhận diện tệp Remote Pairing (public_key / private_key / identifier / alt_irk), nhưng libsec_core.dylib hiện tại chỉ hỗ trợ Lockdown X.509 TLS (HostCertificate & HostPrivateKey trên cổng 62078).".to_string());
        }

        // 1. HostID / SystemBUID (accept SystemBUID as HostID fallback if omitted)
        let system_buid_opt = get_str_ci(dict, &["SystemBUID"]);
        let host_id = get_str_ci(dict, &["HostID"])
            .or_else(|| system_buid_opt.clone())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| format!("Missing required 'HostID'/'SystemBUID' (keys found: [{}])", keys_summary))?;

        // 2. SystemBUID
        let system_buid = system_buid_opt
            .unwrap_or_else(|| "00000000-0000-0000-0000-000000000000".to_string());

        // 3. UDID
        let udid = get_str_ci(dict, &["UDID", "DeviceUDID", "TargetIdentifier", "identifier"])
            .unwrap_or_else(|| "unknown-udid".to_string());

        // 4. HostCertificate
        let host_cert_raw = extract_bytes_ci(dict, &["HostCertificate"])
            .ok_or_else(|| format!("Missing required 'HostCertificate' (keys found: [{}])", keys_summary))?;
        let host_certificate_der = normalize_to_der(&host_cert_raw)?;

        // 5. HostPrivateKey
        let host_key_raw = extract_bytes_ci(dict, &["HostPrivateKey"])
            .ok_or_else(|| format!("Missing required 'HostPrivateKey' (keys found: [{}])", keys_summary))?;
        let host_private_key_der = normalize_to_der(&host_key_raw)?;

        // 6. RootCertificate (optional fallback to empty if Lockdown file omits it)
        let root_certificate_der = match extract_bytes_ci(dict, &["RootCertificate"]) {
            Some(raw) => normalize_to_der(&raw)?,
            None => Vec::new(),
        };

        // 7. DeviceCertificate (optional fallback; `DeviceCertVerifier` tolerates empty)
        let device_certificate_der = match extract_bytes_ci(dict, &["DeviceCertificate"]) {
            Some(raw) => normalize_to_der(&raw)?,
            None => Vec::new(),
        };

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

    /// Loads saved Lockdown pairing file if present in directory, preserving parse diagnostics
    pub fn load_any_from_dir(dir: &Path) -> Option<Result<Self, String>> {
        let candidate1 = dir.join("pairing.mobiledevicepairing");
        let candidate2 = dir.join("pairing.plist");

        let target = if candidate1.exists() {
            candidate1
        } else if candidate2.exists() {
            candidate2
        } else {
            return None;
        };

        Some(
            fs::read(&target)
                .map_err(|e| format!("Failed to read stored pairing: {}", e))
                .and_then(|data| Self::parse(&data)),
        )
    }

    /// Loads pairing file from persistent storage directory
    pub fn load_from_dir(dir: &Path) -> Result<Self, String> {
        match Self::load_any_from_dir(dir) {
            Some(res) => res,
            None => Err("No pairing file found in directory".to_string()),
        }
    }
}

fn get_value_ci<'a>(dict: &'a HashMap<String, PlistValue>, candidates: &[&str]) -> Option<&'a PlistValue> {
    for name in candidates {
        if let Some(v) = dict.get(*name) {
            return Some(v);
        }
    }
    for name in candidates {
        let target = name.to_ascii_lowercase();
        for (k, v) in dict {
            if k.to_ascii_lowercase() == target {
                return Some(v);
            }
        }
    }
    None
}

fn get_str_ci(dict: &HashMap<String, PlistValue>, candidates: &[&str]) -> Option<String> {
    get_value_ci(dict, candidates)
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn unwrap_pairing_dict<'a>(dict: &'a HashMap<String, PlistValue>) -> &'a HashMap<String, PlistValue> {
    for wrapper_key in ["PairRecord", "PairingRecord", "RemotePairing", "pairing_record"] {
        if let Some(PlistValue::Dictionary(inner)) = get_value_ci(dict, &[wrapper_key]) {
            if !inner.is_empty() {
                return inner;
            }
        }
    }
    dict
}

fn is_remote_pairing_dict(dict: &HashMap<String, PlistValue>) -> bool {
    let has_pub = get_value_ci(dict, &["public_key", "PublicKey", "publicKey"]).is_some();
    let has_priv = get_value_ci(dict, &["private_key", "PrivateKey", "privateKey"]).is_some();
    let has_lockdown_cert = get_value_ci(dict, &["HostCertificate"]).is_some()
        && get_value_ci(dict, &["HostPrivateKey"]).is_some();
    has_pub && has_priv && !has_lockdown_cert
}

fn extract_bytes_ci(dict: &HashMap<String, PlistValue>, candidates: &[&str]) -> Option<Vec<u8>> {
    match get_value_ci(dict, candidates)? {
        PlistValue::Data(d) => Some(d.clone()),
        PlistValue::String(s) => {
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
