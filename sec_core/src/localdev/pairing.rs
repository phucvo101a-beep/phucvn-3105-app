//! iOS Pairing File (.mobiledevicepairing / pair.plist / .json) Parser & Storage Manager
//! Fully compatible with iOS 15.0 - iOS 27.2.1

use super::plist_util::{base64_decode, dict_key_names, parse_plist, PlistValue};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde_json::Value as JsonValue;
use std::collections::{HashMap, VecDeque};
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
    /// Parses raw bytes of a .mobiledevicepairing, .plist, or .json pairing file
    pub fn parse(raw_data: &[u8]) -> Result<Self, String> {
        let root = parse_pairing_document(raw_data)?;
        let root_dict = root
            .as_dict()
            .ok_or_else(|| "Pairing file root must be a Dictionary".to_string())?;
        let dict = unwrap_pairing_dict(root_dict);
        let keys_summary = dict_key_names(dict).join(", ");

        // Reject pure Remote Pairing files when caller strictly requests classic Lockdown X.509
        if is_remote_pairing_dict(dict) {
            return Err("REMOTE_PAIRING_ONLY: Tệp sử dụng Remote Pairing (public_key / private_key / identifier / alt_irk).".to_string());
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
        let udid = get_str_ci(dict, &["UDID", "DeviceUDID", "TargetIdentifier", "UniqueDeviceID", "identifier"])
            .unwrap_or_else(|| "unknown-udid".to_string());

        // 4. HostCertificate
        let host_cert_raw = extract_bytes_ci(dict, &["HostCertificate"], None)
            .ok_or_else(|| format!("Missing required 'HostCertificate' (keys found: [{}])", keys_summary))?;
        let host_certificate_der = normalize_to_der(&host_cert_raw)?;

        // 5. HostPrivateKey
        let host_key_raw = extract_bytes_ci(dict, &["HostPrivateKey"], None)
            .ok_or_else(|| format!("Missing required 'HostPrivateKey' (keys found: [{}])", keys_summary))?;
        let host_private_key_der = normalize_to_der(&host_key_raw)?;

        // 6. RootCertificate (optional fallback to empty if Lockdown file omits it)
        let root_certificate_der = match extract_bytes_ci(dict, &["RootCertificate"], None) {
            Some(raw) => normalize_to_der(&raw)?,
            None => Vec::new(),
        };

        // 7. DeviceCertificate (optional fallback; `DeviceCertVerifier` tolerates empty)
        let device_certificate_der = match extract_bytes_ci(dict, &["DeviceCertificate"], None) {
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

fn json_to_plist_value(val: &JsonValue) -> PlistValue {
    match val {
        JsonValue::Null => PlistValue::String(String::new()),
        JsonValue::Bool(b) => PlistValue::Boolean(*b),
        JsonValue::Number(n) => {
            if let Some(i) = n.as_i64() {
                PlistValue::Integer(i)
            } else if let Some(u) = n.as_u64() {
                PlistValue::Integer(i64::try_from(u).unwrap_or(i64::MAX))
            } else {
                PlistValue::Real(n.as_f64().unwrap_or(0.0))
            }
        }
        JsonValue::String(s) => PlistValue::String(s.clone()),
        JsonValue::Array(items) => {
            PlistValue::Array(items.iter().map(json_to_plist_value).collect())
        }
        JsonValue::Object(map) => PlistValue::Dictionary(
            map.iter()
                .map(|(k, v)| (k.clone(), json_to_plist_value(v)))
                .collect(),
        ),
    }
}

fn strip_utf8_bom(data: &[u8]) -> &[u8] {
    if data.starts_with(&[0xEF, 0xBB, 0xBF]) {
        &data[3..]
    } else {
        data
    }
}

/// Parses XML plist, binary `bplist00`, or JSON pairing documents into a unified `PlistValue`.
pub fn parse_pairing_document(raw_data: &[u8]) -> Result<PlistValue, String> {
    let clean = strip_utf8_bom(raw_data);
    let trimmed_start = clean
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .map(|i| &clean[i..])
        .unwrap_or(clean);

    if trimmed_start.starts_with(b"{") {
        if let Ok(json) = serde_json::from_slice::<JsonValue>(trimmed_start) {
            return Ok(json_to_plist_value(&json));
        }
    }

    match parse_plist(clean) {
        Ok(val) => Ok(val),
        Err(plist_err) => {
            if let Ok(json) = serde_json::from_slice::<JsonValue>(trimmed_start) {
                Ok(json_to_plist_value(&json))
            } else {
                Err(plist_err)
            }
        }
    }
}

fn normalize_key_token(key: &str) -> String {
    key.bytes()
        .filter(|&b| b != b'_' && b != b'-' && !b.is_ascii_whitespace())
        .map(|b| b.to_ascii_lowercase() as char)
        .collect()
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
    for name in candidates {
        let target = normalize_key_token(name);
        for (k, v) in dict {
            if normalize_key_token(k) == target {
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

const WRAPPER_DICT_KEYS: &[&str] = &[
    "PairRecord",
    "PairingRecord",
    "pairingRecord",
    "pairing_record",
    "RemotePairing",
    "remotePairing",
    "remote_pairing",
    "pairing",
    "record",
    "identity",
];

fn dict_has_pairing_markers(dict: &HashMap<String, PlistValue>) -> bool {
    const MARKERS: &[&str] = &[
        "HostCertificate",
        "HostPrivateKey",
        "HostID",
        "SystemBUID",
        "public_key",
        "PublicKey",
        "private_key",
        "PrivateKey",
        "alt_irk",
        "AltIRK",
        "identifier",
    ];
    MARKERS.iter().any(|m| get_value_ci(dict, &[m]).is_some())
}

fn collect_candidate_dicts<'a>(root_dict: &'a HashMap<String, PlistValue>) -> Vec<&'a HashMap<String, PlistValue>> {
    let mut result = Vec::new();
    let mut queue = VecDeque::new();
    queue.push_back((root_dict, 0usize));

    while let Some((cur, depth)) = queue.pop_front() {
        if result.iter().any(|existing| std::ptr::eq(*existing, cur)) {
            continue;
        }
        result.push(cur);
        if depth >= 4 {
            continue;
        }
        // Enqueue known wrapper containers first for deterministic matching
        for key in WRAPPER_DICT_KEYS {
            if let Some(PlistValue::Dictionary(inner)) = get_value_ci(cur, &[key]) {
                if !inner.is_empty() {
                    queue.push_back((inner, depth + 1));
                }
            }
        }
        for val in cur.values() {
            if let PlistValue::Dictionary(inner) = val {
                if !inner.is_empty() {
                    queue.push_back((inner, depth + 1));
                }
            }
        }
    }
    result
}

fn unwrap_pairing_dict<'a>(dict: &'a HashMap<String, PlistValue>) -> &'a HashMap<String, PlistValue> {
    let candidates = collect_candidate_dicts(dict);
    if dict_has_pairing_markers(dict) {
        return dict;
    }
    for cand in &candidates {
        if dict_has_pairing_markers(cand) {
            return cand;
        }
    }
    for wrapper_key in WRAPPER_DICT_KEYS {
        if let Some(PlistValue::Dictionary(inner)) = get_value_ci(dict, &[wrapper_key]) {
            if !inner.is_empty() {
                return inner;
            }
        }
    }
    dict
}

fn is_remote_pairing_dict(dict: &HashMap<String, PlistValue>) -> bool {
    let has_pub = get_value_ci(dict, &["public_key", "PublicKey", "publicKey", "ed25519_public_key"]).is_some();
    let has_priv = get_value_ci(dict, &["private_key", "PrivateKey", "privateKey", "ed25519_private_key", "secret_key"]).is_some();
    let has_irk_and_id = get_value_ci(dict, &["alt_irk", "AltIRK", "altIRK"]).is_some()
        && get_value_ci(dict, &["identifier", "Identifier"]).is_some();
    let has_lockdown_cert = get_value_ci(dict, &["HostCertificate"]).is_some()
        && get_value_ci(dict, &["HostPrivateKey"]).is_some();
    ((has_pub && has_priv) || (has_irk_and_id && (has_pub || has_priv))) && !has_lockdown_cert
}

fn decode_string_bytes(raw: &str, prefer_hex_for_len: Option<usize>) -> Option<Vec<u8>> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.contains("BEGIN ") {
        return Some(trimmed.as_bytes().to_vec());
    }
    let hex_candidate = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if hex_candidate.len() >= 16
        && hex_candidate.len() % 2 == 0
        && hex_candidate.bytes().all(|b| b.is_ascii_hexdigit())
    {
        if let Some(expected) = prefer_hex_for_len {
            if hex_candidate.len() == expected * 2 || hex_candidate.len() == expected * 4 {
                if let Ok(bytes) = hex::decode(hex_candidate) {
                    return Some(bytes);
                }
            }
        } else if let Ok(bytes) = hex::decode(hex_candidate) {
            return Some(bytes);
        }
    }

    // Standard or URL-safe Base64 (with optional missing padding)
    let normalized_b64: String = trimmed
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            other => other,
        })
        .collect();
    if normalized_b64.is_empty() {
        return None;
    }
    base64_decode(&normalized_b64).ok().filter(|v| !v.is_empty())
}

fn extract_bytes_ci(
    dict: &HashMap<String, PlistValue>,
    candidates: &[&str],
    prefer_hex_for_len: Option<usize>,
) -> Option<Vec<u8>> {
    match get_value_ci(dict, candidates)? {
        PlistValue::Data(d) => Some(d.clone()),
        PlistValue::String(s) => decode_string_bytes(s, prefer_hex_for_len),
        PlistValue::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    PlistValue::Integer(n) if (0..=255).contains(n) => out.push(*n as u8),
                    _ => return None,
                }
            }
            if out.is_empty() { None } else { Some(out) }
        }
        _ => None,
    }
}

fn normalize_ed25519_private_key(raw: &[u8]) -> Result<[u8; 32], String> {
    let der = if raw.starts_with(b"-----BEGIN") {
        normalize_to_der(raw)?
    } else {
        raw.to_vec()
    };
    if der.len() == 32 {
        return der
            .try_into()
            .map_err(|_| "Invalid 32-byte Ed25519 private_key".to_string());
    }
    if der.len() == 64 {
        // Common seed || public_key concatenation
        return der[..32]
            .try_into()
            .map_err(|_| "Invalid 64-byte Ed25519 private_key".to_string());
    }
    if der.len() >= 48 && der[0] == 0x30 {
        // PKCS#8 Ed25519 private key embeds the 32-byte seed at tail
        return der[der.len() - 32..]
            .try_into()
            .map_err(|_| "Invalid PKCS#8 Ed25519 private_key".to_string());
    }
    Err(format!(
        "Remote Pairing 'private_key' has invalid length {} bytes (expected 32-byte Ed25519 seed)",
        der.len()
    ))
}

fn normalize_ed25519_public_key(raw: &[u8]) -> Result<[u8; 32], String> {
    let der = if raw.starts_with(b"-----BEGIN") {
        normalize_to_der(raw)?
    } else {
        raw.to_vec()
    };
    if der.len() == 32 {
        return der
            .try_into()
            .map_err(|_| "Invalid 32-byte Ed25519 public_key".to_string());
    }
    if der.len() >= 44 && der[0] == 0x30 {
        return der[der.len() - 32..]
            .try_into()
            .map_err(|_| "Invalid SPKI Ed25519 public_key".to_string());
    }
    Err(format!(
        "Remote Pairing 'public_key' has invalid length {} bytes (expected 32-byte Ed25519 key)",
        der.len()
    ))
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

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct RemotePairingFile {
    pub public_key: [u8; 32],
    pub private_key: [u8; 32],
    pub identifier: String,
    pub alt_irk: Option<Vec<u8>>,
    pub tunnel_port: Option<u16>,
    pub udid: Option<String>,
    pub raw_data: Vec<u8>,
}

impl RemotePairingFile {
    pub fn from_dict(dict: &HashMap<String, PlistValue>, raw_data: &[u8]) -> Result<Self, String> {
        let priv_raw = extract_bytes_ci(
            dict,
            &["private_key", "PrivateKey", "privateKey", "ed25519_private_key", "secret_key", "host_private_key"],
            Some(32),
        )
        .ok_or_else(|| "Missing 'private_key' in Remote Pairing file".to_string())?;
        let private_key = normalize_ed25519_private_key(&priv_raw)?;
        let signing_key = SigningKey::from_bytes(&private_key);

        let public_key = match extract_bytes_ci(
            dict,
            &["public_key", "PublicKey", "publicKey", "ed25519_public_key", "host_public_key"],
            Some(32),
        ) {
            Some(pub_raw) => {
                let pk = normalize_ed25519_public_key(&pub_raw)?;
                VerifyingKey::from_bytes(&pk)
                    .map_err(|_| "Remote Pairing 'public_key' is not a valid Ed25519 key".to_string())?;
                pk
            }
            None => signing_key.verifying_key().to_bytes(),
        };

        let identifier = get_str_ci(
            dict,
            &["identifier", "Identifier", "HostIdentifier", "host_identifier", "host_id", "UUID", "uuid", "UDID", "udid", "UniqueDeviceID"],
        )
        .ok_or_else(|| "Missing 'identifier' in Remote Pairing file".to_string())?;
        let alt_irk = extract_bytes_ci(dict, &["alt_irk", "altIRK", "AltIRK", "irk"], Some(16));
        let tunnel_port = extract_port_ci(
            dict,
            &["tunnel_port", "tunnelPort", "RemotePairPort", "remote_pair_port", "rsd_port", "rsdPort", "port"],
        );
        let udid = get_str_ci(dict, &["UDID", "UniqueDeviceID", "DeviceID", "udid", "pairedUDID", "target_identifier"]);

        Ok(Self {
            public_key,
            private_key,
            identifier,
            alt_irk,
            tunnel_port,
            udid,
            raw_data: raw_data.to_vec(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct UnifiedPairing {
    pub lockdown: Option<PairingFile>,
    pub remote: Option<RemotePairingFile>,
    pub tunnel_port: Option<u16>,
    pub udid: String,
}

impl UnifiedPairing {
    /// Parses classic Lockdown X.509, `idevice_pair` Remote Pairing (`public_key`/`private_key`/`identifier`/`alt_irk`),
    /// JSON Remote Pairing exports, or composite plists containing both sets of keys.
    pub fn parse(raw_data: &[u8]) -> Result<Self, String> {
        let root = parse_pairing_document(raw_data)?;
        let root_dict = root
            .as_dict()
            .ok_or_else(|| "Pairing file root must be a Dictionary".to_string())?;

        let candidate_dicts = collect_candidate_dicts(root_dict);
        let unwrapped = unwrap_pairing_dict(root_dict);

        let mut remote: Option<RemotePairingFile> = None;
        let mut remote_err: Option<String> = None;
        for d in &candidate_dicts {
            let has_priv = get_value_ci(
                d,
                &["private_key", "PrivateKey", "privateKey", "ed25519_private_key", "secret_key", "host_private_key"],
            )
            .is_some();
            let has_pub = get_value_ci(
                d,
                &["public_key", "PublicKey", "publicKey", "ed25519_public_key", "host_public_key"],
            )
            .is_some();
            if has_priv || has_pub {
                match RemotePairingFile::from_dict(d, raw_data) {
                    Ok(rp) => {
                        remote = Some(rp);
                        break;
                    }
                    Err(e) => remote_err = Some(e),
                }
            }
        }

        let lockdown = PairingFile::parse(raw_data).ok();

        if remote.is_none() && lockdown.is_none() {
            if let Some(e) = remote_err {
                return Err(e);
            }
            return PairingFile::parse(raw_data).map(|lf| Self {
                udid: lf.udid.clone(),
                tunnel_port: None,
                lockdown: Some(lf),
                remote: None,
            });
        }

        let tunnel_port = remote
            .as_ref()
            .and_then(|r| r.tunnel_port)
            .or_else(|| {
                extract_port_ci(
                    unwrapped,
                    &["tunnel_port", "tunnelPort", "RemotePairPort", "remote_pair_port", "rsd_port", "rsdPort", "port"],
                )
            });

        let udid = lockdown
            .as_ref()
            .map(|l| l.udid.clone())
            .filter(|u| !u.is_empty())
            .or_else(|| remote.as_ref().and_then(|r| r.udid.clone()))
            .or_else(|| remote.as_ref().map(|r| r.identifier.clone()))
            .unwrap_or_default();

        Ok(Self {
            lockdown,
            remote,
            tunnel_port,
            udid,
        })
    }

    pub fn save_to_dir(&self, dir: &Path) -> Result<(), String> {
        if !dir.exists() {
            fs::create_dir_all(dir).map_err(|e| format!("Failed to create storage dir: {}", e))?;
        }
        if let Some(ref lf) = self.lockdown {
            let _ = lf.save_to_dir(dir)?;
            if self.remote.is_none() {
                let _ = fs::remove_file(dir.join("remote_pairing.plist"));
            }
        }
        if let Some(ref rp) = self.remote {
            fs::write(dir.join("remote_pairing.plist"), &rp.raw_data)
                .map_err(|e| format!("Failed to write remote_pairing.plist: {}", e))?;
            if self.lockdown.is_none() {
                let _ = fs::remove_file(dir.join("pairing.mobiledevicepairing"));
                let _ = fs::remove_file(dir.join("pairing.plist"));
            }
        }
        Ok(())
    }

    pub fn load_any_from_dir(dir: &Path) -> Option<Result<Self, String>> {
        let remote_path = dir.join("remote_pairing.plist");
        let ld_1 = dir.join("pairing.mobiledevicepairing");
        let ld_2 = dir.join("pairing.plist");

        let ld_target = if ld_1.exists() {
            Some(ld_1)
        } else if ld_2.exists() {
            Some(ld_2)
        } else {
            None
        };

        match (remote_path.exists(), ld_target) {
            (true, Some(lp)) => {
                let mut base = match fs::read(&lp).map_err(|e| e.to_string()).and_then(|b| Self::parse(&b)) {
                    Ok(u) => u,
                    Err(e) => return Some(Err(e)),
                };
                if base.remote.is_none() {
                    if let Ok(rp_bytes) = fs::read(&remote_path) {
                        if let Ok(rp_parsed) = Self::parse(&rp_bytes) {
                            base.remote = rp_parsed.remote;
                            if base.tunnel_port.is_none() {
                                base.tunnel_port = rp_parsed.tunnel_port;
                            }
                        }
                    }
                }
                Some(Ok(base))
            }
            (true, None) => Some(
                fs::read(&remote_path)
                    .map_err(|e| format!("Failed to read stored remote pairing: {}", e))
                    .and_then(|b| Self::parse(&b)),
            ),
            (false, Some(lp)) => Some(
                fs::read(&lp)
                    .map_err(|e| format!("Failed to read stored pairing: {}", e))
                    .and_then(|b| Self::parse(&b)),
            ),
            (false, None) => None,
        }
    }
}

fn extract_port_ci(dict: &HashMap<String, PlistValue>, candidates: &[&str]) -> Option<u16> {
    let val = get_value_ci(dict, candidates)?;
    match val {
        PlistValue::Integer(n) => u16::try_from(*n).ok().filter(|&p| p > 0),
        PlistValue::String(s) => s.trim().parse::<u16>().ok().filter(|&p| p > 0),
        _ => None,
    }
}
