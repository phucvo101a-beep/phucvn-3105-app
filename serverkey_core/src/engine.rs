use crate::crypto::{
    build_req_aad, build_res_aad, compute_shared_secret, decode_hex_24, decode_hex_32,
    decrypt_request_v3, derive_allowed_bundle_keys, derive_v3_key, random_hex_32,
    random_nonce_24, resolve_preset_statuses, seal_and_sign_response_v3, sha256_hex,
    verify_client_proof, verify_hmac_hex, PresetStatusPayload, ServerKeyMaterial,
};
use crate::storage::{format_vn_time, now_unix, BuildManifest, Storage};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use zeroize::Zeroizing;

const MAX_CLOCK_SKEW_SECS: i64 = 180;

#[derive(Debug, Deserialize)]
pub struct V3EnvelopeRequest {
    pub v: u32,
    pub op: String,
    pub pkg: String,
    pub ver: String,
    #[serde(default)]
    pub bld: String,
    pub nonce: String,
    pub ts: i64,
    pub c_pub: String,
    pub fp: String,
    pub ct: String,
    #[serde(default = "default_ip")]
    pub client_ip: String,
}

fn default_ip() -> String {
    "unknown".to_string()
}

#[derive(Debug, Deserialize)]
pub struct V3InnerPayload {
    pub op: String,
    #[serde(default)]
    pub key: String,
    pub pkg: String,
    pub ver: String,
    #[serde(default)]
    pub bld: String,
    #[serde(default)]
    pub app_hash: String,
    #[serde(default)]
    pub sec_hash: String,
    #[serde(default)]
    pub tamper_flags: u32,
    #[serde(default)]
    pub client_proof: String,
    pub ts: i64,
}

#[derive(Debug, Deserialize)]
pub struct CiRegisterRequest {
    pub package_id: String,
    pub version: String,
    #[serde(default)]
    pub build: String,
    pub app_hash: String,
    pub sec_hash: String,
    #[serde(default)]
    pub note: String,
    #[serde(default)]
    pub auto_update_latest: bool,
    pub nonce: String,
    pub ts: i64,
    pub sig: String,
}

#[derive(Debug, Serialize)]
struct LicenseSummary {
    valid: bool,
    key_masked: String,
    expiry: String,
    expiry_ts: i64,
    remaining_seconds: i64,
    is_permanent: bool,
    role: String,
    used_devices: usize,
    max_devices: u32,
}

impl Default for LicenseSummary {
    fn default() -> Self {
        Self {
            valid: false,
            key_masked: String::new(),
            expiry: String::new(),
            expiry_ts: 0,
            remaining_seconds: 0,
            is_permanent: false,
            role: String::new(),
            used_devices: 0,
            max_devices: 0,
        }
    }
}

/// Compares dotted SemVer strings numerically (returns Ordering: Less if a < b).
pub fn compare_semver(a: &str, b: &str) -> std::cmp::Ordering {
    let parse = |s: &str| -> Vec<u64> {
        s.trim()
            .trim_start_matches(['v', 'V'])
            .split(['-', '+'])
            .next()
            .unwrap_or("")
            .split('.')
            .map(|p| {
                let digits: String = p.chars().take_while(|c| c.is_ascii_digit()).collect();
                digits.parse::<u64>().unwrap_or(0)
            })
            .collect()
    };
    let mut pa = parse(a);
    let mut pb = parse(b);
    let len = pa.len().max(pb.len()).max(3);
    pa.resize(len, 0);
    pb.resize(len, 0);
    pa.cmp(&pb)
}

fn duration_to_seconds(dur: &str) -> Option<i64> {
    let d = dur.trim().to_ascii_lowercase();
    match d.as_str() {
        "permanent" | "lifetime" | "vv" | "forever" => None,
        "1h" | "1hour" => Some(3600),
        "1d" | "1day" => Some(86400),
        "7d" | "1w" => Some(7 * 86400),
        "30d" | "1m" => Some(30 * 86400),
        "90d" | "3m" => Some(90 * 86400),
        "365d" | "1y" => Some(365 * 86400),
        _ => {
            if let Some(num) = d.strip_suffix('h').and_then(|n| n.parse::<i64>().ok()) {
                Some(num.saturating_mul(3600))
            } else if let Some(num) = d.strip_suffix('d').and_then(|n| n.parse::<i64>().ok()) {
                Some(num.saturating_mul(86400))
            } else {
                Some(30 * 86400)
            }
        }
    }
}

/// Parses ISO/space datetime `YYYY-MM-DD HH:MM:SS` in UTC+7 or UTC unix timestamp fallback.
fn parse_expiry_ts(expiry_str: &str) -> Option<i64> {
    let s = expiry_str.trim();
    if s.is_empty() || s.eq_ignore_ascii_case("permanent") || s == "Vĩnh viễn" {
        return None;
    }
    let parts: Vec<&str> = s.split(['-', ' ', ':']).collect();
    if parts.len() != 6 {
        return None;
    }
    let y: i64 = parts[0].parse().ok()?;
    let m: i64 = parts[1].parse().ok()?;
    let d: i64 = parts[2].parse().ok()?;
    let hh: i64 = parts[3].parse().ok()?;
    let mm: i64 = parts[4].parse().ok()?;
    let ss: i64 = parts[5].parse().ok()?;

    // Howard Hinnant days-from-civil inverse (assuming input in UTC+7 -> subtract 7h)
    let y_adj = y - if m <= 2 { 1 } else { 0 };
    let era = if y_adj >= 0 { y_adj } else { y_adj - 399 } / 400;
    let yoe = y_adj - era * 400;
    let m_adj = m + if m > 2 { -3 } else { 9 };
    let doy = (153 * m_adj + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    let ts_vn = days * 86400 + hh * 3600 + mm * 60 + ss;
    Some(ts_vn - 7 * 3600)
}

fn mask_key(key: &str) -> String {
    if key.len() <= 8 {
        return "****".to_string();
    }
    format!("{}****{}", &key[..4], &key[key.len() - 4..])
}

/// Verifies integrity against active build manifests and returns authoritative app version if present.
fn verify_build_integrity(
    manifests: &[BuildManifest],
    pkg: &str,
    claimed_ver: &str,
    app_hash: &str,
    sec_hash: &str,
    enforce_hash: bool,
) -> Result<Option<String>, &'static str> {
    let pkg_manifests: Vec<&BuildManifest> = manifests
        .iter()
        .filter(|m| m.package_id == pkg)
        .collect();

    if app_hash.len() != 64
        || sec_hash.len() != 64
        || !app_hash.chars().all(|c| c.is_ascii_hexdigit())
        || !sec_hash.chars().all(|c| c.is_ascii_hexdigit())
    {
        if enforce_hash || !pkg_manifests.is_empty() {
            return Err("Invalid binary hash telemetry");
        }
        return Ok(None);
    }

    if let Some(m) = pkg_manifests.iter().find(|m| {
        m.app_hash.eq_ignore_ascii_case(app_hash) && m.sec_hash.eq_ignore_ascii_case(sec_hash)
    }) {
        if m.revoked || !m.active {
            return Err("Build hash revoked");
        }
        if compare_semver(claimed_ver, &m.version) != std::cmp::Ordering::Equal {
            return Err("Manifest version mismatch");
        }
        return Ok(Some(m.version.clone()));
    }

    // If any manifest exists with this app_hash only, prevent Info.plist version spoofing
    if let Some(m_app) = pkg_manifests
        .iter()
        .find(|m| m.app_hash.eq_ignore_ascii_case(app_hash))
    {
        if m_app.revoked || !m_app.active {
            return Err("Build hash revoked");
        }
        return Err("Security core dylib hash mismatch");
    }

    if enforce_hash || pkg_manifests.iter().any(|m| m.active && !m.revoked) {
        return Err("Unrecognized client binary hash");
    }

    Ok(None)
}

/// Processes encrypted+signed V3 preflight / activate / heartbeat requests.
pub fn handle_v3_request(
    storage: &Storage,
    keys: &ServerKeyMaterial,
    req: &V3EnvelopeRequest,
) -> Result<Value, (u16, Value)> {
    let now = now_unix();

    if req.v != 3 {
        return Err((400, json!({"error": "Unsupported protocol version"})));
    }
    if !matches!(req.op.as_str(), "preflight" | "activate" | "heartbeat") {
        return Err((400, json!({"error": "Unsupported operation"})));
    }
    if (now - req.ts).abs() > MAX_CLOCK_SKEW_SECS {
        return Err((403, json!({"error": "Timestamp outside permitted skew"})));
    }

    let req_nonce24 = decode_hex_24(&req.nonce, "nonce")
        .map_err(|_| (400, json!({"error": "Malformed nonce"})))?;
    let c_pub = decode_hex_32(&req.c_pub, "c_pub")
        .map_err(|_| (400, json!({"error": "Malformed c_pub"})))?;
    let _fp_bytes = decode_hex_32(&req.fp, "fp")
        .map_err(|_| (400, json!({"error": "Malformed fingerprint"})))?;

    // Rate limiting before expensive operations / key lookup
    let ip_ok = storage
        .check_rate_limit(&format!("ip:{}", req.client_ip), 60, 60, 120, now)
        .unwrap_or(true);
    let fp_ok = storage
        .check_rate_limit(&format!("fp:{}", req.fp), 60, 35, 180, now)
        .unwrap_or(true);
    if !ip_ok || !fp_ok {
        storage.append_log("RATE_LIMIT", "", &req.fp, &req.client_ip, &req.op);
        return Err((429, json!({"error": "Too many requests"})));
    }

    // Strict replay prevention
    match storage.check_and_record_nonce(&req.nonce.to_lowercase(), now) {
        Ok(true) => {}
        Ok(false) => {
            storage.append_log("REPLAY_REJECTED", "", &req.fp, &req.client_ip, &req.nonce);
            return Err((403, json!({"error": "Replay nonce detected"})));
        }
        Err(_) => return Err((500, json!({"error": "Nonce store unavailable"}))),
    }

    // Compute shared ECDH & derive request AEAD key
    let shared = compute_shared_secret(&keys.x25519_priv, &c_pub);
    let req_key = derive_v3_key(&shared, &keys.pepper, b"3105-V3-REQ")
        .map_err(|_| (500, json!({"error": "Key derivation failed"})))?;

    let req_aad = build_req_aad(
        req.v,
        &req.op,
        &req.pkg,
        &req.ver,
        &req.bld,
        &req.fp,
        &req.nonce,
        req.ts,
    );

    let pt = Zeroizing::new(decrypt_request_v3(&req_key, &req_nonce24, &req_aad, &req.ct).map_err(|_| {
        storage.append_log("AEAD_FAIL", "", &req.fp, &req.client_ip, &req.pkg);
        (403, json!({"error": "Cryptographic verification failed"}))
    })?);

    let inner: V3InnerPayload = serde_json::from_slice(&pt)
        .map_err(|_| (400, json!({"error": "Invalid encrypted payload"})))?;

    // Cross-check inner vs outer fields & verify pepper-bound client proof
    if inner.op != req.op || inner.pkg != req.pkg || inner.ver != req.ver || inner.ts != req.ts {
        storage.append_log("AAD_MISMATCH", "", &req.fp, &req.client_ip, &req.pkg);
        return Err((403, json!({"error": "Envelope mismatch"})));
    }
    if !verify_client_proof(&keys.pepper, &req_aad, &inner.key, &inner.client_proof) {
        storage.append_log("PROOF_FAIL", "", &req.fp, &req.client_ip, &req.pkg);
        return Err((403, json!({"error": "Client authentication proof invalid"})));
    }

    // Helper closure to build signed+encrypted V3 response guaranteeing NO keys on failure
    let send_v3 = |status: &str,
                   code: &str,
                   server_open: bool,
                   force_update: bool,
                   min_ver: &str,
                   latest_ver: &str,
                   download_url: &str,
                   message: &str,
                   eph_key: Option<String>,
                   session_token: Option<String>,
                   bundle_keys: std::collections::BTreeMap<String, String>,
                   preset_statuses: std::collections::BTreeMap<String, PresetStatusPayload>,
                   license: LicenseSummary|
     -> Result<Value, (u16, Value)> {
        let s_ts = now_unix();
        let (s_nonce24, s_nonce_hex) = random_nonce_24();
        let res_aad = build_res_aad(
            &req.op,
            &req.pkg,
            &req.ver,
            &req.fp,
            &req.nonce,
            &s_nonce_hex,
            s_ts,
            code,
        );
        let inner_res = json!({
            "status": status,
            "code": code,
            "op": req.op,
            "server_open": server_open,
            "force_update": force_update,
            "min_version": min_ver,
            "latest_version": latest_ver,
            "download_url": download_url,
            "message": message,
            "req_nonce": req.nonce,
            "s_nonce": s_nonce_hex,
            "s_ts": s_ts,
            "ephemeral_session_key": eph_key,
            "session_token": session_token,
            "bundle_keys": bundle_keys,
            "preset_statuses": preset_statuses,
            "license": license,
        });
        let pt_bytes = Zeroizing::new(
            serde_json::to_vec(&inner_res)
                .map_err(|_| (500, json!({"error": "Response serialize error"})))?,
        );
        let (ct_b64, sig_hex) = seal_and_sign_response_v3(
            keys,
            &shared,
            &req_nonce24,
            &s_nonce24,
            &res_aad,
            &pt_bytes,
        )
        .map_err(|_| (500, json!({"error": "Response sign error"})))?;

        Ok(json!({
            "v": 3,
            "op": req.op,
            "pkg": req.pkg,
            "ver": req.ver,
            "fp": req.fp,
            "req_nonce": req.nonce,
            "s_nonce": s_nonce_hex,
            "s_ts": s_ts,
            "code": code,
            "ct": ct_b64,
            "sig": sig_hex,
        }))
    };

    let settings = storage
        .load_settings()
        .map_err(|_| (500, json!({"error": "Settings unavailable"})))?;
    let policy = settings.resolve_policy(&req.pkg);
    let preset_statuses = resolve_preset_statuses(&settings.preset_policies);

    // 1. KILL-SWITCH CHECK FIRST (never issue keys when server is closed)
    if !policy.server_open {
        storage.append_log(
            "SERVER_CLOSED_DENY",
            &mask_key(&inner.key),
            &req.fp,
            &req.client_ip,
            &req.pkg,
        );
        return send_v3(
            "server_closed",
            "SERVER_CLOSED",
            false,
            false,
            &policy.min_required_version,
            &policy.latest_version,
            &policy.download_url,
            &policy.closed_message,
            None,
            None,
            Default::default(),
            Default::default(),
            LicenseSummary::default(),
        );
    }

    // 1b. DEVICE HWID BAN CHECK (blocks banned device at preflight, activate & heartbeat)
    if let Ok(Some(ban_rec)) = storage.find_active_ban(&req.fp) {
        let reason_txt = if ban_rec.reason.trim().is_empty() {
            "Thiết bị này đã bị Admin cấm truy cập vĩnh viễn khỏi hệ thống.".to_string()
        } else {
            format!("Thiết bị này đã bị khóa vĩnh viễn. Lý do: {}", ban_rec.reason.trim())
        };
        storage.append_log(
            "DEVICE_BANNED_DENY",
            &mask_key(&inner.key),
            &req.fp,
            &req.client_ip,
            &reason_txt,
        );
        return send_v3(
            "device_banned",
            "DEVICE_BANNED",
            true,
            false,
            &policy.min_required_version,
            &policy.latest_version,
            &policy.download_url,
            &reason_txt,
            None,
            None,
            Default::default(),
            Default::default(),
            LicenseSummary::default(),
        );
    }

    // 2. ANTI-TAMPER & BINARY HASH CHECK
    if inner.tamper_flags != 0 {
        storage.append_log(
            "CLIENT_TAMPER_FLAGS",
            &mask_key(&inner.key),
            &req.fp,
            &req.client_ip,
            &format!("flags={}", inner.tamper_flags),
        );
        return send_v3(
            "denied",
            "TAMPER_DETECTED",
            true,
            false,
            &policy.min_required_version,
            &policy.latest_version,
            &policy.download_url,
            "Phát hiện can thiệp môi trường thực thi. Phiên bị khóa.",
            None,
            None,
            Default::default(),
            Default::default(),
            LicenseSummary::default(),
        );
    }

    let manifests = storage.load_manifests().unwrap_or_default();
    let authoritative_ver = match verify_build_integrity(
        &manifests,
        &req.pkg,
        &req.ver,
        &inner.app_hash,
        &inner.sec_hash,
        policy.enforce_binary_hash,
    ) {
        Ok(Some(v)) => v,
        Ok(None) => req.ver.clone(),
        Err(reason) => {
            storage.append_log(
                "HASH_DENY",
                &mask_key(&inner.key),
                &req.fp,
                &req.client_ip,
                reason,
            );
            return send_v3(
                "denied",
                "TAMPER_DETECTED",
                true,
                false,
                &policy.min_required_version,
                &policy.latest_version,
                &policy.download_url,
                "Ứng dụng đã bị sửa đổi chữ ký hoặc không hợp lệ.",
                None,
                None,
                Default::default(),
                Default::default(),
                LicenseSummary::default(),
            );
        }
    };

    // 3. FORCE UPDATE CHECK (server open, check version)
    let is_outdated = compare_semver(&authoritative_ver, &policy.min_required_version)
        == std::cmp::Ordering::Less;
    let should_force_update = is_outdated
        || (policy.force_update
            && compare_semver(&authoritative_ver, &policy.latest_version)
                == std::cmp::Ordering::Less);

    if should_force_update {
        storage.append_log(
            "FORCE_UPDATE_DENY",
            &mask_key(&inner.key),
            &req.fp,
            &req.client_ip,
            &format!("ver={authoritative_ver} min={}", policy.min_required_version),
        );
        return send_v3(
            "force_update",
            "FORCE_UPDATE",
            true,
            true,
            &policy.min_required_version,
            &policy.latest_version,
            &policy.download_url,
            &policy.update_message,
            None,
            None,
            Default::default(),
            Default::default(),
            LicenseSummary::default(),
        );
    }

    // 4. PREFLIGHT ONLY: server is open and version is valid -> return signed status, NO keys
    if req.op == "preflight" {
        return send_v3(
            "ok",
            "OK",
            true,
            false,
            &policy.min_required_version,
            &policy.latest_version,
            &policy.download_url,
            "Máy chủ đang hoạt động. Sẵn sàng xác thực key.",
            None,
            None,
            Default::default(),
            preset_statuses,
            LicenseSummary::default(),
        );
    }

    // 5. ACTIVATE / HEARTBEAT: require valid non-empty license key & rate limit brute-force
    let clean_key = inner.key.trim().to_string();
    let key_bucket = format!("kf:{}", &sha256_hex(clean_key.as_bytes())[..16]);
    let ip_kf_bucket = format!("ip_kf:{}", req.client_ip);
    if storage.is_rate_limited(&ip_kf_bucket, now) || storage.is_rate_limited(&key_bucket, now) {
        storage.append_log(
            "KEY_BRUTE_BLOCK",
            &mask_key(&clean_key),
            &req.fp,
            &req.client_ip,
            &req.pkg,
        );
        return Err((429, json!({"error": "Too many failed license attempts"})));
    }
    if clean_key.is_empty() || clean_key.len() > 128 {
        return send_v3(
            "denied",
            "INVALID_KEY",
            true,
            false,
            &policy.min_required_version,
            &policy.latest_version,
            &policy.download_url,
            "Vui lòng nhập mã Key hợp lệ.",
            None,
            None,
            Default::default(),
            Default::default(),
            LicenseSummary::default(),
        );
    }

    enum KeyCheckOutcome {
        Ok(LicenseSummary),
        Fail(&'static str, String),
    }

    let outcome = storage
        .mutate_keys(|keys_vec| {
            let Some(rec) = keys_vec
                .iter_mut()
                .find(|k| k.key.eq_ignore_ascii_case(&clean_key))
            else {
                return Ok(KeyCheckOutcome::Fail(
                    "INVALID_KEY",
                    "Mã Key không tồn tại trên hệ thống!".to_string(),
                ));
            };

            if rec.status.eq_ignore_ascii_case("banned")
                || rec.status.eq_ignore_ascii_case("disabled")
                || rec.status.eq_ignore_ascii_case("revoked")
            {
                let reason = rec.ban_reason.trim();
                let msg = if reason.is_empty() {
                    "Mã Key này đã bị khóa hoặc thu hồi!".to_string()
                } else {
                    format!("Mã Key này đã bị khóa/cấm! Lý do: {reason}")
                };
                return Ok(KeyCheckOutcome::Fail("KEY_REVOKED", msg));
            }

            if !rec.bound_packages.is_empty() && !rec.bound_packages.contains(&req.pkg) {
                return Ok(KeyCheckOutcome::Fail(
                    "PACKAGE_DENIED",
                    "Mã Key này không hợp lệ cho gói ứng dụng hiện tại.".to_string(),
                ));
            }

            // Compute or activate expiry_ts cleanly (fixes bug in old api_v2.php!)
            let mut exp_ts = rec
                .expiry_ts
                .or_else(|| rec.expiry_date.as_deref().and_then(parse_expiry_ts))
                .unwrap_or(0);

            if !rec.is_used && exp_ts == 0 {
                if let Some(dur_secs) = duration_to_seconds(&rec.duration) {
                    exp_ts = now + dur_secs;
                    rec.expiry_ts = Some(exp_ts);
                    rec.expiry_date = Some(format_vn_time(exp_ts));
                } else {
                    rec.expiry_ts = Some(0);
                    rec.expiry_date = None;
                }
            } else if exp_ts > 0 {
                rec.expiry_ts = Some(exp_ts);
            }

            let is_permanent = exp_ts == 0 && duration_to_seconds(&rec.duration).is_none();
            if exp_ts > 0 && now >= exp_ts {
                return Ok(KeyCheckOutcome::Fail(
                    "KEY_EXPIRED",
                    format!(
                        "Key đã hết hạn lúc {}!",
                        rec.expiry_date.as_deref().unwrap_or("")
                    ),
                ));
            }

            // Sync devices / used_by slots cleanly (PHP-compatible DeviceEntry format)
            if rec.devices.is_empty() {
                match &rec.used_by {
                    Some(Value::String(s)) => {
                        for h in s.split(',').map(str::trim).filter(|x| !x.is_empty()) {
                            rec.devices.push(crate::storage::DeviceEntry::Obj(
                                crate::storage::DeviceObject {
                                    hwid: h.to_string(),
                                    activated_at: format_vn_time(now),
                                    last_seen: format_vn_time(now),
                                    ip: req.client_ip.clone(),
                                    extra: Default::default(),
                                },
                            ));
                        }
                    }
                    Some(Value::Array(arr)) => {
                        for h in arr.iter().filter_map(|v| v.as_str()).filter(|x| !x.is_empty()) {
                            rec.devices.push(crate::storage::DeviceEntry::Obj(
                                crate::storage::DeviceObject {
                                    hwid: h.to_string(),
                                    activated_at: format_vn_time(now),
                                    last_seen: format_vn_time(now),
                                    ip: req.client_ip.clone(),
                                    extra: Default::default(),
                                },
                            ));
                        }
                    }
                    _ => {}
                }
            }

            let max_dev = rec.max_devices;
            let existing_idx = rec
                .devices
                .iter()
                .position(|d| d.hwid().eq_ignore_ascii_case(&req.fp));
            let now_str = format_vn_time(now);

            if let Some(idx) = existing_idx {
                if let crate::storage::DeviceEntry::Obj(ref mut obj) = rec.devices[idx] {
                    obj.last_seen = now_str.clone();
                    obj.ip = req.client_ip.clone();
                }
            } else {
                if req.op == "heartbeat" {
                    return Ok(KeyCheckOutcome::Fail(
                        "DEVICE_MISMATCH",
                        "Thiết bị đã bị gỡ khỏi Key trên hệ thống.".to_string(),
                    ));
                }
                if max_dev > 0 && rec.devices.len() as u32 >= max_dev {
                    return Ok(KeyCheckOutcome::Fail(
                        "DEVICE_LIMIT",
                        format!(
                            "Key đã đạt giới hạn thiết bị ({}/{max_dev}).",
                            rec.devices.len()
                        ),
                    ));
                }
                rec.devices.push(crate::storage::DeviceEntry::Obj(
                    crate::storage::DeviceObject {
                        hwid: req.fp.clone(),
                        activated_at: now_str.clone(),
                        last_seen: now_str,
                        ip: req.client_ip.clone(),
                        extra: Default::default(),
                    },
                ));
            }
            let joined_hwids: Vec<&str> = rec.devices.iter().map(|d| d.hwid()).collect();
            rec.used_by = Some(Value::String(joined_hwids.join(", ")));
            rec.is_used = true;

            let rem_secs = if is_permanent {
                i64::MAX
            } else {
                (exp_ts - now).max(0)
            };
            let expiry_label = if is_permanent {
                "Vĩnh viễn".to_string()
            } else {
                rec.expiry_date
                    .clone()
                    .unwrap_or_else(|| format_vn_time(exp_ts))
            };

            Ok(KeyCheckOutcome::Ok(LicenseSummary {
                valid: true,
                key_masked: mask_key(&rec.key),
                expiry: expiry_label,
                expiry_ts: exp_ts,
                remaining_seconds: rem_secs,
                is_permanent,
                role: rec.role.clone(),
                used_devices: rec.devices.len(),
                max_devices: max_dev,
            }))
        })
        .map_err(|_| (500, json!({"error": "License database error"})))?;

    match outcome {
        KeyCheckOutcome::Fail(code, msg) => {
            let _ = storage.check_rate_limit(&key_bucket, 300, 12, 600, now);
            let _ = storage.check_rate_limit(&ip_kf_bucket, 300, 25, 600, now);
            storage.append_log(
                code,
                &mask_key(&clean_key),
                &req.fp,
                &req.client_ip,
                &msg,
            );
            send_v3(
                "denied",
                code,
                true,
                false,
                &policy.min_required_version,
                &policy.latest_version,
                &policy.download_url,
                &msg,
                None,
                None,
                Default::default(),
                Default::default(),
                LicenseSummary::default(),
            )
        }
        KeyCheckOutcome::Ok(summary) => {
            let eph_key = random_hex_32();
            let bundle_keys = derive_allowed_bundle_keys(&keys.bundle_master_key, &preset_statuses)
                .map_err(|_| (500, json!({"error": "Bundle key derivation failed"})))?;
            let session_token = sha256_hex(
                format!("{eph_key}|{}|{}|{}", req.fp, req.pkg, now).as_bytes(),
            );
            storage.append_log(
                "KEY_ACTIVATED",
                &summary.key_masked,
                &req.fp,
                &req.client_ip,
                &format!("ver={authoritative_ver}"),
            );
            send_v3(
                "ok",
                "OK",
                true,
                false,
                &policy.min_required_version,
                &policy.latest_version,
                &policy.download_url,
                "Xác thực thành công!",
                Some(eph_key),
                Some(session_token),
                bundle_keys,
                preset_statuses,
                summary,
            )
        }
    }
}

/// Processes HMAC-authenticated CI build registration from GitHub Actions.
pub fn handle_ci_register_build(
    storage: &Storage,
    keys: &ServerKeyMaterial,
    req: &CiRegisterRequest,
) -> Result<Value, (u16, Value)> {
    let now = now_unix();
    if (now - req.ts).abs() > MAX_CLOCK_SKEW_SECS {
        return Err((403, json!({"error": "Timestamp expired"})));
    }
    if req.app_hash.len() != 64 || req.sec_hash.len() != 64 {
        return Err((400, json!({"error": "Invalid SHA-256 hash format"})));
    }
    let sign_input = format!(
        "CIREG|{}|{}|{}|{}|{}|{}|{}",
        req.package_id, req.version, req.build, req.app_hash, req.sec_hash, req.nonce, req.ts
    );
    if !verify_hmac_hex(&keys.ci_sync_secret, sign_input.as_bytes(), &req.sig) {
        return Err((403, json!({"error": "Invalid CI signature"})));
    }
    match storage.check_and_record_nonce(&format!("ci:{}", req.nonce), now) {
        Ok(true) => {}
        _ => return Err((403, json!({"error": "Duplicate CI nonce"}))),
    }

    storage
        .register_manifest(BuildManifest {
            package_id: req.package_id.clone(),
            version: req.version.clone(),
            build: req.build.clone(),
            app_hash: req.app_hash.to_lowercase(),
            sec_hash: req.sec_hash.to_lowercase(),
            active: true,
            revoked: false,
            registered_at: format_vn_time(now),
            note: req.note.clone(),
        })
        .map_err(|e| (500, json!({"error": e})))?;

    if req.auto_update_latest {
        let _ = storage.save_settings_with(|s| {
            let pkg = s.packages.entry(req.package_id.clone()).or_insert_with(|| {
                crate::storage::PackagePolicy {
                    server_open: None,
                    server_closed_message: None,
                    force_update: None,
                    min_required_version: None,
                    latest_version: None,
                    download_url: None,
                    update_message: None,
                    enforce_binary_hash: None,
                }
            });
            pkg.latest_version = Some(req.version.clone());
            if s.latest_version.is_empty()
                || compare_semver(&s.latest_version, &req.version) == std::cmp::Ordering::Less
            {
                s.latest_version = req.version.clone();
            }
        });
    }

    storage.append_log(
        "CI_BUILD_SYNC",
        "CI",
        &req.version,
        "github-actions",
        &format!("pkg={} app={}", req.package_id, &req.app_hash[..12]),
    );

    Ok(json!({
        "ok": true,
        "package_id": req.package_id,
        "version": req.version,
        "app_hash": req.app_hash.to_lowercase(),
        "sec_hash": req.sec_hash.to_lowercase(),
    }))
}
