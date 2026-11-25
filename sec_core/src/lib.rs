//! 3105 Zero-Trust Security Core (libsec_core.dylib)
//! Implements Control-Flow Flattened V3 Crypto Auth, Anti-Tamper, Self-Integrity & In-RAM V4 Decryptor.

pub mod anti_debug;
pub mod anti_hook;
pub mod crypto;
pub mod device;
pub mod integrity;
pub mod ios_ui;
pub mod localdev;
pub mod network;
pub mod sabotage;
pub mod secrets;
pub mod syscall_arm64;

use obfstr::obfstr;
use serde_json::json;
use std::ffi::{c_char, CStr, CString};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use zeroize::{Zeroize, Zeroizing};

pub use localdev::ffi::*;

static WATCHDOG_STARTED: AtomicBool = AtomicBool::new(false);

const TICKET_VALID_MAGIC: i32 = 0x3105_5A17;

/// Constructor executed automatically before main() on dylib load.
#[used]
#[cfg_attr(target_vendor = "apple", link_section = "__DATA,__mod_init_func")]
pub static INIT_CONSTRUCTOR: extern "C" fn() = init_sec_core;

#[no_mangle]
pub extern "C" fn init_sec_core() {
    anti_debug::enforce_deny_attach();
    if perform_flattened_tamper_scan(false) != 0 {
        sabotage::wipe_vault(true);
    }
    start_watchdog_if_needed();
}

fn start_watchdog_if_needed() {
    if WATCHDOG_STARTED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
    {
        std::thread::spawn(|| loop {
            std::thread::sleep(Duration::from_secs(6));
            if perform_flattened_tamper_scan(true) != 0 {
                sabotage::mark_tampered_and_terminate();
            }
        });
    }
}

/// Control-flow flattened + opaque-predicate tamper evaluation across debug, hooks, and Mach-O integrity.
#[inline(never)]
fn perform_flattened_tamper_scan(include_network_ports: bool) -> u32 {
    let seed = secrets::gen::OPAQUE_SEED;
    // Opaque predicate always true modulo arithmetic invariant: (x * x + x) is always even
    let opaque_even = ((seed.wrapping_mul(seed)).wrapping_add(seed)) & 1;

    let mut state: u32 = if opaque_even == 0 { 0x1A } else { 0x9F };
    let mut acc_flags: u32 = 0;

    loop {
        match state {
            0x1A => {
                acc_flags |= anti_debug::anti_debug_bitmask();
                state = if (seed ^ 0xFF) != 0 { 0x3C } else { 0x7E };
            }
            0x3C => {
                acc_flags |= anti_hook::anti_hook_bitmask(include_network_ports);
                state = 0x5E;
            }
            0x5E => {
                if !integrity::verify_self_text_hash() {
                    acc_flags |= 0x100;
                }
                state = 0x7E;
            }
            0x7E => {
                if integrity::compute_app_binary_hash_bytes().is_none() && cfg!(target_vendor = "apple") {
                    acc_flags |= 0x200;
                }
                break;
            }
            _ => {
                acc_flags |= 0x400;
                break;
            }
        }
    }

    acc_flags
}

fn to_c_string(s: String) -> *mut c_char {
    CString::new(s)
        .map(|c| c.into_raw())
        .unwrap_or(core::ptr::null_mut())
}

enum ExchangeFailure {
    Network(String),
    Crypto(String),
    Tampered(String),
}

impl ExchangeFailure {
    fn into_error_json(self, include_ticket: bool) -> String {
        let (status, code, msg) = match self {
            ExchangeFailure::Network(msg) => ("network_error", "NETWORK_ERROR", msg),
            ExchangeFailure::Crypto(msg) => ("crypto_error", "CRYPTO_ERROR", msg),
            ExchangeFailure::Tampered(msg) => ("tampered", "TAMPER_DETECTED", msg),
        };
        let mut obj = json!({
            "ok": false,
            "status": status,
            "code": code,
            "server_open": true,
            "force_update": false,
            "message": msg,
        });
        if include_ticket {
            obj["ticket"] = json!("");
        }
        obj.to_string()
    }
}

fn execute_v3_exchange_flattened(op: &str, license_key: &str) -> Result<String, ExchangeFailure> {
    let seed = secrets::gen::OPAQUE_SEED;
    let opaque_even = ((seed.wrapping_mul(seed)).wrapping_add(seed)) & 1;
    let mut step: u32 = if opaque_even == 0 { 11 } else { 99 };
    let mut tamper: u32 = 0;
    let mut pkt_opt: Option<crypto::EncryptedExchangePacket> = None;
    let mut resp_raw = Zeroizing::new(String::new());
    let mut result_json = Zeroizing::new(String::new());

    loop {
        match step {
            11 => {
                tamper = perform_flattened_tamper_scan(false);
                if tamper != 0 || sabotage::is_runtime_tamper_latched() {
                    sabotage::wipe_vault(true);
                    return Err(ExchangeFailure::Tampered(format!(
                        "Phát hiện bất thường môi trường thực thi [mã 0x{tamper:x}]."
                    )));
                }
                step = 22;
            }
            22 => {
                let (pkg, ver, bld) = integrity::read_bundle_identity();
                let fp = device::get_device_fingerprint();
                let app_h = integrity::compute_app_binary_hash();
                let sec_h = integrity::compute_sec_core_hash();
                pkt_opt = Some(
                    crypto::build_v3_request(
                        op,
                        &pkg,
                        &ver,
                        &bld,
                        &fp,
                        &app_h,
                        &sec_h,
                        tamper,
                        license_key,
                    )
                    .map_err(ExchangeFailure::Crypto)?,
                );
                step = 33;
            }
            33 => {
                let pkt = pkt_opt
                    .as_ref()
                    .ok_or_else(|| ExchangeFailure::Crypto("Missing packet".to_string()))?;
                let host = secrets::api_host();
                let path = secrets::api_path();
                *resp_raw = network::post_encrypted_json(
                    &host,
                    &path,
                    &pkt.outer_json,
                    secrets::primary_spki_pin(),
                    secrets::backup_spki_pin(),
                    secrets::gen::REQUIRE_SPKI_PIN,
                )
                .map_err(ExchangeFailure::Network)?;
                step = 44;
            }
            44 => {
                let post_tamper = perform_flattened_tamper_scan(false);
                if post_tamper != 0 || sabotage::is_runtime_tamper_latched() {
                    sabotage::wipe_vault(true);
                    return Err(ExchangeFailure::Tampered(format!(
                        "Phát hiện bất thường môi trường thực thi [mã 0x{post_tamper:x}]."
                    )));
                }
                let pkt = pkt_opt
                    .as_ref()
                    .ok_or_else(|| ExchangeFailure::Crypto("Missing packet".to_string()))?;
                let (decoded, raw_env) = crypto::verify_and_decrypt_v3_response(pkt, &resp_raw)
                    .map_err(|e| {
                        sabotage::wipe_vault(false);
                        ExchangeFailure::Crypto(e)
                    })?;
                *resp_raw = String::new();

                let mut ticket = Zeroizing::new(String::new());
                if op == obfstr!("activate") || op == obfstr!("heartbeat") {
                    if decoded.server_open && !decoded.force_update && decoded.license.valid {
                        *ticket = sabotage::activate_vault_session(license_key, &decoded)
                            .map_err(|e| {
                                sabotage::wipe_vault(false);
                                ExchangeFailure::Crypto(e)
                            })?;
                    } else {
                        sabotage::wipe_vault(false);
                    }
                } else if !decoded.server_open || decoded.force_update || decoded.code == "TAMPER_DETECTED" {
                    sabotage::wipe_vault(false);
                }

                let out = json!({
                    "ok": true,
                    "status": decoded.status,
                    "code": decoded.code,
                    "server_open": decoded.server_open,
                    "force_update": decoded.force_update,
                    "min_version": decoded.min_version,
                    "latest_version": decoded.latest_version,
                    "download_url": decoded.download_url,
                    "message": decoded.message,
                    "license": decoded.license,
                    "ticket": ticket.as_str(),
                    "pkg": pkt.pkg,
                    "ver": pkt.ver,
                    "fp": pkt.fp,
                    "req_nonce": pkt.req_nonce_hex,
                    "raw_envelope": raw_env,
                });
                *result_json = out.to_string();
                step = 55;
            }
            55 => return Ok(core::mem::take(&mut *result_json)),
            _ => return Err(ExchangeFailure::Crypto(obfstr!("Control flow integrity error").to_string())),
        }
    }
}

/// Checks server open/closed status & mandatory force update using encrypted + Ed25519-signed V3 preflight.
#[no_mangle]
pub extern "C" fn sec_core_preflight() -> *mut c_char {
    match execute_v3_exchange_flattened(obfstr!("preflight"), "") {
        Ok(json_s) => to_c_string(json_s),
        Err(e) => {
            sabotage::wipe_vault(false);
            to_c_string(e.into_error_json(false))
        }
    }
}

/// Authenticates license key against server V3 API, populating masked RAM session + V4 bundle keys.
#[no_mangle]
pub unsafe extern "C" fn sec_core_activate(key_cstr: *const c_char) -> *mut c_char {
    let mut key_owned = if key_cstr.is_null() {
        String::new()
    } else {
        CStr::from_ptr(key_cstr)
            .to_string_lossy()
            .trim()
            .to_string()
    };
    let res = match execute_v3_exchange_flattened(obfstr!("activate"), &key_owned) {
        Ok(json_s) => to_c_string(json_s),
        Err(e) => {
            sabotage::wipe_vault(false);
            to_c_string(e.into_error_json(true))
        }
    };
    key_owned.zeroize();
    res
}

/// Periodic heartbeat re-verifying kill-switch, force-update, and key expiry.
#[no_mangle]
pub extern "C" fn sec_core_heartbeat() -> *mut c_char {
    let Some(saved_key) = sabotage::get_cached_license_key() else {
        return to_c_string(
            json!({
                "ok": false,
                "status": "denied",
                "code": "NO_SESSION",
                "message": "No active license key in RAM vault"
            })
            .to_string(),
        );
    };
    match execute_v3_exchange_flattened(obfstr!("heartbeat"), &saved_key) {
        Ok(json_s) => to_c_string(json_s),
        Err(e) => to_c_string(e.into_error_json(false)),
    }
}

/// Verifies ticket and runtime tamper state, returning magic marker on valid unlocked session.
#[no_mangle]
pub unsafe extern "C" fn sec_core_verify_ticket(ticket_cstr: *const c_char) -> i32 {
    if perform_flattened_tamper_scan(false) != 0 {
        sabotage::mark_tampered_and_terminate();
    }
    if ticket_cstr.is_null() {
        return 0;
    }
    let ticket = CStr::from_ptr(ticket_cstr).to_string_lossy();
    if sabotage::verify_ticket_valid(&ticket) {
        TICKET_VALID_MAGIC
    } else {
        0
    }
}

/// Stream-decrypts a V4 `.3105` container directly in RAM. Returns NULL unless ticket & server keys are valid.
#[no_mangle]
pub unsafe extern "C" fn sec_core_decrypt_v4(
    asset_ptr: *const u8,
    asset_len: usize,
    ticket_cstr: *const c_char,
    out_len: *mut usize,
) -> *mut u8 {
    if !out_len.is_null() {
        *out_len = 0;
    }
    if perform_flattened_tamper_scan(false) != 0 {
        sabotage::mark_tampered_and_terminate();
    }
    if asset_ptr.is_null() || asset_len == 0 || ticket_cstr.is_null() || out_len.is_null() {
        return core::ptr::null_mut();
    }
    let ticket = CStr::from_ptr(ticket_cstr).to_string_lossy();
    let asset_slice = core::slice::from_raw_parts(asset_ptr, asset_len);

    match sabotage::decrypt_v4_asset_in_ram(asset_slice, &ticket) {
        Ok(pt_zero) => {
            let mut boxed = pt_zero.to_vec().into_boxed_slice();
            let ptr = boxed.as_mut_ptr();
            let len = boxed.len();
            core::mem::forget(boxed);
            *out_len = len;
            ptr
        }
        Err(_) => core::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn sec_core_device_fp() -> *mut c_char {
    to_c_string(device::get_device_fingerprint())
}

#[no_mangle]
pub extern "C" fn sec_core_wipe_session() {
    sabotage::wipe_vault(false);
}

#[no_mangle]
pub extern "C" fn sec_core_tamper_detected() -> bool {
    sabotage::is_runtime_tamper_latched() || perform_flattened_tamper_scan(false) != 0
}

#[no_mangle]
pub unsafe extern "C" fn sec_core_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        let c = CString::from_raw(ptr);
        let mut z = c.into_bytes();
        z.zeroize();
    }
}

#[no_mangle]
pub unsafe extern "C" fn sec_core_free_bytes(ptr: *mut u8, len: usize) {
    if !ptr.is_null() && len > 0 {
        let mut slice = Box::from_raw(core::ptr::slice_from_raw_parts_mut(ptr, len));
        (*slice).zeroize();
    }
}
