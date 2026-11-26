//! C-ABI FFI Bridge for Swift & UIKit Integration
//! All functions are thread-safe, return structured JSON and guarantee safe memory management

use super::afc_client::AfcClient;
use super::house_arrest::HouseArrestClient;
use super::with_manager;
use serde_json::json;
use std::ffi::{c_char, CStr, CString};

// Service types:
// 1 = Device AFC (afc2 / afc)
// 2 = App Container House Arrest (VendContainer / VendDocuments)
pub const SERVICE_TYPE_DEVICE_AFC: i32 = 1;
pub const SERVICE_TYPE_HOUSE_ARREST: i32 = 2;

/// Initializes LocalDev manager with storage path and optional loopback host/port
#[no_mangle]
pub unsafe extern "C" fn localdev_init(
    storage_path: *const c_char,
    default_host: *const c_char,
    port: u16,
) -> i32 {
    let storage_str = if !storage_path.is_null() {
        CStr::from_ptr(storage_path).to_str().ok()
    } else {
        None
    };

    let host_str = if !default_host.is_null() {
        CStr::from_ptr(default_host).to_str().ok()
    } else {
        None
    };

    let port_opt = if port > 0 { Some(port) } else { None };

    with_manager(|mgr| {
        mgr.init(storage_str, host_str, port_opt);
    });

    0
}

/// Registers Swift Network.framework callbacks (`NWBrowser`/`NWConnection` pre-warm + relay proxy)
/// so iOS 26/27 NECP policy blocks (`EPERM / os error 1`) can be unlocked and relayed seamlessly
#[no_mangle]
pub unsafe extern "C" fn localdev_register_nw_callbacks(
    prewarm_cb: Option<super::tunnel::LocalDevNwPrewarmFn>,
    relay_connect_cb: Option<super::tunnel::LocalDevNwRelayConnectFn>,
) -> i32 {
    super::tunnel::register_nw_callbacks(prewarm_cb, relay_connect_cb);
    0
}

/// Receives dynamically discovered `utun` endpoints (JSON array) and Swift Local Network state (`1` OK, `-1` denied, `0` unknown)
#[no_mangle]
pub unsafe extern "C" fn localdev_set_candidates(
    candidates_json: *const c_char,
    local_network_state: i32,
) -> i32 {
    let candidates = if !candidates_json.is_null() {
        CStr::from_ptr(candidates_json)
            .to_str()
            .ok()
            .and_then(|s| serde_json::from_str::<Vec<super::TunnelCandidate>>(s).ok())
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    with_manager(|mgr| {
        mgr.set_candidates(candidates, local_network_state);
    });
    0
}

/// Imports raw bytes of a .mobiledevicepairing or .plist file
/// Returns JSON status report string
#[no_mangle]
pub unsafe extern "C" fn localdev_import_pairing(data: *const u8, len: usize) -> *const c_char {
    if data.is_null() || len == 0 {
        return to_json_cstr(json!({
            "code": 5,
            "status": "PAIRING FILE HẾT HẠN / LỖI",
            "message": "Dữ liệu tệp ghép nối rỗng"
        }));
    }

    let slice = std::slice::from_raw_parts(data, len);
    let res = with_manager(|mgr| mgr.import_pairing(slice));

    match res {
        Ok(report) => to_json_cstr(json!(report)),
        Err(e) => to_json_cstr(json!({
            "code": 5,
            "status": "PAIRING FILE HẾT HẠN / LỖI",
            "message": e
        })),
    }
}

/// Checks current LocalDev status and returns one of the 5 exact status reports
#[no_mangle]
pub extern "C" fn localdev_status() -> *const c_char {
    let res = with_manager(|mgr| mgr.check_status_report());
    match res {
        Ok(report) => to_json_cstr(json!(report)),
        Err(e) => to_json_cstr(json!({
            "code": 5,
            "status": "PAIRING FILE HẾT HẠN / LỖI",
            "message": e
        })),
    }
}

/// Scans installed user applications via `com.apple.mobile.installation_proxy`
/// Returns JSON array of applications
#[no_mangle]
pub extern "C" fn localdev_scan_apps() -> *const c_char {
    let res = with_manager(|mgr| mgr.scan_apps());
    match res {
        Ok(apps) => to_json_cstr(json!({
            "success": true,
            "apps": apps
        })),
        Err(e) => to_json_cstr(json!({
            "success": false,
            "error": e,
            "apps": []
        })),
    }
}

/// Lists files in directory (either device root/Media via AFC, or app sandbox via HouseArrest)
#[no_mangle]
pub unsafe extern "C" fn localdev_list_dir(
    service_type: i32,
    bundle_id: *const c_char,
    path: *const c_char,
) -> *const c_char {
    let path_str = if !path.is_null() {
        CStr::from_ptr(path).to_str().unwrap_or("/")
    } else {
        "/"
    };

    let b_id = if !bundle_id.is_null() {
        CStr::from_ptr(bundle_id).to_str().unwrap_or("")
    } else {
        ""
    };

    let res = with_manager(|mgr| -> Result<(Vec<String>, Vec<super::house_arrest::HouseArrestDirItem>, String), String> {
        let pairing = mgr.active_pairing.as_ref().ok_or_else(|| "Chưa có pairing file".to_string())?;

        if service_type == SERVICE_TYPE_HOUSE_ARREST {
            if b_id.is_empty() {
                return Err("bundle_id is required for HouseArrest".to_string());
            }
            HouseArrestClient::list_dir_detailed(&mgr.host, mgr.port, pairing, b_id, path_str)
        } else {
            let (mut afc, source) = AfcClient::connect_device_afc(&mgr.host, mgr.port, pairing)?;
            let entries = afc.list_dir(path_str)?;
            let prefix = path_str.trim_end_matches('/');
            let mut items = Vec::with_capacity(entries.len());
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
                items.push(super::house_arrest::HouseArrestDirItem {
                    name: name.clone(),
                    is_dir,
                    size,
                });
            }
            Ok((entries, items, source))
        }
    });

    match res {
        Ok((entries, items, mode)) => to_json_cstr(json!({
            "success": true,
            "path": path_str,
            "mode": mode,
            "entries": entries,
            "items": items
        })),
        Err(e) => to_json_cstr(json!({
            "success": false,
            "error": e,
            "entries": [],
            "items": []
        })),
    }
}

/// Reads file bytes from device or app container
/// Returns raw heap buffer. `out_len` receives the byte count.
/// Caller must free buffer via `localdev_free_bytes`.
#[no_mangle]
pub unsafe extern "C" fn localdev_read_file(
    service_type: i32,
    bundle_id: *const c_char,
    path: *const c_char,
    out_len: *mut usize,
) -> *mut u8 {
    if path.is_null() || out_len.is_null() {
        return std::ptr::null_mut();
    }

    let path_str = CStr::from_ptr(path).to_str().unwrap_or("");
    let b_id = if !bundle_id.is_null() {
        CStr::from_ptr(bundle_id).to_str().unwrap_or("")
    } else {
        ""
    };

    let res: Result<Vec<u8>, String> = with_manager(|mgr| {
        let pairing = mgr.active_pairing.as_ref().ok_or_else(|| "Chưa có pairing file".to_string())?;

        if service_type == SERVICE_TYPE_HOUSE_ARREST {
            HouseArrestClient::read_file(&mgr.host, mgr.port, pairing, b_id, path_str)
        } else {
            let (mut afc, _src) = AfcClient::connect_device_afc(&mgr.host, mgr.port, pairing)?;
            afc.read_file_full(path_str)
        }
    });

    match res {
        Ok(mut bytes) => {
            *out_len = bytes.len();
            let ptr = bytes.as_mut_ptr();
            std::mem::forget(bytes);
            ptr
        }
        Err(_) => {
            *out_len = 0;
            std::ptr::null_mut()
        }
    }
}

/// Writes file bytes into device or app container with automatic .bak backup
#[no_mangle]
pub unsafe extern "C" fn localdev_write_file(
    service_type: i32,
    bundle_id: *const c_char,
    path: *const c_char,
    data: *const u8,
    len: usize,
) -> *const c_char {
    if path.is_null() || data.is_null() || len == 0 {
        return to_json_cstr(json!({
            "success": false,
            "error": "Tham số tệp không hợp lệ"
        }));
    }

    let path_str = CStr::from_ptr(path).to_str().unwrap_or("");
    let b_id = if !bundle_id.is_null() {
        CStr::from_ptr(bundle_id).to_str().unwrap_or("")
    } else {
        ""
    };
    let slice = std::slice::from_raw_parts(data, len);

    let res: Result<(), String> = with_manager(|mgr| {
        let pairing = mgr.active_pairing.as_ref().ok_or_else(|| "Chưa có pairing file".to_string())?;

        if service_type == SERVICE_TYPE_HOUSE_ARREST {
            HouseArrestClient::write_file_safe(&mgr.host, mgr.port, pairing, b_id, path_str, slice)
        } else {
            let (mut afc, _src) = AfcClient::connect_device_afc(&mgr.host, mgr.port, pairing)?;
            // Safety backup
            if let Ok(existing) = afc.read_file_full(path_str) {
                let backup_path = format!("{}.bak", path_str);
                let _ = afc.write_file_full(&backup_path, &existing);
            }
            afc.write_file_full(path_str, slice)
        }
    });

    match res {
        Ok(_) => to_json_cstr(json!({
            "success": true,
            "path": path_str,
            "written_bytes": len
        })),
        Err(e) => to_json_cstr(json!({
            "success": false,
            "error": e
        })),
    }
}

/// Frees C-string allocated by Rust
#[no_mangle]
pub unsafe extern "C" fn localdev_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        let _ = CString::from_raw(ptr);
    }
}

/// Frees byte buffer allocated by `localdev_read_file`
#[no_mangle]
pub unsafe extern "C" fn localdev_free_bytes(ptr: *mut u8, len: usize) {
    if !ptr.is_null() && len > 0 {
        let _ = Vec::from_raw_parts(ptr, len, len);
    }
}

fn to_json_cstr(val: serde_json::Value) -> *const c_char {
    let s = val.to_string();
    CString::new(s).unwrap_or_default().into_raw()
}
