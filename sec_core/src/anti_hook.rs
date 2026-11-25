#[cfg(target_vendor = "apple")]
use crate::integrity::apple_sys::{_dyld_get_image_name, _dyld_image_count};
use obfstr::obfstr;
#[cfg(target_vendor = "apple")]
use std::ffi::{CStr, CString};

/// Detects Substrate, Substitute, ElleKit, Frida, SSLKillSwitch, Cycript and similar tweak images.
pub fn scan_injected_dylibs() -> bool {
    #[cfg(target_vendor = "apple")]
    unsafe {
        let count = _dyld_image_count();
        for i in 0..count {
            let ptr = _dyld_get_image_name(i);
            if ptr.is_null() {
                continue;
            }
            if let Ok(raw) = CStr::from_ptr(ptr).to_str() {
                let lower = raw.to_ascii_lowercase();
                // Skip Apple system frameworks/libraries inside the dyld shared cache
                if lower.starts_with(obfstr!("/system/")) || lower.starts_with(obfstr!("/usr/lib/")) {
                    continue;
                }
                let filename = lower.rsplit('/').next().unwrap_or(lower.as_str());
                if lower.contains(obfstr!("frida"))
                    || lower.contains(obfstr!("substrate"))
                    || lower.contains(obfstr!("substitute"))
                    || lower.contains(obfstr!("ellekit"))
                    || lower.contains(obfstr!("tweakinject"))
                    || lower.contains(obfstr!("libhooker"))
                    || lower.contains(obfstr!("sslkillswitch"))
                    || lower.contains(obfstr!("cycript"))
                    || lower.contains(obfstr!("objection"))
                    || lower.contains(obfstr!("mobileloader"))
                    || filename.contains(obfstr!("reveal"))
                    || filename.contains(obfstr!("shadow"))
                    || filename.contains(obfstr!("choicy"))
                    || filename.contains(obfstr!("liberty"))
                    || filename.contains(obfstr!("flyjb"))
                    || filename.starts_with(obfstr!("flex"))
                    || filename.contains(obfstr!("libflex"))
                {
                    return true;
                }
            }
        }
    }
    false
}

/// Rejects any DYLD_INSERT_LIBRARIES environment injection (normal app uses LC_LOAD_DYLIB).
pub fn check_dyld_insert_env() -> bool {
    #[cfg(target_vendor = "apple")]
    unsafe {
        if let Ok(key) = CString::new(obfstr!("DYLD_INSERT_LIBRARIES")) {
            let val = libc::getenv(key.as_ptr());
            if !val.is_null() {
                if let Ok(s) = CStr::from_ptr(val).to_str() {
                    if !s.trim().is_empty() {
                        return true;
                    }
                }
            }
        }
    }
    false
}

/// Checks ARM64 first two instructions at target pointer for common inline hook trampolines (`LDR X16/X17 + BR`).
///
/// # Safety
/// Caller must guarantee `fn_ptr` is null or points to readable executable instructions (at least 12 bytes).
#[inline(always)]
pub unsafe fn is_trampoline_hooked(fn_ptr: *const u8) -> bool {
    if fn_ptr.is_null() {
        return false;
    }
    #[cfg(target_arch = "aarch64")]
    {
        let insn0 = core::ptr::read_unaligned(fn_ptr as *const u32);
        let insn1 = core::ptr::read_unaligned(fn_ptr.add(4) as *const u32);
        // LDR X16, #... (0x58000010) / LDR X17, #... (0x58000011) followed by BR X16/X17.
        // Note: unconditional `B imm26` and `ADRP+ADD+BR` are legitimate dyld shared-cache stubs/tail calls on iOS ARM64/ARM64e.
        let is_ldr_scratch = (insn0 & 0xFF00_001E) == 0x5800_0010;
        let is_br_scratch = insn1 == 0xD61F_0200 || insn1 == 0xD61F_0220;
        if is_ldr_scratch && is_br_scratch {
            return true;
        }
    }
    false
}

/// Inspects critical runtime symbols for inline hook trampolines.
pub fn scan_critical_trampolines() -> bool {
    #[cfg(target_vendor = "apple")]
    unsafe {
        let targets = [
            obfstr!("objc_msgSend").to_string(),
            obfstr!("dlsym").to_string(),
            obfstr!("dlopen").to_string(),
            obfstr!("SecItemCopyMatching").to_string(),
        ];
        for sym in &targets {
            if let Ok(c_sym) = CString::new(sym.as_str()) {
                let ptr = libc::dlsym(libc::RTLD_DEFAULT, c_sym.as_ptr());
                if is_trampoline_hooked(ptr as *const u8) {
                    return true;
                }
            }
        }
    }
    false
}

/// Checks local Frida Gadget/Server TCP ports quickly without blocking long.
pub fn scan_frida_ports() -> bool {
    use std::net::{SocketAddr, TcpStream};
    use std::time::Duration;
    for port in [27042u16, 27043u16] {
        let addr: SocketAddr = ([127, 0, 0, 1], port).into();
        if TcpStream::connect_timeout(&addr, Duration::from_millis(12)).is_ok() {
            return true;
        }
    }
    false
}

/// Aggregate anti-hook bitmask (0 = clean).
pub fn anti_hook_bitmask(include_port_scan: bool) -> u32 {
    let mut mask = 0u32;
    if scan_injected_dylibs() {
        mask |= 0x10;
    }
    if check_dyld_insert_env() {
        mask |= 0x20;
    }
    if scan_critical_trampolines() {
        mask |= 0x40;
    }
    if include_port_scan && scan_frida_ports() {
        mask |= 0x80;
    }
    mask
}
