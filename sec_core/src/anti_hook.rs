//! Anti-Hooking, Anti-Frida & Dylib Injection Detection

use std::ffi::CStr;
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;
use obfstr::obfstr;

extern "C" {
    fn _dyld_image_count() -> u32;
    fn _dyld_get_image_name(image_index: u32) -> *const libc::c_char;
    fn getenv(name: *const libc::c_char) -> *const libc::c_char;
}

mod libc {
    pub type c_char = i8;
}

/// Blacklisted hook libraries and tweak dylibs
#[inline(always)]
fn get_suspicious_patterns() -> [&'static str; 16] {
    [
        obfstr!("FridaGadget"),
        obfstr!("frida-agent"),
        obfstr!("Substrate"),
        obfstr!("ElleKit"),
        obfstr!("Substitute"),
        obfstr!("TweakInject"),
        obfstr!("SSLKillSwitch"),
        obfstr!("Shadow"),
        obfstr!("Choicy"),
        obfstr!("iGameGod"),
        obfstr!("Flex"),
        obfstr!("bfdecrypt"),
        obfstr!("CrackerXI"),
        obfstr!("TrollDecrypt"),
        obfstr!("libcycript"),
        obfstr!("libhooker"),
    ]
}

/// Scan all loaded dynamic libraries via `_dyld_get_image_name`
pub fn scan_loaded_dyld_images() -> bool {
    let patterns = get_suspicious_patterns();
    unsafe {
        let count = _dyld_image_count();
        for i in 0..count {
            let name_ptr = _dyld_get_image_name(i);
            if name_ptr.is_null() {
                continue;
            }
            if let Ok(name_str) = CStr::from_ptr(name_ptr).to_str() {
                for pattern in &patterns {
                    if name_str.contains(pattern) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

/// Verify `DYLD_INSERT_LIBRARIES` environment variable
pub fn check_dyld_insert_libraries() -> bool {
    unsafe {
        let env_key = obfstr!("DYLD_INSERT_LIBRARIES");
        let mut key_buf = [0i8; 32];
        for (i, b) in env_key.bytes().enumerate() {
            if i < 31 {
                key_buf[i] = b as i8;
            }
        }
        let ptr = getenv(key_buf.as_ptr());
        if !ptr.is_null() {
            if let Ok(val) = CStr::from_ptr(ptr).to_str() {
                // If any inserted dylib is present that isn't our own module
                let my_name = obfstr!("libsec_core");
                if !val.trim().is_empty() && !val.contains(my_name) {
                    return true;
                }
            }
        }
    }
    false
}

/// Check if local Frida server/gadget ports (27042, 27043) are accepting connections
pub fn check_frida_listening_ports() -> bool {
    let addrs = [
        SocketAddr::from(([127, 0, 0, 1], 27042)),
        SocketAddr::from(([127, 0, 0, 1], 27043)),
    ];

    for addr in &addrs {
        if TcpStream::connect_timeout(addr, Duration::from_millis(15)).is_ok() {
            return true;
        }
    }
    false
}

/// Anti-Trampoline Check:
/// Inspects the first 16 bytes of an ARM64 function address in memory.
/// Detects Frida/Dobby/ElleKit detour patterns:
/// 1. `LDR X16, #8; BR X16` -> 0x58000050 followed by 0xd61f0200
/// 2. Direct branch `B` -> opcodes with high 6 bits `000101` (0x14000000..=0x17ffffff)
/// 3. `ADRP X16, ...; ADD X16, X16, ...; BR X16`
#[inline(always)]
pub unsafe fn is_function_trampoline_hooked(func_ptr: *const ()) -> bool {
    if func_ptr.is_null() {
        return false;
    }

    let code_ptr = func_ptr as *const u32;
    let insn0 = core::ptr::read_volatile(code_ptr);
    let insn1 = core::ptr::read_volatile(code_ptr.add(1));

    // Check 1: LDR X16, #8 (0x58000050) + BR X16 (0xd61f0200)
    if insn0 == 0x58000050 && insn1 == 0xd61f0200 {
        return true;
    }

    // Check 2: Direct unconditional branch B (0x14000000..0x17ffffff)
    if (insn0 & 0xFC000000) == 0x14000000 {
        return true;
    }

    // Check 3: ADRP + ADD + BR X16
    let insn2 = core::ptr::read_volatile(code_ptr.add(2));
    if (insn0 & 0x9F000000) == 0x90000000 && insn2 == 0xd61f0200 {
        return true;
    }

    false
}

/// Full Anti-Hook & Environment scan
pub fn check_hook_environment() -> bool {
    if scan_loaded_dyld_images() {
        return true;
    }
    if check_dyld_insert_libraries() {
        return true;
    }
    if check_frida_listening_ports() {
        return true;
    }
    false
}
