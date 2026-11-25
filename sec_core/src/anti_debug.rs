use crate::syscall_arm64;
use obfstr::obfstr;
use std::ffi::{c_char, c_void, CString};

#[cfg(target_vendor = "apple")]
extern "C" {
    fn sysctlbyname(
        name: *const c_char,
        oldp: *mut c_void,
        oldlenp: *mut usize,
        newp: *const c_void,
        newlen: usize,
    ) -> i32;
}

const CTL_KERN: i32 = 1;
const KERN_PROC: i32 = 14;
const KERN_PROC_PID: i32 = 1;
const P_TRACED: i32 = 0x0000_0800;
const PT_DENY_ATTACH: i32 = 31;
const CS_OPS_STATUS: u32 = 0;
const CS_DEBUGGED: u32 = 0x1000_0000;
const CS_VALID: u32 = 0x0000_0001;

#[repr(C)]
struct KInfoProc {
    _opaque: [u8; 648],
}

impl Default for KInfoProc {
    fn default() -> Self {
        Self { _opaque: [0u8; 648] }
    }
}

/// Applies PT_DENY_ATTACH via direct ARM64 SVC #0x80 without trusting libc ptrace.
pub fn enforce_deny_attach() {
    let _ = unsafe { syscall_arm64::raw_ptrace(PT_DENY_ATTACH, 0, core::ptr::null_mut(), 0) };
}

/// Checks whether kernel process flags mark current PID as traced.
pub fn is_traced_sysctl() -> bool {
    let pid = unsafe { syscall_arm64::raw_getpid() };
    let mut mib = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid];
    let mut info = KInfoProc::default();
    let mut size = core::mem::size_of::<KInfoProc>();

    let res = unsafe {
        syscall_arm64::raw_sysctl(
            mib.as_mut_ptr(),
            4,
            &mut info as *mut KInfoProc as *mut c_void,
            &mut size,
            core::ptr::null_mut(),
            0,
        )
    };
    if res == 0 && size >= 40 {
        let p_flag = i32::from_le_bytes([
            info._opaque[32],
            info._opaque[33],
            info._opaque[34],
            info._opaque[35],
        ]);
        if (p_flag & P_TRACED) != 0 {
            return true;
        }
    }
    false
}

/// Checks code-signing debugger status flags directly from XNU csops syscall.
pub fn check_csops_flags() -> bool {
    let pid = unsafe { syscall_arm64::raw_getpid() };
    let mut flags: u32 = 0;
    let res = unsafe {
        syscall_arm64::raw_csops(
            pid,
            CS_OPS_STATUS,
            &mut flags as *mut u32 as *mut c_void,
            core::mem::size_of::<u32>(),
        )
    };
    if res == 0 {
        if (flags & CS_DEBUGGED) != 0 {
            return true;
        }
        // In non-simulator Apple ARM64 devices, invalid CS_VALID indicates patched pages in memory
        #[cfg(all(target_os = "ios", target_arch = "aarch64"))]
        if (flags & CS_VALID) == 0 {
            return true;
        }
    }
    false
}

/// Reads Darwin kernel osrelease string if needed for telemetry.
pub fn get_darwin_osrelease() -> String {
    #[cfg(target_vendor = "apple")]
    if let Ok(name) = CString::new(obfstr!("kern.osrelease")) {
        let mut size: usize = 0;
        unsafe {
            sysctlbyname(name.as_ptr(), core::ptr::null_mut(), &mut size, core::ptr::null(), 0);
            if size > 0 && size < 64 {
                let mut buf = vec![0u8; size];
                if sysctlbyname(
                    name.as_ptr(),
                    buf.as_mut_ptr() as *mut c_void,
                    &mut size,
                    core::ptr::null(),
                    0,
                ) == 0
                {
                    if let Some(pos) = buf.iter().position(|&b| b == 0) {
                        buf.truncate(pos);
                    }
                    if let Ok(s) = String::from_utf8(buf) {
                        return s;
                    }
                }
            }
        }
    }
    String::new()
}

/// Aggregate debugger / memory-cs detection bitmask (0 = clean).
pub fn anti_debug_bitmask() -> u32 {
    let mut mask: u32 = 0;
    if is_traced_sysctl() {
        mask |= 0x01;
    }
    if check_csops_flags() {
        mask |= 0x02;
    }
    mask
}
