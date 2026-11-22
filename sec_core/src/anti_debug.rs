//! Anti-Debugging via Direct XNU Syscalls & XNU Kernel Process Flags
//! Supports Intelligent LocalDev Mode for iOS 18.7.2 - 18.7.10

use crate::syscall_arm64::*;
use obfstr::obfstr;

extern "C" {
    fn sysctlbyname(
        name: *const i8,
        oldp: *mut core::ffi::c_void,
        oldlenp: *mut usize,
        newp: *const core::ffi::c_void,
        newlen: usize,
    ) -> i32;
}

/// Kinfo proc layout on Darwin / iOS 64-bit
/// Buffer size needs to be at least 648 bytes (sizeof(struct kinfo_proc))
#[repr(C)]
struct KinfoProcBuf {
    raw: [u8; 1024],
}

impl KinfoProcBuf {
    fn new() -> Self {
        Self { raw: [0u8; 1024] }
    }

    /// On iOS ARM64 Darwin, `kp_proc.p_flag` is located at byte offset 32 in `kinfo_proc`
    fn p_flag(&self) -> i32 {
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&self.raw[32..36]);
        i32::from_ne_bytes(bytes)
    }
}

/// Representation of parsed iOS Version (Major.Minor.Patch)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IosVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

/// Reads the OS product version string via `sysctlbyname("kern.osproductversion")`
pub fn get_ios_product_version() -> Option<IosVersion> {
    let prop_name = obfstr!("kern.osproductversion");
    let mut name_buf = [0i8; 32];
    for (i, b) in prop_name.bytes().enumerate() {
        if i < 31 {
            name_buf[i] = b as i8;
        }
    }

    let mut size: usize = 0;
    unsafe {
        let ret = sysctlbyname(
            name_buf.as_ptr(),
            core::ptr::null_mut(),
            &mut size,
            core::ptr::null_mut(),
            0,
        );
        if ret != 0 || size == 0 {
            return None;
        }

        let mut buf = vec![0u8; size];
        let ret = sysctlbyname(
            name_buf.as_ptr(),
            buf.as_mut_ptr() as *mut core::ffi::c_void,
            &mut size,
            core::ptr::null_mut(),
            0,
        );
        if ret != 0 {
            return None;
        }

        let nul_pos = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        let ver_str = std::str::from_utf8(&buf[..nul_pos]).ok()?;
        parse_ios_version(ver_str)
    }
}

/// Parses an iOS version string like "18.7.4" or "17.2" into `IosVersion`
pub fn parse_ios_version(ver_str: &str) -> Option<IosVersion> {
    let parts: Vec<&str> = ver_str.trim().split('.').collect();
    if parts.is_empty() {
        return None;
    }
    let major = parts[0].parse::<u32>().ok()?;
    let minor = if parts.len() > 1 {
        parts[1].parse::<u32>().ok()?
    } else {
        0
    };
    let patch = if parts.len() > 2 {
        parts[2].parse::<u32>().ok().unwrap_or(0)
    } else {
        0
    };
    Some(IosVersion { major, minor, patch })
}

/// Check if the current device is in the LocalDev window:
/// 18.7.2 <= iOS version <= 18.7.10
pub fn is_localdev_supported_ios() -> bool {
    if let Some(v) = get_ios_product_version() {
        v.major == 18 && v.minor == 7 && (v.patch >= 2 && v.patch <= 10)
    } else {
        false
    }
}

/// Invokes `ptrace(PT_DENY_ATTACH, 0, 0, 0)` directly through SVC #0x80
#[inline(always)]
pub fn deny_debugger() -> bool {
    unsafe {
        let ret = syscall4(SYS_PTRACE, PT_DENY_ATTACH, 0, 0, 0);
        ret == 0
    }
}

/// Query XNU Kernel for `P_TRACED` flag without calling libc `sysctl()`
#[inline(always)]
pub fn is_ptraced_direct() -> bool {
    unsafe {
        let pid = syscall0(SYS_GETPID);
        if pid == 0 {
            return false;
        }

        // MIB: [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid]
        let mib = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid as i32];
        let mut proc_info = KinfoProcBuf::new();
        let mut size = core::mem::size_of::<KinfoProcBuf>();

        let ret = syscall6(
            SYS_SYSCTL,
            mib.as_ptr() as usize,
            4,
            proc_info.raw.as_mut_ptr() as usize,
            &mut size as *mut usize as usize,
            0,
            0,
        );

        if ret == 0 {
            let flags = proc_info.p_flag();
            (flags & P_TRACED) != 0
        } else {
            false
        }
    }
}

/// Check if process has the `CS_DEBUGGED` (0x10000000) flag via direct XNU `csops` syscall (x16 = 169)
#[inline(always)]
pub fn is_cs_debugged() -> bool {
    unsafe {
        let pid = syscall0(SYS_GETPID);
        let mut status: u32 = 0;
        let ret = syscall4(
            SYS_CSOPS,
            pid,
            CS_OPS_STATUS,
            &mut status as *mut u32 as usize,
            core::mem::size_of::<u32>(),
        );
        if ret == 0 {
            (status & CS_DEBUGGED) != 0
        } else {
            false
        }
    }
}

/// Comprehensive intelligent anti-debug probe:
/// - In LocalDev mode (iOS 18.7.2..18.7.10): allows authorized developer debugging (where CS_DEBUGGED is set).
///   Flags as debugger presence only if P_TRACED is set without CS_DEBUGGED, or if an unauthorized process attached.
/// - Outside LocalDev (e.g. iOS 15..17, 18.0..18.7.1, 26, 27.2.1): strictly flags any P_TRACED state.
#[inline(always)]
pub fn check_debugger_presence() -> bool {
    if is_localdev_supported_ios() {
        if is_ptraced_direct() {
            !is_cs_debugged()
        } else {
            false
        }
    } else {
        is_ptraced_direct()
    }
}
