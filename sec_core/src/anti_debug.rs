//! Anti-Debugging via Direct XNU Syscalls & XNU Kernel Process Flags

use crate::syscall_arm64::*;

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

/// Invokes `ptrace(PT_DENY_ATTACH, 0, 0, 0)` directly through SVC #0x80
/// If a debugger is currently attached, the process terminates immediately with SIGSEGV.
/// If a debugger tries to attach later, it will be denied.
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

/// Comprehensive anti-debug probe
#[inline(always)]
pub fn check_debugger_presence() -> bool {
    is_ptraced_direct()
}
