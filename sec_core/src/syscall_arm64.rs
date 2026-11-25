//! Direct ARM64 XNU Darwin Syscalls (SVC #0x80)
//! Bypasses C library hooks (fishhook / Frida / ElleKit) on libSystem.dylib

#[allow(dead_code)]
pub const SYS_EXIT: usize = 1;
#[allow(dead_code)]
pub const SYS_GETPID: usize = 20;
#[allow(dead_code)]
pub const SYS_PTRACE: usize = 26;
#[allow(dead_code)]
pub const SYS_CSOPS: usize = 169;
#[allow(dead_code)]
pub const SYS_SYSCTL: usize = 202;

pub const PT_DENY_ATTACH: usize = 31;
pub const P_TRACED: i32 = 0x00000800;

pub const CS_OPS_STATUS: usize = 0;
pub const CS_DEBUGGED: u32 = 0x10000000;

#[allow(dead_code)]
pub const CTL_KERN: i32 = 1;
#[allow(dead_code)]
pub const KERN_PROC: i32 = 14;
#[allow(dead_code)]
pub const KERN_PROC_PID: i32 = 1;

/// Raw XNU Darwin ARM64 direct syscall invocation
/// Register conventions:
/// - x16: Syscall number
/// - x0..x5: Arguments
/// - Result in x0
#[inline(always)]
#[cfg(target_arch = "aarch64")]
pub unsafe fn syscall0(num: usize) -> usize {
    let mut ret: usize;
    core::arch::asm!(
        "svc #0x80",
        in("x16") num,
        lateout("x0") ret,
        options(nostack)
    );
    ret
}

#[inline(always)]
#[cfg(target_arch = "aarch64")]
pub unsafe fn syscall1(num: usize, arg0: usize) -> usize {
    let mut ret: usize;
    core::arch::asm!(
        "svc #0x80",
        in("x16") num,
        inout("x0") arg0 => ret,
        options(nostack)
    );
    ret
}

#[inline(always)]
#[cfg(target_arch = "aarch64")]
pub unsafe fn syscall4(num: usize, arg0: usize, arg1: usize, arg2: usize, arg3: usize) -> usize {
    let mut ret: usize;
    core::arch::asm!(
        "svc #0x80",
        in("x16") num,
        inout("x0") arg0 => ret,
        in("x1") arg1,
        in("x2") arg2,
        in("x3") arg3,
        options(nostack)
    );
    ret
}

#[inline(always)]
#[cfg(target_arch = "aarch64")]
pub unsafe fn syscall6(
    num: usize,
    arg0: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
    arg5: usize,
) -> usize {
    let mut ret: usize;
    core::arch::asm!(
        "svc #0x80",
        in("x16") num,
        inout("x0") arg0 => ret,
        in("x1") arg1,
        in("x2") arg2,
        in("x3") arg3,
        in("x4") arg4,
        in("x5") arg5,
        options(nostack)
    );
    ret
}

// Fallbacks for non-aarch64 compilation (e.g. host cargo check/tests)
#[inline(always)]
#[cfg(not(target_arch = "aarch64"))]
pub unsafe fn syscall0(_num: usize) -> usize { 0 }
#[inline(always)]
#[cfg(not(target_arch = "aarch64"))]
pub unsafe fn syscall1(_num: usize, _arg0: usize) -> usize { 0 }
#[inline(always)]
#[cfg(not(target_arch = "aarch64"))]
pub unsafe fn syscall4(_num: usize, _arg0: usize, _arg1: usize, _arg2: usize, _arg3: usize) -> usize { 0 }
#[inline(always)]
#[cfg(not(target_arch = "aarch64"))]
pub unsafe fn syscall6(_num: usize, _a0: usize, _a1: usize, _a2: usize, _a3: usize, _a4: usize, _a5: usize) -> usize { 0 }

/// Direct XNU `SYS_exit` call
#[inline(always)]
pub fn direct_exit(code: i32) -> ! {
    unsafe {
        syscall1(SYS_EXIT, code as usize);
        force_hard_crash();
    }
}

/// Hard memory crash that cannot be trapped or caught by exception handlers
#[inline(always)]
pub fn force_hard_crash() -> ! {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("brk #0x1", options(noreturn));
    }
    #[cfg(not(target_arch = "aarch64"))]
    unsafe {
        let p = 0xdeadbeefusize as *mut u8;
        core::ptr::write_volatile(p, 0x42);
        core::hint::unreachable_unchecked();
    }
}

#[inline(always)]
pub unsafe fn raw_exit(code: i32) -> ! {
    direct_exit(code)
}

#[inline(always)]
pub unsafe fn raw_getpid() -> i32 {
    syscall0(SYS_GETPID) as i32
}

#[inline(always)]
pub unsafe fn raw_ptrace(
    request: i32,
    pid: i32,
    addr: *mut core::ffi::c_void,
    data: i32,
) -> isize {
    syscall4(
        SYS_PTRACE,
        request as usize,
        pid as usize,
        addr as usize,
        data as usize,
    ) as isize
}

#[inline(always)]
pub unsafe fn raw_sysctl(
    name: *mut i32,
    namelen: u32,
    oldp: *mut core::ffi::c_void,
    oldlenp: *mut usize,
    newp: *mut core::ffi::c_void,
    newlen: usize,
) -> i32 {
    syscall6(
        SYS_SYSCTL,
        name as usize,
        namelen as usize,
        oldp as usize,
        oldlenp as usize,
        newp as usize,
        newlen,
    ) as i32
}

#[inline(always)]
pub unsafe fn raw_csops(
    pid: i32,
    ops: u32,
    useraddr: *mut core::ffi::c_void,
    usersize: usize,
) -> i32 {
    syscall4(
        SYS_CSOPS,
        pid as usize,
        ops as usize,
        useraddr as usize,
        usersize,
    ) as i32
}
