use crate::secrets;
use obfstr::obfstr;
use sha2::{Digest, Sha256};
use std::ffi::{c_char, c_void, CStr};
use subtle::ConstantTimeEq;

#[cfg(target_vendor = "apple")]
pub(crate) mod apple_sys {
    use std::ffi::{c_char, c_void};
    extern "C" {
        pub fn _dyld_image_count() -> u32;
        pub fn _dyld_get_image_header(image_index: u32) -> *const c_void;
        pub fn _dyld_get_image_name(image_index: u32) -> *const c_char;

        pub fn CFBundleGetMainBundle() -> *const c_void;
        pub fn CFBundleGetIdentifier(bundle: *const c_void) -> *const c_void;
        pub fn CFBundleGetValueForInfoDictionaryKey(
            bundle: *const c_void,
            key: *const c_void,
        ) -> *const c_void;
        pub fn CFStringCreateWithCString(
            alloc: *const c_void,
            c_str: *const c_char,
            encoding: u32,
        ) -> *const c_void;
        pub fn CFStringGetCString(
            the_string: *const c_void,
            buffer: *mut c_char,
            buffer_size: isize,
            encoding: u32,
        ) -> bool;
        pub fn CFRelease(cf: *const c_void);
        pub static kCFAllocatorDefault: *const c_void;
        pub static kCFBundleVersionKey: *const c_void;
    }
}

#[repr(C)]
struct MachHeader64 {
    magic: u32,
    cputype: i32,
    cpusubtype: i32,
    filetype: u32,
    ncmds: u32,
    sizeofcmds: u32,
    flags: u32,
    reserved: u32,
}

#[repr(C)]
struct LoadCommand {
    cmd: u32,
    cmdsize: u32,
}

#[repr(C)]
struct SegmentCommand64 {
    cmd: u32,
    cmdsize: u32,
    segname: [u8; 16],
    vmaddr: u64,
    vmsize: u64,
    fileoff: u64,
    filesize: u64,
    maxprot: i32,
    initprot: i32,
    nsects: u32,
    flags: u32,
}

#[repr(C)]
struct Section64 {
    sectname: [u8; 16],
    segname: [u8; 16],
    addr: u64,
    size: u64,
    offset: u32,
    align: u32,
    reloff: u32,
    nreloc: u32,
    flags: u32,
    reserved1: u32,
    reserved2: u32,
    reserved3: u32,
}

const MH_MAGIC_64: u32 = 0xfeed_facf;
const LC_SEGMENT_64: u32 = 0x19;

unsafe fn hash_text_section_from_header(hdr_ptr: *const c_void) -> Option<[u8; 32]> {
    if hdr_ptr.is_null() {
        return None;
    }
    let hdr = &*(hdr_ptr as *const MachHeader64);
    if hdr.magic != MH_MAGIC_64 {
        return None;
    }
    let base = hdr_ptr as usize;
    let mut cmd_ptr = base + core::mem::size_of::<MachHeader64>();

    for _ in 0..hdr.ncmds {
        let lc = &*(cmd_ptr as *const LoadCommand);
        if lc.cmd == LC_SEGMENT_64 {
            let seg = &*(cmd_ptr as *const SegmentCommand64);
            let seg_name = core::str::from_utf8(&seg.segname)
                .unwrap_or("")
                .trim_end_matches('\0');
            if seg_name == obfstr!("__TEXT") {
                let aslr_slide = base.wrapping_sub(seg.vmaddr as usize);
                let sect_ptr = cmd_ptr + core::mem::size_of::<SegmentCommand64>();
                for i in 0..seg.nsects as usize {
                    let sect = &*((sect_ptr + i * core::mem::size_of::<Section64>()) as *const Section64);
                    let sect_name = core::str::from_utf8(&sect.sectname)
                        .unwrap_or("")
                        .trim_end_matches('\0');
                    if sect_name == obfstr!("__text") && sect.size > 0 && sect.size < 64 * 1024 * 1024 {
                        let start = (sect.addr as usize).wrapping_add(aslr_slide) as *const u8;
                        let slice = core::slice::from_raw_parts(start, sect.size as usize);
                        let digest = Sha256::digest(slice);
                        let mut out = [0u8; 32];
                        out.copy_from_slice(&digest);
                        return Some(out);
                    }
                }
            }
        }
        if lc.cmdsize == 0 {
            break;
        }
        cmd_ptr += lc.cmdsize as usize;
    }
    None
}

/// Computes SHA-256 of main iOS executable `__TEXT,__text` (dyld image 0).
pub fn compute_app_binary_hash_bytes() -> Option<[u8; 32]> {
    #[cfg(target_vendor = "apple")]
    unsafe {
        if apple_sys::_dyld_image_count() > 0 {
            return hash_text_section_from_header(apple_sys::_dyld_get_image_header(0));
        }
    }
    None
}

pub fn compute_app_binary_hash() -> String {
    compute_app_binary_hash_bytes()
        .map(hex::encode)
        .unwrap_or_else(|| "0".repeat(64))
}

/// Computes SHA-256 of this `libsec_core.dylib` image's `__TEXT,__text` section using dladdr.
pub fn compute_sec_core_hash_bytes() -> Option<[u8; 32]> {
    #[cfg(target_vendor = "apple")]
    unsafe {
        let mut info = core::mem::zeroed::<libc::Dl_info>();
        let anchor = compute_sec_core_hash_bytes as *const () as *const c_void;
        if libc::dladdr(anchor, &mut info) != 0 && !info.dli_fbase.is_null() {
            return hash_text_section_from_header(info.dli_fbase as *const c_void);
        }
        // Fallback scan by image name
        let count = apple_sys::_dyld_image_count();
        for idx in 0..count {
            let name_ptr = apple_sys::_dyld_get_image_name(idx);
            if name_ptr.is_null() {
                continue;
            }
            if let Ok(name) = CStr::from_ptr(name_ptr).to_str() {
                if name.contains(obfstr!("libsec_core")) {
                    return hash_text_section_from_header(apple_sys::_dyld_get_image_header(idx));
                }
            }
        }
    }
    None
}

pub fn compute_sec_core_hash() -> String {
    compute_sec_core_hash_bytes()
        .map(hex::encode)
        .unwrap_or_else(|| "0".repeat(64))
}

/// Verifies libsec_core.dylib __TEXT,__text SHA-256 against sealed hash in __DATA,__sechash.
pub fn verify_self_text_hash() -> bool {
    let seal = secrets::read_self_seal();
    let tag_all_zero = seal[0..16].iter().all(|&b| b == 0);

    if !tag_all_zero {
        // Binary was not post-processed by macho_hash.py; reject only if SEAL_REQUIRED in CI build.
        return !secrets::gen::SEAL_REQUIRED;
    }

    let Some(actual) = compute_sec_core_hash_bytes() else {
        return !secrets::gen::SEAL_REQUIRED;
    };

    let mut expected = [0u8; 32];
    for (out_b, (&m_b, &h_b)) in expected
        .iter_mut()
        .zip(seal[16..48].iter().zip(seal[48..80].iter()))
    {
        *out_b = m_b ^ h_b;
    }
    bool::from(actual.ct_eq(&expected))
}

#[cfg(target_vendor = "apple")]
unsafe fn cfstring_to_rust(cf_str: *const c_void) -> Option<String> {
    if cf_str.is_null() {
        return None;
    }
    let mut buf: [c_char; 256] = [0; 256];
    if apple_sys::CFStringGetCString(cf_str, buf.as_mut_ptr(), 256, 0x0800_0100) {
        return CStr::from_ptr(buf.as_ptr()).to_str().ok().map(|s| s.to_string());
    }
    None
}

/// Reads real Bundle ID, ShortVersion, and Build directly from main CFBundle.
pub fn read_bundle_identity() -> (String, String, String) {
    #[cfg(target_vendor = "apple")]
    unsafe {
        let bundle = apple_sys::CFBundleGetMainBundle();
        if !bundle.is_null() {
            let pkg = cfstring_to_rust(apple_sys::CFBundleGetIdentifier(bundle))
                .unwrap_or_else(|| obfstr!("com.phucvn.threeoneosfive").to_string());
            let key_short = std::ffi::CString::new(obfstr!("CFBundleShortVersionString")).ok();
            let ver = key_short
                .and_then(|c| {
                    let cf_k = apple_sys::CFStringCreateWithCString(
                        apple_sys::kCFAllocatorDefault,
                        c.as_ptr(),
                        0x0800_0100,
                    );
                    let res = cfstring_to_rust(apple_sys::CFBundleGetValueForInfoDictionaryKey(
                        bundle, cf_k,
                    ));
                    if !cf_k.is_null() {
                        apple_sys::CFRelease(cf_k);
                    }
                    res
                })
                .unwrap_or_else(|| obfstr!("2.1.0").to_string());
            let bld = cfstring_to_rust(apple_sys::CFBundleGetValueForInfoDictionaryKey(
                bundle,
                apple_sys::kCFBundleVersionKey,
            ))
            .unwrap_or_else(|| obfstr!("9").to_string());
            return (pkg, ver, bld);
        }
    }
    (
        obfstr!("com.phucvn.threeoneosfive").to_string(),
        obfstr!("2.1.0").to_string(),
        obfstr!("9").to_string(),
    )
}
