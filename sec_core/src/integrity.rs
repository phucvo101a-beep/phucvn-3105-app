//! Runtime Self-Integrity Verification
//! Computes SHA-256 over Mach-O `__TEXT,__text` to detect binary patching (IDA/Ghidra HEX edits)

use sha2::{Digest, Sha256};
use std::ffi::CStr;

extern "C" {
    fn _dyld_image_count() -> u32;
    fn _dyld_get_image_header(image_index: u32) -> *const MachHeader64;
    fn _dyld_get_image_vmaddr_slide(image_index: u32) -> isize;
    fn _dyld_get_image_name(image_index: u32) -> *const libc::c_char;
}

mod libc {
    pub type c_char = i8;
}

const MH_MAGIC_64: u32 = 0xfeedfacf;
const LC_SEGMENT_64: u32 = 0x19;

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

/// Compute SHA-256 hash of the `__TEXT,__text` section of the main executable or specific dylib
pub fn compute_text_section_hash(target_image_name: Option<&str>) -> Option<[u8; 32]> {
    unsafe {
        let count = _dyld_image_count();
        let mut target_index: Option<u32> = None;

        if let Some(target) = target_image_name {
            for i in 0..count {
                let name_ptr = _dyld_get_image_name(i);
                if !name_ptr.is_null() {
                    if let Ok(name_str) = CStr::from_ptr(name_ptr).to_str() {
                        if name_str.contains(target) {
                            target_index = Some(i);
                            break;
                        }
                    }
                }
            }
        } else {
            // Default: Main binary is image 0
            target_index = Some(0);
        }

        let idx = target_index?;
        let header_ptr = _dyld_get_image_header(idx);
        if header_ptr.is_null() || (*header_ptr).magic != MH_MAGIC_64 {
            return None;
        }

        let slide = _dyld_get_image_vmaddr_slide(idx);
        let mut cmd_ptr = (header_ptr as *const u8).add(core::mem::size_of::<MachHeader64>()) as *const LoadCommand;

        for _ in 0..(*header_ptr).ncmds {
            if (*cmd_ptr).cmd == LC_SEGMENT_64 {
                let seg_ptr = cmd_ptr as *const SegmentCommand64;
                let segname = &(*seg_ptr).segname;

                // Match "__TEXT"
                if &segname[0..6] == b"__TEXT" {
                    let mut sect_ptr = (seg_ptr as *const u8).add(core::mem::size_of::<SegmentCommand64>()) as *const Section64;

                    for _ in 0..(*seg_ptr).nsects {
                        let sectname = &(*sect_ptr).sectname;
                        // Match "__text"
                        if &sectname[0..6] == b"__text" {
                            let actual_addr = ((*sect_ptr).addr as isize + slide) as *const u8;
                            let sect_size = (*sect_ptr).size as usize;

                            if !actual_addr.is_null() && sect_size > 0 {
                                let code_slice = core::slice::from_raw_parts(actual_addr, sect_size);
                                let mut hasher = Sha256::new();
                                hasher.update(code_slice);
                                let hash_output: [u8; 32] = hasher.finalize().into();
                                return Some(hash_output);
                            }
                        }
                        sect_ptr = (sect_ptr as *const u8).add(core::mem::size_of::<Section64>()) as *const Section64;
                    }
                }
            }
            cmd_ptr = (cmd_ptr as *const u8).add((*cmd_ptr).cmdsize as usize) as *const LoadCommand;
        }
    }
    None
}
