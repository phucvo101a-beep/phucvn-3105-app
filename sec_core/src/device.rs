use obfstr::obfstr;
use sha2::{Digest, Sha256};
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

    static kCFAllocatorDefault: *const c_void;
    static kCFBooleanTrue: *const c_void;

    static kSecClass: *const c_void;
    static kSecClassGenericPassword: *const c_void;
    static kSecAttrService: *const c_void;
    static kSecAttrAccount: *const c_void;
    static kSecAttrAccessible: *const c_void;
    static kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly: *const c_void;
    static kSecValueData: *const c_void;
    static kSecReturnData: *const c_void;
    static kSecMatchLimit: *const c_void;
    static kSecMatchLimitOne: *const c_void;

    fn CFDictionaryCreateMutable(
        allocator: *const c_void,
        capacity: isize,
        key_callbacks: *const c_void,
        value_callbacks: *const c_void,
    ) -> *mut c_void;
    fn CFDictionaryAddValue(the_dict: *mut c_void, key: *const c_void, value: *const c_void);
    fn CFStringCreateWithCString(
        alloc: *const c_void,
        c_str: *const c_char,
        encoding: u32,
    ) -> *const c_void;
    fn CFDataCreate(alloc: *const c_void, bytes: *const u8, length: isize) -> *const c_void;
    fn CFDataGetLength(the_data: *const c_void) -> isize;
    fn CFDataGetBytePtr(the_data: *const c_void) -> *const u8;
    fn CFRelease(cf: *const c_void);

    fn SecItemCopyMatching(query: *const c_void, result: *mut *const c_void) -> i32;
    fn SecItemAdd(attributes: *const c_void, result: *mut *const c_void) -> i32;
}

const K_CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;

/// Retrieves device hardware model (e.g. "iPhone16,2").
pub fn get_hardware_machine() -> String {
    #[cfg(target_vendor = "apple")]
    {
        if let Ok(name) = CString::new(obfstr!("hw.machine")) {
            let mut size: usize = 0;
            unsafe {
                sysctlbyname(name.as_ptr(), core::ptr::null_mut(), &mut size, core::ptr::null(), 0);
                if size > 0 && size < 128 {
                    let mut buf = vec![0u8; size];
                    if sysctlbyname(
                        name.as_ptr(),
                        buf.as_mut_ptr() as *mut c_void,
                        &mut size,
                        core::ptr::null(),
                        0,
                    ) == 0
                    {
                        if let Some(end) = buf.iter().position(|&b| b == 0) {
                            buf.truncate(end);
                        }
                        if let Ok(s) = String::from_utf8(buf) {
                            return s;
                        }
                    }
                }
            }
        }
    }
    obfstr!("unknown-apple").to_string()
}

/// Reads persistent device salt string from iOS Keychain.
#[cfg(target_vendor = "apple")]
fn keychain_read_string(service: &str, account: &str) -> Option<String> {
    let svc_c = CString::new(service).ok()?;
    let acc_c = CString::new(account).ok()?;
    unsafe {
        let cf_svc = CFStringCreateWithCString(kCFAllocatorDefault, svc_c.as_ptr(), K_CF_STRING_ENCODING_UTF8);
        let cf_acc = CFStringCreateWithCString(kCFAllocatorDefault, acc_c.as_ptr(), K_CF_STRING_ENCODING_UTF8);
        let dict = CFDictionaryCreateMutable(kCFAllocatorDefault, 6, core::ptr::null(), core::ptr::null());
        if dict.is_null() || cf_svc.is_null() || cf_acc.is_null() {
            if !cf_svc.is_null() { CFRelease(cf_svc); }
            if !cf_acc.is_null() { CFRelease(cf_acc); }
            if !dict.is_null() { CFRelease(dict); }
            return None;
        }
        CFDictionaryAddValue(dict, kSecClass, kSecClassGenericPassword);
        CFDictionaryAddValue(dict, kSecAttrService, cf_svc);
        CFDictionaryAddValue(dict, kSecAttrAccount, cf_acc);
        CFDictionaryAddValue(dict, kSecReturnData, kCFBooleanTrue);
        CFDictionaryAddValue(dict, kSecMatchLimit, kSecMatchLimitOne);

        let mut out_ref: *const c_void = core::ptr::null();
        let status = SecItemCopyMatching(dict, &mut out_ref);
        CFRelease(dict);
        CFRelease(cf_svc);
        CFRelease(cf_acc);

        if status == 0 && !out_ref.is_null() {
            let len = CFDataGetLength(out_ref);
            let ptr = CFDataGetBytePtr(out_ref);
            let res = if len > 0 && !ptr.is_null() {
                let slice = core::slice::from_raw_parts(ptr, len as usize);
                String::from_utf8(slice.to_vec()).ok()
            } else {
                None
            };
            CFRelease(out_ref);
            return res;
        }
    }
    None
}

#[cfg(target_vendor = "apple")]
fn keychain_write_string(service: &str, account: &str, val: &str) -> bool {
    let (Ok(svc_c), Ok(acc_c)) = (CString::new(service), CString::new(account)) else {
        return false;
    };
    unsafe {
        let cf_svc = CFStringCreateWithCString(kCFAllocatorDefault, svc_c.as_ptr(), K_CF_STRING_ENCODING_UTF8);
        let cf_acc = CFStringCreateWithCString(kCFAllocatorDefault, acc_c.as_ptr(), K_CF_STRING_ENCODING_UTF8);
        let cf_data = CFDataCreate(kCFAllocatorDefault, val.as_ptr(), val.len() as isize);
        let dict = CFDictionaryCreateMutable(kCFAllocatorDefault, 6, core::ptr::null(), core::ptr::null());
        if dict.is_null() || cf_svc.is_null() || cf_acc.is_null() || cf_data.is_null() {
            if !cf_svc.is_null() { CFRelease(cf_svc); }
            if !cf_acc.is_null() { CFRelease(cf_acc); }
            if !cf_data.is_null() { CFRelease(cf_data); }
            if !dict.is_null() { CFRelease(dict); }
            return false;
        }
        CFDictionaryAddValue(dict, kSecClass, kSecClassGenericPassword);
        CFDictionaryAddValue(dict, kSecAttrService, cf_svc);
        CFDictionaryAddValue(dict, kSecAttrAccount, cf_acc);
        CFDictionaryAddValue(dict, kSecAttrAccessible, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly);
        CFDictionaryAddValue(dict, kSecValueData, cf_data);

        let status = SecItemAdd(dict, core::ptr::null_mut());
        CFRelease(dict);
        CFRelease(cf_svc);
        CFRelease(cf_acc);
        CFRelease(cf_data);
        status == 0
    }
}

#[cfg(not(target_vendor = "apple"))]
fn keychain_read_string(_service: &str, _account: &str) -> Option<String> {
    None
}

#[cfg(not(target_vendor = "apple"))]
fn keychain_write_string(_service: &str, _account: &str, _val: &str) -> bool {
    false
}

/// Computes persistent hardware-bound SHA-256 device fingerprint (64 hex chars).
pub fn get_device_fingerprint() -> String {
    let hw = get_hardware_machine();
    let svc = obfstr!("com.phucvn.3105.devfp").to_string();
    let acc = obfstr!("device_secret_id").to_string();

    let persistent_id = match keychain_read_string(&svc, &acc) {
        Some(existing) if !existing.trim().is_empty() => existing,
        _ => {
            let mut rnd = [0u8; 16];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut rnd);
            let generated = hex::encode(rnd);
            let _ = keychain_write_string(&svc, &acc, &generated);
            keychain_read_string(&svc, &acc).unwrap_or(generated)
        }
    };

    let hwid_tag = obfstr!("PHUCVN3105-HWID-V3|").to_string();
    let mut hasher = Sha256::new();
    hasher.update(hwid_tag.as_bytes());
    hasher.update(hw.as_bytes());
    hasher.update(b"|");
    hasher.update(persistent_id.as_bytes());
    hex::encode(hasher.finalize())
}
