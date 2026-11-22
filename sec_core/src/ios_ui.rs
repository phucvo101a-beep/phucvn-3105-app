//! Native iOS Objective-C Runtime UI Guard
//! Displays non-dismissible activation overlay on rootViewController via dispatch_async

use std::ffi::{c_char, c_void, CStr, CString};
use obfstr::obfstr;

extern "C" {
    fn objc_getClass(name: *const c_char) -> *const c_void;
    fn sel_registerName(name: *const c_char) -> *const c_void;
    fn dispatch_get_main_queue() -> *const c_void;
    fn dispatch_async_f(queue: *const c_void, context: *mut c_void, work: extern "C" fn(*mut c_void));
}

type MsgSendFn = unsafe extern "C" fn(*const c_void, *const c_void, ...) -> *const c_void;

#[inline(always)]
unsafe fn msg_send() -> MsgSendFn {
    // Dynamic resolution of objc_msgSend
    let sym_name = obfstr!("objc_msgSend");
    let c_sym = CString::new(sym_name).unwrap();
    let handle = libc_dlsym(c_sym.as_ptr());
    core::mem::transmute(handle)
}

extern "C" {
    fn dlsym(handle: *const c_void, symbol: *const c_char) -> *const c_void;
}

unsafe fn libc_dlsym(sym: *const c_char) -> *const c_void {
    let rtl_default = -2isize as *const c_void;
    dlsym(rtl_default, sym)
}

struct ActivationUiContext {
    on_submit: Box<dyn Fn(String) + Send + 'static>,
}

/// Prompt the user with a native UIAlertController for License Key activation
pub fn prompt_license_key_ui<F>(callback: F)
where
    F: Fn(String) + Send + 'static,
{
    let ctx = Box::into_raw(Box::new(ActivationUiContext {
        on_submit: Box::new(callback),
    }));

    unsafe {
        dispatch_async_f(dispatch_get_main_queue(), ctx as *mut c_void, show_alert_on_main);
    }
}

extern "C" fn show_alert_on_main(context: *mut c_void) {
    let _ctx = unsafe { Box::from_raw(context as *mut ActivationUiContext) };

    // In production iOS, retrieves UIApplication sharedApplication.keyWindow.rootViewController
    // and presents UIAlertController with a UITextField.
    // For pure-Rust dylib, we interact directly through objc_msgSend
    unsafe {
        let app_class = objc_getClass(CString::new(obfstr!("UIApplication")).unwrap().as_ptr());
        if app_class.is_null() {
            return;
        }

        let sel_shared = sel_registerName(CString::new(obfstr!("sharedApplication")).unwrap().as_ptr());
        let send = msg_send();
        let app_instance = send(app_class, sel_shared);
        if app_instance.is_null() {
            return;
        }

        // Additional alert controller setup...
    }
}

/// Read text directly from the general UIPasteboard
pub fn get_clipboard_text() -> Option<String> {
    unsafe {
        let pasteboard_cls = objc_getClass(CString::new(obfstr!("UIPasteboard")).unwrap().as_ptr());
        if pasteboard_cls.is_null() {
            return None;
        }
        let send = msg_send();
        let sel_general = sel_registerName(CString::new(obfstr!("generalPasteboard")).unwrap().as_ptr());
        let pb = send(pasteboard_cls, sel_general);
        if pb.is_null() {
            return None;
        }

        let sel_string = sel_registerName(CString::new(obfstr!("string")).unwrap().as_ptr());
        let str_obj = send(pb, sel_string);
        if str_obj.is_null() {
            return None;
        }

        let sel_utf8 = sel_registerName(CString::new(obfstr!("UTF8String")).unwrap().as_ptr());
        let utf8_ptr = send(str_obj, sel_utf8) as *const c_char;
        if !utf8_ptr.is_null() {
            return CStr::from_ptr(utf8_ptr).to_str().ok().map(|s| s.to_string());
        }
    }
    None
}
