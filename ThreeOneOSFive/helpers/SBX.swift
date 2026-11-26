import Foundation
import Darwin

func sandbox_extension_consume(_ token: String) -> Int64? {
    let cleanToken = token.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !cleanToken.isEmpty else { return nil }
    typealias Fn = @convention(c) (UnsafePointer<CChar>?) -> Int64
    guard let lib = dlopen("/usr/lib/system/libsystem_sandbox.dylib", RTLD_NOW) else { return nil }
    defer { dlclose(lib) }
    guard let sym = dlsym(lib, "sandbox_extension_consume") else { return nil }
    let fn = unsafeBitCast(sym, to: Fn.self)
    let handle = cleanToken.withCString { fn($0) }
    return handle >= 0 ? handle : nil
}

func sandbox_extension_issue_file(path: String) -> String? {
    guard let fileURL = ContainerStore.validatedLocalFileURL(fromPath: path, requireExists: true) else {
        log("sbx: skipped sandbox_extension_issue_file for invalid/missing path")
        return nil
    }
    typealias Fn = @convention(c) (UnsafePointer<CChar>?, UnsafePointer<CChar>?, UInt32) -> UnsafeMutablePointer<CChar>?
    guard let lib = dlopen("/usr/lib/system/libsystem_sandbox.dylib", RTLD_NOW) else { return nil }
    defer { dlclose(lib) }
    guard let sym = dlsym(lib, "sandbox_extension_issue_file") else { return nil }
    let fn = unsafeBitCast(sym, to: Fn.self)
    guard let ptr = "com.apple.app-sandbox.read-write".withCString({ extPtr in
        fileURL.path.withCString { pathPtr in
            fn(extPtr, pathPtr, 0)
        }
    }) else {
        return nil
    }
    defer { free(ptr) }
    return String(cString: ptr)
}
