import Darwin
import Foundation
import Security

/// Scrubs sensitive Data buffers explicitly via volatile byte wipe (safe against dead-store elimination).
func secureWipeData(_ data: inout Data) {
    let count = data.count
    if count > 0 {
        data.withUnsafeMutableBytes { buf in
            if let base = buf.baseAddress {
                p3105_secure_zero(base, count)
            }
        }
    }
    data = Data()
}

/// Heap-allocated mutable byte box that guarantees memset_s zeroization on wipe or deinit.
final class SecureBytes {
    private var storage: UnsafeMutableBufferPointer<UInt8>

    init(copying ptr: UnsafePointer<UInt8>, count: Int) {
        let alloc = UnsafeMutablePointer<UInt8>.allocate(capacity: max(1, count))
        if count > 0 {
            alloc.initialize(from: ptr, count: count)
        } else {
            alloc.initialize(to: 0)
        }
        self.storage = UnsafeMutableBufferPointer(start: alloc, count: count)
    }

    init(data: inout Data) {
        let count = data.count
        let alloc = UnsafeMutablePointer<UInt8>.allocate(capacity: max(1, count))
        if count > 0 {
            data.withUnsafeBytes { src in
                if let base = src.bindMemory(to: UInt8.self).baseAddress {
                    alloc.initialize(from: base, count: count)
                }
            }
        } else {
            alloc.initialize(to: 0)
        }
        self.storage = UnsafeMutableBufferPointer(start: alloc, count: count)
        secureWipeData(&data)
    }

    var count: Int { storage.count }

    func withReadOnlyData<T>(_ body: (Data) throws -> T) rethrows -> T {
        guard let base = storage.baseAddress, storage.count > 0 else {
            return try body(Data())
        }
        let view = Data(bytesNoCopy: base, count: storage.count, deallocator: .none)
        return try body(view)
    }

    func wipe() {
        if let base = storage.baseAddress, storage.count > 0 {
            p3105_secure_zero(base, storage.count)
        }
    }

    deinit {
        if let base = storage.baseAddress {
            if storage.count > 0 {
                p3105_secure_zero(base, storage.count)
            }
            base.deallocate()
        }
    }
}

/// Stores ONLY the user's license string in iOS Keychain; never persists offline auth booleans.
enum KeychainLicenseVault {
    private static let service = "com.tobiaim.3105.license"
    private static let account = "saved_key"

    static func saveLicenseKey(_ key: String) {
        let trimmed = key.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, var data = trimmed.data(using: .utf8) else { return }
        defer { secureWipeData(&data) }
        deleteLicenseKey()
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecValueData as String: data
        ]
        SecItemAdd(query as CFDictionary, nil)
    }

    static func loadLicenseKey() -> String {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecSuccess, var rawData = result as? Data {
            defer { secureWipeData(&rawData) }
            return String(data: rawData, encoding: .utf8) ?? ""
        }
        return ""
    }

    static func deleteLicenseKey() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        SecItemDelete(query as CFDictionary)
    }
}

/// Numeric dotted SemVer comparison helper.
enum SemVerComparator {
    static func compare(_ lhs: String, _ rhs: String) -> ComparisonResult {
        func parse(_ s: String) -> [Int] {
            let trimmed = s.trimmingCharacters(in: .whitespacesAndNewlines)
                .trimmingCharacters(in: CharacterSet(charactersIn: "vV"))
            let core = trimmed.components(separatedBy: CharacterSet(charactersIn: "-+")).first ?? ""
            var parts = core.split(separator: ".").map { part -> Int in
                let digits = part.prefix { $0.isNumber }
                return Int(digits) ?? 0
            }
            while parts.count < 3 { parts.append(0) }
            return parts
        }
        let a = parse(lhs)
        let b = parse(rhs)
        let count = max(a.count, b.count)
        for i in 0..<count {
            let av = i < a.count ? a[i] : 0
            let bv = i < b.count ? b[i] : 0
            if av < bv { return .orderedAscending }
            if av > bv { return .orderedDescending }
        }
        return .orderedSame
    }
}
