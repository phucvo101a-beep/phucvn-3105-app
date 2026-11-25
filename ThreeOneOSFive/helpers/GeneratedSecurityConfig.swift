import Foundation

/// CI Build-Time Security Constants Template for Swift
/// Replaced automatically by scripts/obfuscate_build.py in GitHub Actions.
enum GeneratedSecurityConfig {
    static let enforceStrictCrypto: Bool = false
    static let opaqueSeed: UInt64 = 0x5A17_3105_CAFE_BEEF

    static let ed25519ShareA: [UInt8] = Array(repeating: 0, count: 32)
    static let ed25519ShareB: [UInt8] = Array(repeating: 0, count: 32)

    static let v4TagA: [UInt8] = [0xC1, 0x22, 0x10, 0x99]
    static let v4TagB: [UInt8] = [0x5C, 0x58, 0x51, 0x7A] // XOR = [0x9D, 0x7A, 0x41, 0xE3]

    // Split legacy magic bytes for local user-created .3105 archives without plaintext literal strings
    static let legacyMagicA: [UInt8] = [0x61, 0x62, 0x63, 0x64, 0x01, 0x12, 0x07, 0x17, 0x1A, 0x52]
    static let legacyMagicB: [UInt8] = [0x52, 0x53, 0x53, 0x51, 0x51, 0x53, 0x53, 0x54, 0x52, 0x52]

    // Dynamic C-ABI symbol names (synchronized with sec_core exports by obfuscate_build.py)
    static let symPreflight = "sec_core_preflight"
    static let symActivate = "sec_core_activate"
    static let symHeartbeat = "sec_core_heartbeat"
    static let symDecryptV4 = "sec_core_decrypt_v4"
    static let symVerifyTicket = "sec_core_verify_ticket"
    static let symWipeSession = "sec_core_wipe_session"
    static let symDeviceFP = "sec_core_device_fp"
    static let symTamperDetected = "sec_core_tamper_detected"
    static let symFreeString = "sec_core_free_string"
    static let symFreeBytes = "sec_core_free_bytes"

    static func serverEd25519PublicKeyData() -> Data {
        var out = Data(count: 32)
        for i in 0..<32 {
            out[i] = ed25519ShareA[i] ^ ed25519ShareB[i]
        }
        return out
    }

    static func v4FormatTag() -> Data {
        var out = Data(count: 4)
        for i in 0..<4 {
            out[i] = v4TagA[i] ^ v4TagB[i]
        }
        return out
    }

    static func legacyMagicData() -> Data {
        var out = Data(count: 10)
        for i in 0..<10 {
            out[i] = legacyMagicA[i] ^ legacyMagicB[i]
        }
        return out
    }

    /// Stack-decoded obfuscated literal helper rewritten by CI obfuscator.
    @inline(never)
    static func _d(_ encoded: [UInt8], mask: UInt8) -> String {
        var bytes = encoded.map { $0 ^ mask }
        defer {
            bytes.withUnsafeMutableBytes { buf in
                if let base = buf.baseAddress {
                    memset_s(base, buf.count, 0, buf.count)
                }
            }
        }
        return String(bytes: bytes, encoding: .utf8) ?? ""
    }
}
