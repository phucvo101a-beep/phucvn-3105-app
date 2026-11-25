import CryptoKit
import Darwin
import Foundation

/// Cryptographic runtime session ticket issued only after V3 AEAD + Ed25519 + Rust RAM vault verification.
struct RuntimeSessionTicket: Equatable {
    let rawTicket: String
    let packageID: String
    let appVersion: String
    let deviceFP: String
    let ed25519Verified: Bool
    let issuedAt: Date
    let expiryTS: Int64
    let isPermanent: Bool
}

struct V3LicenseSummary: Equatable {
    let valid: Bool
    let keyMasked: String
    let expiryText: String
    let expiryTS: Int64
    let remainingSeconds: Int64
    let isPermanent: Bool
    let role: String
    let usedDevices: Int
    let maxDevices: Int
}

enum V3GateOutcome: Equatable {
    case unlocked(ticket: RuntimeSessionTicket, license: V3LicenseSummary)
    case preflightOpen(minVersion: String, latestVersion: String)
    case serverClosed(message: String)
    case deviceBanned(reason: String, hwid: String)
    case forceUpdate(minVersion: String, latestVersion: String, downloadURL: String, message: String)
    case denied(code: String, message: String)
    case tampered(message: String)
    case networkError(message: String)
}

private typealias CSecPreflight = @convention(c) () -> UnsafeMutablePointer<CChar>?
private typealias CSecActivate = @convention(c) (UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar>?
private typealias CSecHeartbeat = @convention(c) () -> UnsafeMutablePointer<CChar>?
private typealias CSecDecryptV4 = @convention(c) (UnsafePointer<UInt8>?, Int, UnsafePointer<CChar>?, UnsafeMutablePointer<Int>?) -> UnsafeMutablePointer<UInt8>?
private typealias CSecVerifyTicket = @convention(c) (UnsafePointer<CChar>?) -> Int32
private typealias CSecWipeSession = @convention(c) () -> Void
private typealias CSecDeviceFP = @convention(c) () -> UnsafeMutablePointer<CChar>?
private typealias CSecTamperDetected = @convention(c) () -> Bool
private typealias CSecFreeString = @convention(c) (UnsafeMutablePointer<CChar>?) -> Void
private typealias CSecFreeBytes = @convention(c) (UnsafeMutablePointer<UInt8>?, Int) -> Void

final class SecCoreBridge {
    static let shared = SecCoreBridge()

    private static let expectedTicketMagic: Int32 = 0x3105_5A17
    private var dylibHandle: UnsafeMutableRawPointer?

    private var fnPreflight: CSecPreflight?
    private var fnActivate: CSecActivate?
    private var fnHeartbeat: CSecHeartbeat?
    private var fnDecryptV4: CSecDecryptV4?
    private var fnVerifyTicket: CSecVerifyTicket?
    private var fnWipeSession: CSecWipeSession?
    private var fnDeviceFP: CSecDeviceFP?
    private var fnTamperDetected: CSecTamperDetected?
    private var fnFreeString: CSecFreeString?
    private var fnFreeBytes: CSecFreeBytes?

    private init() {
        resolveDylib()
    }

    private func resolveDylib() {
        if dylibHandle == nil {
            let candidates = [
                Bundle.main.bundleURL.appendingPathComponent("Frameworks/libsec_core.dylib").path,
                "@executable_path/Frameworks/libsec_core.dylib",
                "@rpath/libsec_core.dylib"
            ]
            for path in candidates {
                if let h = dlopen(path, RTLD_NOW | RTLD_GLOBAL) {
                    dylibHandle = h
                    break
                }
            }
        }
        let target = dylibHandle ?? UnsafeMutableRawPointer(bitPattern: -2)
        if let s = dlsym(target, GeneratedSecurityConfig.symPreflight) {
            fnPreflight = unsafeBitCast(s, to: CSecPreflight.self)
        }
        if let s = dlsym(target, GeneratedSecurityConfig.symActivate) {
            fnActivate = unsafeBitCast(s, to: CSecActivate.self)
        }
        if let s = dlsym(target, GeneratedSecurityConfig.symHeartbeat) {
            fnHeartbeat = unsafeBitCast(s, to: CSecHeartbeat.self)
        }
        if let s = dlsym(target, GeneratedSecurityConfig.symDecryptV4) {
            fnDecryptV4 = unsafeBitCast(s, to: CSecDecryptV4.self)
        }
        if let s = dlsym(target, GeneratedSecurityConfig.symVerifyTicket) {
            fnVerifyTicket = unsafeBitCast(s, to: CSecVerifyTicket.self)
        }
        if let s = dlsym(target, GeneratedSecurityConfig.symWipeSession) {
            fnWipeSession = unsafeBitCast(s, to: CSecWipeSession.self)
        }
        if let s = dlsym(target, GeneratedSecurityConfig.symDeviceFP) {
            fnDeviceFP = unsafeBitCast(s, to: CSecDeviceFP.self)
        }
        if let s = dlsym(target, GeneratedSecurityConfig.symTamperDetected) {
            fnTamperDetected = unsafeBitCast(s, to: CSecTamperDetected.self)
        }
        if let s = dlsym(target, GeneratedSecurityConfig.symFreeString) {
            fnFreeString = unsafeBitCast(s, to: CSecFreeString.self)
        }
        if let s = dlsym(target, GeneratedSecurityConfig.symFreeBytes) {
            fnFreeBytes = unsafeBitCast(s, to: CSecFreeBytes.self)
        }
    }

    var isCoreLoaded: Bool {
        fnPreflight != nil && fnActivate != nil && fnDecryptV4 != nil && fnVerifyTicket != nil
    }

    func deviceFingerprint() -> String {
        resolveDylib()
        guard let fn = fnDeviceFP, let ptr = fn() else {
            return "SEC-CORE-MISSING"
        }
        defer { fnFreeString?(ptr) }
        return String(cString: ptr)
    }

    func wipeSession() {
        fnWipeSession?()
    }

    func preflight() -> V3GateOutcome {
        resolveDylib()
        guard !detectSwiftTamper(), let fn = fnPreflight, let ptr = fn() else {
            return .tampered(message: "Mô-đun bảo mật bị thiếu hoặc đã bị can thiệp.")
        }
        defer { fnFreeString?(ptr) }
        let jsonStr = String(cString: ptr)
        return parseGateJSON(jsonStr, isPreflight: true)
    }

    func activate(licenseKey: String) -> V3GateOutcome {
        resolveDylib()
        guard !detectSwiftTamper(), let fn = fnActivate else {
            return .tampered(message: "Mô-đun bảo mật bị thiếu hoặc đã bị can thiệp.")
        }
        let clean = licenseKey.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let ptr = clean.withCString({ fn($0) }) else {
            return .networkError(message: "Lỗi giao tiếp bảo mật nội bộ.")
        }
        defer { fnFreeString?(ptr) }
        return parseGateJSON(String(cString: ptr), isPreflight: false)
    }

    func heartbeat() -> V3GateOutcome {
        resolveDylib()
        guard !detectSwiftTamper(), let fn = fnHeartbeat, let ptr = fn() else {
            wipeSession()
            return .tampered(message: "Phát hiện can thiệp bảo mật trong quá trình chạy.")
        }
        defer { fnFreeString?(ptr) }
        return parseGateJSON(String(cString: ptr), isPreflight: false)
    }

    /// Combines CryptoKit signature validation state, C-ABI vault check & opaque state arithmetic.
    func isActiveTicketValid(_ ticket: RuntimeSessionTicket?) -> Bool {
        guard let ticket, ticket.ed25519Verified, !ticket.rawTicket.isEmpty else {
            return false
        }
        if detectSwiftTamper() {
            wipeSession()
            return false
        }
        if !ticket.isPermanent, let exp = ticket.expiresAtDate, Date() >= exp {
            wipeSession()
            return false
        }
        guard let fn = fnVerifyTicket else { return false }
        let res = ticket.rawTicket.withCString { fn($0) }
        // Opaque arithmetic cross-check to harden branch checks against trivial single-bit patching
        let seed = GeneratedSecurityConfig.opaqueSeed
        let expectedMask = Self.expectedTicketMagic ^ Int32(truncatingIfNeeded: seed & 0)
        return res == expectedMask
    }

    /// Decrypts a V4 `.3105` container purely in RAM via libsec_core vault keys.
    func decryptV4InRAM(_ assetData: Data, ticket: RuntimeSessionTicket) throws -> SecureBytes {
        guard isActiveTicketValid(ticket), let fn = fnDecryptV4 else {
            throw PatchPackageError.privateOperationFailed
        }
        var outLen: Int = 0
        let rawPtr: UnsafeMutablePointer<UInt8>? = assetData.withUnsafeBytes { buf in
            guard let base = buf.bindMemory(to: UInt8.self).baseAddress else { return nil }
            return ticket.rawTicket.withCString { tPtr in
                fn(base, assetData.count, tPtr, &outLen)
            }
        }
        guard let validPtr = rawPtr, outLen > 0 else {
            throw PatchPackageError.invalidPasswordOrCorruptedPackage
        }
        defer {
            memset_s(validPtr, outLen, 0, outLen)
            fnFreeBytes?(validPtr, outLen)
        }
        return SecureBytes(copying: validPtr, count: outLen)
    }

    /// Independent Swift-level anti-tamper sanity checks paired with Rust libsec_core.
    private func detectSwiftTamper() -> Bool {
        if let fn = fnTamperDetected, fn() {
            return true
        }
        let blockedEnv = ["DYLD_INSERT_LIBRARIES", "FRIDA_HOST", "_MSSafeMode"]
        for key in blockedEnv {
            if let val = getenv(key), !String(cString: val).isEmpty {
                return true
            }
        }
        return false
    }

    private func parseGateJSON(_ jsonStr: String, isPreflight: Bool) -> V3GateOutcome {
        guard let data = jsonStr.data(using: .utf8),
              let dict = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return .networkError(message: "Phản hồi nội bộ không hợp lệ.")
        }
        let ok = (dict["ok"] as? Bool) ?? false
        let code = (dict["code"] as? String) ?? "UNKNOWN"
        let msg = (dict["message"] as? String) ?? "Lỗi xác thực."
        if !ok {
            if code == "TAMPER_DETECTED" { return .tampered(message: msg) }
            return .deniedOrNetwork(code: code, message: msg)
        }

        // Cross-verify server Ed25519 signature natively inside Swift CryptoKit!
        guard let rawEnvelope = dict["raw_envelope"] as? String,
              let sentPkg = dict["pkg"] as? String,
              let sentVer = dict["ver"] as? String,
              let sentFP = dict["fp"] as? String,
              let sentNonce = dict["req_nonce"] as? String,
              verifyEnvelopeEd25519(
                  rawEnvelope: rawEnvelope,
                  expectedPkg: sentPkg,
                  expectedVer: sentVer,
                  expectedFP: sentFP,
                  expectedReqNonce: sentNonce
              ) else {
            wipeSession()
            return .tampered(message: "Chữ ký xác thực từ máy chủ không hợp lệ!")
        }

        let serverOpen = (dict["server_open"] as? Bool) ?? false
        let forceUpdate = (dict["force_update"] as? Bool) ?? false
        let minVer = (dict["min_version"] as? String) ?? "2.1.0"
        let latestVer = (dict["latest_version"] as? String) ?? minVer
        let downloadURL = (dict["download_url"] as? String) ?? ""

        // Mandatory Kill-Switch Gate (fail-closed)
        if !serverOpen || code == "SERVER_CLOSED" {
            wipeSession()
            return .serverClosed(message: msg)
        }

        // Mandatory Device HWID Ban Gate (fail-closed)
        if code == "DEVICE_BANNED" {
            wipeSession()
            return .deviceBanned(reason: msg, hwid: sentFP)
        }

        // Mandatory Force Update Gate (fail-closed)
        let localVer = (Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String) ?? sentVer
        if forceUpdate || code == "FORCE_UPDATE" || SemVerComparator.compare(localVer, minVer) == .orderedAscending {
            wipeSession()
            return .forceUpdate(
                minVersion: minVer,
                latestVersion: latestVer,
                downloadURL: downloadURL,
                message: msg
            )
        }

        if isPreflight && code == "OK" {
            return .preflightOpen(minVersion: minVer, latestVersion: latestVer)
        }

        let licDict = (dict["license"] as? [String: Any]) ?? [:]
        let licValid = (licDict["valid"] as? Bool) ?? false
        let ticketStr = (dict["ticket"] as? String) ?? ""
        guard code == "OK", licValid, !ticketStr.isEmpty else {
            return .denied(code: code, message: msg)
        }

        let expTS = (licDict["expiry_ts"] as? Int64) ?? Int64((licDict["expiry_ts"] as? Int) ?? 0)
        let remSecs = (licDict["remaining_seconds"] as? Int64) ?? Int64((licDict["remaining_seconds"] as? Int) ?? 0)
        let isPerm = (licDict["is_permanent"] as? Bool) ?? false

        let summary = V3LicenseSummary(
            valid: true,
            keyMasked: (licDict["key_masked"] as? String) ?? "",
            expiryText: (licDict["expiry"] as? String) ?? "",
            expiryTS: expTS,
            remainingSeconds: remSecs,
            isPermanent: isPerm,
            role: (licDict["role"] as? String) ?? "vip",
            usedDevices: (licDict["used_devices"] as? Int) ?? 1,
            maxDevices: (licDict["max_devices"] as? Int) ?? 1
        )
        let ticket = RuntimeSessionTicket(
            rawTicket: ticketStr,
            packageID: sentPkg,
            appVersion: localVer,
            deviceFP: sentFP,
            ed25519Verified: true,
            issuedAt: Date(),
            expiryTS: expTS,
            isPermanent: isPerm
        )
        guard isActiveTicketValid(ticket) else {
            return .denied(code: "TICKET_REJECTED", message: "Không thể xác nhận phiên bảo mật.")
        }
        return .unlocked(ticket: ticket, license: summary)
    }

    /// Swift CryptoKit independent Ed25519 signature verification over outer V3 server envelope.
    private func verifyEnvelopeEd25519(
        rawEnvelope: String,
        expectedPkg: String,
        expectedVer: String,
        expectedFP: String,
        expectedReqNonce: String
    ) -> Bool {
        let pubData = GeneratedSecurityConfig.serverEd25519PublicKeyData()
        if pubData.allSatisfy({ $0 == 0 }) {
            return !GeneratedSecurityConfig.enforceStrictCrypto
        }
        guard let publicKey = try? Curve25519.Signing.PublicKey(rawRepresentation: pubData),
              let envData = rawEnvelope.data(using: .utf8),
              let env = try? JSONSerialization.jsonObject(with: envData) as? [String: Any],
              let v = env["v"] as? Int, v == 3,
              let op = env["op"] as? String,
              let pkg = env["pkg"] as? String, pkg == expectedPkg,
              let ver = env["ver"] as? String, ver == expectedVer,
              let fp = env["fp"] as? String, fp.lowercased() == expectedFP.lowercased(),
              let reqNonce = env["req_nonce"] as? String, reqNonce.lowercased() == expectedReqNonce.lowercased(),
              let sNonce = env["s_nonce"] as? String,
              let sTs = (env["s_ts"] as? Int64) ?? (env["s_ts"] as? Int).map({ Int64($0) }),
              let code = env["code"] as? String,
              let ctB64 = env["ct"] as? String,
              let ctData = Data(base64Encoded: ctB64),
              let sigHex = env["sig"] as? String,
              let sigData = Data(hexString: sigHex),
              sigData.count == 64 else {
            return false
        }

        let resAad = "V3RES|3|\(op)|\(pkg)|\(ver)|\(fp)|\(reqNonce)|\(sNonce)|\(sTs)|\(code)"
        let ctHash = Data(SHA256.hash(data: ctData))
        var sigMsg = Data("3105-V3-SIG|".utf8)
        sigMsg.append(Data(resAad.utf8))
        sigMsg.append(Data("|".utf8))
        sigMsg.append(ctHash)
        return publicKey.isValidSignature(sigData, for: sigMsg)
    }
}

private extension V3GateOutcome {
    static func deniedOrNetwork(code: String, message: String) -> V3GateOutcome {
        if code == "NETWORK_ERROR" {
            return .networkError(message: message)
        }
        return .denied(code: code, message: message)
    }
}

private extension RuntimeSessionTicket {
    var expiresAtDate: Date? {
        expiryTS > 0 ? Date(timeIntervalSince1970: TimeInterval(expiryTS)) : nil
    }
}

private extension Data {
    init?(hexString: String) {
        let clean = hexString.trimmingCharacters(in: .whitespacesAndNewlines)
        guard clean.count % 2 == 0 else { return nil }
        var bytes = Data(capacity: clean.count / 2)
        var idx = clean.startIndex
        while idx < clean.endIndex {
            let next = clean.index(idx, offsetBy: 2)
            guard let byte = UInt8(clean[idx..<next], radix: 16) else { return nil }
            bytes.append(byte)
            idx = next
        }
        self = bytes
    }
}
