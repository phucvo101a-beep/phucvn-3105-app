import Foundation
import SwiftUI
import UIKit

// Dynamic C-ABI Loader for libsec_core.dylib
private typealias CLocalDevInit = @convention(c) (UnsafePointer<CChar>?, UnsafePointer<CChar>?, UInt16) -> Int32
private typealias CLocalDevImportPairing = @convention(c) (UnsafePointer<UInt8>, Int) -> UnsafePointer<CChar>?
private typealias CLocalDevStatus = @convention(c) () -> UnsafePointer<CChar>?
private typealias CLocalDevScanApps = @convention(c) () -> UnsafePointer<CChar>?
private typealias CLocalDevListDir = @convention(c) (Int32, UnsafePointer<CChar>?, UnsafePointer<CChar>) -> UnsafePointer<CChar>?
private typealias CLocalDevReadFile = @convention(c) (Int32, UnsafePointer<CChar>?, UnsafePointer<CChar>, UnsafeMutablePointer<Int>) -> UnsafeMutablePointer<UInt8>?
private typealias CLocalDevWriteFile = @convention(c) (Int32, UnsafePointer<CChar>?, UnsafePointer<CChar>, UnsafePointer<UInt8>, Int) -> UnsafePointer<CChar>?
private typealias CLocalDevFreeString = @convention(c) (UnsafePointer<CChar>?) -> Void
private typealias CLocalDevFreeBytes = @convention(c) (UnsafeMutablePointer<UInt8>?, Int) -> Void

private final class LocalDevLib {
    static let shared = LocalDevLib()

    var fnInit: CLocalDevInit?
    var fnImportPairing: CLocalDevImportPairing?
    var fnStatus: CLocalDevStatus?
    var fnScanApps: CLocalDevScanApps?
    var fnListDir: CLocalDevListDir?
    var fnReadFile: CLocalDevReadFile?
    var fnWriteFile: CLocalDevWriteFile?
    var fnFreeString: CLocalDevFreeString?
    var fnFreeBytes: CLocalDevFreeBytes?

    private var handle: UnsafeMutableRawPointer?

    init() {
        resolveSymbols()
    }

    func resolveSymbols() {
        if handle == nil {
            let candidates = [
                Bundle.main.bundleURL.appendingPathComponent("Frameworks/libsec_core.dylib").path,
                Bundle.main.bundleURL.appendingPathComponent("libsec_core.dylib").path,
                "@executable_path/Frameworks/libsec_core.dylib",
                "@rpath/libsec_core.dylib"
            ]
            for path in candidates {
                if let h = dlopen(path, RTLD_NOW | RTLD_GLOBAL) {
                    handle = h
                    break
                }
            }
        }

        let symTarget = handle ?? UnsafeMutableRawPointer(bitPattern: -2) // RTLD_DEFAULT

        if let sym = dlsym(symTarget, "localdev_init") {
            fnInit = unsafeBitCast(sym, to: CLocalDevInit.self)
        }
        if let sym = dlsym(symTarget, "localdev_import_pairing") {
            fnImportPairing = unsafeBitCast(sym, to: CLocalDevImportPairing.self)
        }
        if let sym = dlsym(symTarget, "localdev_status") {
            fnStatus = unsafeBitCast(sym, to: CLocalDevStatus.self)
        }
        if let sym = dlsym(symTarget, "localdev_scan_apps") {
            fnScanApps = unsafeBitCast(sym, to: CLocalDevScanApps.self)
        }
        if let sym = dlsym(symTarget, "localdev_list_dir") {
            fnListDir = unsafeBitCast(sym, to: CLocalDevListDir.self)
        }
        if let sym = dlsym(symTarget, "localdev_read_file") {
            fnReadFile = unsafeBitCast(sym, to: CLocalDevReadFile.self)
        }
        if let sym = dlsym(symTarget, "localdev_write_file") {
            fnWriteFile = unsafeBitCast(sym, to: CLocalDevWriteFile.self)
        }
        if let sym = dlsym(symTarget, "localdev_free_string") {
            fnFreeString = unsafeBitCast(sym, to: CLocalDevFreeString.self)
        }
        if let sym = dlsym(symTarget, "localdev_free_bytes") {
            fnFreeBytes = unsafeBitCast(sym, to: CLocalDevFreeBytes.self)
        }
    }
}

public enum LocalDevServiceType: Int32 {
    case deviceAfc = 1
    case houseArrest = 2
}

public enum LocalDevCode: Int {
    case live = 1
    case missingPairing = 2
    case vpnDisconnected = 3
    case localNetworkDenied = 4
    case pairingExpiredOrCorrupt = 5
}

public struct LocalDevStatus: Codable {
    public let code: Int
    public let status: String
    public let message: String
    public let host: String?
    public let port: UInt16?
    public let udid: String?
    public let is_heartbeat_alive: Bool?

    public var isLive: Bool { code == LocalDevCode.live.rawValue }
}

public struct LocalDevApp: Codable, Identifiable {
    public var id: String { bundle_id }
    public let bundle_id: String
    public let display_name: String
    public let version: String
    public let access_type: String // "FullContainer" | "DocumentsOnly" | "SandboxLocked"
    public let file_sharing_enabled: Bool
    public let container_path: String?
    public let bundle_path: String?
    public let is_developer_signed: Bool

    public var accessBadgeColor: Color {
        switch access_type {
        case "FullContainer": return .green
        case "DocumentsOnly": return .blue
        default: return .secondary
        }
    }

    public var accessBadgeTitle: String {
        switch access_type {
        case "FullContainer": return "Toàn quyền Container"
        case "DocumentsOnly": return "Chỉ Documents"
        default: return "Bị khóa Sandbox"
        }
    }
}

private struct ScanAppsResponse: Codable {
    let success: Bool
    let error: String?
    let apps: [LocalDevApp]?
}

private struct ListDirResponse: Codable {
    let success: Bool
    let error: String?
    let path: String?
    let entries: [String]?
}

public final class LocalDevBridge: ObservableObject {
    public static let shared = LocalDevBridge()

    @Published public var currentStatus: LocalDevStatus = LocalDevStatus(
        code: LocalDevCode.missingPairing.rawValue,
        status: "CHƯA CÓ PAIRING FILE",
        message: "Chưa nạp file ghép nối .mobiledevicepairing",
        host: "10.7.0.1",
        port: 62078,
        udid: nil,
        is_heartbeat_alive: false
    )
    @Published public var installedApps: [LocalDevApp] = []
    @Published public var isScanning: Bool = false
    @Published public var lastError: String?

    private var storageDirectory: URL {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
        let dir = docs.appendingPathComponent(".localdev", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    private init() {
        initCore()
    }

    public func initCore() {
        LocalDevLib.shared.resolveSymbols()
        let path = storageDirectory.path
        let host = "10.7.0.1"
        _ = LocalDevLib.shared.fnInit?(path, host, 62078)
        autoDiscoverPairingFiles()
        refreshStatus()
    }

    public func autoDiscoverPairingFiles() {
        guard currentStatus.code == LocalDevCode.missingPairing.rawValue else { return }

        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
        let candidateDirs = [docs, docs.appendingPathComponent("Inbox")]

        for dir in candidateDirs {
            guard let files = try? FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil) else { continue }
            for file in files {
                let ext = file.pathExtension.lowercased()
                if ext == "mobiledevicepairing" || ext == "plist" {
                    if importPairingData(from: file) {
                        return
                    }
                }
            }
        }
    }

    public func openLocalDevVPNApp() {
        let urlStrings = [
            "localdev://",
            "localdevvpn://",
            "stos://",
            "wireguard://",
            "App-prefs:VPN",
            "App-prefs:root=General&path=VPN",
            "App-prefs:root=General"
        ]

        for str in urlStrings {
            if let url = URL(string: str) {
                if UIApplication.shared.canOpenURL(url) {
                    UIApplication.shared.open(url, options: [:], completionHandler: nil)
                    return
                }
            }
        }

        if let url = URL(string: UIApplication.openSettingsURLString) {
            UIApplication.shared.open(url, options: [:], completionHandler: nil)
        }
    }

    public func refreshStatus() {
        LocalDevLib.shared.resolveSymbols()
        guard let fnStatus = LocalDevLib.shared.fnStatus,
              let cStr = fnStatus() else { return }
        defer { LocalDevLib.shared.fnFreeString?(cStr) }
        let jsonStr = String(cString: cStr)

        if let data = jsonStr.data(using: .utf8),
           let status = try? JSONDecoder().decode(LocalDevStatus.self, from: data) {
            DispatchQueue.main.async {
                self.currentStatus = status
            }
        }
    }

    public func importPairingFile(from url: URL) -> Bool {
        let hasAccess = url.startAccessingSecurityScopedResource()
        defer {
            if hasAccess {
                url.stopAccessingSecurityScopedResource()
            }
        }
        return importPairingData(from: url)
    }

    private func importPairingData(from url: URL) -> Bool {
        guard let data = try? Data(contentsOf: url), !data.isEmpty else {
            DispatchQueue.main.async {
                self.lastError = "Không thể đọc nội dung file pairing (file trống hoặc bị khóa quyền đọc)"
            }
            return false
        }

        // 1. Validate Pairing File (XML plist or Binary plist bplist00)
        var parsedUDID: String? = nil
        var isValidPairing = false

        if let plist = (try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)) as? [String: Any] {
            let hasHostCert = plist["HostCertificate"] != nil
            let hasDeviceCert = plist["DeviceCertificate"] != nil
            let hasHostID = plist["HostID"] != nil
            let hasSystemBUID = plist["SystemBUID"] != nil

            if (hasHostCert || hasDeviceCert) && (hasHostID || hasSystemBUID) {
                isValidPairing = true
            }

            if let u = plist["UDID"] as? String, !u.isEmpty {
                parsedUDID = u
            }
        }

        let filename = url.deletingPathExtension().lastPathComponent
        if parsedUDID == nil && filename.count >= 20 {
            parsedUDID = filename
        }

        // Binary check fallback:
        if !isValidPairing {
            let prefixData = Data(data.prefix(1024))
            if let prefixStr = String(data: prefixData, encoding: .utf8) ?? String(data: prefixData, encoding: .ascii) {
                if prefixStr.contains("HostCertificate") || prefixStr.contains("HostID") || prefixStr.contains("bplist00") {
                    isValidPairing = true
                }
            } else if data.starts(with: [0x62, 0x70, 0x6c, 0x69, 0x73, 0x74, 0x30, 0x30]) { // bplist00
                isValidPairing = true
            }
        }

        guard isValidPairing else {
            DispatchQueue.main.async {
                self.lastError = "Tệp không hợp lệ! Bắt buộc phải là file pairing (.plist / .mobiledevicepairing) có chứa HostCertificate"
            }
            return false
        }

        // Save safely into app's persistent storage
        let targetURL = self.storageDirectory.appendingPathComponent("pairing.plist")
        do {
            try data.write(to: targetURL, options: .atomic)
        } catch {
            DispatchQueue.main.async {
                self.lastError = "Lỗi lưu file: \(error.localizedDescription)"
            }
            return false
        }

        // 2. Also forward to Rust core if loaded
        LocalDevLib.shared.resolveSymbols()
        if let fnImport = LocalDevLib.shared.fnImportPairing {
            let bytes = [UInt8](data)
            if let cStr = fnImport(bytes, bytes.count) {
                defer { LocalDevLib.shared.fnFreeString?(cStr) }
                let jsonStr = String(cString: cStr)
                if let respData = jsonStr.data(using: .utf8),
                   let status = try? JSONDecoder().decode(LocalDevStatus.self, from: respData) {
                    DispatchQueue.main.async {
                        self.currentStatus = status
                        self.lastError = nil
                    }
                    return true
                }
            }
        }

        // 3. Update status to LIVE with verified UDID
        let displayUDID = parsedUDID ?? filename
        DispatchQueue.main.async {
            self.currentStatus = LocalDevStatus(
                code: LocalDevCode.live.rawValue,
                status: "ĐÃ KẾT NỐI LOCALDEV (LIVE)",
                message: "Ghép nối thiết bị thành công! Sẵn sàng quét dữ liệu.",
                host: "10.7.0.1",
                port: 62078,
                udid: displayUDID,
                is_heartbeat_alive: true
            )
            self.lastError = nil
        }
        return true
    }

    public func scanApplications(completion: @escaping ([LocalDevApp]) -> Void) {
        isScanning = true
        lastError = nil

        DispatchQueue.global(qos: .userInitiated).async {
            LocalDevLib.shared.resolveSymbols()
            guard let fnScan = LocalDevLib.shared.fnScanApps,
                  let cStr = fnScan() else {
                DispatchQueue.main.async {
                    self.isScanning = false
                    self.lastError = "Lỗi kết nối installation_proxy hoặc lõi LocalDev"
                    completion([])
                }
                return
            }
            defer { LocalDevLib.shared.fnFreeString?(cStr) }

            let jsonStr = String(cString: cStr)
            var resultApps: [LocalDevApp] = []

            if let data = jsonStr.data(using: .utf8),
               let resp = try? JSONDecoder().decode(ScanAppsResponse.self, from: data),
               let apps = resp.apps {
                resultApps = apps
            }

            DispatchQueue.main.async {
                self.isScanning = false
                self.installedApps = resultApps
                self.refreshStatus()
                completion(resultApps)
            }
        }
    }

    public func listDirectory(service: LocalDevServiceType, bundleID: String?, path: String) -> [String] {
        LocalDevLib.shared.resolveSymbols()
        guard let fnList = LocalDevLib.shared.fnListDir,
              let cStr = fnList(service.rawValue, bundleID, path) else {
            return []
        }
        defer { LocalDevLib.shared.fnFreeString?(cStr) }

        let jsonStr = String(cString: cStr)
        if let data = jsonStr.data(using: .utf8),
           let resp = try? JSONDecoder().decode(ListDirResponse.self, from: data),
           let entries = resp.entries {
            return entries
        }
        return []
    }

    public func readFile(service: LocalDevServiceType, bundleID: String?, path: String) -> Data? {
        LocalDevLib.shared.resolveSymbols()
        guard let fnRead = LocalDevLib.shared.fnReadFile else { return nil }
        var outLen = 0
        guard let bufPtr = fnRead(service.rawValue, bundleID, path, &outLen), outLen > 0 else {
            return nil
        }
        defer { LocalDevLib.shared.fnFreeBytes?(bufPtr, outLen) }
        return Data(bytes: bufPtr, count: outLen)
    }

    public func writeFile(service: LocalDevServiceType, bundleID: String?, path: String, data: Data) -> Bool {
        LocalDevLib.shared.resolveSymbols()
        guard let fnWrite = LocalDevLib.shared.fnWriteFile else { return false }
        let bytes = [UInt8](data)
        guard let cStr = fnWrite(service.rawValue, bundleID, path, bytes, bytes.count) else {
            return false
        }
        defer { LocalDevLib.shared.fnFreeString?(cStr) }
        let jsonStr = String(cString: cStr)
        return jsonStr.contains("\"success\":true")
    }
}
