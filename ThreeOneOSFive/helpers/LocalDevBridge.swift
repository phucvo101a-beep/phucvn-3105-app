import Foundation
import SwiftUI

// C-ABI Linkage to libsec_core.dylib
@_silgen_name("localdev_init")
private func c_localdev_init(_ storagePath: UnsafePointer<CChar>?, _ defaultHost: UnsafePointer<CChar>?, _ port: UInt16) -> Int32

@_silgen_name("localdev_import_pairing")
private func c_localdev_import_pairing(_ data: UnsafePointer<UInt8>, _ len: Int) -> UnsafePointer<CChar>?

@_silgen_name("localdev_status")
private func c_localdev_status() -> UnsafePointer<CChar>?

@_silgen_name("localdev_scan_apps")
private func c_localdev_scan_apps() -> UnsafePointer<CChar>?

@_silgen_name("localdev_list_dir")
private func c_localdev_list_dir(_ serviceType: Int32, _ bundleID: UnsafePointer<CChar>?, _ path: UnsafePointer<CChar>) -> UnsafePointer<CChar>?

@_silgen_name("localdev_read_file")
private func c_localdev_read_file(_ serviceType: Int32, _ bundleID: UnsafePointer<CChar>?, _ path: UnsafePointer<CChar>, _ outLen: UnsafeMutablePointer<Int>) -> UnsafeMutablePointer<UInt8>?

@_silgen_name("localdev_write_file")
private func c_localdev_write_file(_ serviceType: Int32, _ bundleID: UnsafePointer<CChar>?, _ path: UnsafePointer<CChar>, _ data: UnsafePointer<UInt8>, _ len: Int) -> UnsafePointer<CChar>?

@_silgen_name("localdev_free_string")
private func c_localdev_free_string(_ ptr: UnsafePointer<CChar>?)

@_silgen_name("localdev_free_bytes")
private func c_localdev_free_bytes(_ ptr: UnsafeMutablePointer<UInt8>?, _ len: Int)

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
        let path = storageDirectory.path
        let host = "10.7.0.1"
        _ = c_localdev_init(path, host, 62078)
        refreshStatus()
    }

    public func refreshStatus() {
        guard let cStr = c_localdev_status() else { return }
        defer { c_localdev_free_string(cStr) }
        let jsonStr = String(cString: cStr)

        if let data = jsonStr.data(using: .utf8),
           let status = try? JSONDecoder().decode(LocalDevStatus.self, from: data) {
            DispatchQueue.main.async {
                self.currentStatus = status
            }
        }
    }

    public func importPairingFile(from url: URL) -> Bool {
        guard url.startAccessingSecurityScopedResource() else {
            // Fallback for non-scoped file access
            return importPairingData(from: url)
        }
        defer { url.stopAccessingSecurityScopedResource() }
        return importPairingData(from: url)
    }

    private func importPairingData(from url: URL) -> Bool {
        guard let data = try? Data(contentsOf: url) else {
            DispatchQueue.main.async {
                self.lastError = "Không thể đọc nội dung file pairing"
            }
            return false
        }

        let bytes = [UInt8](data)
        guard let cStr = c_localdev_import_pairing(bytes, bytes.count) else {
            return false
        }
        defer { c_localdev_free_string(cStr) }

        let jsonStr = String(cString: cStr)
        if let respData = jsonStr.data(using: .utf8),
           let status = try? JSONDecoder().decode(LocalDevStatus.self, from: respData) {
            DispatchQueue.main.async {
                self.currentStatus = status
                self.lastError = status.isLive ? nil : status.message
            }
            return status.isLive
        }
        return false
    }

    public func scanApplications(completion: @escaping ([LocalDevApp]) -> Void) {
        isScanning = true
        lastError = nil

        DispatchQueue.global(qos: .userInitiated).async {
            guard let cStr = c_localdev_scan_apps() else {
                DispatchQueue.main.async {
                    self.isScanning = false
                    self.lastError = "Lỗi kết nối installation_proxy"
                    completion([])
                }
                return
            }
            defer { c_localdev_free_string(cStr) }

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
        guard let cStr = c_localdev_list_dir(service.rawValue, bundleID, path) else {
            return []
        }
        defer { c_localdev_free_string(cStr) }

        let jsonStr = String(cString: cStr)
        if let data = jsonStr.data(using: .utf8),
           let resp = try? JSONDecoder().decode(ListDirResponse.self, from: data),
           let entries = resp.entries {
            return entries
        }
        return []
    }

    public func readFile(service: LocalDevServiceType, bundleID: String?, path: String) -> Data? {
        var outLen = 0
        guard let bufPtr = c_localdev_read_file(service.rawValue, bundleID, path, &outLen), outLen > 0 else {
            return nil
        }
        defer { c_localdev_free_bytes(bufPtr, outLen) }
        return Data(bytes: bufPtr, count: outLen)
    }

    public func writeFile(service: LocalDevServiceType, bundleID: String?, path: String, data: Data) -> Bool {
        let bytes = [UInt8](data)
        guard let cStr = c_localdev_write_file(service.rawValue, bundleID, path, bytes, bytes.count) else {
            return false
        }
        defer { c_localdev_free_string(cStr) }
        let jsonStr = String(cString: cStr)
        return jsonStr.contains("\"success\":true")
    }
}
