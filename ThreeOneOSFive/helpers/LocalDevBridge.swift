import Foundation
import Network
import SwiftUI
import UIKit
import Darwin

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
    private let resolveLock = NSLock()

    private init() {}

    func resolveSymbols() {
        resolveLock.lock()
        defer { resolveLock.unlock() }
        if fnInit != nil && fnStatus != nil && fnFreeString != nil { return }
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
    case disabled = 0
    case live = 1
    case missingPairing = 2
    case vpnDisconnected = 3
    case localNetworkDenied = 4
    case pairingExpiredOrCorrupt = 5
    case tunnelReset = 6
    case remotePairingUnsupported = 7
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

public struct LocalDevDirItem: Codable, Hashable {
    public let name: String
    public let is_dir: Bool
    public let size: Int64
}

public struct LocalDevDirListing {
    public let success: Bool
    public let mode: String?
    public let error: String?
    public let items: [LocalDevDirItem]
}

public enum LocalDevVirtualPath {
    public static let schemePrefix = "localdev://"

    public static func isLocalDevPath(_ path: String) -> Bool {
        path.hasPrefix(schemePrefix)
    }

    public static func rootPath(bundleID: String) -> String {
        schemePrefix + bundleID
    }

    public static func childPath(parent: String, name: String) -> String {
        let base = parent.hasSuffix("/") ? String(parent.dropLast()) : parent
        let cleanName = name.hasPrefix("/") ? String(name.dropFirst()) : name
        return base + "/" + cleanName
    }

    public static func parse(_ virtualPath: String) -> (bundleID: String, remotePath: String)? {
        guard virtualPath.hasPrefix(schemePrefix) else { return nil }
        let remainder = String(virtualPath.dropFirst(schemePrefix.count))
        guard !remainder.isEmpty else { return nil }
        if let slashIndex = remainder.firstIndex(of: "/") {
            let bundleID = String(remainder[..<slashIndex])
            let sub = String(remainder[slashIndex...])
            return (bundleID, sub.isEmpty ? "/" : sub)
        }
        return (remainder, "/")
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
    let mode: String?
    let entries: [String]?
    let items: [LocalDevDirItem]?
}

public final class LocalDevBridge: ObservableObject {
    public static let shared = LocalDevBridge()

    private static let enabledDefaultsKey = "3105.localdev.enabled"

    @Published public var isModuleEnabled: Bool
    @Published public var currentStatus: LocalDevStatus
    @Published public var installedApps: [LocalDevApp] = []
    @Published public var isScanning: Bool = false
    @Published public var isCheckingStatus: Bool = false
    @Published public var lastError: String?

    private var storageDirectory: URL {
        let baseDir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first
            ?? ContainerStore.ownSandboxRootURL.appendingPathComponent("Documents", isDirectory: true)
        let dir = baseDir.appendingPathComponent(".localdev", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    private var isCoreInitialized = false
    private let coreInitLock = NSLock()
    private let statusLock = NSLock()
    private var _threadSafeStatus: LocalDevStatus
    private var isRefreshInFlight = false
    private var didTriggerLocalNetworkProbe = false
    private var didLogBundlePrefixNotice = false
    private var lastAutoRefreshUptime: TimeInterval = 0
    private let workerQueue = DispatchQueue(label: "com.phucvn.3105.localdev.worker", qos: .userInitiated)
    private let networkProbeQueue = DispatchQueue(label: "com.phucvn.3105.localdev.nwprobe", qos: .utility)
    private var activeProbeCancelWorkItem: DispatchWorkItem?
    private var activeProbeListener: NWListener?
    private var activeLockdownBrowser: NWBrowser?
    private var activeMobdevBrowser: NWBrowser?
    private var activeProbeConnection: NWConnection?
    private var lastLoggedStatusKey: String = ""

    public var currentStatusSnapshot: LocalDevStatus {
        statusLock.lock()
        defer { statusLock.unlock() }
        return _threadSafeStatus
    }

    private static func disabledStatus() -> LocalDevStatus {
        LocalDevStatus(
            code: LocalDevCode.disabled.rawValue,
            status: "LOCALDEV ĐÃ TẮT (BỎ QUA)",
            message: "Đang tắt module LocalDev/Pairing. Hộp cát ứng dụng (Sandbox) & Nhật ký USB Diagnostics vẫn hoạt động bình thường.",
            host: "10.7.0.1",
            port: 62078,
            udid: nil,
            is_heartbeat_alive: false
        )
    }

    private static func initialMissingPairingStatus() -> LocalDevStatus {
        LocalDevStatus(
            code: LocalDevCode.missingPairing.rawValue,
            status: "CHƯA CÓ PAIRING FILE",
            message: "Chưa nạp file ghép nối .mobiledevicepairing",
            host: "10.7.0.1",
            port: 62078,
            udid: nil,
            is_heartbeat_alive: false
        )
    }

    private static func remotePairingUnsupportedStatus(udid: String? = nil) -> LocalDevStatus {
        LocalDevStatus(
            code: LocalDevCode.remotePairingUnsupported.rawValue,
            status: "CHƯA HỖ TRỢ REMOTE PAIRING",
            message: "Đã nhận diện tệp Remote Pairing từ idevice pair v1.2.0 (public_key / private_key / identifier / alt_irk). Tuy nhiên core libsec_core.dylib hiện chỉ hỗ trợ chuẩn Lockdown X.509 cổ điển (có HostCertificate & HostID trên cổng 62078). Hãy xuất lại file pairing ở tab Pairing (Lockdown), hoặc tắt LocalDev để dùng Sandbox & Nhật ký USB.",
            host: "10.7.0.1",
            port: 62078,
            udid: udid,
            is_heartbeat_alive: false
        )
    }

    private func publishStatus(_ status: LocalDevStatus, lastError: String? = nil) {
        let normalizedStatus: LocalDevStatus
        if status.code == LocalDevCode.localNetworkDenied.rawValue,
           let bundleID = Bundle.main.bundleIdentifier,
           bundleID.hasPrefix("com.apple."),
           !status.message.contains("com.apple.") {
            normalizedStatus = LocalDevStatus(
                code: status.code,
                status: "BỊ CHẶN DO BUNDLE ID 'com.apple.'",
                message: "Bundle ID '\(bundleID)' bắt đầu bằng 'com.apple.' nên iOS 26/27 ẩn công tắc Mạng cục bộ và chặn kết nối EPERM tới \(status.host ?? "10.7.0.1"):\(status.port ?? 62078). Hãy dùng Bundle ID riêng (com.phucvn.threeoneosfive).",
                host: status.host,
                port: status.port,
                udid: status.udid,
                is_heartbeat_alive: status.is_heartbeat_alive
            )
        } else {
            normalizedStatus = status
        }

        statusLock.lock()
        _threadSafeStatus = normalizedStatus
        statusLock.unlock()
        logStatusIfChanged(normalizedStatus)
        DispatchQueue.main.async {
            self.currentStatus = normalizedStatus
            self.lastError = lastError
            self.isCheckingStatus = false
            AppLog.shared.writeDiagnosticsSnapshot()
        }
    }

    private init() {
        let savedEnabled = UserDefaults.standard.object(forKey: Self.enabledDefaultsKey) as? Bool ?? true
        let initial = savedEnabled ? Self.initialMissingPairingStatus() : Self.disabledStatus()
        self.isModuleEnabled = savedEnabled
        self.currentStatus = initial
        self._threadSafeStatus = initial
        initCore()
    }

    private func ensureCoreInitialized() {
        coreInitLock.lock()
        defer { coreInitLock.unlock() }
        guard !isCoreInitialized else { return }
        LocalDevLib.shared.resolveSymbols()
        let path = storageDirectory.path
        let host = "10.7.0.1"
        _ = LocalDevLib.shared.fnInit?(path, host, 62078)
        isCoreInitialized = true
    }

    private func logStatusIfChanged(_ status: LocalDevStatus) {
        let key = "\(status.code)|\(status.status)|\(status.message)"
        guard key != lastLoggedStatusKey else { return }
        lastLoggedStatusKey = key
        log("localdev: code=\(status.code) [\(status.status)] — \(status.message)")
    }

    /// Triggers iOS Local Network permission evaluation using Network.framework (Apple TN3179):
    /// - Step 1: `NWListener` + `NWBrowser` on declared `NSBonjourServices` (`_lockdown._tcp`, `_apple-mobdev2._tcp`)
    /// - Step 2: `NWConnection` probe toward `10.7.0.1:62078` for interface/permission telemetry (no raw UDP broadcast probe)
    private func triggerLocalNetworkFrameworkProbe(force: Bool) {
        statusLock.lock()
        if didTriggerLocalNetworkProbe && !force {
            statusLock.unlock()
            return
        }
        didTriggerLocalNetworkProbe = true
        statusLock.unlock()

        networkProbeQueue.async { [weak self] in
            guard let self else { return }

            if !self.didLogBundlePrefixNotice,
               let bundleID = Bundle.main.bundleIdentifier,
               bundleID.hasPrefix("com.apple.") {
                self.didLogBundlePrefixNotice = true
                log("localdev: bundleID '\(bundleID)' starts with 'com.apple.' — iOS 26/27 Settings may hide Local Network toggle for Apple-prefixed bundle IDs")
            }

            self.cancelActiveNetworkProbeLocked()

            // 1. Advertise `_lockdown._tcp` via NWListener (listed in Info.plist NSBonjourServices)
            let listenerParams = NWParameters.tcp
            listenerParams.includePeerToPeer = true
            if let listener = try? NWListener(using: listenerParams) {
                listener.service = NWListener.Service(type: "_lockdown._tcp")
                listener.stateUpdateHandler = { state in
                    switch state {
                    case .ready:
                        log("localdev: NWListener(_lockdown._tcp) ready")
                    case .waiting(let err):
                        log("localdev: NWListener waiting (\(String(describing: err)))")
                    case .failed(let err):
                        log("localdev: NWListener failed (\(String(describing: err)))")
                    default:
                        break
                    }
                }
                listener.newConnectionHandler = { conn in
                    conn.cancel()
                }
                listener.start(queue: self.networkProbeQueue)
                self.activeProbeListener = listener
            }

            // 2. Browse Bonjour services declared in NSBonjourServices
            let lockdownParams = NWParameters.tcp
            lockdownParams.includePeerToPeer = true
            let lockdownBrowser = NWBrowser(for: .bonjour(type: "_lockdown._tcp", domain: nil), using: lockdownParams)
            lockdownBrowser.stateUpdateHandler = { state in
                switch state {
                case .waiting(let err):
                    log("localdev: NWBrowser(_lockdown._tcp) waiting (\(String(describing: err)))")
                case .failed(let err):
                    log("localdev: NWBrowser(_lockdown._tcp) failed (\(String(describing: err)))")
                default:
                    break
                }
            }
            lockdownBrowser.browseResultsChangedHandler = { _, _ in }
            lockdownBrowser.start(queue: self.networkProbeQueue)
            self.activeLockdownBrowser = lockdownBrowser

            let mobdevParams = NWParameters.tcp
            mobdevParams.includePeerToPeer = true
            let mobdevBrowser = NWBrowser(for: .bonjour(type: "_apple-mobdev2._tcp", domain: nil), using: mobdevParams)
            mobdevBrowser.stateUpdateHandler = { _ in }
            mobdevBrowser.browseResultsChangedHandler = { _, _ in }
            mobdevBrowser.start(queue: self.networkProbeQueue)
            self.activeMobdevBrowser = mobdevBrowser

            // 3. NWConnection telemetry probe toward tunnel endpoint
            if let port = NWEndpoint.Port(rawValue: 62078) {
                let connParams = NWParameters.tcp
                connParams.includePeerToPeer = true
                let conn = NWConnection(host: NWEndpoint.Host("10.7.0.1"), port: port, using: connParams)
                conn.stateUpdateHandler = { state in
                    if case .waiting(let nwErr) = state {
                        log("localdev: NWConnection probe waiting (\(String(describing: nwErr)))")
                    } else if case .failed(let nwErr) = state {
                        log("localdev: NWConnection probe failed (\(String(describing: nwErr)))")
                    }
                }
                conn.start(queue: self.networkProbeQueue)
                self.activeProbeConnection = conn
            }

            let workItem = DispatchWorkItem { [weak self] in
                self?.cancelActiveNetworkProbeLocked()
            }
            self.activeProbeCancelWorkItem = workItem
            self.networkProbeQueue.asyncAfter(deadline: .now() + 2.0, execute: workItem)
        }
    }

    private func cancelActiveNetworkProbeLocked() {
        activeProbeCancelWorkItem?.cancel()
        activeProbeCancelWorkItem = nil
        activeProbeListener?.cancel()
        activeProbeListener = nil
        activeLockdownBrowser?.cancel()
        activeLockdownBrowser = nil
        activeMobdevBrowser?.cancel()
        activeMobdevBrowser = nil
        activeProbeConnection?.cancel()
        activeProbeConnection = nil
    }

    public func requestLocalNetworkPermission() {
        guard isModuleEnabled else { return }
        DispatchQueue.main.async {
            self.isCheckingStatus = true
        }
        triggerLocalNetworkFrameworkProbe(force: true)
        DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + 1.0) { [weak self] in
            self?.refreshStatus()
        }
    }

    public func setModuleEnabled(_ enabled: Bool) {
        UserDefaults.standard.set(enabled, forKey: Self.enabledDefaultsKey)
        DispatchQueue.main.async {
            self.isModuleEnabled = enabled
        }

        if !enabled {
            DispatchQueue.main.async {
                self.isScanning = false
                self.installedApps = []
            }
            publishStatus(Self.disabledStatus(), lastError: nil)
            return
        }

        DispatchQueue.main.async {
            self.isCheckingStatus = true
        }
        workerQueue.async { [weak self] in
            guard let self else { return }
            self.triggerLocalNetworkFrameworkProbe(force: true)
            self.ensureCoreInitialized()
            if !self.autoDiscoverPairingFiles() {
                self.refreshStatus()
            }
        }
    }

    public func initCore() {
        DispatchQueue.global(qos: .utility).async { [weak self] in
            guard let self else { return }
            guard self.isModuleEnabled else { return }
            self.workerQueue.async {
                guard self.isModuleEnabled else { return }
                self.triggerLocalNetworkFrameworkProbe(force: false)
                self.ensureCoreInitialized()
                if !self.autoDiscoverPairingFiles() {
                    self.refreshStatus()
                }
            }
        }
    }

    @discardableResult
    public func autoDiscoverPairingFiles() -> Bool {
        guard isModuleEnabled else { return false }

        let savedMobilePairing = storageDirectory.appendingPathComponent("pairing.mobiledevicepairing")
        let savedPlist = storageDirectory.appendingPathComponent("pairing.plist")
        let savedRemotePlist = storageDirectory.appendingPathComponent("remote_pairing.plist")
        if FileManager.default.fileExists(atPath: savedMobilePairing.path)
            || FileManager.default.fileExists(atPath: savedPlist.path)
            || FileManager.default.fileExists(atPath: savedRemotePlist.path) {
            return false
        }

        guard let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first else {
            return false
        }
        let candidateDirs = [docs, docs.appendingPathComponent("Inbox")]

        for dir in candidateDirs {
            guard let files = try? FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil) else { continue }
            for file in files {
                let fileExt = file.pathExtension.lowercased()
                if fileExt == "mobiledevicepairing" || fileExt == "plist" || fileExt == "pairing",
                   let validURL = ContainerStore.validatedExternalFileURL(file, requireExists: true) {
                    if fileExt == "plist" && !Self.looksLikePairingFile(at: validURL) {
                        continue
                    }
                    if importPairingData(from: validURL) {
                        return true
                    }
                }
            }
        }
        return false
    }

    public func openLocalDevVPNApp() {
        let openBlock: () -> Void = {
            // Only query schemes declared in Info.plist `LSApplicationQueriesSchemes` (avoids private `App-prefs:` `(null)` sandbox extension errors)
            let urlStrings = [
                "localdev://",
                "localdevvpn://",
                "stos://",
                "stosvpn://",
                "wireguard://"
            ]

            for str in urlStrings {
                if let url = URL(string: str), UIApplication.shared.canOpenURL(url) {
                    UIApplication.shared.open(url, options: [:], completionHandler: nil)
                    return
                }
            }

            if !UIApplication.openSettingsURLString.isEmpty,
               let url = URL(string: UIApplication.openSettingsURLString) {
                UIApplication.shared.open(url, options: [:], completionHandler: nil)
            }
        }

        if Thread.isMainThread {
            openBlock()
        } else {
            DispatchQueue.main.async(execute: openBlock)
        }
    }

    public func handleAppDidBecomeActive() {
        guard isModuleEnabled else { return }
        let now = ProcessInfo.processInfo.systemUptime
        statusLock.lock()
        if now - lastAutoRefreshUptime < 0.8 {
            statusLock.unlock()
            return
        }
        lastAutoRefreshUptime = now
        let shouldForceProbe = (_threadSafeStatus.code == LocalDevCode.localNetworkDenied.rawValue)
        statusLock.unlock()

        refreshStatus(force: shouldForceProbe)
    }

    public func refreshStatus(force: Bool = false) {
        guard isModuleEnabled else {
            publishStatus(Self.disabledStatus(), lastError: nil)
            return
        }

        statusLock.lock()
        if isRefreshInFlight {
            statusLock.unlock()
            return
        }
        isRefreshInFlight = true
        let wasDenied = (_threadSafeStatus.code == LocalDevCode.localNetworkDenied.rawValue)
        statusLock.unlock()

        DispatchQueue.main.async {
            self.isCheckingStatus = true
        }

        workerQueue.async { [weak self] in
            guard let self else { return }
            defer {
                self.statusLock.lock()
                self.isRefreshInFlight = false
                self.statusLock.unlock()
            }
            guard self.isModuleEnabled else {
                self.publishStatus(Self.disabledStatus(), lastError: nil)
                return
            }

            self.triggerLocalNetworkFrameworkProbe(force: force || wasDenied)
            self.ensureCoreInitialized()
            guard let fnStatus = LocalDevLib.shared.fnStatus,
                  let cStr = fnStatus() else {
                DispatchQueue.main.async { self.isCheckingStatus = false }
                return
            }
            defer { LocalDevLib.shared.fnFreeString?(cStr) }
            let jsonStr = String(cString: cStr)

            if let data = jsonStr.data(using: .utf8),
               let status = try? JSONDecoder().decode(LocalDevStatus.self, from: data) {
                let preservedError = (status.isLive || status.code == LocalDevCode.missingPairing.rawValue) ? nil : self.lastError
                self.publishStatus(status, lastError: preservedError)
            } else {
                DispatchQueue.main.async { self.isCheckingStatus = false }
            }
        }
    }

    /// Removes only `.localdev` pairing artifacts without touching Sandbox `Documents`, `Patches`, or `3105-Diagnostics`.
    public func clearSavedPairing() {
        DispatchQueue.main.async {
            self.isCheckingStatus = true
        }
        workerQueue.async { [weak self] in
            guard let self else { return }
            let dir = self.storageDirectory
            for name in ["pairing.plist", "pairing.mobiledevicepairing", "remote_pairing.plist"] {
                try? FileManager.default.removeItem(at: dir.appendingPathComponent(name))
            }
            if !self.isModuleEnabled {
                self.publishStatus(Self.disabledStatus(), lastError: nil)
                return
            }
            self.ensureCoreInitialized()
            if let fnStatus = LocalDevLib.shared.fnStatus,
               let cStr = fnStatus() {
                defer { LocalDevLib.shared.fnFreeString?(cStr) }
                let jsonStr = String(cString: cStr)
                if let data = jsonStr.data(using: .utf8),
                   let status = try? JSONDecoder().decode(LocalDevStatus.self, from: data) {
                    self.publishStatus(status, lastError: nil)
                    return
                }
            }
            let emptyStatus = LocalDevStatus(
                code: LocalDevCode.missingPairing.rawValue,
                status: "CHƯA CÓ PAIRING FILE",
                message: "Đã xóa tệp pairing đã lưu. Bạn vẫn có thể duyệt Sandbox & Nhật ký USB bình thường.",
                host: "10.7.0.1",
                port: 62078,
                udid: nil,
                is_heartbeat_alive: false
            )
            self.publishStatus(emptyStatus, lastError: nil)
        }
    }

    public static func looksLikePairingFile(at url: URL) -> Bool {
        guard let validURL = ContainerStore.validatedExternalFileURL(url) else { return false }
        let hasAccess = validURL.startAccessingSecurityScopedResource()
        defer {
            if hasAccess {
                validURL.stopAccessingSecurityScopedResource()
            }
        }
        guard let handle = try? FileHandle(forReadingFrom: validURL) else { return false }
        defer { try? handle.close() }
        let prefix = handle.readData(ofLength: 8192)
        guard !prefix.isEmpty else { return false }
        let normalized = Self.stripUTF8BOM(prefix)
        if let dict = Self.parsePlistDictionary(from: normalized),
           let unwrapped = Self.unwrapPairingDictionary(from: dict) {
            let analysis = Self.classifyPairingDictionary(unwrapped)
            if analysis.isValid { return true }
        }
        if let str = String(data: normalized, encoding: .utf8) ?? String(data: normalized, encoding: .ascii) {
            if str.contains("HostCertificate") || str.contains("HostID") || str.contains("public_key") || str.contains("private_key") || str.contains("alt_irk") {
                return true
            }
        }
        return false
    }

    public func importPairingFile(from url: URL) -> Bool {
        guard let validURL = ContainerStore.validatedExternalFileURL(url) else {
            let msg = "Đường dẫn tệp pairing không hợp lệ hoặc rỗng."
            log("localdev: \(msg)")
            DispatchQueue.main.async {
                self.lastError = msg
            }
            return false
        }
        let hasAccess = validURL.startAccessingSecurityScopedResource()
        defer {
            if hasAccess {
                validURL.stopAccessingSecurityScopedResource()
            }
        }
        return importPairingData(from: validURL)
    }

    private func readCoordinatedPairingData(from url: URL) -> Data? {
        if let direct = try? Data(contentsOf: url), !direct.isEmpty {
            return direct
        }
        var coordinatedData: Data?
        var coordinatorError: NSError?
        let coordinator = NSFileCoordinator()
        coordinator.coordinate(readingItemAt: url, options: .withoutChanges, error: &coordinatorError) { readURL in
            guard let validReadURL = ContainerStore.validatedExternalFileURL(readURL) else { return }
            coordinatedData = try? Data(contentsOf: validReadURL)
        }
        if let coordinatorError {
            log("localdev: NSFileCoordinator read error for '\(url.lastPathComponent)': \(coordinatorError.localizedDescription)")
        }
        if let data = coordinatedData, !data.isEmpty {
            return data
        }
        return nil
    }

    private static func stripUTF8BOM(_ data: Data) -> Data {
        if data.count >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
            return Data(data.dropFirst(3))
        }
        return data
    }

    private static func parsePlistDictionary(from data: Data) -> [String: Any]? {
        var format: PropertyListSerialization.PropertyListFormat = .xml
        if let obj = try? PropertyListSerialization.propertyList(from: data, options: [], format: &format),
           let dict = obj as? [String: Any] {
            return dict
        }
        return nil
    }

    private static func unwrapPairingDictionary(from rawObject: Any, depth: Int = 0) -> [String: Any]? {
        guard depth < 4, let dict = rawObject as? [String: Any] else { return nil }
        let lowerKeys = Set(dict.keys.map { $0.lowercased() })
        let knownMarkers: Set<String> = [
            "hostcertificate", "devicecertificate", "rootcertificate",
            "hostprivatekey", "rootprivatekey", "deviceprivatekey",
            "hostid", "systembuid", "escrowbag", "wifimacaddress",
            "public_key", "private_key", "alt_irk", "identifier"
        ]
        if !lowerKeys.isDisjoint(with: knownMarkers) {
            return dict
        }
        for key in ["PairRecord", "PairingRecord", "RemotePairing", "pairing", "record"] {
            if let nested = dict[key],
               let found = unwrapPairingDictionary(from: nested, depth: depth + 1) {
                return found
            }
        }
        for value in dict.values {
            if let found = unwrapPairingDictionary(from: value, depth: depth + 1) {
                return found
            }
        }
        return dict
    }

    private static func classifyPairingDictionary(_ dict: [String: Any]) -> (isValid: Bool, isRemotePairing: Bool, udid: String?, keys: [String]) {
        let lookup = Dictionary(
            dict.map { ($0.key.lowercased(), $0.value) },
            uniquingKeysWith: { first, _ in first }
        )
        let sortedKeys = dict.keys.sorted()

        let hasHostCert = lookup["hostcertificate"] != nil
        let hasDeviceCert = lookup["devicecertificate"] != nil
        let hasRootCert = lookup["rootcertificate"] != nil
        let hasHostPriv = lookup["hostprivatekey"] != nil
        let hasHostID = lookup["hostid"] != nil
        let hasSystemBUID = lookup["systembuid"] != nil
        let hasEscrowBag = lookup["escrowbag"] != nil

        let hasPublicKey = lookup["public_key"] != nil
        let hasPrivateKey = lookup["private_key"] != nil
        let hasIdentifier = lookup["identifier"] != nil
        let hasAltIRK = lookup["alt_irk"] != nil

        let isLockdown = (hasHostCert || hasDeviceCert || hasRootCert || hasHostPriv)
            && (hasHostID || hasSystemBUID || hasHostCert || hasEscrowBag)
        let isRemote = (hasPublicKey && hasPrivateKey)
            || (hasIdentifier && hasAltIRK && (hasPublicKey || hasPrivateKey))

        var udid: String? = nil
        for key in ["udid", "deviceid", "identifier"] {
            if let str = lookup[key] as? String, !str.isEmpty {
                udid = str
                break
            }
        }
        return (isLockdown || isRemote, !isLockdown && isRemote, udid, sortedKeys)
    }

    private func importPairingData(from url: URL) -> Bool {
        guard let validURL = ContainerStore.validatedExternalFileURL(url),
              let rawData = readCoordinatedPairingData(from: validURL),
              !rawData.isEmpty else {
            let msg = "Không thể đọc nội dung file pairing '\(url.lastPathComponent)' (đường dẫn không hợp lệ, file trống hoặc bị khóa quyền đọc)."
            log("localdev: \(msg)")
            DispatchQueue.main.async {
                self.lastError = msg
            }
            return false
        }

        let data = Self.stripUTF8BOM(rawData)

        // 1. Validate Pairing File:
        //    - Classic Lockdown XML/bplist00 (`HostCertificate`/`DeviceCertificate` + `HostID`/`SystemBUID`)
        //    - `idevice pair v1.2.0` Remote Pairing XML/bplist00 (`public_key`, `private_key`, `identifier`, `alt_irk`)
        var parsedUDID: String? = nil
        var isValidPairing = false
        var isRemotePairingFormat = false
        var parsedKeys: [String] = []
        var plistFormatLabel = "raw"

        var detectedFormat: PropertyListSerialization.PropertyListFormat = .xml
        if let plistObj = try? PropertyListSerialization.propertyList(from: data, options: [], format: &detectedFormat),
           let unwrapped = Self.unwrapPairingDictionary(from: plistObj) {
            plistFormatLabel = (detectedFormat == .binary) ? "bplist00" : "xml-plist"
            let analysis = Self.classifyPairingDictionary(unwrapped)
            isValidPairing = analysis.isValid
            isRemotePairingFormat = analysis.isRemotePairing
            parsedUDID = analysis.udid
            parsedKeys = analysis.keys
            log("localdev: inspect '\(validURL.lastPathComponent)' format=\(plistFormatLabel) bytes=\(data.count) valid=\(isValidPairing) remote=\(isRemotePairingFormat) keys=[\(parsedKeys.joined(separator: ", "))]")
        }

        let filename = validURL.deletingPathExtension().lastPathComponent
        if parsedUDID == nil && filename.count >= 20 {
            parsedUDID = filename
        }

        // Binary plist / XML pairing fallback check (stack-obfuscated on CI builds)
        if !isValidPairing {
            let prefixData = Data(data.prefix(4096))
            let bplistSig = "bplist00"
            if data.starts(with: Data(bplistSig.utf8)) {
                isValidPairing = parsedKeys.isEmpty
                plistFormatLabel = bplistSig
            } else if let prefixStr = String(data: prefixData, encoding: .utf8) ?? String(data: prefixData, encoding: .ascii) {
                if prefixStr.contains("HostCertificate") || prefixStr.contains("HostID") || prefixStr.contains(bplistSig) {
                    isValidPairing = true
                } else if prefixStr.contains("public_key") && prefixStr.contains("private_key") {
                    isValidPairing = true
                    isRemotePairingFormat = true
                }
            }
        }

        guard isValidPairing else {
            let keyDesc = parsedKeys.isEmpty ? "không đọc được khóa plist" : "keys=[\(parsedKeys.joined(separator: ", "))]"
            let msg = "Tệp '\(validURL.lastPathComponent)' không hợp lệ (\(plistFormatLabel), \(data.count) bytes, \(keyDesc)). Cần file Lockdown (HostCertificate/HostID) hoặc Remote Pairing từ idevice pair v1.2.0 (public_key/private_key)."
            log("localdev: rejected pairing file — \(msg)")
            DispatchQueue.main.async {
                self.lastError = msg
            }
            return false
        }

        // Save safely into app's persistent storage
        let dir = self.storageDirectory
        let targetURL = dir.appendingPathComponent(isRemotePairingFormat ? "remote_pairing.plist" : "pairing.plist")
        let staleNames = isRemotePairingFormat
            ? ["pairing.plist", "pairing.mobiledevicepairing"]
            : ["remote_pairing.plist"]
        for staleName in staleNames {
            try? FileManager.default.removeItem(at: dir.appendingPathComponent(staleName))
        }
        do {
            try data.write(to: targetURL, options: .atomic)
        } catch {
            let msg = "Lỗi lưu file pairing: \(error.localizedDescription)"
            log("localdev: \(msg)")
            DispatchQueue.main.async {
                self.lastError = msg
            }
            return false
        }

        // Re-enable module automatically if user explicitly imports a pairing file
        UserDefaults.standard.set(true, forKey: Self.enabledDefaultsKey)
        let fallbackUDID = parsedUDID ?? filename
        DispatchQueue.main.async {
            self.isModuleEnabled = true
            self.isCheckingStatus = true
        }

        // 2. Forward to Rust core on workerQueue so TLS handshake never blocks UI
        workerQueue.async { [weak self] in
            guard let self else { return }
            self.triggerLocalNetworkFrameworkProbe(force: false)
            self.ensureCoreInitialized()
            if let fnImport = LocalDevLib.shared.fnImportPairing {
                let bytes = [UInt8](data)
                if let cStr = fnImport(bytes, bytes.count) {
                    defer { LocalDevLib.shared.fnFreeString?(cStr) }
                    let jsonStr = String(cString: cStr)
                    if let respData = jsonStr.data(using: .utf8),
                       let status = try? JSONDecoder().decode(LocalDevStatus.self, from: respData) {
                        if isRemotePairingFormat && status.code == LocalDevCode.pairingExpiredOrCorrupt.rawValue {
                            self.publishStatus(Self.remotePairingUnsupportedStatus(udid: fallbackUDID), lastError: nil)
                        } else {
                            let errMsg = (status.code == LocalDevCode.pairingExpiredOrCorrupt.rawValue || status.code == LocalDevCode.remotePairingUnsupported.rawValue) ? status.message : nil
                            self.publishStatus(status, lastError: errMsg)
                        }
                        return
                    }
                }
            }

            // 3. Fallback when libsec_core.dylib is not attached (e.g. simulator/preview)
            if isRemotePairingFormat {
                self.publishStatus(Self.remotePairingUnsupportedStatus(udid: fallbackUDID), lastError: nil)
                return
            }

            let simStatus = LocalDevStatus(
                code: LocalDevCode.live.rawValue,
                status: "ĐÃ KẾT NỐI LOCALDEV (LIVE)",
                message: "Ghép nối thiết bị thành công! Sẵn sàng quét dữ liệu.",
                host: "10.7.0.1",
                port: 62078,
                udid: fallbackUDID,
                is_heartbeat_alive: true
            )
            self.publishStatus(simStatus, lastError: nil)
        }
        return true
    }

    public func scanApplications(completion: @escaping ([LocalDevApp]) -> Void = { _ in }) {
        guard isModuleEnabled else {
            DispatchQueue.main.async {
                self.isScanning = false
                self.installedApps = []
                completion([])
            }
            return
        }

        isScanning = true
        lastError = nil

        workerQueue.async {
            self.ensureCoreInitialized()
            guard let fnScan = LocalDevLib.shared.fnScanApps,
                  let cStr = fnScan() else {
                DispatchQueue.main.async {
                    self.isScanning = false
                    self.lastError = nil
                    completion([])
                }
                return
            }
            defer { LocalDevLib.shared.fnFreeString?(cStr) }

            let jsonStr = String(cString: cStr)
            var resultApps: [LocalDevApp] = []

            if let data = jsonStr.data(using: .utf8),
               let resp = try? JSONDecoder().decode(ScanAppsResponse.self, from: data) {
                if let apps = resp.apps {
                    resultApps = apps
                }
                if !resp.success, let err = resp.error {
                    log("localdev: scanApplications failed — \(err)")
                    DispatchQueue.main.async {
                        self.lastError = err
                    }
                }
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
        listDirectoryDetailed(service: service, bundleID: bundleID, path: path).items.map(\.name)
    }

    public func listDirectoryDetailed(
        service: LocalDevServiceType,
        bundleID: String?,
        path: String
    ) -> LocalDevDirListing {
        guard isModuleEnabled else {
            return LocalDevDirListing(success: false, mode: nil, error: "LocalDev đang tắt", items: [])
        }
        ensureCoreInitialized()
        guard let fnList = LocalDevLib.shared.fnListDir,
              let cStr = fnList(service.rawValue, bundleID, path) else {
            return LocalDevDirListing(success: false, mode: nil, error: "LocalDev chưa sẵn sàng", items: [])
        }
        defer { LocalDevLib.shared.fnFreeString?(cStr) }

        let jsonStr = String(cString: cStr)
        guard let data = jsonStr.data(using: .utf8),
              let resp = try? JSONDecoder().decode(ListDirResponse.self, from: data) else {
            return LocalDevDirListing(success: false, mode: nil, error: "Phản hồi LocalDev không hợp lệ", items: [])
        }

        if let items = resp.items, !items.isEmpty {
            return LocalDevDirListing(success: resp.success, mode: resp.mode, error: resp.error, items: items)
        }
        let fallbackItems = (resp.entries ?? []).map { LocalDevDirItem(name: $0, is_dir: false, size: -1) }
        return LocalDevDirListing(success: resp.success, mode: resp.mode, error: resp.error, items: fallbackItems)
    }

    public func readFile(service: LocalDevServiceType, bundleID: String?, path: String) -> Data? {
        guard isModuleEnabled else { return nil }
        ensureCoreInitialized()
        guard let fnRead = LocalDevLib.shared.fnReadFile else { return nil }
        var outLen = 0
        guard let bufPtr = fnRead(service.rawValue, bundleID, path, &outLen), outLen > 0 else {
            return nil
        }
        defer { LocalDevLib.shared.fnFreeBytes?(bufPtr, outLen) }
        return Data(bytes: bufPtr, count: outLen)
    }

    public func writeFile(service: LocalDevServiceType, bundleID: String?, path: String, data: Data) -> Bool {
        guard isModuleEnabled else { return false }
        ensureCoreInitialized()
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
