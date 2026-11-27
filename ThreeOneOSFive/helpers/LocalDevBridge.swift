import Foundation
import Network
import SwiftUI
import UIKit
import Darwin

// Dynamic C-ABI Loader for libsec_core.dylib
private typealias CLocalDevInit = @convention(c) (UnsafePointer<CChar>?, UnsafePointer<CChar>?, UInt16) -> Int32
private typealias CLocalDevNwPrewarmCallback = @convention(c) (UnsafePointer<CChar>?, UInt16) -> Int32
private typealias CLocalDevNwRelayConnectCallback = @convention(c) (UnsafePointer<CChar>?, UInt16, UInt32, UnsafeMutablePointer<Int32>?) -> Int32
private typealias CLocalDevRegisterNwCallbacks = @convention(c) (CLocalDevNwPrewarmCallback?, CLocalDevNwRelayConnectCallback?) -> Int32
private typealias CLocalDevSetCandidates = @convention(c) (UnsafePointer<CChar>?, Int32) -> Int32
private typealias CLocalDevImportPairing = @convention(c) (UnsafePointer<UInt8>, Int) -> UnsafePointer<CChar>?
private typealias CLocalDevStatus = @convention(c) () -> UnsafePointer<CChar>?
private typealias CLocalDevScanApps = @convention(c) () -> UnsafePointer<CChar>?
private typealias CLocalDevListDir = @convention(c) (Int32, UnsafePointer<CChar>?, UnsafePointer<CChar>) -> UnsafePointer<CChar>?
private typealias CLocalDevReadFile = @convention(c) (Int32, UnsafePointer<CChar>?, UnsafePointer<CChar>, UnsafeMutablePointer<Int>) -> UnsafeMutablePointer<UInt8>?
private typealias CLocalDevWriteFile = @convention(c) (Int32, UnsafePointer<CChar>?, UnsafePointer<CChar>, UnsafePointer<UInt8>, Int) -> UnsafePointer<CChar>?
private typealias CLocalDevMb2ExtractApp = @convention(c) (UnsafePointer<CChar>?, UnsafePointer<CChar>?, UInt64) -> UnsafePointer<CChar>?
private typealias CLocalDevMb2Status = @convention(c) () -> UnsafePointer<CChar>?
private typealias CLocalDevMb2Cancel = @convention(c) () -> Int32
private typealias CLocalDevFreeString = @convention(c) (UnsafePointer<CChar>?) -> Void
private typealias CLocalDevFreeBytes = @convention(c) (UnsafeMutablePointer<UInt8>?, Int) -> Void

private func localdevSwiftNwPrewarmTrampoline(_ hostPtr: UnsafePointer<CChar>?, _ port: UInt16) -> Int32 {
    let targetHost = hostPtr.flatMap { String(cString: $0) }
    let targetPort = port > 0 ? port : 49152
    let hosts = targetHost.flatMap { $0.isEmpty ? nil : [$0] }
    return LocalDevBridge.shared.prewarmLocalNetworkSynchronously(
        targetHosts: hosts,
        port: targetPort,
        force: true,
        openTcpProbe: true,
        timeoutMs: 1200
    )
}

private func localdevSwiftNwRelayConnectTrampoline(
    _ hostPtr: UnsafePointer<CChar>?,
    _ port: UInt16,
    _ timeoutMs: UInt32,
    _ errOut: UnsafeMutablePointer<Int32>?
) -> Int32 {
    guard let hostPtr else {
        errOut?.pointee = EINVAL
        return -1
    }
    let hostStr = String(cString: hostPtr)
    let resolvedPort = port > 0 ? port : 49152
    return NWConnectionRelaySession.connectBlocking(
        host: hostStr,
        port: resolvedPort,
        timeoutMs: timeoutMs,
        errOut: errOut
    )
}

/// Bridges an anonymous AF_UNIX socketpair FD to Apple `Network.framework` (`NWConnection`),
/// eliminating iOS 27+ NECP `EPERM / os error 1` blocks on loopback/tunnel POSIX sockets.
private final class NWConnectionRelaySession {
    private static let registryLock = NSLock()
    private static var activeSessions: [ObjectIdentifier: NWConnectionRelaySession] = [:]

    private let relayQueue: DispatchQueue
    private let connection: NWConnection
    private let relayFD: Int32
    private var readSource: DispatchSourceRead?
    private var isPumpingStarted = false
    private var isReadSuspended = false
    private var isClosed = false
    private var localDidFinishSending = false
    private var remoteDidFinishReceiving = false

    private init(connection: NWConnection, relayFD: Int32, queue: DispatchQueue) {
        self.connection = connection
        self.relayFD = relayFD
        self.relayQueue = queue
    }

    private static func retainSession(_ session: NWConnectionRelaySession) {
        registryLock.lock()
        activeSessions[ObjectIdentifier(session)] = session
        registryLock.unlock()
    }

    private static func releaseSession(_ session: NWConnectionRelaySession) {
        registryLock.lock()
        activeSessions.removeValue(forKey: ObjectIdentifier(session))
        registryLock.unlock()
    }

    static func extractPosixErrno(from error: NWError, path: NWPath?) -> Int32? {
        if #available(iOS 14.2, *),
           let path,
           path.status == .unsatisfied,
           path.unsatisfiedReason == .localNetworkDenied {
            return EPERM
        }
        switch error {
        case .posix(let code):
            return code.rawValue
        case .dns, .tls:
            return nil
        @unknown default:
            return nil
        }
    }

    static func connectBlocking(
        host: String,
        port: UInt16,
        timeoutMs: UInt32,
        errOut: UnsafeMutablePointer<Int32>?
    ) -> Int32 {
        guard !host.isEmpty, let nwPort = NWEndpoint.Port(rawValue: port) else {
            errOut?.pointee = EINVAL
            return -1
        }

        var fds: [Int32] = [-1, -1]
        guard Darwin.socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0,
              fds[0] >= 0, fds[1] >= 0 else {
            errOut?.pointee = errno > 0 ? errno : EIO
            return -1
        }
        let rustFD = fds[0]
        let relayFD = fds[1]

        var noSigPipe: Int32 = 1
        _ = Darwin.setsockopt(rustFD, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, socklen_t(MemoryLayout<Int32>.size))
        _ = Darwin.setsockopt(relayFD, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, socklen_t(MemoryLayout<Int32>.size))

        let existingFlags = Darwin.fcntl(relayFD, F_GETFL, 0)
        if existingFlags >= 0 {
            _ = Darwin.fcntl(relayFD, F_SETFL, existingFlags | O_NONBLOCK)
        }

        let tcpOptions = NWProtocolTCP.Options()
        tcpOptions.noDelay = true
        let params = NWParameters(tls: nil, tcp: tcpOptions)
        params.includePeerToPeer = true

        let conn = NWConnection(host: NWEndpoint.Host(host), port: nwPort, using: params)
        let queue = DispatchQueue(label: "3105.localdev.nwrelay.\(rustFD)", qos: .userInitiated)
        let session = NWConnectionRelaySession(connection: conn, relayFD: relayFD, queue: queue)

        let connectLock = NSLock()
        let semaphore = DispatchSemaphore(value: 0)
        var connectSettled = false
        var didBecomeReady = false
        var lastObservedErrno: Int32 = ETIMEDOUT
        var scheduledRefusedGrace = false

        conn.pathUpdateHandler = { path in
            if #available(iOS 14.2, *),
               path.status == .unsatisfied,
               path.unsatisfiedReason == .localNetworkDenied {
                connectLock.lock()
                lastObservedErrno = EPERM
                connectLock.unlock()
            }
        }

        conn.stateUpdateHandler = { state in
            switch state {
            case .ready:
                connectLock.lock()
                let alreadySettled = connectSettled
                if !alreadySettled {
                    connectSettled = true
                    didBecomeReady = true
                    Self.retainSession(session)
                    session.startPumpingOnQueue()
                }
                connectLock.unlock()
                if !alreadySettled {
                    semaphore.signal()
                    LocalDevBridge.shared.handleNWConnectionBecameReady(host: host, port: port)
                }
            case .waiting(let nwErr):
                let code = Self.extractPosixErrno(from: nwErr, path: conn.currentPath)
                connectLock.lock()
                if let code {
                    lastObservedErrno = code
                }
                let triggerGrace = (code == ECONNREFUSED) && !scheduledRefusedGrace && !connectSettled
                if triggerGrace {
                    scheduledRefusedGrace = true
                }
                connectLock.unlock()
                if triggerGrace {
                    queue.asyncAfter(deadline: .now() + 0.18) {
                        connectLock.lock()
                        let settleNow = !connectSettled
                        if settleNow {
                            connectSettled = true
                            didBecomeReady = false
                        }
                        connectLock.unlock()
                        if settleNow {
                            semaphore.signal()
                        }
                    }
                }
            case .failed(let nwErr):
                let code = Self.extractPosixErrno(from: nwErr, path: conn.currentPath) ?? ECONNREFUSED
                connectLock.lock()
                lastObservedErrno = code
                let alreadySettled = connectSettled
                if !alreadySettled {
                    connectSettled = true
                    didBecomeReady = false
                }
                connectLock.unlock()
                if !alreadySettled {
                    semaphore.signal()
                } else {
                    session.closeFromRelayQueue()
                }
            case .cancelled:
                connectLock.lock()
                let alreadySettled = connectSettled
                if !alreadySettled {
                    connectSettled = true
                    didBecomeReady = false
                }
                connectLock.unlock()
                if !alreadySettled {
                    semaphore.signal()
                } else {
                    session.closeFromRelayQueue()
                }
            default:
                break
            }
        }

        conn.start(queue: queue)
        let clampedMs = Int(min(max(timeoutMs, 250), 1500))
        _ = semaphore.wait(timeout: .now() + .milliseconds(clampedMs))

        connectLock.lock()
        if !connectSettled {
            connectSettled = true
        }
        let succeeded = didBecomeReady
        let finalErrno = lastObservedErrno
        connectLock.unlock()

        if succeeded {
            errOut?.pointee = 0
            return rustFD
        }

        conn.cancel()
        Darwin.close(rustFD)
        Darwin.close(relayFD)
        errOut?.pointee = finalErrno > 0 ? finalErrno : ETIMEDOUT
        return -1
    }

    private func startPumpingOnQueue() {
        isPumpingStarted = true
        let fd = relayFD
        let src = DispatchSource.makeReadSource(fileDescriptor: fd, queue: relayQueue)
        src.setCancelHandler {
            Darwin.close(fd)
        }
        src.setEventHandler { [weak self] in
            self?.handleRelayFDReadableOnQueue()
        }
        self.readSource = src
        src.resume()
        receiveFromNWConnectionOnQueue()
    }

    private func handleRelayFDReadableOnQueue() {
        guard !isClosed, let src = readSource else { return }
        var buf = [UInt8](repeating: 0, count: 65536)
        let n = buf.withUnsafeMutableBytes { ptr -> Int in
            guard let base = ptr.baseAddress else { return -1 }
            return Darwin.read(relayFD, base, 65536)
        }
        if n > 0 {
            let chunk = Data(buf[0..<n])
            if !isReadSuspended {
                src.suspend()
                isReadSuspended = true
            }
            connection.send(content: chunk, completion: .contentProcessed { [weak self] sendErr in
                guard let self else { return }
                if sendErr != nil {
                    self.closeFromRelayQueue()
                    return
                }
                if !self.isClosed, self.isReadSuspended, let activeSrc = self.readSource {
                    self.isReadSuspended = false
                    activeSrc.resume()
                }
            })
        } else if n == 0 {
            localDidFinishSending = true
            if !isReadSuspended {
                src.suspend()
                isReadSuspended = true
            }
            connection.send(
                content: nil,
                contentContext: .finalMessage,
                isComplete: true,
                completion: .contentProcessed { [weak self] _ in
                    guard let self else { return }
                    if self.remoteDidFinishReceiving {
                        self.closeFromRelayQueue()
                    } else {
                        self.relayQueue.asyncAfter(deadline: .now() + 0.5) { [weak self] in
                            self?.closeFromRelayQueue()
                        }
                    }
                }
            )
        } else {
            let err = errno
            if err == EINTR || err == EAGAIN || err == EWOULDBLOCK {
                return
            }
            closeFromRelayQueue()
        }
    }

    private func receiveFromNWConnectionOnQueue() {
        guard !isClosed else { return }
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] content, _, isComplete, error in
            guard let self, !self.isClosed else { return }
            if let data = content, !data.isEmpty {
                if !self.writeAllToRelayFD(data) {
                    self.closeFromRelayQueue()
                    return
                }
            }
            if error != nil {
                self.closeFromRelayQueue()
                return
            }
            if isComplete {
                self.remoteDidFinishReceiving = true
                _ = Darwin.shutdown(self.relayFD, SHUT_WR)
                if self.localDidFinishSending {
                    self.closeFromRelayQueue()
                }
                return
            }
            self.receiveFromNWConnectionOnQueue()
        }
    }

    private func writeAllToRelayFD(_ data: Data) -> Bool {
        return data.withUnsafeBytes { rawBuf -> Bool in
            guard let base = rawBuf.baseAddress else { return true }
            let bytes = base.assumingMemoryBound(to: UInt8.self)
            var offset = 0
            while offset < data.count {
                if isClosed { return false }
                let wrote = Darwin.write(relayFD, bytes.advanced(by: offset), data.count - offset)
                if wrote > 0 {
                    offset += wrote
                } else if wrote < 0 {
                    let err = errno
                    if err == EINTR {
                        continue
                    }
                    if err == EAGAIN || err == EWOULDBLOCK {
                        var pfd = pollfd(fd: relayFD, events: Int16(POLLOUT), revents: 0)
                        let pollRes = Darwin.poll(&pfd, 1, 200)
                        if pollRes < 0 && errno != EINTR {
                            return false
                        }
                        if (pfd.revents & Int16(POLLERR | POLLHUP | POLLNVAL)) != 0 {
                            return false
                        }
                        continue
                    }
                    return false
                } else {
                    return false
                }
            }
            return true
        }
    }

    private func closeFromRelayQueue() {
        guard isPumpingStarted, !isClosed else { return }
        isClosed = true
        if let src = readSource {
            if isReadSuspended {
                src.resume()
                isReadSuspended = false
            }
            readSource = nil
            src.cancel()
        }
        connection.cancel()
        Self.releaseSession(self)
    }
}

private final class LocalDevLib {
    static let shared = LocalDevLib()

    var fnInit: CLocalDevInit?
    var fnRegisterNwCallbacks: CLocalDevRegisterNwCallbacks?
    var fnSetCandidates: CLocalDevSetCandidates?
    var fnImportPairing: CLocalDevImportPairing?
    var fnStatus: CLocalDevStatus?
    var fnScanApps: CLocalDevScanApps?
    var fnListDir: CLocalDevListDir?
    var fnReadFile: CLocalDevReadFile?
    var fnWriteFile: CLocalDevWriteFile?
    var fnMb2ExtractApp: CLocalDevMb2ExtractApp?
    var fnMb2Status: CLocalDevMb2Status?
    var fnMb2Cancel: CLocalDevMb2Cancel?
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
        if let sym = dlsym(symTarget, "localdev_register_nw_callbacks") {
            fnRegisterNwCallbacks = unsafeBitCast(sym, to: CLocalDevRegisterNwCallbacks.self)
        }
        if let sym = dlsym(symTarget, "localdev_set_candidates") {
            fnSetCandidates = unsafeBitCast(sym, to: CLocalDevSetCandidates.self)
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
        if let sym = dlsym(symTarget, "localdev_mb2_extract_app") {
            fnMb2ExtractApp = unsafeBitCast(sym, to: CLocalDevMb2ExtractApp.self)
        }
        if let sym = dlsym(symTarget, "localdev_mb2_status") {
            fnMb2Status = unsafeBitCast(sym, to: CLocalDevMb2Status.self)
        }
        if let sym = dlsym(symTarget, "localdev_mb2_cancel") {
            fnMb2Cancel = unsafeBitCast(sym, to: CLocalDevMb2Cancel.self)
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

public struct LocalDevTunnelEndpoint: Codable, Hashable, Identifiable {
    public var id: String { "\(host):\(port)|\(iface ?? "")" }
    public let host: String
    public let port: UInt16
    public let iface: String?
    public let source: String?
}

public struct LocalDevStatus: Codable {
    public let code: Int
    public let status: String
    public let message: String
    public let host: String?
    public let port: UInt16?
    public let interface_name: String?
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
        default: return .orange
        }
    }

    public var accessBadgeTitle: String {
        switch access_type {
        case "FullContainer": return "Toàn quyền Container"
        case "DocumentsOnly": return "Chỉ Documents"
        default: return "Bị khóa Sandbox"
        }
    }

    public var accessBadgeIcon: String {
        switch access_type {
        case "FullContainer": return "lock.open.fill"
        case "DocumentsOnly": return "doc.text.fill"
        default: return "lock.fill"
        }
    }

    public var isSandboxLocked: Bool {
        access_type != "FullContainer" && access_type != "DocumentsOnly"
    }

    public var isAccessible: Bool {
        !isSandboxLocked
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

public struct LocalDevMb2Progress: Codable, Equatable {
    public let running: Bool
    public let phase: String
    public let files_received: UInt64
    public let bytes_received: UInt64
    public let last_path: String
    public let error: String?
}

public struct LocalDevMb2Report: Codable {
    public let udid: String
    public let bundle_id: String
    public let staging_udid_dir: String
    public let manifest_db_path: String?
    public let files_received: UInt64
    public let bytes_received: UInt64
}

private struct Mb2ExtractResponse: Codable {
    let success: Bool
    let error: String?
    let report: LocalDevMb2Report?
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
    @Published public var detectedTunnelEndpoints: [LocalDevTunnelEndpoint] = []
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
    private let probeLock = NSLock()
    private var _threadSafeStatus: LocalDevStatus
    private var isRefreshInFlight = false
    private var didTriggerLocalNetworkProbe = false
    private var didLogBundlePrefixNotice = false
    private var lastAutoRefreshUptime: TimeInterval = 0
    private var lastPrewarmUptime: TimeInterval = 0
    private var lastReadyRefreshUptime: TimeInterval = 0
    private var lastLocalNetworkState: Int32 = 0 // 1 = OK, -1 = Denied, 0 = Unknown
    private var lastLoggedDiscoveryKey: String = ""
    private let workerQueue = DispatchQueue(label: "com.phucvn.3105.localdev.worker", qos: .userInitiated)
    private let networkProbeQueue = DispatchQueue(label: "com.phucvn.3105.localdev.nwprobe", qos: .utility)
    private var activeProbeCancelWorkItem: DispatchWorkItem?
    private var activePathMonitor: NWPathMonitor?
    private var activeProbeListener: NWListener?
    private var activeProbeBrowsers: [NWBrowser] = []
    private var activeProbeConnections: [NWConnection] = []
    private var foregroundObserver: NSObjectProtocol?
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
            host: nil,
            port: defaultRemotePairingPort,
            interface_name: nil,
            udid: nil,
            is_heartbeat_alive: false
        )
    }

    public static let defaultRemotePairingPort: UInt16 = 49152

    private static func initialMissingPairingStatus() -> LocalDevStatus {
        LocalDevStatus(
            code: LocalDevCode.missingPairing.rawValue,
            status: "CHƯA CÓ PAIRING FILE",
            message: "Chưa nạp file ghép nối (Remote Pairing hoặc .mobiledevicepairing)",
            host: nil,
            port: defaultRemotePairingPort,
            interface_name: nil,
            udid: nil,
            is_heartbeat_alive: false
        )
    }

    private static func remotePairingNeededForRsdStatus(udid: String? = nil) -> LocalDevStatus {
        LocalDevStatus(
            code: LocalDevCode.remotePairingUnsupported.rawValue,
            status: "CẦN FILE REMOTE PAIRING CHO CỔNG 49152",
            message: "Phát hiện cổng RemotePairing/RSD 10.7.0.1:49152 đang mở. Hãy tạo & nhập file Remote Pairing từ idevice pair v1.2.0 (public_key / private_key / identifier / alt_irk), hoặc tắt LocalDev để dùng Sandbox & Nhật ký USB.",
            host: "10.7.0.1",
            port: defaultRemotePairingPort,
            interface_name: "RSD",
            udid: udid,
            is_heartbeat_alive: false
        )
    }

    private func detectPreferredTunnelPort() -> UInt16 {
        let dir = self.storageDirectory
        for fileName in ["remote_pairing.plist", "pairing.mobiledevicepairing", "pairing.plist"] {
            let fileURL = dir.appendingPathComponent(fileName)
            guard let data = try? Data(contentsOf: fileURL),
                  let parsed = Self.parsePairingObject(from: Self.stripUTF8BOM(data)).object,
                  let unwrapped = Self.unwrapPairingDictionary(from: parsed) else { continue }
            for key in ["tunnel_port", "tunnelPort", "RemotePairPort", "remote_pair_port", "rsd_port", "rsdPort", "port"] {
                if let portNum = Self.lookupPairingValue(unwrapped, keys: [key]) as? Int, portNum > 0 && portNum <= 65535 {
                    return UInt16(portNum)
                }
                if let portStr = Self.lookupPairingValue(unwrapped, keys: [key]) as? String,
                   let portNum = UInt16(portStr.trimmingCharacters(in: .whitespacesAndNewlines)),
                   portNum > 0 {
                    return portNum
                }
            }
        }
        return Self.defaultRemotePairingPort
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
                message: "Bundle ID '\(bundleID)' bắt đầu bằng 'com.apple.' nên iOS 26/27 ẩn công tắc Mạng cục bộ và chặn kết nối EPERM tới \(status.host ?? "tunnel"):\(status.port ?? Self.defaultRemotePairingPort). Hãy dùng Bundle ID riêng (com.phucvn.threeoneosfive).",
                host: status.host,
                port: status.port,
                interface_name: status.interface_name,
                udid: status.udid,
                is_heartbeat_alive: status.is_heartbeat_alive
            )
        } else {
            normalizedStatus = status
        }

        statusLock.lock()
        _threadSafeStatus = normalizedStatus
        statusLock.unlock()
        BackgroundKeepAliveManager.shared.setConnectionLive(isModuleEnabled && normalizedStatus.isLive)
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
        self.foregroundObserver = NotificationCenter.default.addObserver(
            forName: UIApplication.willEnterForegroundNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            self?.handleAppDidBecomeActive()
        }
        initCore()
    }

    private func ensureCoreInitialized() {
        coreInitLock.lock()
        defer { coreInitLock.unlock() }
        guard !isCoreInitialized else { return }
        LocalDevLib.shared.resolveSymbols()
        _ = LocalDevLib.shared.fnRegisterNwCallbacks?(
            localdevSwiftNwPrewarmTrampoline,
            localdevSwiftNwRelayConnectTrampoline
        )
        let preferredPort = detectPreferredTunnelPort()
        let candidates = detectTunnelEndpoints(port: preferredPort)
        syncCandidatesToCore(candidates)
        let path = storageDirectory.path
        let initialHost = candidates.first?.host ?? "10.7.0.1"
        _ = LocalDevLib.shared.fnInit?(path, initialHost, preferredPort)
        isCoreInitialized = true
    }

    private static func extractIPv4HostOrder(from saPtr: UnsafeMutablePointer<sockaddr>?) -> UInt32? {
        guard let saPtr, saPtr.pointee.sa_family == sa_family_t(AF_INET) else { return nil }
        var sin = sockaddr_in()
        let copyLen = saPtr.pointee.sa_len > 0
            ? min(Int(saPtr.pointee.sa_len), MemoryLayout<sockaddr_in>.size)
            : MemoryLayout<sockaddr_in>.size
        Darwin.memcpy(&sin, saPtr, copyLen)
        return UInt32(bigEndian: sin.sin_addr.s_addr)
    }

    private static func formatIPv4(_ hostOrder: UInt32) -> String {
        let a = (hostOrder >> 24) & 0xFF
        let b = (hostOrder >> 16) & 0xFF
        let c = (hostOrder >> 8) & 0xFF
        let d = hostOrder & 0xFF
        return "\(a).\(b).\(c).\(d)"
    }

    private static func isPrivateOrTunnelIPv4(_ ip: UInt32) -> Bool {
        if ip == 0 || (ip >> 24) == 127 || (ip >> 16) == 0xA9FE {
            return false
        }
        if (ip >> 24) == 10 { return true }
        if (ip & 0xFFF0_0000) == 0xAC10_0000 { return true }
        if (ip & 0xFFFF_0000) == 0xC0A8_0000 { return true }
        if (ip & 0xFFC0_0000) == 0x6440_0000 { return true }
        return false
    }

    private static func extractIPv6Bytes(from saPtr: UnsafeMutablePointer<sockaddr>?) -> [UInt8]? {
        guard let saPtr, saPtr.pointee.sa_family == sa_family_t(AF_INET6) else { return nil }
        var sin6 = sockaddr_in6()
        let copyLen = saPtr.pointee.sa_len > 0
            ? min(Int(saPtr.pointee.sa_len), MemoryLayout<sockaddr_in6>.size)
            : MemoryLayout<sockaddr_in6>.size
        Darwin.memcpy(&sin6, saPtr, copyLen)
        return withUnsafeBytes(of: sin6.sin6_addr) { Array($0) }
    }

    private static func formatIPv6(_ rawBytes: [UInt8], ifaceScope: String? = nil) -> String? {
        guard rawBytes.count == 16 else { return nil }
        var clean = rawBytes
        let isLinkLocal = (clean[0] == 0xFE && (clean[1] & 0xC0) == 0x80)
        // Strip Darwin KAME embedded scope index bytes [2..3] before formatting link-local address
        if isLinkLocal {
            clean[2] = 0
            clean[3] = 0
        }
        var addr = in6_addr()
        withUnsafeMutableBytes(of: &addr) { dst in
            clean.withUnsafeBytes { src in
                if let d = dst.baseAddress, let s = src.baseAddress {
                    Darwin.memcpy(d, s, 16)
                }
            }
        }
        var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        guard Darwin.inet_ntop(AF_INET6, &addr, &buf, socklen_t(buf.count)) != nil else {
            return nil
        }
        let baseStr = String(cString: buf)
        if isLinkLocal, let scope = ifaceScope, !scope.isEmpty {
            return "\(baseStr)%\(scope)"
        }
        return baseStr
    }

    private static func isTunnelOrPrivateIPv6(_ b: [UInt8]) -> Bool {
        guard b.count == 16 else { return false }
        let isAllZero = b.allSatisfy { $0 == 0 }
        let isLoopback = b[0..<15].allSatisfy { $0 == 0 } && b[15] == 1
        if isAllZero || isLoopback { return false }
        let isULA = (b[0] & 0xFE) == 0xFC // fc00::/7 includes fd... LocalDev/CDTunnel ULA
        let isLinkLocal = b[0] == 0xFE && (b[1] & 0xC0) == 0x80
        return isULA || isLinkLocal
    }

    /// Scans active `utun` interfaces via `getifaddrs()` (`IFF_UP | IFF_RUNNING`, IPv4 + IPv6 `fd...`/`fe80::%utunX` + `ifa_dstaddr`)
    /// and orders tunnel endpoints: `utun` IPv4 `dstaddr` -> `utun` peer / `10.7.0.1` & `10.7.0.0` -> `utun` IPv6 -> `127.0.0.1` fallback.
    @discardableResult
    public func detectTunnelEndpoints(port: UInt16 = LocalDevBridge.defaultRemotePairingPort) -> [LocalDevTunnelEndpoint] {
        var dstEndpoints: [LocalDevTunnelEndpoint] = []
        var gatewayEndpoints: [LocalDevTunnelEndpoint] = []
        var ipv6Endpoints: [LocalDevTunnelEndpoint] = []
        var preferred107Iface: String? = nil
        var utunSummaries: [String] = []

        var ifaddrPtr: UnsafeMutablePointer<ifaddrs>?
        if Darwin.getifaddrs(&ifaddrPtr) == 0, let firstAddr = ifaddrPtr {
            defer { Darwin.freeifaddrs(firstAddr) }
            var cursor: UnsafeMutablePointer<ifaddrs>? = firstAddr
            while let ptr = cursor {
                let ifa = ptr.pointee
                cursor = ifa.ifa_next

                let flags = Int32(ifa.ifa_flags)
                let isUpRunning = (flags & (IFF_UP | IFF_RUNNING)) == (IFF_UP | IFF_RUNNING)
                let isLoopback = (flags & IFF_LOOPBACK) != 0
                guard isUpRunning, !isLoopback, let cName = ifa.ifa_name else { continue }
                let name = String(cString: cName)
                guard name.hasPrefix("utun") else { continue }

                if let sa = ifa.ifa_addr, sa.pointee.sa_family == sa_family_t(AF_INET6) {
                    if let localV6 = Self.extractIPv6Bytes(from: sa), Self.isTunnelOrPrivateIPv6(localV6) {
                        let isULA = (localV6[0] & 0xFE) == 0xFC
                        if let localV6Str = Self.formatIPv6(localV6, ifaceScope: name) {
                            utunSummaries.append("\(name)(v6:\(localV6Str))")
                        }
                        if (flags & IFF_POINTOPOINT) != 0,
                           let dstV6 = Self.extractIPv6Bytes(from: ifa.ifa_dstaddr),
                           Self.isTunnelOrPrivateIPv6(dstV6),
                           dstV6 != localV6,
                           let dstV6Str = Self.formatIPv6(dstV6, ifaceScope: name) {
                            ipv6Endpoints.append(LocalDevTunnelEndpoint(
                                host: dstV6Str,
                                port: port,
                                iface: name,
                                source: isULA ? "utun-v6-ula-dst" : "utun-v6-ll-dst"
                            ))
                        }
                        if isULA && (localV6[14] != 0 || localV6[15] != 1) {
                            var peerV6 = localV6
                            peerV6[14] = 0
                            peerV6[15] = 1
                            if let peerV6Str = Self.formatIPv6(peerV6, ifaceScope: name) {
                                ipv6Endpoints.append(LocalDevTunnelEndpoint(
                                    host: peerV6Str,
                                    port: port,
                                    iface: name,
                                    source: "utun-v6-ula-peer"
                                ))
                            }
                        }
                        if let localV6Str = Self.formatIPv6(localV6, ifaceScope: name) {
                            ipv6Endpoints.append(LocalDevTunnelEndpoint(
                                host: localV6Str,
                                port: port,
                                iface: name,
                                source: isULA ? "utun-v6-ula" : "utun-v6-ll"
                            ))
                        }
                    }
                    continue
                }

                guard let localIP = Self.extractIPv4HostOrder(from: ifa.ifa_addr),
                      Self.isPrivateOrTunnelIPv4(localIP) else { continue }

                let localStr = Self.formatIPv4(localIP)
                let is107Range = (localIP & 0xFFFF_0000) == 0x0A07_0000
                if is107Range && preferred107Iface == nil {
                    preferred107Iface = name
                }

                var dstStrForLog = "none"
                if (flags & IFF_POINTOPOINT) != 0,
                   let dstIP = Self.extractIPv4HostOrder(from: ifa.ifa_dstaddr),
                   dstIP != 0,
                   (dstIP >> 24) != 127,
                   dstIP != localIP {
                    let dstStr = Self.formatIPv4(dstIP)
                    dstStrForLog = dstStr
                    dstEndpoints.append(LocalDevTunnelEndpoint(
                        host: dstStr,
                        port: port,
                        iface: name,
                        source: "utun-dstaddr"
                    ))
                }

                let maskIP = Self.extractIPv4HostOrder(from: ifa.ifa_netmask)
                let effectiveMask: UInt32 = {
                    if let m = maskIP, m != 0, m != 0xFFFF_FFFF, (m & 0xFFFF_0000) == 0xFFFF_0000 {
                        return m
                    }
                    return 0xFFFF_FF00
                }()
                let netBase = localIP & effectiveMask
                let peerIP = netBase | 1
                if peerIP != localIP && peerIP != 0 {
                    gatewayEndpoints.append(LocalDevTunnelEndpoint(
                        host: Self.formatIPv4(peerIP),
                        port: port,
                        iface: name,
                        source: "utun-peer"
                    ))
                }
                if is107Range {
                    gatewayEndpoints.append(LocalDevTunnelEndpoint(
                        host: "10.7.0.1",
                        port: port,
                        iface: name,
                        source: "utun-localdev"
                    ))
                    gatewayEndpoints.append(LocalDevTunnelEndpoint(
                        host: "10.7.0.0",
                        port: port,
                        iface: name,
                        source: "utun-subnet"
                    ))
                }
                utunSummaries.append("\(name)(\(localStr)->\(dstStrForLog))")
            }
        }

        // Prioritize LocalDevVPN 10.7.x endpoints ahead of non-10.7 system `utun` interfaces
        dstEndpoints.sort { ($0.host.hasPrefix("10.7.") ? 0 : 1) < ($1.host.hasPrefix("10.7.") ? 0 : 1) }
        gatewayEndpoints.sort { ($0.host.hasPrefix("10.7.") ? 0 : 1) < ($1.host.hasPrefix("10.7.") ? 0 : 1) }
        ipv6Endpoints.sort { ($0.host.hasPrefix("fd") ? 0 : 1) < ($1.host.hasPrefix("fd") ? 0 : 1) }

        var rawOrdered: [LocalDevTunnelEndpoint] = []
        rawOrdered.append(contentsOf: dstEndpoints)
        rawOrdered.append(contentsOf: gatewayEndpoints)
        rawOrdered.append(LocalDevTunnelEndpoint(host: "10.7.0.1", port: port, iface: preferred107Iface, source: "standard-localdev"))
        rawOrdered.append(LocalDevTunnelEndpoint(host: "10.7.0.0", port: port, iface: preferred107Iface, source: "standard-localdev"))
        rawOrdered.append(contentsOf: ipv6Endpoints)
        rawOrdered.append(LocalDevTunnelEndpoint(host: "127.0.0.1", port: port, iface: "lo0", source: "loopback-fallback"))

        var deduplicated: [LocalDevTunnelEndpoint] = []
        var seenKeys: Set<String> = []
        for item in rawOrdered {
            let k = "\(item.host):\(item.port)"
            if seenKeys.insert(k).inserted {
                deduplicated.append(item)
            }
        }

        let summaryKey = "\(utunSummaries.joined(separator: ","))|\(deduplicated.map { "\($0.host):\($0.port)@\($0.iface ?? "-")" }.joined(separator: ","))"
        probeLock.lock()
        let changed = (summaryKey != lastLoggedDiscoveryKey)
        if changed {
            lastLoggedDiscoveryKey = summaryKey
        }
        probeLock.unlock()
        if changed {
            let utunDesc = utunSummaries.isEmpty ? "none" : utunSummaries.joined(separator: ", ")
            let candDesc = deduplicated.map { "\($0.host):\($0.port)[\($0.iface ?? $0.source ?? "-")]" }.joined(separator: " -> ")
            log("localdev: getifaddrs utun=[\(utunDesc)] candidates=[\(candDesc)]")
        }

        DispatchQueue.main.async {
            self.detectedTunnelEndpoints = deduplicated
        }
        return deduplicated
    }

    private func syncCandidatesToCore(_ candidates: [LocalDevTunnelEndpoint]) {
        LocalDevLib.shared.resolveSymbols()
        guard let fnSet = LocalDevLib.shared.fnSetCandidates,
              let data = try? JSONEncoder().encode(candidates),
              let jsonStr = String(data: data, encoding: .utf8) else { return }
        probeLock.lock()
        let netState = lastLocalNetworkState
        probeLock.unlock()
        _ = jsonStr.withCString { ptr in
            fnSet(ptr, netState)
        }
    }

    private func logStatusIfChanged(_ status: LocalDevStatus) {
        let key = "\(status.code)|\(status.status)|\(status.message)"
        guard key != lastLoggedStatusKey else { return }
        lastLoggedStatusKey = key
        log("localdev: code=\(status.code) [\(status.status)] — \(status.message)")
    }

    /// Pre-warms iOS Local Network NECP policy using `Network.framework` (`NWPathMonitor` + `NWListener` + `NWBrowser` on declared `NSBonjourServices`).
    /// Only opens an active TCP `NWConnection` probe when `openTcpProbe == true` (avoiding throwaway connect+RST on port `62078` before Rust handshake).
    @discardableResult
    public func prewarmLocalNetworkSynchronously(
        targetHosts: [String]? = nil,
        port: UInt16 = LocalDevBridge.defaultRemotePairingPort,
        force: Bool = false,
        openTcpProbe: Bool = false,
        timeoutMs: Int = 1500
    ) -> Int32 {
        let now = ProcessInfo.processInfo.systemUptime
        probeLock.lock()
        if didTriggerLocalNetworkProbe && !force {
            probeLock.unlock()
            return 1
        }
        if force && (now - lastPrewarmUptime) < 0.6 {
            let cachedState = lastLocalNetworkState
            probeLock.unlock()
            Thread.sleep(forTimeInterval: 0.15)
            return cachedState
        }
        didTriggerLocalNetworkProbe = true
        lastPrewarmUptime = now
        probeLock.unlock()

        if !didLogBundlePrefixNotice,
           let bundleID = Bundle.main.bundleIdentifier,
           bundleID.hasPrefix("com.apple.") {
            didLogBundlePrefixNotice = true
            log("localdev: bundleID '\(bundleID)' starts with 'com.apple.' — iOS 26/27 Settings may hide Local Network toggle for Apple-prefixed bundle IDs")
        }

        let probeTargets: [String] = {
            if let explicit = targetHosts, !explicit.isEmpty {
                return explicit
            }
            let nonLoopback = detectTunnelEndpoints(port: port)
                .map(\.host)
                .filter { $0 != "127.0.0.1" }
            return nonLoopback.isEmpty ? ["10.7.0.1", "10.7.0.0"] : Array(nonLoopback.prefix(3))
        }()

        let semaphore = DispatchSemaphore(value: 0)
        let settleLock = NSLock()
        var settled = false
        var outcome: Int32 = 0 // 1 = ready/satisfied, -1 = EPERM denied, 0 = inconclusive
        var sawBrowserReady = false
        var sawExplicitDenial = false

        let settle: (Int32, Bool, UInt16, String?) -> Void = { code, becameReady, readyPort, readyHost in
            settleLock.lock()
            let already = settled
            if !already {
                settled = true
                outcome = code
            }
            settleLock.unlock()
            if !already {
                semaphore.signal()
            }
            if becameReady, let readyHost {
                self.handleNWConnectionBecameReady(host: readyHost, port: readyPort)
            }
        }

        networkProbeQueue.async { [weak self] in
            guard let self else {
                settle(0, false, port, nil)
                return
            }

            self.cancelActiveNetworkProbeOnProbeQueue()

            // 1. Monitor path state & iOS localNetworkDenied telemetry
            let monitor = NWPathMonitor()
            monitor.pathUpdateHandler = { path in
                if #available(iOS 14.2, *), path.status == .unsatisfied, path.unsatisfiedReason == .localNetworkDenied {
                    log("localdev: NWPathMonitor reported localNetworkDenied")
                    settleLock.lock()
                    sawExplicitDenial = true
                    settleLock.unlock()
                    self.probeLock.lock()
                    self.lastLocalNetworkState = -1
                    self.probeLock.unlock()
                    settle(-1, false, port, nil)
                }
            }
            monitor.start(queue: self.networkProbeQueue)
            self.activePathMonitor = monitor

            // 2. Advertise `_lockdown._tcp` via NWListener (declared in Info.plist NSBonjourServices)
            let listenerParams = NWParameters.tcp
            listenerParams.includePeerToPeer = true
            if let listener = try? NWListener(using: listenerParams) {
                listener.service = NWListener.Service(type: "_lockdown._tcp")
                listener.stateUpdateHandler = { state in
                    if case .failed(let err) = state {
                        log("localdev: NWListener failed (\(String(describing: err)))")
                    }
                }
                listener.newConnectionHandler = { conn in
                    conn.cancel()
                }
                listener.start(queue: self.networkProbeQueue)
                self.activeProbeListener = listener
            }

            // 3. Browse all declared NSBonjourServices to confirm Local Network permission & trigger NECP
            let bonjourTypes = [
                "_apple-mobdev2._tcp",
                "_remotepairing._tcp",
                "_lockdown._tcp",
                "_localdev._tcp"
            ]
            var browsers: [NWBrowser] = []
            for serviceType in bonjourTypes {
                let browserParams = NWParameters.tcp
                browserParams.includePeerToPeer = true
                let browser = NWBrowser(for: .bonjour(type: serviceType, domain: nil), using: browserParams)
                browser.stateUpdateHandler = { state in
                    switch state {
                    case .ready:
                        settleLock.lock()
                        sawBrowserReady = true
                        let denied = sawExplicitDenial
                        settleLock.unlock()
                        if !denied {
                            self.probeLock.lock()
                            self.lastLocalNetworkState = 1
                            self.probeLock.unlock()
                        }
                        if serviceType == "_apple-mobdev2._tcp" || serviceType == "_remotepairing._tcp" {
                            log("localdev: NWBrowser(\(serviceType)) ready")
                        }
                        if !openTcpProbe && !denied {
                            settle(1, false, port, nil)
                        }
                    case .waiting(let err):
                        if case .posix(let code) = err, code == .EPERM {
                            log("localdev: NWBrowser(\(serviceType)) waiting EPERM")
                            settleLock.lock()
                            sawExplicitDenial = true
                            settleLock.unlock()
                            self.probeLock.lock()
                            self.lastLocalNetworkState = -1
                            self.probeLock.unlock()
                            settle(-1, false, port, nil)
                        }
                    case .failed(let err):
                        log("localdev: NWBrowser(\(serviceType)) failed (\(String(describing: err)))")
                    default:
                        break
                    }
                }
                browser.browseResultsChangedHandler = { _, _ in }
                browser.start(queue: self.networkProbeQueue)
                browsers.append(browser)
            }
            self.activeProbeBrowsers = browsers

            // 4. NWConnection TCP probe only when explicitly requested (`openTcpProbe == true`) so normal refresh doesn't abort sockets on 62078
            if openTcpProbe, let nwPort = NWEndpoint.Port(rawValue: port) {
                var conns: [NWConnection] = []
                for probeHost in probeTargets {
                    let tcpOptions = NWProtocolTCP.Options()
                    tcpOptions.noDelay = true
                    let connParams = NWParameters(tls: nil, tcp: tcpOptions)
                    connParams.includePeerToPeer = true
                    let conn = NWConnection(host: NWEndpoint.Host(probeHost), port: nwPort, using: connParams)
                    conn.stateUpdateHandler = { state in
                        switch state {
                        case .ready:
                            log("localdev: NWConnection(\(probeHost):\(port)) ready")
                            self.probeLock.lock()
                            self.lastLocalNetworkState = 1
                            self.probeLock.unlock()
                            conn.cancel()
                            settle(1, true, port, probeHost)
                        case .waiting(let nwErr):
                            if let code = NWConnectionRelaySession.extractPosixErrno(from: nwErr, path: conn.currentPath) {
                                if #available(iOS 14.2, *),
                                   let path = conn.currentPath,
                                   path.status == .unsatisfied,
                                   path.unsatisfiedReason == .localNetworkDenied {
                                    self.probeLock.lock()
                                    self.lastLocalNetworkState = -1
                                    self.probeLock.unlock()
                                    log("localdev: NWConnection(\(probeHost):\(port)) localNetworkDenied")
                                    settle(-1, false, port, nil)
                                } else {
                                    log("localdev: NWConnection(\(probeHost):\(port)) waiting errno=\(code)")
                                }
                            }
                        case .failed(let nwErr):
                            log("localdev: NWConnection(\(probeHost):\(port)) failed (\(String(describing: nwErr)))")
                        default:
                            break
                        }
                    }
                    conn.start(queue: self.networkProbeQueue)
                    conns.append(conn)
                }
                self.activeProbeConnections = conns
            }

            let workItem = DispatchWorkItem { [weak self] in
                settleLock.lock()
                let confirmed = sawBrowserReady && !sawExplicitDenial
                settleLock.unlock()
                settle(confirmed ? 1 : 0, false, port, nil)
                self?.cancelActiveNetworkProbeOnProbeQueue()
            }
            self.activeProbeCancelWorkItem = workItem
            self.networkProbeQueue.asyncAfter(deadline: .now() + .milliseconds(max(timeoutMs, 300)), execute: workItem)
        }

        _ = semaphore.wait(timeout: .now() + .milliseconds(max(timeoutMs, 300) + 150))
        networkProbeQueue.async { [weak self] in
            self?.activeProbeConnections.forEach { $0.cancel() }
            self?.activeProbeConnections.removeAll()
        }
        return outcome
    }

    fileprivate func handleNWConnectionBecameReady(host: String, port: UInt16) {
        let now = ProcessInfo.processInfo.systemUptime
        statusLock.lock()
        let currentCode = _threadSafeStatus.code
        let refreshRunning = isRefreshInFlight
        let recentlyTriggered = (now - lastReadyRefreshUptime) < 1.0
        let shouldAutoRefresh = isModuleEnabled
            && !refreshRunning
            && !recentlyTriggered
            && currentCode != LocalDevCode.live.rawValue
            && currentCode != LocalDevCode.disabled.rawValue
        if shouldAutoRefresh {
            lastReadyRefreshUptime = now
        }
        statusLock.unlock()

        if shouldAutoRefresh {
            log("localdev: NWConnection(\(host):\(port)) .ready -> refreshing UI status")
            DispatchQueue.main.async {
                self.refreshStatus(force: false)
            }
        }
    }

    private func cancelActiveNetworkProbeOnProbeQueue() {
        activeProbeCancelWorkItem?.cancel()
        activeProbeCancelWorkItem = nil
        activePathMonitor?.cancel()
        activePathMonitor = nil
        activeProbeListener?.cancel()
        activeProbeListener = nil
        activeProbeBrowsers.forEach { $0.cancel() }
        activeProbeBrowsers.removeAll()
        activeProbeConnections.forEach { $0.cancel() }
        activeProbeConnections.removeAll()
    }

    public func requestLocalNetworkPermission() {
        guard isModuleEnabled else { return }
        statusLock.lock()
        if isRefreshInFlight {
            statusLock.unlock()
            return
        }
        isRefreshInFlight = true
        statusLock.unlock()

        DispatchQueue.main.async {
            self.isCheckingStatus = true
        }
        workerQueue.async { [weak self] in
            guard let self else { return }
            let preferredPort = self.detectPreferredTunnelPort()
            let candidates = self.detectTunnelEndpoints(port: preferredPort)
            let targets = candidates.map(\.host).filter { $0 != "127.0.0.1" }
            _ = self.prewarmLocalNetworkSynchronously(
                targetHosts: targets.isEmpty ? ["10.7.0.1", "10.7.0.0"] : targets,
                port: preferredPort,
                force: true,
                openTcpProbe: true,
                timeoutMs: 1500
            )
            self.refreshStatusOnWorkerQueue(forcePrewarm: false, precomputedCandidates: candidates)
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
            let preferredPort = self.detectPreferredTunnelPort()
            let candidates = self.detectTunnelEndpoints(port: preferredPort)
            let targets = candidates.map(\.host).filter { $0 != "127.0.0.1" }
            _ = self.prewarmLocalNetworkSynchronously(
                targetHosts: targets.isEmpty ? ["10.7.0.1", "10.7.0.0"] : targets,
                port: preferredPort,
                force: true,
                timeoutMs: 1500
            )
            self.ensureCoreInitialized()
            self.syncCandidatesToCore(candidates)
            if !self.autoDiscoverPairingFiles() {
                self.refreshStatusOnWorkerQueue(forcePrewarm: false, precomputedCandidates: candidates)
            }
        }
    }

    public func initCore() {
        DispatchQueue.global(qos: .utility).async { [weak self] in
            guard let self else { return }
            guard self.isModuleEnabled else { return }
            self.workerQueue.async {
                guard self.isModuleEnabled else { return }
                let preferredPort = self.detectPreferredTunnelPort()
                let candidates = self.detectTunnelEndpoints(port: preferredPort)
                let targets = candidates.map(\.host).filter { $0 != "127.0.0.1" }
                _ = self.prewarmLocalNetworkSynchronously(
                    targetHosts: targets.isEmpty ? ["10.7.0.1", "10.7.0.0"] : targets,
                    port: preferredPort,
                    force: false,
                    timeoutMs: 1500
                )
                self.ensureCoreInitialized()
                self.syncCandidatesToCore(candidates)
                if !self.autoDiscoverPairingFiles() {
                    self.refreshStatusOnWorkerQueue(forcePrewarm: false, precomputedCandidates: candidates)
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
                if fileExt == "mobiledevicepairing" || fileExt == "plist" || fileExt == "pairing" || fileExt == "json",
                   let validURL = ContainerStore.validatedExternalFileURL(file, requireExists: true) {
                    if (fileExt == "plist" || fileExt == "json") && !Self.looksLikePairingFile(at: validURL) {
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
            self.refreshStatusOnWorkerQueue(forcePrewarm: force || wasDenied)
        }
    }

    private func refreshStatusOnWorkerQueue(
        forcePrewarm: Bool,
        precomputedCandidates: [LocalDevTunnelEndpoint]? = nil
    ) {
        statusLock.lock()
        isRefreshInFlight = true
        let wasDenied = (_threadSafeStatus.code == LocalDevCode.localNetworkDenied.rawValue)
        statusLock.unlock()

        defer {
            statusLock.lock()
            isRefreshInFlight = false
            statusLock.unlock()
        }

        guard isModuleEnabled else {
            publishStatus(Self.disabledStatus(), lastError: nil)
            return
        }

        let preferredPort = detectPreferredTunnelPort()
        let candidates = precomputedCandidates ?? detectTunnelEndpoints(port: preferredPort)
        let nonLoopbackTargets = candidates.map(\.host).filter { $0 != "127.0.0.1" }
        _ = prewarmLocalNetworkSynchronously(
            targetHosts: nonLoopbackTargets.isEmpty ? ["10.7.0.1", "10.7.0.0"] : nonLoopbackTargets,
            port: preferredPort,
            force: forcePrewarm || wasDenied,
            timeoutMs: 1500
        )
        ensureCoreInitialized()
        syncCandidatesToCore(candidates)
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
            publishStatus(status, lastError: preservedError)
        } else {
            DispatchQueue.main.async { self.isCheckingStatus = false }
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
                host: nil,
                port: Self.defaultRemotePairingPort,
                interface_name: nil,
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
        let prefix = handle.readData(ofLength: 65536)
        guard !prefix.isEmpty else { return false }
        let normalized = Self.stripUTF8BOM(prefix)
        if let parsedObj = Self.parsePairingObject(from: normalized).object,
           let unwrapped = Self.unwrapPairingDictionary(from: parsedObj) {
            let analysis = Self.classifyPairingDictionary(unwrapped)
            if analysis.isValid { return true }
        }
        if let str = String(data: normalized, encoding: .utf8) ?? String(data: normalized, encoding: .ascii) {
            let lower = str.lowercased()
            if lower.contains("hostcertificate")
                || lower.contains("hostid")
                || lower.contains("public_key")
                || lower.contains("publickey")
                || lower.contains("private_key")
                || lower.contains("privatekey")
                || lower.contains("alt_irk")
                || lower.contains("altirk")
                || lower.contains("remotepairing") {
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

    private static func normalizePairingKey(_ key: String) -> String {
        key.lowercased()
            .replacingOccurrences(of: "_", with: "")
            .replacingOccurrences(of: "-", with: "")
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private static func lookupPairingValue(_ dict: [String: Any], keys: [String]) -> Any? {
        for key in keys {
            if let v = dict[key] { return v }
        }
        let targets = Set(keys.map(normalizePairingKey))
        for (k, v) in dict {
            if targets.contains(normalizePairingKey(k)) {
                return v
            }
        }
        return nil
    }

    private static func parsePairingObject(from data: Data) -> (object: Any?, formatLabel: String) {
        if let firstByte = data.first(where: { $0 != 0x20 && $0 != 0x09 && $0 != 0x0A && $0 != 0x0D }),
           firstByte == 0x7B || firstByte == 0x5B {
            if let jsonObj = try? JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed]) {
                return (jsonObj, "json")
            }
        }

        var format: PropertyListSerialization.PropertyListFormat = .xml
        if let plistObj = try? PropertyListSerialization.propertyList(from: data, options: [], format: &format) {
            let label = (format == .binary) ? "bplist00" : "xml-plist"
            return (plistObj, label)
        }

        if let jsonObj = try? JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed]) {
            return (jsonObj, "json")
        }
        return (nil, "raw")
    }

    private static let pairingKnownMarkers: Set<String> = [
        "hostcertificate", "devicecertificate", "rootcertificate",
        "hostprivatekey", "rootprivatekey", "deviceprivatekey",
        "hostid", "systembuid", "escrowbag", "wifimacaddress",
        "publickey", "ed25519publickey", "hostpublickey",
        "privatekey", "ed25519privatekey", "secretkey",
        "altirk", "irk", "identifier", "hostidentifier"
    ]

    private static func unwrapPairingDictionary(from rawObject: Any, depth: Int = 0) -> [String: Any]? {
        guard depth < 5, let dict = rawObject as? [String: Any] else { return nil }
        let normalizedKeys = Set(dict.keys.map(normalizePairingKey))
        if !normalizedKeys.isDisjoint(with: pairingKnownMarkers) {
            return dict
        }
        let wrapperKeys = ["PairRecord", "PairingRecord", "pairingRecord", "pairing_record", "RemotePairing", "remotePairing", "remote_pairing", "pairing", "record", "data", "identity"]
        if let nested = lookupPairingValue(dict, keys: wrapperKeys),
           let found = unwrapPairingDictionary(from: nested, depth: depth + 1) {
            return found
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
            dict.map { (normalizePairingKey($0.key), $0.value) },
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

        let hasPublicKey = lookup["publickey"] != nil || lookup["ed25519publickey"] != nil || lookup["hostpublickey"] != nil
        let hasPrivateKey = lookup["privatekey"] != nil || lookup["ed25519privatekey"] != nil || lookup["secretkey"] != nil
        let hasIdentifier = lookup["identifier"] != nil || lookup["hostidentifier"] != nil
        let hasAltIRK = lookup["altirk"] != nil || lookup["irk"] != nil

        let isLockdown = (hasHostCert || hasDeviceCert || hasRootCert || hasHostPriv)
            && (hasHostID || hasSystemBUID || hasHostCert || hasEscrowBag)
        let isRemote = (hasPrivateKey && (hasPublicKey || hasIdentifier || hasAltIRK))
            || (hasPublicKey && hasPrivateKey)
            || (hasIdentifier && hasAltIRK && (hasPublicKey || hasPrivateKey))

        var udid: String? = nil
        for key in ["udid", "uniquedeviceid", "deviceid", "pairedudid", "identifier", "hostidentifier"] {
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
        //    - `idevice pair v1.2.0` Remote Pairing (XML/bplist00/JSON: `public_key`/`PublicKey`, `private_key`/`PrivateKey`, `identifier`/`Identifier`, `alt_irk`/`AltIRK`)
        //    - Classic Lockdown X.509 (`HostCertificate`/`DeviceCertificate` + `HostID`/`SystemBUID`)
        var parsedUDID: String? = nil
        var isValidPairing = false
        var isRemotePairingFormat = false
        var parsedKeys: [String] = []
        let parsedDoc = Self.parsePairingObject(from: data)
        var plistFormatLabel = parsedDoc.formatLabel

        if let parsedObj = parsedDoc.object,
           let unwrapped = Self.unwrapPairingDictionary(from: parsedObj) {
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

        // Binary plist / XML / JSON pairing fallback check (stack-obfuscated on CI builds)
        if !isValidPairing {
            let prefixData = Data(data.prefix(8192))
            let bplistSig = "bplist00"
            if data.starts(with: Data(bplistSig.utf8)) {
                isValidPairing = parsedKeys.isEmpty
                plistFormatLabel = bplistSig
            } else if let prefixStr = String(data: prefixData, encoding: .utf8) ?? String(data: prefixData, encoding: .ascii) {
                let lower = prefixStr.lowercased()
                if prefixStr.contains("HostCertificate") || prefixStr.contains("HostID") || prefixStr.contains(bplistSig) {
                    isValidPairing = true
                } else if (lower.contains("public_key") || lower.contains("publickey"))
                    && (lower.contains("private_key") || lower.contains("privatekey")) {
                    isValidPairing = true
                    isRemotePairingFormat = true
                }
            }
        }

        guard isValidPairing else {
            let keyDesc = parsedKeys.isEmpty ? "không đọc được khóa plist/json" : "keys=[\(parsedKeys.joined(separator: ", "))]"
            let msg = "Tệp '\(validURL.lastPathComponent)' không hợp lệ (\(plistFormatLabel), \(data.count) bytes, \(keyDesc)). Cần file Remote Pairing từ idevice pair v1.2.0 (Plist/JSON có public_key, private_key, identifier, alt_irk) hoặc file Lockdown (HostCertificate/HostID)."
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

        // 2. Forward to Rust core on workerQueue so TLS/RPPairing/RSD handshake never blocks UI
        workerQueue.async { [weak self] in
            guard let self else { return }
            let preferredPort = self.detectPreferredTunnelPort()
            let candidates = self.detectTunnelEndpoints(port: preferredPort)
            let nonLoopback = candidates.map(\.host).filter { $0 != "127.0.0.1" }
            _ = self.prewarmLocalNetworkSynchronously(
                targetHosts: nonLoopback.isEmpty ? ["10.7.0.1", "10.7.0.0"] : nonLoopback,
                port: preferredPort,
                force: false,
                timeoutMs: 1500
            )
            self.ensureCoreInitialized()
            self.syncCandidatesToCore(candidates)
            if let fnImport = LocalDevLib.shared.fnImportPairing {
                let bytes = [UInt8](data)
                if let cStr = fnImport(bytes, bytes.count) {
                    defer { LocalDevLib.shared.fnFreeString?(cStr) }
                    let jsonStr = String(cString: cStr)
                    if let respData = jsonStr.data(using: .utf8),
                       let status = try? JSONDecoder().decode(LocalDevStatus.self, from: respData) {
                        let errMsg = (status.code == LocalDevCode.pairingExpiredOrCorrupt.rawValue || status.code == LocalDevCode.remotePairingUnsupported.rawValue) ? status.message : nil
                        self.publishStatus(status, lastError: errMsg)
                        return
                    }
                }
            }

            // 3. Fallback when libsec_core.dylib is not attached (e.g. simulator/preview)
            let simStatus = LocalDevStatus(
                code: LocalDevCode.live.rawValue,
                status: "LOCALDEV LIVE",
                message: isRemotePairingFormat
                    ? "Ghép nối RemotePairing/RSD thành công! Sẵn sàng quét dữ liệu."
                    : "Ghép nối thiết bị thành công! Sẵn sàng quét dữ liệu.",
                host: "10.7.0.1",
                port: preferredPort,
                interface_name: isRemotePairingFormat ? "utun4 · RSD" : "utun4",
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
            let keepAliveToken = BackgroundKeepAliveManager.shared.beginWorkToken()
            defer { BackgroundKeepAliveManager.shared.endWorkToken(keepAliveToken) }
            let preferredPort = self.detectPreferredTunnelPort()
            let candidates = self.detectTunnelEndpoints(port: preferredPort)
            self.ensureCoreInitialized()
            self.syncCandidatesToCore(candidates)
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
                if resp.success {
                    log("localdev: scanApplications -> \(resultApps.count) apps")
                } else if let err = resp.error {
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
        let keepAliveToken = BackgroundKeepAliveManager.shared.beginWorkToken()
        defer { BackgroundKeepAliveManager.shared.endWorkToken(keepAliveToken) }
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
        let keepAliveToken = BackgroundKeepAliveManager.shared.beginWorkToken()
        defer { BackgroundKeepAliveManager.shared.endWorkToken(keepAliveToken) }
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
        let keepAliveToken = BackgroundKeepAliveManager.shared.beginWorkToken()
        defer { BackgroundKeepAliveManager.shared.endWorkToken(keepAliveToken) }
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

    public func extractBackupDomain(
        bundleID: String,
        stagingDirectory: URL,
        freeBytes: UInt64
    ) -> Result<LocalDevMb2Report, String> {
        guard isModuleEnabled else {
            return .failure("LocalDev đang tắt — hãy bật LocalDevVPN & Pairing để dùng mobilebackup2.")
        }
        let keepAliveToken = BackgroundKeepAliveManager.shared.beginWorkToken()
        defer { BackgroundKeepAliveManager.shared.endWorkToken(keepAliveToken) }
        ensureCoreInitialized()
        guard let fnExtract = LocalDevLib.shared.fnMb2ExtractApp,
              let cStr = fnExtract(bundleID, stagingDirectory.path, freeBytes) else {
            return .failure("Chức năng mobilebackup2 chưa sẵn sàng trong libsec_core.")
        }
        defer { LocalDevLib.shared.fnFreeString?(cStr) }
        let jsonStr = String(cString: cStr)
        guard let data = jsonStr.data(using: .utf8),
              let resp = try? JSONDecoder().decode(Mb2ExtractResponse.self, from: data) else {
            return .failure("Phản hồi mobilebackup2 không hợp lệ")
        }
        if resp.success, let report = resp.report {
            return .success(report)
        }
        return .failure(resp.error ?? "Trích xuất mobilebackup2 thất bại")
    }

    public func currentBackupProgress() -> LocalDevMb2Progress? {
        ensureCoreInitialized()
        guard let fnStatus = LocalDevLib.shared.fnMb2Status,
              let cStr = fnStatus() else {
            return nil
        }
        defer { LocalDevLib.shared.fnFreeString?(cStr) }
        let jsonStr = String(cString: cStr)
        guard let data = jsonStr.data(using: .utf8) else { return nil }
        return try? JSONDecoder().decode(LocalDevMb2Progress.self, from: data)
    }

    public func cancelBackupExtraction() {
        ensureCoreInitialized()
        _ = LocalDevLib.shared.fnMb2Cancel?()
    }
}
