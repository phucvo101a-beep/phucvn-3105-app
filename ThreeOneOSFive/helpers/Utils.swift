import Foundation
import UIKit
import Darwin
import Combine
import OSLog

// MARK: - Global logger
class AppLog: ObservableObject {
    static let shared = AppLog()
    @Published var entries: [String] = []

    private static let maxInMemoryEntries = 2_000
    private static let maxLogFileBytes: UInt64 = 512 * 1_024
    private let logger = Logger(
        subsystem: Bundle.main.bundleIdentifier ?? "com.phucvn.3105",
        category: "runtime"
    )
    private let fileQueue = DispatchQueue(label: "com.phucvn.3105.applog.file", qos: .utility)

    var diagnosticsDirectoryURL: URL? {
        guard let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first else {
            return nil
        }
        let dir = docs.appendingPathComponent("3105-Diagnostics", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    var sessionLogFileURL: URL? {
        diagnosticsDirectoryURL?.appendingPathComponent("session-latest.log")
    }

    var environmentFileURL: URL? {
        diagnosticsDirectoryURL?.appendingPathComponent("environment.json")
    }

    func append(_ msg: String) {
        let sanitized = Self.sanitizeForDiagnostics(msg)
        guard !sanitized.isEmpty else { return }

        let timestamp = Self.isoTimestamp()
        let fileLine = "[\(timestamp)] \(sanitized)\n"
        logger.notice("\(sanitized, privacy: .public)")

        fileQueue.async { [weak self] in
            self?.appendLineToDisk(fileLine)
        }

        DispatchQueue.main.async {
            self.entries.append(sanitized)
            if self.entries.count > Self.maxInMemoryEntries {
                self.entries.removeFirst(self.entries.count - Self.maxInMemoryEntries)
            }
        }
    }

    func writeDiagnosticsSnapshot(extra: [String: String] = [:]) {
        let homePath = NSHomeDirectory()
        let docsPath = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first?.path ?? ""
        let cachesPath = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask).first?.path ?? ""
        let fileSharingEnabled = (Bundle.main.object(forInfoDictionaryKey: "UIFileSharingEnabled") as? Bool) ?? false
        let openInPlaceEnabled = (Bundle.main.object(forInfoDictionaryKey: "LSSupportsOpeningDocumentsInPlace") as? Bool) ?? false

        var payload: [String: Any] = [
            "generated_at": Self.isoTimestamp(),
            "bundle_id": Bundle.main.bundleIdentifier ?? "",
            "app_version": (Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String) ?? "",
            "app_build": (Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String) ?? "",
            "ios_version": AppInfo.osVersion,
            "ios_build": AppInfo.osBuild,
            "machine": AppInfo.displayMachineName,
            "sandbox_home": homePath,
            "documents_path": docsPath,
            "caches_path": cachesPath,
            "ui_file_sharing_enabled": fileSharingEnabled,
            "open_documents_in_place": openInPlaceEnabled,
            "access_mode": ContainerStore.accessModeDescription,
            "privileged_container_access": ContainerStore.hasPrivilegedContainerAccess(),
            "kernel_exploit_applicable": ExploitSupportPolicy.supportsKernelExploit(
                major: AppInfo.versionTuple.major,
                minor: AppInfo.versionTuple.minor,
                patch: AppInfo.versionTuple.patch
            ),
            "localdev_code": LocalDevBridge.shared.currentStatus.code,
            "localdev_status": LocalDevBridge.shared.currentStatus.status
        ]
        for (k, v) in extra {
            payload[k] = Self.sanitizeForDiagnostics(v)
        }

        fileQueue.async { [weak self] in
            guard let url = self?.environmentFileURL,
                  let data = try? JSONSerialization.data(withJSONObject: payload, options: [.prettyPrinted, .sortedKeys]) else {
                return
            }
            try? data.write(to: url, options: .atomic)
        }
    }

    private func appendLineToDisk(_ line: String) {
        guard let url = sessionLogFileURL,
              let data = line.data(using: .utf8) else { return }

        let fm = FileManager.default
        if let attrs = try? fm.attributesOfItem(atPath: url.path),
           let size = attrs[.size] as? UInt64,
           size >= Self.maxLogFileBytes,
           let dir = diagnosticsDirectoryURL {
            let previousURL = dir.appendingPathComponent("session-previous.log")
            try? fm.removeItem(at: previousURL)
            try? fm.moveItem(at: url, to: previousURL)
        }

        if !fm.fileExists(atPath: url.path) {
            fm.createFile(atPath: url.path, contents: data, attributes: nil)
            return
        }

        guard let handle = try? FileHandle(forWritingTo: url) else { return }
        defer { try? handle.close() }
        _ = try? handle.seekToEnd()
        try? handle.write(contentsOf: data)
    }

    private static func sanitizeForDiagnostics(_ raw: String) -> String {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return "" }
        // Never persist potential license keys or runtime session tickets into shared diagnostics.
        if trimmed.contains("PHUCVN-") || trimmed.localizedCaseInsensitiveContains("ticket=") {
            return "[3105] [redacted sensitive diagnostic line]"
        }
        return trimmed
    }

    private static func isoTimestamp() -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.string(from: Date())
    }
}

func log(_ msg: String) { AppLog.shared.append("[3105] \(msg)") }

// Retain the pipe for the app's lifetime so stdout/stderr stay redirected.
private var logCapturePipe: Pipe?

// Redirect stdout/stderr (C printf / NSLog) into the in-app log view and USB diagnostics mirror.
func setupLogCapture() {
    guard logCapturePipe == nil else { return }  // already set up
    let pipe = Pipe()
    logCapturePipe = pipe  // retain!

    setvbuf(stdout, nil, _IONBF, 0)
    setvbuf(stderr, nil, _IONBF, 0)
    let writeFd = pipe.fileHandleForWriting.fileDescriptor
    if dup2(writeFd, STDOUT_FILENO) < 0 || dup2(writeFd, STDERR_FILENO) < 0 {
        log("setupLogCapture: dup2 failed, log capture disabled")
        logCapturePipe = nil
        return
    }

    pipe.fileHandleForReading.readabilityHandler = { handle in
        let data = handle.availableData
        guard !data.isEmpty else { return }
        if let text = String(data: data, encoding: .utf8) {
            for line in text.components(separatedBy: .newlines) {
                let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
                if !trimmed.isEmpty {
                    AppLog.shared.append(trimmed)
                }
            }
        }
    }
}

// MARK: - App Info
enum AppInfo {
    static var osVersion: String {
        let v = ProcessInfo.processInfo.operatingSystemVersion
        return "\(v.majorVersion).\(v.minorVersion).\(v.patchVersion)"
    }
    static var versionTuple: (major: Int, minor: Int, patch: Int) {
        let v = ProcessInfo.processInfo.operatingSystemVersion
        return (v.majorVersion, v.minorVersion, v.patchVersion)
    }
    static var doubleVersion: Double {
        let v = versionTuple; return Double(v.major) + Double(v.minor) / 10.0
    }
    static var osBuild: String {
        var size: size_t = 0
        guard sysctlbyname("kern.osversion", nil, &size, nil, 0) == 0, size > 0 else {
            return "Không rõ"
        }
        var value = [CChar](repeating: 0, count: size)
        guard sysctlbyname("kern.osversion", &value, &size, nil, 0) == 0 else {
            return "Không rõ"
        }
        return String(cString: value)
    }
    static var machineName: String {
        var s = utsname(); uname(&s)
        return Mirror(reflecting: s.machine).children.reduce("") { id, e in
            guard let v = e.value as? Int8, v != 0 else { return id }
            return id + String(UnicodeScalar(UInt8(v)))
        }
    }
    static var displayMachineName: String {
#if targetEnvironment(simulator)
        return ProcessInfo.processInfo.environment["SIMULATOR_MODEL_IDENTIFIER"] ?? machineName
#else
        return machineName
#endif
    }
    static var hardwareDisplayName: String {
        switch displayMachineName {
        case "iPhone12,1": return "iPhone 11"
        case "iPhone15,2": return "iPhone 14 Pro"
        case "iPhone15,3": return "iPhone 14 Pro Max"
        default: return displayMachineName
        }
    }
    static var isHomeButton: Bool {
        let sel = NSSelectorFromString("_hasHomeButton")
        return UIDevice.responds(to: sel) && (UIDevice.perform(sel)?.takeUnretainedValue() as? Bool ?? false)
    }
}

// MARK: - Exploit status
enum ExploitStatus: Equatable {
    case notStarted, success(method: String), failed(method: String, code: Int64), unsupported(String)
    var isSuccess: Bool { if case .success = self { return true }; return false }
    var isFailed: Bool { if case .failed = self { return true }; return false }
    var displayText: String {
        switch self {
        case .notStarted: return "Chưa thực hiện"
        case .success(let m): return "Thành công qua \(m)"
        case .failed(let m, let c): return "Thất bại qua \(m) (\(c))"
        case .unsupported(let m): return "Không hỗ trợ: \(m)"
        }
    }
}

enum AppPaths {
    static var backups: String {
        let u = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
        let b = u.appendingPathComponent("backups", isDirectory: true)
        try? FileManager.default.createDirectory(at: b, withIntermediateDirectories: true)
        return b.path
    }

    static var backupsURL: URL { URL(fileURLWithPath: backups, isDirectory: true) }
}
