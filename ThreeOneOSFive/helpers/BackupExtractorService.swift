import Combine
import Foundation
import SQLite3

struct BackupExtractionResult {
    let bundleID: String
    let outputDirectoryURL: URL
    let zipArchiveURL: URL?
    let extractedFileCount: Int
    let totalBytes: Int64
    let warningMessage: String?
}

@MainActor
final class BackupExtractorService: ObservableObject {
    static let shared = BackupExtractorService()

    @Published private(set) var isRunning = false
    @Published private(set) var activeBundleID: String?
    @Published private(set) var statusText = ""
    @Published private(set) var filesReceived: UInt64 = 0
    @Published private(set) var bytesReceived: UInt64 = 0
    @Published private(set) var lastResult: BackupExtractionResult?
    @Published private(set) var errorMessage: String?

    private var pollTimer: Timer?

    private init() {}

    nonisolated static func extractsRootURL(fileManager: FileManager = .default) throws -> URL {
        let documents = try PatchWorkspaceService.documentsRootURL(fileManager: fileManager)
        let dir = documents.appendingPathComponent("BackupExtracts", isDirectory: true)
        try fileManager.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    func existingExtractedDirectory(for bundleID: String) -> URL? {
        guard let root = try? Self.extractsRootURL() else { return nil }
        let clean = sanitizedBundleSegment(bundleID)
        let dir = root.appendingPathComponent(clean, isDirectory: true)
        var isDir: ObjCBool = false
        if FileManager.default.fileExists(atPath: dir.path, isDirectory: &isDir), isDir.boolValue {
            return dir
        }
        return nil
    }

    func startExtraction(bundleID: String, createZip: Bool = true) {
        guard !isRunning else { return }
        let cleanBundle = bundleID.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !cleanBundle.isEmpty else { return }

        isRunning = true
        activeBundleID = cleanBundle
        statusText = "Đang khởi tạo kết nối com.apple.mobilebackup2 qua RSD..."
        filesReceived = 0
        bytesReceived = 0
        errorMessage = nil
        lastResult = nil
        startPollingProgress()

        DispatchQueue.global(qos: .userInitiated).async {
            let outcome = self.performExtractionSync(bundleID: cleanBundle, createZip: createZip)
            DispatchQueue.main.async {
                self.stopPollingProgress()
                self.isRunning = false
                switch outcome {
                case .success(let res):
                    self.lastResult = res
                    self.statusText = "Đã trích xuất \(res.extractedFileCount) tệp vào \(res.outputDirectoryURL.lastPathComponent)."
                    NotificationCenter.default.post(name: .airliftFilesChanged, object: nil)
                case .failure(let err):
                    self.errorMessage = err.localizedDescription
                    self.statusText = "Trích xuất thất bại"
                }
            }
        }
    }

    func cancel() {
        LocalDevBridge.shared.cancelBackupExtraction()
        statusText = "Đang dừng trích xuất Backup..."
    }

    private func startPollingProgress() {
        stopPollingProgress()
        pollTimer = Timer.scheduledTimer(withTimeInterval: 0.35, repeats: true) { [weak self] _ in
            guard let self else { return }
            guard let snap = LocalDevBridge.shared.currentBackupProgress() else { return }
            DispatchQueue.main.async {
                if self.isRunning {
                    if !snap.phase.isEmpty {
                        self.statusText = snap.phase
                    }
                    self.filesReceived = snap.files_received
                    self.bytesReceived = snap.bytes_received
                }
            }
        }
    }

    private func stopPollingProgress() {
        pollTimer?.invalidate()
        pollTimer = nil
    }

    private nonisolated func performExtractionSync(
        bundleID: String,
        createZip: Bool
    ) -> Result<BackupExtractionResult, NSError> {
        let fm = FileManager.default
        let cachesURL = fm.urls(for: .cachesDirectory, in: .userDomainMask).first
            ?? fm.temporaryDirectory
        let stagingRoot = cachesURL
            .appendingPathComponent("3105-MB2-Staging", isDirectory: true)
            .appendingPathComponent(sanitizedBundleSegment(bundleID), isDirectory: true)

        defer {
            // Reclaim non-target backup blobs cleanly once target domain is mapped
            try? fm.removeItem(at: stagingRoot)
        }

        do {
            if fm.fileExists(atPath: stagingRoot.path) {
                try? fm.removeItem(at: stagingRoot)
            }
            try fm.createDirectory(at: stagingRoot, withIntermediateDirectories: true)

            let freeBytes = availableDiskBytes(at: cachesURL)
            let mb2Result = LocalDevBridge.shared.extractBackupDomain(
                bundleID: bundleID,
                stagingDirectory: stagingRoot,
                freeBytes: freeBytes
            )

            switch mb2Result {
            case .failure(let err):
                return .failure(makeError(err.message))
            case .success(let report):
                let udidDir = URL(fileURLWithPath: report.staging_udid_dir, isDirectory: true)
                let manifestURL = report.manifest_db_path.map { URL(fileURLWithPath: $0) }
                    ?? udidDir.appendingPathComponent("Manifest.db")

                guard fm.fileExists(atPath: manifestURL.path) else {
                    return .failure(makeError(
                        "Không tìm thấy Manifest.db trong bản sao lưu (nhận \(report.files_received) tệp). Hãy đảm bảo máy không bật Encrypt local backup."
                    ))
                }

                let extractsRoot = try Self.extractsRootURL(fileManager: fm)
                let safeName = sanitizedBundleSegment(bundleID)
                let outputDir = extractsRoot.appendingPathComponent(safeName, isDirectory: true)
                let tempOutput = extractsRoot.appendingPathComponent(".\(safeName)-\(UUID().uuidString)", isDirectory: true)
                defer { try? fm.removeItem(at: tempOutput) }
                try fm.createDirectory(at: tempOutput, withIntermediateDirectories: true)

                let (count, copiedBytes, warning) = try extractDomainFilesFromManifest(
                    manifestURL: manifestURL,
                    backupRootDir: udidDir,
                    bundleID: bundleID,
                    destinationRoot: tempOutput
                )

                if fm.fileExists(atPath: outputDir.path) {
                    try fm.removeItem(at: outputDir)
                }
                try fm.moveItem(at: tempOutput, to: outputDir)

                var zipURL: URL?
                if createZip && count > 0 {
                    let candidateZip = extractsRoot.appendingPathComponent("\(safeName)-backup.zip")
                    if fm.fileExists(atPath: candidateZip.path) {
                        try? fm.removeItem(at: candidateZip)
                    }
                    if (try? ZIPArchiveWriter.write(items: [outputDir], to: candidateZip, fileManager: fm)) != nil {
                        zipURL = candidateZip
                    }
                }

                return .success(BackupExtractionResult(
                    bundleID: bundleID,
                    outputDirectoryURL: outputDir,
                    zipArchiveURL: zipURL,
                    extractedFileCount: count,
                    totalBytes: copiedBytes,
                    warningMessage: warning
                ))
            }
        } catch {
            return .failure(makeError(error.localizedDescription))
        }
    }

    private nonisolated func extractDomainFilesFromManifest(
        manifestURL: URL,
        backupRootDir: URL,
        bundleID: String,
        destinationRoot: URL
    ) throws -> (count: Int, bytes: Int64, warning: String?) {
        var db: OpaquePointer?
        guard sqlite3_open_v2(manifestURL.path, &db, SQLITE_OPEN_READONLY, nil) == SQLITE_OK,
              let db else {
            throw makeError("Không thể mở SQLite Manifest.db của bản sao lưu.")
        }
        defer { sqlite3_close(db) }

        let targetDomain = "AppDomain-\(bundleID)"
        let sql = """
        SELECT fileID, domain, relativePath, flags
        FROM Files
        WHERE domain = ?1 OR domain LIKE ?2
        ORDER BY relativePath ASC;
        """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK, let stmt else {
            let reason = String(cString: sqlite3_errmsg(db))
            throw makeError("Lỗi truy vấn Manifest.db: \(reason)")
        }
        defer { sqlite3_finalize(stmt) }

        let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
        sqlite3_bind_text(stmt, 1, targetDomain, -1, transient)
        sqlite3_bind_text(stmt, 2, "AppDomainGroup-%.\(bundleID)", -1, transient)

        let fm = FileManager.default
        var copiedCount = 0
        var copiedBytes: Int64 = 0
        var missingBlobs = 0

        while sqlite3_step(stmt) == SQLITE_ROW {
            guard let fidPtr = sqlite3_column_text(stmt, 0),
                  let domainPtr = sqlite3_column_text(stmt, 1),
                  let relPtr = sqlite3_column_text(stmt, 2) else {
                continue
            }
            let fileID = String(cString: fidPtr)
            let domain = String(cString: domainPtr)
            let relPath = String(cString: relPtr)
            let flags = sqlite3_column_int(stmt, 3)

            guard !relPath.isEmpty,
                  !relPath.hasPrefix("/"),
                  !relPath.contains("\\"),
                  !relPath.split(separator: "/").contains("..") else {
                continue
            }

            let baseDest = (domain == targetDomain)
                ? destinationRoot
                : destinationRoot.appendingPathComponent("AppGroups/\(sanitizedBundleSegment(domain))", isDirectory: true)
            let targetURL = baseDest.appendingPathComponent(relPath)

            if flags == 2 {
                try fm.createDirectory(at: targetURL, withIntermediateDirectories: true)
                continue
            }

            // Standard unencrypted iOS backup layout places file blobs under `<udid>/<fileID[0..2]>/<fileID>`
            let prefix = String(fileID.prefix(2))
            let hashedBlob = backupRootDir
                .appendingPathComponent(prefix, isDirectory: true)
                .appendingPathComponent(fileID)
            let directBlob = backupRootDir.appendingPathComponent(fileID)
            let sourceBlob: URL? = fm.fileExists(atPath: hashedBlob.path)
                ? hashedBlob
                : (fm.fileExists(atPath: directBlob.path) ? directBlob : nil)

            guard let sourceBlob else {
                missingBlobs += 1
                continue
            }

            try fm.createDirectory(at: targetURL.deletingLastPathComponent(), withIntermediateDirectories: true)
            if fm.fileExists(atPath: targetURL.path) {
                try fm.removeItem(at: targetURL)
            }
            try fm.copyItem(at: sourceBlob, to: targetURL)
            let fsize = (try? targetURL.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0
            copiedCount += 1
            copiedBytes += Int64(fsize)
        }

        let warning: String?
        if copiedCount == 0 {
            warning = "Ứng dụng \(bundleID) không có dữ liệu sao lưu hợp lệ (hoặc bị iTunes/iOS loại trừ khỏi bản backup)."
        } else if missingBlobs > 0 {
            warning = "Đã trích xuất \(copiedCount) tệp (\(missingBlobs) mục bị iOS loại trừ hoặc chỉ có ở trạng thái incremental)."
        } else {
            warning = nil
        }

        return (copiedCount, copiedBytes, warning)
    }

    private nonisolated func sanitizedBundleSegment(_ raw: String) -> String {
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: ".-_"))
        let cleaned = raw.unicodeScalars.map { allowed.contains($0) ? Character($0) : "_" }
        let s = String(cleaned)
        return s.isEmpty ? "app" : s
    }

    private nonisolated func availableDiskBytes(at url: URL) -> UInt64 {
        let vals = try? url.resourceValues(forKeys: [.volumeAvailableCapacityForImportantUsageKey])
        let cap = vals?.volumeAvailableCapacityForImportantUsage ?? 4 * 1024 * 1024 * 1024
        return UInt64(max(0, cap))
    }

    private nonisolated func makeError(_ message: String) -> NSError {
        NSError(domain: "com.phucvn.3105.mb2", code: -1, userInfo: [NSLocalizedDescriptionKey: message])
    }
}
