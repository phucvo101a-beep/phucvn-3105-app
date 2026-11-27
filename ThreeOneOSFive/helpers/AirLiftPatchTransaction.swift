import CryptoKit
import Darwin
import Foundation

/// Describes a single target file mutation within an `AirLiftPatchTransaction`.
struct AirLiftPatchWriteDescriptor: Codable, Identifiable, Equatable {
    let ruleID: UUID
    let bundleID: String
    let relativePath: String
    let replacementFilename: String
    let replacementData: Data
    let replacementDigest: Data

    var id: UUID { ruleID }

    static func makeDescriptors(
        from project: PatchProject
    ) throws -> (
        directories: [(bundleID: String, relativePath: String)],
        descriptors: [AirLiftPatchWriteDescriptor]
    ) {
        guard !project.rules.isEmpty || !project.directories.isEmpty else {
            throw PatchPackageError.invalidProject
        }

        var requestedDirectories = Set<String>()
        for directory in project.directories {
            let bundleID = try PatchPathValidator.canonicalBundleIdentifier(directory.bundleID)
            guard bundleID == directory.bundleID else { throw PatchPackageError.invalidProject }
            let relPath = try PatchPathValidator.canonicalRelativePath(directory.relativePath)
            requestedDirectories.insert(bundleID + "\0" + relPath)
        }

        var seenTargets = Set<String>()
        var descriptors: [AirLiftPatchWriteDescriptor] = []
        descriptors.reserveCapacity(project.rules.count)

        for rule in project.rules {
            let bundleID = try PatchPathValidator.canonicalBundleIdentifier(rule.bundleID)
            guard bundleID == rule.bundleID else { throw PatchPackageError.invalidProject }
            let relPath = try PatchPathValidator.canonicalRelativePath(rule.relativePath)
            let dedupeKey = bundleID + "\0" + relPath
            guard seenTargets.insert(dedupeKey).inserted else {
                throw PatchPackageError.duplicateTarget
            }

            let components = relPath.split(separator: "/").map(String.init)
            if components.count > 1 {
                for count in 1..<components.count {
                    requestedDirectories.insert(
                        bundleID + "\0" + components.prefix(count).joined(separator: "/")
                    )
                }
            }

            let digestData = Data(SHA256.hash(data: rule.replacementData))
            descriptors.append(
                AirLiftPatchWriteDescriptor(
                    ruleID: rule.id,
                    bundleID: bundleID,
                    relativePath: relPath,
                    replacementFilename: rule.replacementFilename,
                    replacementData: rule.replacementData,
                    replacementDigest: digestData
                )
            )
        }

        let sortedDirectories: [(bundleID: String, relativePath: String)] = try requestedDirectories
            .sorted { lhs, rhs in
                let leftDepth = lhs.filter { $0 == "/" }.count
                let rightDepth = rhs.filter { $0 == "/" }.count
                return leftDepth == rightDepth ? lhs < rhs : leftDepth < rightDepth
            }
            .map { key in
                let parts = key.split(separator: "\0", maxSplits: 1, omittingEmptySubsequences: false)
                guard parts.count == 2 else { throw PatchPackageError.invalidProject }
                return (String(parts[0]), String(parts[1]))
            }

        return (sortedDirectories, descriptors)
    }
}

struct AirLiftPatchDirectoryRecord: Codable, Equatable {
    let bundleID: String
    let relativePath: String
}

struct AirLiftPatchBackupEntry: Codable, Equatable {
    let ruleID: UUID
    let bundleID: String
    let relativePath: String
    let originalExisted: Bool
    let backupRelativePath: String?
    let originalDigest: Data?
    let replacementDigest: Data
    let replacementByteCount: Int
    let backend: String
    let fallbackUsed: Bool
    let fallbackReason: String?
    let dataContainerURL: String?
    let appGroupIdentifiers: [String]
}

struct AirLiftPatchBackupManifest: Codable, Equatable {
    enum Status: String, Codable {
        case prepared
        case applied
        case rolledBack
        case restored
    }

    let schemaVersion: Int
    let transactionID: UUID
    let projectID: UUID
    let projectName: String
    let createdAt: Date
    let timestampTag: String
    let isRemoteTransaction: Bool
    let backupDirectoryName: String
    var status: Status
    let createdDirectories: [AirLiftPatchDirectoryRecord]
    let entries: [AirLiftPatchBackupEntry]
}

struct AirLiftDiscardedBackupSummary: Identifiable, Equatable {
    var id: String { directoryURL.path }
    let directoryURL: URL
    let manifest: AirLiftPatchBackupManifest
}

enum AirLiftPatchError: Error, LocalizedError {
    case localDevUnavailable(String)
    case sandboxLockedRequiresBackup(bundleID: String, detail: String)
    case settleCheckFailed(bundleID: String, relativePath: String, reason: String)
    case discardedBackupMissing(String)

    var errorDescription: String? {
        switch self {
        case .localDevUnavailable(let detail):
            return "LocalDev / RSD chưa sẵn sàng: \(detail)"
        case .sandboxLockedRequiresBackup(let bundleID, let detail):
            return "Ứng dụng '\(bundleID)' bị khóa Sandbox bởi iOS (CoreDevice FileService và HouseArrest đều bị từ chối: \(detail)). Hãy bật UIFileSharingEnabled bằng Công cụ IPA hoặc Trích xuất dữ liệu qua Backup (mobilebackup2)."
        case .settleCheckFailed(let bundleID, let relPath, let reason):
            return "Xác nhận ghi tệp (settle check) thất bại cho \(bundleID)/\(relPath): \(reason). Đã tự động hoàn tác bản gốc."
        case .discardedBackupMissing(let name):
            return "Không tìm thấy bản sao lưu gốc tại \(name)."
        }
    }
}

/// Manages `AirLiftPatchWriteDescriptor` transactions with automatic `.DiscardedPatchBackups-<timestamp>`
/// backup snapshots in `Documents` and read-back SHA-256 settle checks over CoreDevice FileService / HouseArrest / AFC
/// as well as local filesystem containers.
enum AirLiftPatchTransaction {
    static let discardedBackupPrefix = ".DiscardedPatchBackups-"
    private static let manifestFilename = "airlift_manifest.plist"
    private static let remoteReceiptMarkerFilename = "airlift_receipt.plist"
    private static let settleMaxAttempts = 3
    private static let settleRetryDelays: [TimeInterval] = [0.05, 0.12, 0.25]

    private struct RemoteReceiptMarker: Codable {
        let schemaVersion: Int
        let transactionID: UUID
        let projectID: UUID
        let createdAt: Date
        var status: AirLiftPatchBackupManifest.Status
        let backupDirectoryURLPath: String
        let bundleIdentifiers: [String]
    }

    // MARK: - Discarded Backups Directory Helpers

    static func discardedBackupsParentURL(fileManager: FileManager = .default) throws -> URL {
        try PatchWorkspaceService.documentsRootURL(fileManager: fileManager)
    }

    static func createDiscardedBackupDirectory(
        timestamp: Date = Date(),
        transactionID: UUID,
        documentsRoot: URL? = nil,
        fileManager: FileManager = .default
    ) throws -> (directoryURL: URL, timestampTag: String) {
        let root = try documentsRoot ?? discardedBackupsParentURL(fileManager: fileManager)
        try fileManager.createDirectory(at: root, withIntermediateDirectories: true)

        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyyMMdd-HHmmss"
        let tag = "\(formatter.string(from: timestamp))-\(transactionID.uuidString.prefix(8))"
        let folderName = "\(discardedBackupPrefix)\(tag)"
        let url = root.appendingPathComponent(folderName, isDirectory: true)
        try fileManager.createDirectory(at: url, withIntermediateDirectories: true)
        return (url, tag)
    }

    static func listDiscardedBackups(
        documentsRoot: URL? = nil,
        fileManager: FileManager = .default
    ) -> [AirLiftDiscardedBackupSummary] {
        guard let root = try? (documentsRoot ?? discardedBackupsParentURL(fileManager: fileManager)),
              let children = try? fileManager.contentsOfDirectory(
                  at: root,
                  includingPropertiesForKeys: [.isDirectoryKey],
                  options: []
              ) else {
            return []
        }

        var results: [AirLiftDiscardedBackupSummary] = []
        for child in children where child.lastPathComponent.hasPrefix(discardedBackupPrefix) {
            let manifestURL = child.appendingPathComponent(manifestFilename)
            if let manifest = try? readManifest(at: manifestURL) {
                results.append(AirLiftDiscardedBackupSummary(directoryURL: child, manifest: manifest))
            }
        }
        return results.sorted { $0.manifest.createdAt > $1.manifest.createdAt }
    }

    /// Mirrors local backups into `Documents/.DiscardedPatchBackups-<timestamp>` and runs SHA-256 settle check
    /// when `PatchTransaction` executes against writable local filesystem containers.
    static func mirrorLocalTransactionBackupAndSettle(
        project: PatchProject,
        receipt: PatchTransactionReceipt,
        roots: [String: URL],
        descriptors: [AirLiftPatchWriteDescriptor],
        documentsRoot: URL? = nil,
        fileManager: FileManager = .default
    ) throws {
        let (backupDir, timestampTag) = try createDiscardedBackupDirectory(
            transactionID: receipt.id,
            documentsRoot: documentsRoot,
            fileManager: fileManager
        )
        let srcTxDir = receipt.journalURL.deletingLastPathComponent()
        var entries: [AirLiftPatchBackupEntry] = []

        for desc in descriptors {
            let originalFile = srcTxDir.appendingPathComponent("\(desc.ruleID.uuidString).original")
            let originalExisted = fileManager.fileExists(atPath: originalFile.path)
            var backupRel: String?
            var origDigest: Data?

            if originalExisted {
                let rel = "originals/\(safePathSegment(desc.bundleID))/\(desc.ruleID.uuidString).original"
                let dst = backupDir.appendingPathComponent(rel)
                try fileManager.createDirectory(at: dst.deletingLastPathComponent(), withIntermediateDirectories: true)
                let origData = try Data(contentsOf: originalFile)
                try origData.write(to: dst, options: .atomic)
                origDigest = Data(SHA256.hash(data: origData))
                backupRel = rel
            }

            // Settle check against local container target
            if let root = roots[desc.bundleID] {
                let target = try PatchPathValidator.resolveContainedTargetURL(
                    relativePath: desc.relativePath,
                    containerRoot: root
                )
                try verifyLocalSettleCheck(
                    target: target,
                    bundleID: desc.bundleID,
                    relativePath: desc.relativePath,
                    expectedDigest: desc.replacementDigest,
                    expectedCount: desc.replacementData.count,
                    fileManager: fileManager
                )
            }

            entries.append(
                AirLiftPatchBackupEntry(
                    ruleID: desc.ruleID,
                    bundleID: desc.bundleID,
                    relativePath: desc.relativePath,
                    originalExisted: originalExisted,
                    backupRelativePath: backupRel,
                    originalDigest: origDigest,
                    replacementDigest: desc.replacementDigest,
                    replacementByteCount: desc.replacementData.count,
                    backend: "local_filesystem",
                    fallbackUsed: false,
                    fallbackReason: nil,
                    dataContainerURL: roots[desc.bundleID]?.path,
                    appGroupIdentifiers: []
                )
            )
        }

        let manifest = AirLiftPatchBackupManifest(
            schemaVersion: 1,
            transactionID: receipt.id,
            projectID: project.id,
            projectName: project.name,
            createdAt: Date(),
            timestampTag: timestampTag,
            isRemoteTransaction: false,
            backupDirectoryName: backupDir.lastPathComponent,
            status: .applied,
            createdDirectories: [],
            entries: entries
        )
        try writeManifest(manifest, to: backupDir.appendingPathComponent(manifestFilename))
    }

    // MARK: - Remote AirLift Transaction Apply (CoreDevice FileService -> HouseArrest -> afc.shim.remote)

    static func applyRemoteAirLift(
        project: PatchProject,
        backupRoot: URL,
        documentsRoot: URL? = nil,
        fileManager: FileManager = .default
    ) throws -> PatchTransactionReceipt {
        guard latestRemoteReceipt(projectID: project.id, backupRoot: backupRoot, fileManager: fileManager) == nil else {
            throw PatchPackageError.projectAlreadyApplied
        }
        guard LocalDevBridge.shared.isModuleEnabled else {
            throw AirLiftPatchError.localDevUnavailable("Module LocalDev đang tắt.")
        }

        let (directories, descriptors) = try AirLiftPatchWriteDescriptor.makeDescriptors(from: project)
        let transactionID = UUID()
        let (backupDir, timestampTag) = try createDiscardedBackupDirectory(
            transactionID: transactionID,
            documentsRoot: documentsRoot,
            fileManager: fileManager
        )

        let txDir = backupRoot
            .appendingPathComponent(project.id.uuidString, isDirectory: true)
            .appendingPathComponent(transactionID.uuidString, isDirectory: true)
        try fileManager.createDirectory(at: txDir, withIntermediateDirectories: true)
        let markerURL = txDir.appendingPathComponent(remoteReceiptMarkerFilename)

        var entries: [AirLiftPatchBackupEntry] = []
        var createdDirRecords: [AirLiftPatchDirectoryRecord] = []
        var writtenDescriptors: [(descriptor: AirLiftPatchWriteDescriptor, entry: AirLiftPatchBackupEntry)] = []

        do {
            // 1. Pre-check target accessibility + ensure directories via `patch.airlift` router
            for dir in directories {
                let remotePath = "/" + dir.relativePath
                let mkdirOutcome = LocalDevBridge.shared.createDirectoryWithAirLift(
                    bundleID: dir.bundleID,
                    path: remotePath
                )
                if !mkdirOutcome.success {
                    let errStr = mkdirOutcome.error ?? "mkdir failed"
                    if errStr.localizedCaseInsensitiveContains("SANDBOX_LOCKED")
                        || mkdirOutcome.route?.backend == "sandbox_locked" {
                        throw AirLiftPatchError.sandboxLockedRequiresBackup(bundleID: dir.bundleID, detail: errStr)
                    }
                    if let backend = mkdirOutcome.route?.backend, backend != "sandbox_locked" {
                        throw AirLiftPatchError.localDevUnavailable("[\(backend)] mkdir '\(remotePath)': \(errStr)")
                    }
                    // Fallback probe only when container backend wasn't confirmed open
                    let probe = LocalDevBridge.shared.listDirectoryWithAirLift(bundleID: dir.bundleID, path: "/")
                    if !probe.success {
                        let probeErr = probe.error ?? errStr
                        if probeErr.localizedCaseInsensitiveContains("SANDBOX_LOCKED")
                            || probe.route?.backend == "sandbox_locked" {
                            throw AirLiftPatchError.sandboxLockedRequiresBackup(bundleID: dir.bundleID, detail: probeErr)
                        }
                        throw AirLiftPatchError.localDevUnavailable(probeErr)
                    }
                } else {
                    createdDirRecords.append(
                        AirLiftPatchDirectoryRecord(bundleID: dir.bundleID, relativePath: dir.relativePath)
                    )
                }
            }

            // 2. Snapshot original device files into `.DiscardedPatchBackups-<timestamp>` BEFORE overwriting.
            // If target file does not exist (`ObjectNotFound` / `0x00000008`), treat as new file and skip original backup.
            for desc in descriptors {
                let remotePath = "/" + desc.relativePath
                let readRes = LocalDevBridge.shared.readFileWithAirLift(bundleID: desc.bundleID, path: remotePath)

                var originalExisted = false
                var backupRel: String?
                var originalDigest: Data?

                if readRes.success, let originalBytes = readRes.data {
                    originalExisted = true
                    let rel = "originals/\(safePathSegment(desc.bundleID))/\(desc.ruleID.uuidString).original"
                    let backupFileURL = backupDir.appendingPathComponent(rel)
                    try fileManager.createDirectory(
                        at: backupFileURL.deletingLastPathComponent(),
                        withIntermediateDirectories: true
                    )
                    try originalBytes.write(to: backupFileURL, options: .atomic)
                    let writtenDigest = Data(SHA256.hash(data: try Data(contentsOf: backupFileURL)))
                    originalDigest = Data(SHA256.hash(data: originalBytes))
                    guard writtenDigest == originalDigest else {
                        throw PatchPackageError.applyFailed
                    }
                    backupRel = rel
                } else if readRes.isNotFoundError {
                    // Target file does not yet exist on device: treat as new file, skip original backup, proceed to write
                    originalExisted = false
                } else if let readErr = readRes.error,
                          readErr.localizedCaseInsensitiveContains("SANDBOX_LOCKED")
                            || readRes.route?.backend == "sandbox_locked" {
                    throw AirLiftPatchError.sandboxLockedRequiresBackup(bundleID: desc.bundleID, detail: readErr)
                } else if let backend = readRes.route?.backend, backend != "sandbox_locked" {
                    let readErr = readRes.error ?? "AFC read error"
                    throw AirLiftPatchError.localDevUnavailable("[\(backend)] read '\(remotePath)': \(readErr)")
                } else {
                    let rootProbe = LocalDevBridge.shared.listDirectoryWithAirLift(bundleID: desc.bundleID, path: "/")
                    if !rootProbe.success {
                        let probeErr = rootProbe.error ?? readRes.error ?? "Container không thể truy cập"
                        if probeErr.localizedCaseInsensitiveContains("SANDBOX_LOCKED")
                            || rootProbe.route?.backend == "sandbox_locked" {
                            throw AirLiftPatchError.sandboxLockedRequiresBackup(bundleID: desc.bundleID, detail: probeErr)
                        }
                        throw AirLiftPatchError.localDevUnavailable(probeErr)
                    }
                }

                let routeInfo = readRes.route
                entries.append(
                    AirLiftPatchBackupEntry(
                        ruleID: desc.ruleID,
                        bundleID: desc.bundleID,
                        relativePath: desc.relativePath,
                        originalExisted: originalExisted,
                        backupRelativePath: backupRel,
                        originalDigest: originalDigest,
                        replacementDigest: desc.replacementDigest,
                        replacementByteCount: desc.replacementData.count,
                        backend: routeInfo?.backend ?? "coredevice.fileservice.data",
                        fallbackUsed: routeInfo?.fallback ?? false,
                        fallbackReason: routeInfo?.reason,
                        dataContainerURL: routeInfo?.data_container_url,
                        appGroupIdentifiers: routeInfo?.app_group_identifiers ?? []
                    )
                )
            }

            let manifestURL = backupDir.appendingPathComponent(manifestFilename)
            var manifest = AirLiftPatchBackupManifest(
                schemaVersion: 1,
                transactionID: transactionID,
                projectID: project.id,
                projectName: project.name,
                createdAt: Date(),
                timestampTag: timestampTag,
                isRemoteTransaction: true,
                backupDirectoryName: backupDir.lastPathComponent,
                status: .prepared,
                createdDirectories: createdDirRecords,
                entries: entries
            )
            try writeManifest(manifest, to: manifestURL)

            // 3. Apply each `AirLiftPatchWriteDescriptor` + perform read-back SHA-256 settle check
            for (idx, desc) in descriptors.enumerated() {
                let remotePath = "/" + desc.relativePath
                let writeRes = LocalDevBridge.shared.writeFileWithAirLift(
                    bundleID: desc.bundleID,
                    path: remotePath,
                    data: desc.replacementData
                )
                guard writeRes.success else {
                    let errMsg = writeRes.error ?? "Ghi tệp qua AirLift thất bại"
                    if errMsg.localizedCaseInsensitiveContains("SANDBOX_LOCKED")
                        || writeRes.route?.backend == "sandbox_locked" {
                        throw AirLiftPatchError.sandboxLockedRequiresBackup(bundleID: desc.bundleID, detail: errMsg)
                    }
                    if let backend = writeRes.route?.backend {
                        throw AirLiftPatchError.localDevUnavailable("[\(backend)] write '\(remotePath)': \(errMsg)")
                    }
                    throw AirLiftPatchError.localDevUnavailable(errMsg)
                }

                writtenDescriptors.append((desc, entries[idx]))
                try verifyRemoteSettleCheck(descriptor: desc)
            }

            manifest.status = .applied
            try writeManifest(manifest, to: manifestURL)

            let marker = RemoteReceiptMarker(
                schemaVersion: 1,
                transactionID: transactionID,
                projectID: project.id,
                createdAt: manifest.createdAt,
                status: .applied,
                backupDirectoryURLPath: backupDir.path,
                bundleIdentifiers: project.allBundleIdentifiers
            )
            try writeRemoteMarker(marker, to: markerURL)

            return PatchTransactionReceipt(
                id: transactionID,
                projectID: project.id,
                journalURL: markerURL
            )
        } catch {
            // Rollback any already-written descriptors using `.DiscardedPatchBackups-<timestamp>`
            rollbackRemoteDescriptors(writtenDescriptors, backupDir: backupDir)
            throw error
        }
    }

    // MARK: - Settle Checks

    private static func verifyLocalSettleCheck(
        target: URL,
        bundleID: String,
        relativePath: String,
        expectedDigest: Data,
        expectedCount: Int,
        fileManager: FileManager
    ) throws {
        var lastReason = "Tệp không tồn tại sau khi ghi"
        for (attempt, delay) in settleRetryDelays.enumerated() {
            if attempt > 0 {
                usleep(useconds_t(delay * 1_000_000))
            }
            if fileManager.fileExists(atPath: target.path),
               let currentData = try? Data(contentsOf: target) {
                if currentData.count == expectedCount && Data(SHA256.hash(data: currentData)) == expectedDigest {
                    return
                }
                lastReason = "Kích thước/SHA-256 chưa khớp (attempt \(attempt + 1)/\(settleMaxAttempts))"
            }
        }
        throw AirLiftPatchError.settleCheckFailed(
            bundleID: bundleID,
            relativePath: relativePath,
            reason: lastReason
        )
    }

    private static func verifyRemoteSettleCheck(descriptor: AirLiftPatchWriteDescriptor) throws {
        let remotePath = "/" + descriptor.relativePath
        var lastReason = "Không đọc lại được tệp từ thiết bị sau khi ghi"
        for (attempt, delay) in settleRetryDelays.enumerated() {
            if attempt > 0 {
                usleep(useconds_t(delay * 1_000_000))
            }
            let verifyRead = LocalDevBridge.shared.readFileWithAirLift(
                bundleID: descriptor.bundleID,
                path: remotePath
            )
            if verifyRead.success, let verifiedBytes = verifyRead.data {
                let actualDigest = Data(SHA256.hash(data: verifiedBytes))
                if verifiedBytes.count == descriptor.replacementData.count && actualDigest == descriptor.replacementDigest {
                    return
                }
                lastReason = "Byte/SHA-256 sai lệch (\(verifiedBytes.count) vs \(descriptor.replacementData.count))"
            } else if let err = verifyRead.error {
                lastReason = err
            }
        }
        throw AirLiftPatchError.settleCheckFailed(
            bundleID: descriptor.bundleID,
            relativePath: descriptor.relativePath,
            reason: lastReason
        )
    }

    // MARK: - Restore / Receipt Lookup for Remote AirLift Transactions

    static func isRemoteAirLiftReceipt(_ receipt: PatchTransactionReceipt) -> Bool {
        receipt.journalURL.lastPathComponent == remoteReceiptMarkerFilename
    }

    static func latestRemoteReceipt(
        projectID: UUID,
        backupRoot: URL,
        fileManager: FileManager = .default
    ) -> PatchTransactionReceipt? {
        let projectDir = backupRoot.appendingPathComponent(projectID.uuidString, isDirectory: true)
        guard let subdirs = try? fileManager.contentsOfDirectory(
            at: projectDir,
            includingPropertiesForKeys: nil,
            options: [.skipsHiddenFiles]
        ) else {
            return nil
        }

        return subdirs.compactMap { dir -> (RemoteReceiptMarker, URL)? in
            let url = dir.appendingPathComponent(remoteReceiptMarkerFilename)
            guard let marker = try? readRemoteMarker(at: url),
                  marker.status == .applied || marker.status == .prepared else {
                return nil
            }
            return (marker, url)
        }
        .sorted { $0.0.createdAt > $1.0.createdAt }
        .first
        .map {
            PatchTransactionReceipt(
                id: $0.0.transactionID,
                projectID: $0.0.projectID,
                journalURL: $0.1
            )
        }
    }

    static func restoreRemoteAirLift(
        receipt: PatchTransactionReceipt,
        fileManager: FileManager = .default
    ) throws {
        var marker = try readRemoteMarker(at: receipt.journalURL)
        let backupDir = URL(fileURLWithPath: marker.backupDirectoryURLPath, isDirectory: true)
        let manifestURL = backupDir.appendingPathComponent(manifestFilename)
        guard fileManager.fileExists(atPath: manifestURL.path) else {
            throw AirLiftPatchError.discardedBackupMissing(backupDir.lastPathComponent)
        }

        var manifest = try readManifest(at: manifestURL)
        for entry in manifest.entries.reversed() {
            let remotePath = "/" + entry.relativePath
            if entry.originalExisted {
                guard let rel = entry.backupRelativePath else {
                    throw PatchPackageError.restoreFailed
                }
                let srcURL = backupDir.appendingPathComponent(rel)
                let origBytes = try Data(contentsOf: srcURL)
                let writeRes = LocalDevBridge.shared.writeFileWithAirLift(
                    bundleID: entry.bundleID,
                    path: remotePath,
                    data: origBytes
                )
                guard writeRes.success else {
                    throw PatchPackageError.restoreFailed
                }
            } else {
                _ = LocalDevBridge.shared.removePathWithAirLift(bundleID: entry.bundleID, path: remotePath)
            }
        }

        for createdDir in manifest.createdDirectories.reversed() {
            let listing = LocalDevBridge.shared.listDirectoryWithAirLift(
                bundleID: createdDir.bundleID,
                path: "/" + createdDir.relativePath
            )
            if listing.success && listing.items.isEmpty {
                _ = LocalDevBridge.shared.removePathWithAirLift(
                    bundleID: createdDir.bundleID,
                    path: "/" + createdDir.relativePath
                )
            }
        }

        manifest.status = .restored
        try writeManifest(manifest, to: manifestURL)
        marker.status = .restored
        try writeRemoteMarker(marker, to: receipt.journalURL)
    }

    private static func rollbackRemoteDescriptors(
        _ written: [(descriptor: AirLiftPatchWriteDescriptor, entry: AirLiftPatchBackupEntry)],
        backupDir: URL
    ) {
        for (desc, entry) in written.reversed() {
            let remotePath = "/" + desc.relativePath
            if entry.originalExisted, let rel = entry.backupRelativePath {
                let srcURL = backupDir.appendingPathComponent(rel)
                if let origBytes = try? Data(contentsOf: srcURL) {
                    _ = LocalDevBridge.shared.writeFileWithAirLift(
                        bundleID: entry.bundleID,
                        path: remotePath,
                        data: origBytes
                    )
                }
            } else {
                _ = LocalDevBridge.shared.removePathWithAirLift(bundleID: entry.bundleID, path: remotePath)
            }
        }
    }

    private static func safePathSegment(_ raw: String) -> String {
        raw.replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "\\", with: "_")
            .replacingOccurrences(of: "..", with: "_")
    }

    private static func writeManifest(_ manifest: AirLiftPatchBackupManifest, to url: URL) throws {
        let encoder = PropertyListEncoder()
        encoder.outputFormat = .binary
        try encoder.encode(manifest).write(to: url, options: .atomic)
    }

    private static func readManifest(at url: URL) throws -> AirLiftPatchBackupManifest {
        try PropertyListDecoder().decode(AirLiftPatchBackupManifest.self, from: Data(contentsOf: url))
    }

    private static func writeRemoteMarker(_ marker: RemoteReceiptMarker, to url: URL) throws {
        let encoder = PropertyListEncoder()
        encoder.outputFormat = .binary
        try encoder.encode(marker).write(to: url, options: .atomic)
    }

    private static func readRemoteMarker(at url: URL) throws -> RemoteReceiptMarker {
        try PropertyListDecoder().decode(RemoteReceiptMarker.self, from: Data(contentsOf: url))
    }
}
