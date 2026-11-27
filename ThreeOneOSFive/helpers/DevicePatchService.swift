import Foundation

enum DevicePatchService {
    private static let directGroupsMetadataFilename = "direct_app_groups.plist"

    static func apply(project: PatchProject) throws -> PatchTransactionReceipt {
        let bundleIDs = orderedBundleIdentifiers(in: project)
        let (_, descriptors) = try AirLiftPatchWriteDescriptor.makeDescriptors(from: project)
        let backupRoot = try PatchProjectLibrary.backupRootURL()

        // Step 1 (< 1s): Fast local path via declared App Group (`containerURL(forSecurityApplicationGroupIdentifier:)`)
        // or entitled container returned by `libsystem_containermanager.dylib` (`MCMActivateContainerPath`).
        if let localRoots = tryResolveAllDirectContainers(project: project, bundleIDs: bundleIDs) {
            let receipt = try PatchTransaction.apply(
                project: project,
                backupRoot: backupRoot,
                containerResolver: { bundleID in
                    guard let root = localRoots[bundleID] else {
                        throw PatchPackageError.targetAppUnavailable(bundleID)
                    }
                    return root
                }
            )
            saveDirectAppGroupsMetadata(
                project.declaredAppGroupIdentifiers,
                for: receipt
            )
            try AirLiftPatchTransaction.mirrorLocalTransactionBackupAndSettle(
                project: project,
                receipt: receipt,
                roots: localRoots,
                descriptors: descriptors
            )
            return receipt
        }

        // Step 2: Direct filesystem access denied by sandbox -> silently load any sandbox pairing
        // and prepare `strategy=lockdown_first` (`en0:62078 -> CoreDeviceProxy`) or IPv6 ULA / RSD tunnel.
        if LocalDevBridge.shared.isModuleEnabled {
            if !LocalDevBridge.shared.currentStatusSnapshot.isLive {
                _ = LocalDevBridge.shared.prepareTunnelAndPairingForApply(timeoutSeconds: 4.5)
            }
            if LocalDevBridge.shared.currentStatusSnapshot.isLive {
                return try AirLiftPatchTransaction.applyRemoteAirLift(
                    project: project,
                    backupRoot: backupRoot
                )
            }
            let statusMsg = LocalDevBridge.shared.currentStatusSnapshot.message
            if !statusMsg.isEmpty {
                throw AirLiftPatchError.localDevUnavailable(statusMsg)
            }
        }

        if let firstMissing = bundleIDs.first {
            throw PatchPackageError.targetAppUnavailable(firstMissing)
        }
        throw PatchPackageError.invalidProject
    }

    static func inspectRestore(receipt: PatchTransactionReceipt) throws -> PatchRestoreInspection {
        if AirLiftPatchTransaction.isRemoteAirLiftReceipt(receipt) {
            return PatchRestoreInspection(changedTargets: [])
        }
        let bundleIDs = try PatchTransaction.requiredBundleIdentifiers(for: receipt)
        let groupIDs = loadDirectAppGroupsMetadata(for: receipt)
        return try withResolvedContainers(bundleIDs: bundleIDs, appGroupIdentifiers: groupIDs) { roots in
            try PatchTransaction.inspectRestore(
                receipt: receipt,
                containerResolver: { bundleID in
                    guard let root = roots[bundleID] else {
                        throw PatchPackageError.targetAppUnavailable(bundleID)
                    }
                    return root
                }
            )
        }
    }

    static func restore(
        receipt: PatchTransactionReceipt,
        allowChangedTargets: Bool = false
    ) throws {
        if AirLiftPatchTransaction.isRemoteAirLiftReceipt(receipt) {
            try AirLiftPatchTransaction.restoreRemoteAirLift(receipt: receipt)
            return
        }
        let bundleIDs = try PatchTransaction.requiredBundleIdentifiers(for: receipt)
        let groupIDs = loadDirectAppGroupsMetadata(for: receipt)
        try withResolvedContainers(bundleIDs: bundleIDs, appGroupIdentifiers: groupIDs) { roots in
            try PatchTransaction.restore(
                receipt: receipt,
                allowChangedTargets: allowChangedTargets,
                containerResolver: { bundleID in
                    guard let root = roots[bundleID] else {
                        throw PatchPackageError.targetAppUnavailable(bundleID)
                    }
                    return root
                }
            )
        }
    }

    static func resetToAppliedState(
        receipt: PatchTransactionReceipt,
        project: PatchProject
    ) throws {
        if AirLiftPatchTransaction.isRemoteAirLiftReceipt(receipt) {
            let backupRoot = try PatchProjectLibrary.backupRootURL()
            try AirLiftPatchTransaction.restoreRemoteAirLift(receipt: receipt)
            _ = try AirLiftPatchTransaction.applyRemoteAirLift(project: project, backupRoot: backupRoot)
            return
        }
        let bundleIDs = try PatchTransaction.requiredBundleIdentifiers(for: receipt)
        let groupIDs = Array(Set(loadDirectAppGroupsMetadata(for: receipt) + project.declaredAppGroupIdentifiers))
        try withResolvedContainers(bundleIDs: bundleIDs, appGroupIdentifiers: groupIDs) { roots in
            try PatchTransaction.resetToAppliedState(
                receipt: receipt,
                fallbackProject: project,
                containerResolver: { bundleID in
                    guard let root = roots[bundleID] else {
                        throw PatchPackageError.targetAppUnavailable(bundleID)
                    }
                    return root
                }
            )
        }
    }

    static func latestReceipt(projectID: UUID) -> PatchTransactionReceipt? {
        guard let backupRoot = try? PatchProjectLibrary.backupRootURL() else { return nil }
        return PatchTransaction.latestReceipt(projectID: projectID, backupRoot: backupRoot)
            ?? AirLiftPatchTransaction.latestRemoteReceipt(projectID: projectID, backupRoot: backupRoot)
    }

    private static func orderedBundleIdentifiers(in project: PatchProject) -> [String] {
        project.allBundleIdentifiers
    }

    private static func tryResolveAllDirectContainers(
        project: PatchProject,
        bundleIDs: [String]
    ) -> [String: URL]? {
        let declaredGroups = project.declaredAppGroupIdentifiers
        var roots: [String: URL] = [:]
        for bundleID in bundleIDs {
            guard let resolved = LocalDevBridge.shared.resolveDirectLocalContainerRoot(
                bundleID: bundleID,
                appGroupIdentifiers: declaredGroups
            ) else {
                return nil
            }
            roots[bundleID] = PatchPathValidator.canonicalFileURL(resolved)
        }
        return roots
    }

    private static func withResolvedContainers<T>(
        bundleIDs: [String],
        appGroupIdentifiers: [String] = [],
        operation: ([String: URL]) throws -> T
    ) throws -> T {
        var roots: [String: URL] = [:]

        for bundleID in bundleIDs {
            if let resolved = LocalDevBridge.shared.resolveDirectLocalContainerRoot(
                bundleID: bundleID,
                appGroupIdentifiers: appGroupIdentifiers,
                requireWritable: false
            ) {
                roots[bundleID] = PatchPathValidator.canonicalFileURL(resolved)
                continue
            }
            throw PatchPackageError.targetAppUnavailable(bundleID)
        }
        return try operation(roots)
    }

    private static func saveDirectAppGroupsMetadata(_ groupIDs: [String], for receipt: PatchTransactionReceipt) {
        guard !groupIDs.isEmpty else { return }
        let url = receipt.journalURL.deletingLastPathComponent().appendingPathComponent(directGroupsMetadataFilename)
        guard let data = try? PropertyListEncoder().encode(groupIDs) else { return }
        try? data.write(to: url, options: .atomic)
    }

    private static func loadDirectAppGroupsMetadata(for receipt: PatchTransactionReceipt) -> [String] {
        let url = receipt.journalURL.deletingLastPathComponent().appendingPathComponent(directGroupsMetadataFilename)
        guard let data = try? Data(contentsOf: url),
              let ids = try? PropertyListDecoder().decode([String].self, from: data) else {
            return []
        }
        return ids
    }
}
