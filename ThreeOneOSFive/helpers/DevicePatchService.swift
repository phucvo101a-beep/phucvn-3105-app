import Foundation

enum DevicePatchService {
    static func apply(project: PatchProject) throws -> PatchTransactionReceipt {
        let bundleIDs = orderedBundleIdentifiers(in: project)
        let (_, descriptors) = try AirLiftPatchWriteDescriptor.makeDescriptors(from: project)
        let backupRoot = try PatchProjectLibrary.backupRootURL()

        if let localRoots = tryResolveAllLocalContainers(bundleIDs: bundleIDs) {
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
            try AirLiftPatchTransaction.mirrorLocalTransactionBackupAndSettle(
                project: project,
                receipt: receipt,
                roots: localRoots,
                descriptors: descriptors
            )
            return receipt
        }

        if LocalDevBridge.shared.isModuleEnabled && LocalDevBridge.shared.currentStatusSnapshot.isLive {
            return try AirLiftPatchTransaction.applyRemoteAirLift(
                project: project,
                backupRoot: backupRoot
            )
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
        return try withResolvedContainers(bundleIDs: bundleIDs) { roots in
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
        try withResolvedContainers(bundleIDs: bundleIDs) { roots in
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
        try withResolvedContainers(bundleIDs: bundleIDs) { roots in
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

    private static func tryResolveAllLocalContainers(bundleIDs: [String]) -> [String: URL]? {
        var roots: [String: URL] = [:]
        for bundleID in bundleIDs {
            guard let path = ContainerStore.resolveAppContainerPath(bundleID: bundleID),
                  ContainerStore.isApplicationContainerPath(path),
                  let containerURL = ContainerStore.validatedLocalFileURL(
                      fromPath: path,
                      isDirectory: true,
                      requireExists: true
                  ),
                  FileManager.default.isWritableFile(atPath: containerURL.path) else {
                return nil
            }
            roots[bundleID] = PatchPathValidator.canonicalFileURL(containerURL)
        }
        return roots
    }

    private static func withResolvedContainers<T>(
        bundleIDs: [String],
        operation: ([String: URL]) throws -> T
    ) throws -> T {
        var roots: [String: URL] = [:]

        for bundleID in bundleIDs {
            guard let path = ContainerStore.resolveAppContainerPath(bundleID: bundleID),
                  ContainerStore.isApplicationContainerPath(path),
                  let containerURL = ContainerStore.validatedLocalFileURL(
                      fromPath: path,
                      isDirectory: true,
                      requireExists: true
                  ) else {
                throw PatchPackageError.targetAppUnavailable(bundleID)
            }
            roots[bundleID] = PatchPathValidator.canonicalFileURL(containerURL)
        }
        return try operation(roots)
    }
}
