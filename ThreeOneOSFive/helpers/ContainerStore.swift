import Foundation
import Darwin
import UIKit

// MARK: - Models

struct InstalledApp: Identifiable, Hashable {
    let bundleID: String
    let name: String
    let containerPath: String
    let version: String
    let icon: UIImage?

    var id: String { bundleID }
    var displayName: String {
        AppDisplayNamePolicy.resolve(bundleID: bundleID, candidates: [name])
    }

    static func == (lhs: InstalledApp, rhs: InstalledApp) -> Bool { lhs.id == rhs.id }
    func hash(into hasher: inout Hasher) { hasher.combine(id) }
}

struct FileEntry: Identifiable, Hashable {
    let name: String
    let path: String
    let isDirectory: Bool
    let size: Int64
    let modifiedAt: Date?
    let childCount: Int?

    var id: String { path }
    var sizeText: String {
        guard size >= 0 else { return "—" }
        return ByteCountFormatter.string(fromByteCount: size, countStyle: .file)
    }

    init(
        name: String,
        path: String,
        isDirectory: Bool,
        size: Int64,
        modifiedAt: Date? = nil,
        childCount: Int? = nil
    ) {
        self.name = name
        self.path = path
        self.isDirectory = isDirectory
        self.size = size
        self.modifiedAt = modifiedAt
        self.childCount = childCount
    }

    func withDirectorySummary(_ summary: FileBrowserDirectorySummary?) -> FileEntry {
        FileEntry(
            name: name,
            path: path,
            isDirectory: isDirectory,
            size: summary?.byteCount ?? -2,
            modifiedAt: modifiedAt,
            childCount: summary?.childCount
        )
    }
}

enum ContainerAccessEnvironment: Equatable {
    case appSandboxOnly(iosVersion: String)
    case localDevTunnel(udid: String?)
    case privilegedSandboxAccess
}

// MARK: - Store

enum ContainerStore {
    static let researchAppIdentifiers = [
        "com.apple.mobilesafari", "com.apple.mobilenotes", "com.apple.Maps",
        "com.apple.facetime", "com.apple.iBooks", "com.apple.podcasts",
        "com.apple.PosterBoard", "com.apple.mobilemail", "com.apple.weather",
        "com.apple.camera", "com.apple.Health", "com.apple.Fitness",
        "com.apple.tips", "com.apple.Passbook", "com.apple.reminders",
        "com.apple.stocks", "com.apple.news", "com.apple.Home", "com.apple.tv",
        "com.apple.shortcuts", "com.apple.freeform", "com.apple.calculator",
        "com.apple.MobileSMS", "com.apple.InCallService", "com.apple.Preferences",
        "com.apple.springboard", "com.apple.Photos", "com.apple.AppStore",
        "com.apple.Music", "com.apple.Bridge", "com.apple.Clock",
        "com.apple.VoiceMemos", "com.apple.Translate", "com.apple.measure",
        "com.apple.compass", "com.apple.Magnifier", "com.apple.DocumentsApp"
    ]

    private static let privilegedLock = NSLock()
    private static var didLogSandboxNotice = false
    private static var registeredAppGroupRootPaths = Set<String>()
    private static var activeWorseQueryHandles: [String: Int64] = [:]

    static var shouldUseWorseQuery: Bool {
        let v = ProcessInfo.processInfo.operatingSystemVersion
        if v.majorVersion == 26 {
            return v.minorVersion > 6 || (v.minorVersion == 6 && v.patchVersion >= 2)
        }
        if v.majorVersion == 27 {
            return v.minorVersion <= 3
        }
        return false
    }

    @discardableResult
    static func ensureWorseQueryGrant(groupID: String? = nil) -> Bool {
        guard shouldUseWorseQuery else { return false }
        let trimmed = groupID?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        let key = trimmed.isEmpty ? "systemgroup.com.apple.mobilegestaltcache" : trimmed
        privilegedLock.lock()
        if let existing = activeWorseQueryHandles[key], existing >= 0 {
            privilegedLock.unlock()
            return true
        }
        privilegedLock.unlock()

        let handle: Int64 = key.withCString { cStr in
            worse_query(cStr)
        }
        if handle >= 0 {
            privilegedLock.lock()
            activeWorseQueryHandles[key] = handle
            privilegedLock.unlock()
            log("[3105] access=worse_query group=\(key) handle=\(handle)")
            return true
        }
        log("worse_query grant refused for \(key)")
        return false
    }

    // MARK: - Standard iOS Sandbox Roots

    static var ownBundleID: String {
        Bundle.main.bundleIdentifier ?? "com.phucvn.threeoneosfive"
    }

    static var ownSandboxRootURL: URL {
        let home = NSHomeDirectory().trimmingCharacters(in: .whitespacesAndNewlines)
        if let valid = validatedLocalFileURL(fromPath: home, isDirectory: true) {
            return valid
        }
        return FileManager.default.temporaryDirectory.standardizedFileURL
    }

    static var ownDocumentsURL: URL? {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first?.standardizedFileURL
    }

    static var ownApplicationSupportURL: URL? {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first?.standardizedFileURL
    }

    static var ownCachesURL: URL? {
        FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask).first?.standardizedFileURL
    }

    static var ownTemporaryURL: URL {
        FileManager.default.temporaryDirectory.standardizedFileURL
    }

    static var ownDiagnosticsURL: URL? {
        guard let docs = ownDocumentsURL else { return nil }
        let dir = docs.appendingPathComponent("3105-Diagnostics", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    static var ownInstalledApp: InstalledApp {
        let info = Bundle.main.infoDictionary ?? [:]
        let localized = Bundle.main.localizedInfoDictionary ?? [:]
        let displayName = (localized["CFBundleDisplayName"] as? String)
            ?? (info["CFBundleDisplayName"] as? String)
            ?? (info["CFBundleName"] as? String)
            ?? AppBrand.name
        let version = (info["CFBundleShortVersionString"] as? String) ?? ""
        return InstalledApp(
            bundleID: ownBundleID,
            name: displayName,
            containerPath: ownSandboxRootURL.path,
            version: version,
            icon: iconForBundleID(ownBundleID)
        )
    }

    static func appGroupContainerURLs(identifiers: [String] = []) -> [URL] {
        var groupIDs = Set(identifiers)
        if let declared = Bundle.main.object(forInfoDictionaryKey: "AppGroupIdentifiers") as? [String] {
            groupIDs.formUnion(declared)
        }
        return groupIDs.sorted().compactMap { id in
            FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: id)?.standardizedFileURL
        }
    }

    /// Dynamically derives the parent container directory from NSHomeDirectory()
    /// without hardcoding any fixed application container root path.
    static var derivedContainersParentPath: String? {
        let resolvedHome = ownSandboxRootURL.resolvingSymlinksInPath().standardizedFileURL
        guard UUID(uuidString: resolvedHome.lastPathComponent) != nil else { return nil }
        let parent = resolvedHome.deletingLastPathComponent().path
        return parent.isEmpty ? nil : parent
    }

    static var derivedBundleParentPath: String? {
        let resolvedBundle = Bundle.main.bundleURL.resolvingSymlinksInPath().standardizedFileURL
        let uuidDir = resolvedBundle.deletingLastPathComponent()
        guard UUID(uuidString: uuidDir.lastPathComponent) != nil else { return nil }
        let parent = uuidDir.deletingLastPathComponent().path
        return parent.isEmpty ? nil : parent
    }

    static func isWithinOwnSandbox(_ path: String, appGroupIdentifiers: [String] = []) -> Bool {
        let candidate = canonicalResolvedPath(path)
        guard !candidate.isEmpty else { return false }

        var allowedRoots = [canonicalResolvedPath(ownSandboxRootURL.path)]
        for groupURL in appGroupContainerURLs(identifiers: appGroupIdentifiers) {
            allowedRoots.append(canonicalResolvedPath(groupURL.path))
        }
        privilegedLock.lock()
        let dynamicRoots = registeredAppGroupRootPaths
        privilegedLock.unlock()
        allowedRoots.append(contentsOf: dynamicRoots)

        for root in allowedRoots where !root.isEmpty {
            if candidate == root || candidate.hasPrefix(root + "/") {
                return true
            }
        }
        return false
    }

    static func hasPrivilegedContainerAccess() -> Bool {
#if targetEnvironment(simulator)
        if ProcessInfo.processInfo.arguments.contains("--simulate-access") {
            return true
        }
#endif
        let v = ProcessInfo.processInfo.operatingSystemVersion
        if ExploitSupportPolicy.supportsKernelExploit(
            major: v.majorVersion,
            minor: v.minorVersion,
            patch: v.patchVersion
        ), KernelExploit.hasSandboxAccess() {
            return true
        }

        // Non-jailbroken standard iOS apps cannot read the parent container directory
        // or enumerate external app containers via LSApplicationWorkspace.
        if let parent = derivedContainersParentPath,
           FileManager.default.isReadableFile(atPath: parent) {
            let entries = (try? FileManager.default.contentsOfDirectory(atPath: parent)) ?? []
            if entries.count > 1 {
                return true
            }
        }
        return false
    }

    static func currentAccessEnvironment() -> ContainerAccessEnvironment {
        if hasPrivilegedContainerAccess() {
            return .privilegedSandboxAccess
        }
        let snapshot = LocalDevBridge.shared.currentStatusSnapshot
        if snapshot.isLive {
            return .localDevTunnel(udid: snapshot.udid)
        }
        return .appSandboxOnly(iosVersion: AppInfo.osVersion)
    }

    static var accessModeDescription: String {
        switch currentAccessEnvironment() {
        case .privilegedSandboxAccess:
            return "Privileged Container Access"
        case .localDevTunnel:
            return "Sandbox + LocalDev Tunnel (LIVE)"
        case .appSandboxOnly:
            return "App Sandbox (Non-JB)"
        }
    }

    static func logSandboxModeNoticeOnce(context: String) {
        privilegedLock.lock()
        let shouldLog = !didLogSandboxNotice
        didLogSandboxNotice = true
        privilegedLock.unlock()

        guard shouldLog else { return }
        log(
            "\(context): iOS \(AppInfo.osVersion) (\(AppInfo.osBuild)) chạy trong App Sandbox (non-JB) — " +
            "giới hạn an toàn trong container của \(ownBundleID) / Documents / LocalDev (không phải lỗi phiên bản iOS)"
        )
    }

    private static func canonicalResolvedPath(_ rawPath: String) -> String {
        let trimmed = rawPath.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, trimmed.hasPrefix("/") else { return "" }
        let resolved = URL(fileURLWithPath: trimmed).resolvingSymlinksInPath().standardizedFileURL.path
        return ContainerDiscoveryMerger.canonicalPath(resolved)
    }

    /// Validates a local filesystem path before constructing a file URL, preventing empty/`(null)`
    /// or virtual (`localdev://`) paths from reaching `sandbox_extension_issue_file` (`EINVAL 22`).
    static func validatedLocalFileURL(
        fromPath rawPath: String,
        isDirectory: Bool? = nil,
        requireExists: Bool = false
    ) -> URL? {
        let trimmed = rawPath.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty,
              trimmed.hasPrefix("/"),
              !trimmed.contains("://"),
              !trimmed.contains("\0") else {
            return nil
        }
        let components = (trimmed as NSString).pathComponents
        guard !components.contains("..") else { return nil }

        let url = isDirectory.map {
            URL(fileURLWithPath: trimmed, isDirectory: $0).standardizedFileURL
        } ?? URL(fileURLWithPath: trimmed).standardizedFileURL
        let path = url.path
        guard !path.isEmpty, path.hasPrefix("/") else { return nil }
        if requireExists && !FileManager.default.fileExists(atPath: path) {
            return nil
        }
        return url
    }

    /// Validates an external document URL (picker / Open-In) before calling security-scoped APIs.
    static func validatedExternalFileURL(_ url: URL, requireExists: Bool = false) -> URL? {
        guard url.isFileURL else { return nil }
        return validatedLocalFileURL(fromPath: url.path, requireExists: requireExists)
    }

    // MARK: - Container Resolution

    static func resolveAppContainerPath(bundleID: String) -> String? {
        guard (try? PatchPathValidator.canonicalBundleIdentifier(bundleID)) == bundleID else {
            return nil
        }

        if bundleID == ownBundleID {
            return ownSandboxRootURL.path
        }

        if shouldUseWorseQuery {
            _ = ensureWorseQueryGrant()
            var mcmLookupError: NSString?
            if let path = MCMContainerPathForIdentifier(2, bundleID, false, &mcmLookupError),
               isApplicationContainerPath(path) {
                log("patch: worse_query resolved \(bundleID) -> \(path)")
                return path
            }
            if let actPath = MCMActivateContainerPath(2, bundleID, false, &mcmLookupError),
               isApplicationContainerPath(actPath) {
                log("patch: worse_query resolved \(bundleID) -> \(actPath)")
                return actPath
            }
            let detail = mcmLookupError.map(String.init) ?? "unavailable"
            log("patch: worse_query could not grant \(bundleID), detail=\(detail)")
        }

        guard hasPrivilegedContainerAccess() else {
            logSandboxModeNoticeOnce(context: "resolve")
            return nil
        }

        var lookupError: NSString?
        if let path = MCMActivateContainerPath(2, bundleID, false, &lookupError),
           isApplicationContainerPath(path) {
            log("patch: MHA-C2 resolved \(bundleID)")
            return path
        }
        let detail = lookupError.map(String.init) ?? "unavailable"
        log("patch: MHA-C2 unavailable for \(bundleID), detail=\(detail)")

        if let scanned = resolveAppContainerPathByMetadataScan(bundleID: bundleID) {
            log("patch: filesystem metadata scan resolved \(bundleID)")
            return scanned
        }
        return nil
    }

    static func registerPermittedAppGroupRoot(_ path: String) {
        let canonical = canonicalResolvedPath(path)
        guard !canonical.isEmpty else { return }
        privilegedLock.lock()
        registeredAppGroupRootPaths.insert(canonical)
        privilegedLock.unlock()
    }

    /// Resolves a writable App Group container URL granted by the signing profile (`FileManager`)
    /// or `libsystem_containermanager.dylib` (`MCMActivateContainerPath(7, ...)`).
    static func resolvePermittedAppGroupURL(
        identifiers: [String],
        requireWritable: Bool = true
    ) -> URL? {
        for rawID in identifiers {
            let groupID = rawID.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !groupID.isEmpty,
                  !groupID.contains("/"),
                  !groupID.contains("\\"),
                  !groupID.contains("..") else { continue }

            if let stdURL = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: groupID),
               let validURL = validatedLocalFileURL(fromPath: stdURL.path, isDirectory: true, requireExists: true),
               (!requireWritable || FileManager.default.isWritableFile(atPath: validURL.path)) {
                registerPermittedAppGroupRoot(validURL.path)
                return validURL
            }

            if MCMBridgeAvailable() {
                var lookupError: NSString?
                if let mcmPath = MCMActivateContainerPath(7, groupID, true, &lookupError),
                   let validURL = validatedLocalFileURL(fromPath: mcmPath, isDirectory: true, requireExists: true),
                   (!requireWritable || FileManager.default.isWritableFile(atPath: validURL.path)) {
                    registerPermittedAppGroupRoot(validURL.path)
                    return validURL
                }
            }
        }
        return nil
    }

    /// Resolves a direct on-device local container or App Group root without opening any tunnel,
    /// respecting iOS sandbox / entitlement enforcement.
    static func resolvePermittedDirectContainerURL(
        bundleID: String,
        appGroupIdentifiers: [String] = [],
        requireWritable: Bool = true
    ) -> URL? {
        if shouldUseWorseQuery {
            _ = ensureWorseQueryGrant()
            for grp in appGroupIdentifiers {
                _ = ensureWorseQueryGrant(groupID: grp)
            }
        }

        if !appGroupIdentifiers.isEmpty,
           let groupURL = resolvePermittedAppGroupURL(identifiers: appGroupIdentifiers, requireWritable: requireWritable) {
            return groupURL
        }

        if bundleID == ownBundleID {
            let url = ownSandboxRootURL
            if !requireWritable || FileManager.default.isWritableFile(atPath: url.path) {
                return url
            }
        }

        if let path = resolveAppContainerPath(bundleID: bundleID),
           isApplicationContainerPath(path),
           let containerURL = validatedLocalFileURL(fromPath: path, isDirectory: true, requireExists: true),
           (!requireWritable || FileManager.default.isWritableFile(atPath: containerURL.path)) {
            return containerURL
        }

        if MCMBridgeAvailable() {
            var lookupError: NSString?
            if let path = MCMActivateContainerPath(2, bundleID, false, &lookupError),
               isApplicationContainerPath(path),
               let containerURL = validatedLocalFileURL(fromPath: path, isDirectory: true, requireExists: true),
               (!requireWritable || FileManager.default.isWritableFile(atPath: containerURL.path)) {
                return containerURL
            }
        }

        let defaultGroup = "group.\(bundleID)"
        if !appGroupIdentifiers.contains(defaultGroup),
           let groupURL = resolvePermittedAppGroupURL(identifiers: [defaultGroup], requireWritable: requireWritable) {
            return groupURL
        }
        return nil
    }

    static func resolveAppContainerPathByMetadataScan(bundleID: String) -> String? {
        if bundleID == ownBundleID {
            return ownSandboxRootURL.path
        }
        guard hasPrivilegedContainerAccess(),
              let appRoot = derivedContainersParentPath else {
            return nil
        }
        let dirs = enumerateDirectories(path: appRoot)
        guard !dirs.isEmpty else {
            return nil
        }
        for dir in dirs {
            guard UUID(uuidString: (dir as NSString).lastPathComponent) != nil else { continue }
            guard let metadata = readContainerMetadata(containerPath: dir),
                  metadata.bundleID == bundleID else { continue }
            let canonical = ContainerDiscoveryMerger.canonicalPath(dir)
            guard isApplicationContainerPath(canonical) else { continue }
            return canonical
        }
        return nil
    }

    // MARK: Primary — MobileInstallation / LSApplicationWorkspace

    static func installedAppsFromAPI() -> [InstalledApp] {
        guard hasPrivilegedContainerAccess() else {
            logSandboxModeNoticeOnce(context: "browser")
            return [ownInstalledApp]
        }

        let raw = installedAppInfo() as? [String: [String: Any]] ?? [:]
        var apps: [InstalledApp] = []
        var missingContainer = 0
        for (bundleID, info) in raw {
            var containerPath = info["container"] as? String ?? ""
            if containerPath.isEmpty {
                if bundleID == ownBundleID {
                    containerPath = ownSandboxRootURL.path
                } else {
                    var lookupError: NSString?
                    if let resolved = MCMActivateContainerPath(2, bundleID, false, &lookupError),
                       isApplicationContainerPath(resolved) {
                        containerPath = resolved
                    } else {
                        missingContainer += 1
                    }
                }
            }
            guard !containerPath.isEmpty else { continue }
            apps.append(InstalledApp(
                bundleID: bundleID,
                name: info["name"] as? String ?? "",
                containerPath: containerPath,
                version: info["version"] as? String ?? "",
                icon: info["icon"] as? UIImage
            ))
        }
        if !apps.contains(where: { $0.bundleID == ownBundleID }) {
            apps.append(ownInstalledApp)
        }
        log("browser: LS/API apps=\(apps.count) raw=\(raw.count) missingContainer=\(missingContainer)")
        return apps
    }

    static func applicationBundleMetadataCatalog() -> [String: ApplicationBundleMetadata] {
        var catalog: [String: ApplicationBundleMetadata] = [:]

        // Always include own app metadata using standard Bundle API.
        if let infoURL = Bundle.main.url(forResource: "Info", withExtension: "plist"),
           let data = try? Data(contentsOf: infoURL),
           let ownMetadata = ApplicationBundleMetadataReader.metadata(
               from: data,
               localizedInfo: Bundle.main.localizedInfoDictionary
           ) {
            catalog[ownMetadata.bundleID] = ownMetadata
        }

        guard hasPrivilegedContainerAccess(),
              let bundleParent = derivedBundleParentPath else {
            return catalog
        }

        for metadata in applicationBundleMetadata(at: bundleParent, nested: true) {
            catalog[metadata.bundleID] = metadata
        }
        log("browser: app-bundle metadata resolved \(catalog.count) names")
        return catalog
    }

    static func applyingBundleMetadata(
        to apps: [InstalledApp],
        catalog: [String: ApplicationBundleMetadata]
    ) -> [InstalledApp] {
        apps.map { app in
            guard let metadata = catalog[app.bundleID] else { return app }
            return InstalledApp(
                bundleID: app.bundleID,
                name: AppDisplayNamePolicy.resolve(
                    bundleID: app.bundleID,
                    candidates: [metadata.displayName, app.name]
                ),
                containerPath: app.containerPath,
                version: app.version.isEmpty ? metadata.version : app.version,
                icon: app.icon
            )
        }
    }

    static func dynamicAppIdentifiers() -> [String] {
        guard hasPrivilegedContainerAccess() else {
            return [ownBundleID]
        }
        var enumerationError: NSString?
        let identifiers = MCMEnumerateIdentifiersForClass(2, 1_024, &enumerationError)
        let enumerationDetail = enumerationError.map { String($0) } ?? "none"
        log("browser: MCM class-2 identifiers=\(identifiers.count) detail=\(enumerationDetail)")
        return identifiers
    }

    static func installedAppsFromMCM(
        identifiers: [String]? = nil,
        bundleMetadata: [String: ApplicationBundleMetadata] = [:]
    ) -> [InstalledApp] {
        guard hasPrivilegedContainerAccess() else {
            return [ownInstalledApp]
        }

        let identifiers = identifiers ?? dynamicAppIdentifiers()
        var apps: [InstalledApp] = []
        for (index, bundleID) in identifiers.enumerated() {
            var lookupError: NSString?
            guard let containerPath = MCMActivateContainerPath(2, bundleID, false, &lookupError) else {
                let lookupDetail = lookupError.map { String($0) } ?? "no path"
                if index < 3 { log("mcm[\(index)]: \(bundleID) -> \(lookupDetail)") }
                continue
            }
            if index < 3 { log("mcm[\(index)]: \(bundleID) -> \(containerPath)") }

            let rawInfo = appInfoForBundleID(bundleID) as? [String: Any] ?? [:]
            let metadata = bundleMetadata[bundleID]
            apps.append(InstalledApp(
                bundleID: bundleID,
                name: AppDisplayNamePolicy.resolve(
                    bundleID: bundleID,
                    candidates: [metadata?.displayName, rawInfo["name"] as? String]
                ),
                containerPath: containerPath,
                version: rawInfo["version"] as? String ?? metadata?.version ?? "",
                icon: rawInfo["icon"] as? UIImage
            ))
        }
        log("browser: MCM resolved \(apps.count)/\(identifiers.count) app paths")
        return apps
    }

    // MARK: LaunchServices store discovery

    static func installedAppsFromMHACandidates(
        identifiers: [String],
        bundleMetadata: [String: ApplicationBundleMetadata] = [:],
        progress: (([InstalledApp]) -> Void)? = nil
    ) -> [InstalledApp] {
        guard hasPrivilegedContainerAccess() else {
            let ownOnly = [ownInstalledApp]
            progress?(ownOnly)
            return ownOnly
        }
        guard !identifiers.isEmpty else {
            return []
        }

        var apps: [InstalledApp] = []
        var lastProgressPublication = ProcessInfo.processInfo.systemUptime
        for (index, bundleID) in identifiers.enumerated() {
            var lookupError: NSString?
            guard let containerPath = MCMActivateContainerPath(
                2,
                bundleID,
                false,
                &lookupError
            ),
                  isApplicationContainerPath(containerPath) else {
                if index < 3 {
                    let detail = lookupError.map { String($0) } ?? "invalid app-data path"
                    log("mha-candidate[\(index)]: \(bundleID) -> \(detail)")
                }
                continue
            }

            let rawInfo = appInfoForBundleID(bundleID) as? [String: Any] ?? [:]
            let metadata = bundleMetadata[bundleID]
            apps.append(InstalledApp(
                bundleID: bundleID,
                name: AppDisplayNamePolicy.resolve(
                    bundleID: bundleID,
                    candidates: [metadata?.displayName, rawInfo["name"] as? String]
                ),
                containerPath: containerPath,
                version: rawInfo["version"] as? String ?? metadata?.version ?? "",
                icon: rawInfo["icon"] as? UIImage
            ))
            if apps.count <= 5 {
                log("browser: MHA-C2 resolved \(bundleID) -> \(containerPath)")
            }
            if apps.count.isMultiple(of: 32) {
                let now = ProcessInfo.processInfo.systemUptime
                if now - lastProgressPublication >= 0.35 {
                    lastProgressPublication = now
                    progress?(apps)
                }
            }
        }

        progress?(apps)
        log("browser: MHA-C2 resolved \(apps.count)/\(identifiers.count) bundle candidates")
        return apps
    }

    private static func applicationBundleMetadata(
        at rootPath: String,
        nested: Bool
    ) -> [ApplicationBundleMetadata] {
        let fileManager = FileManager.default
        guard let rootEntries = try? fileManager.contentsOfDirectory(atPath: rootPath) else {
            return []
        }

        let bundlePaths: [String]
        if nested {
            bundlePaths = rootEntries.prefix(2_048).flatMap { entry -> [String] in
                guard UUID(uuidString: entry) != nil else { return [] }
                let containerPath = (rootPath as NSString).appendingPathComponent(entry)
                let children = (try? fileManager.contentsOfDirectory(atPath: containerPath)) ?? []
                return children.prefix(16).compactMap { child in
                    guard child.hasSuffix(".app") else { return nil }
                    return (containerPath as NSString).appendingPathComponent(child)
                }
            }
        } else {
            bundlePaths = rootEntries.prefix(2_048).compactMap { entry in
                guard entry.hasSuffix(".app") else { return nil }
                return (rootPath as NSString).appendingPathComponent(entry)
            }
        }

        return bundlePaths.compactMap { bundlePath in
            let infoPath = (bundlePath as NSString).appendingPathComponent("Info.plist")
            let infoSize = (try? fileManager.attributesOfItem(atPath: infoPath)[.size] as? NSNumber)?
                .int64Value ?? 0
            guard infoSize > 0, infoSize <= 2 * 1_024 * 1_024 else { return nil }
            guard let infoURL = validatedLocalFileURL(fromPath: infoPath, isDirectory: false, requireExists: true),
                  let plistData = try? Data(contentsOf: infoURL) else {
                return nil
            }
            return ApplicationBundleMetadataReader.metadata(
                from: plistData,
                localizedInfo: Bundle(path: bundlePath)?.localizedInfoDictionary
            )
        }
    }

    static func launchServicesStoreIdentifiers() -> [String] {
        guard hasPrivilegedContainerAccess() else {
            return [ownBundleID]
        }

        var cachePaths: [String] = []
        var seenCachePaths = Set<String>()

        func addCachePath(_ rawPath: String) {
            let path = ContainerDiscoveryMerger.canonicalPath(rawPath)
            guard !path.isEmpty, seenCachePaths.insert(path).inserted else { return }
            cachePaths.append(path)
        }

        var serviceLookupError: NSString?
        if let servicePath = MCMActivateContainerPath(
            10,
            "com.apple.lsd",
            false,
            &serviceLookupError
        ) {
            addCachePath((servicePath as NSString).appendingPathComponent("Library/Caches"))
        }

        var identifiers: [String] = []
        var seenIdentifiers = Set<String>()
        let maximumCandidateCount = 65_536

        for cachePath in cachePaths where identifiers.count < maximumCandidateCount {
            let names = (try? FileManager.default.contentsOfDirectory(atPath: cachePath)) ?? []
            for name in names where identifiers.count < maximumCandidateCount {
                guard name.hasPrefix("com.apple.LaunchServices-"),
                      name.hasSuffix("-v2.csstore") else {
                    continue
                }
                let storePath = (cachePath as NSString).appendingPathComponent(name)
                guard let storeURL = validatedLocalFileURL(fromPath: storePath, isDirectory: false, requireExists: true),
                      let size = (try? FileManager.default.attributesOfItem(atPath: storeURL.path)[.size]) as? NSNumber,
                      size.uint64Value > 0,
                      size.uint64Value <= 64 * 1_024 * 1_024,
                      let data = try? Data(contentsOf: storeURL, options: .mappedIfSafe) else {
                    continue
                }
                let remaining = maximumCandidateCount - identifiers.count
                let extracted = LaunchServicesCandidateExtractor.identifiers(from: data, limit: remaining)
                for identifier in extracted where seenIdentifiers.insert(identifier).inserted {
                    identifiers.append(identifier)
                }
            }
        }

        log("browser: LaunchServices store total candidates=\(identifiers.count)")
        return identifiers
    }

    static func isApplicationContainerPath(_ path: String) -> Bool {
        let canonical = canonicalResolvedPath(path)
        guard !canonical.isEmpty else { return false }

        let ownCanonical = canonicalResolvedPath(ownSandboxRootURL.path)
        if canonical == ownCanonical {
            return true
        }
        for groupURL in appGroupContainerURLs() where canonical == canonicalResolvedPath(groupURL.path) {
            return true
        }
        privilegedLock.lock()
        let isRegisteredGroup = registeredAppGroupRootPaths.contains(canonical)
        privilegedLock.unlock()
        if isRegisteredGroup {
            return true
        }

        let lastComponent = (canonical as NSString).lastPathComponent
        guard UUID(uuidString: lastComponent) != nil else { return false }
        if let derivedParent = derivedContainersParentPath {
            let parent = (canonical as NSString).deletingLastPathComponent
            return parent == canonicalResolvedPath(derivedParent)
        }
        return false
    }

    // MARK: Filesystem discovery

    static func enumerateDirectories(path: String, maxInode: Int64 = 2_000_000) -> [String] {
        let clean = path.hasSuffix("/") ? String(path.dropLast()) : path
        guard clean.hasPrefix("/") else { return [] }
        guard isWithinOwnSandbox(clean) || hasPrivilegedContainerAccess() else {
            return []
        }

        if let names = try? FileManager.default.contentsOfDirectory(atPath: clean), !names.isEmpty {
            return names.map { (clean as NSString).appendingPathComponent($0) }
        }

        if isWithinOwnSandbox(clean) {
            var pathC = clean.utf8CString.map { Int8($0) }
            guard let result = bad_query_list(&pathC, maxInode) else {
                return []
            }
            defer { free(result) }
            return String(cString: result).components(separatedBy: "\n").filter { !$0.isEmpty }
        }
        return []
    }

    static func enumerateDirectoriesWithTraversalGrant(path: String) -> [String] {
        enumerateDirectories(path: path)
    }

    static func readContainerMetadata(containerPath: String) -> ContainerMetadata? {
        guard isWithinOwnSandbox(containerPath) || hasPrivilegedContainerAccess() else {
            return nil
        }
        let metadataPath = metadataPath(for: containerPath)
        guard let metadataURL = validatedLocalFileURL(fromPath: metadataPath, isDirectory: false, requireExists: true),
              FileManager.default.isReadableFile(atPath: metadataURL.path),
              let validData = try? Data(contentsOf: metadataURL),
              let plist = try? PropertyListSerialization.propertyList(
                  from: validData,
                  options: [],
                  format: nil
              ) as? [String: Any] else {
            return nil
        }

        let bundleID = plist["MCMMetadataIdentifier"] as? String ?? ""
        var displayName = ""
        if let info = plist["MCMMetadataInfo"] as? [String: Any] {
            displayName = (info["CFBundleDisplayName"] as? String)
                ?? (info["CFBundleName"] as? String)
                ?? ""
        }
        return ContainerMetadata(bundleID: bundleID, displayName: displayName)
    }

    static func metadataPath(for containerPath: String) -> String {
        (containerPath as NSString).appendingPathComponent(
            ".com.apple.mobile_container_manager.metadata.plist"
        )
    }

    static func grantContainerAccess(_ containerPath: String) -> Int64 {
        // Parent-directory traversal via containermanagerd is permanently disabled.
        // Own sandbox paths are accessed directly via standard FileManager APIs.
        _ = containerPath
        return -1
    }

    static func containersFromFilesystem() -> [InstalledApp] {
        guard hasPrivilegedContainerAccess(),
              let appRoot = derivedContainersParentPath else {
            return [ownInstalledApp]
        }

        let dirs = enumerateDirectories(path: appRoot)
        let apps = dirs.compactMap { dir -> InstalledApp? in
            let uuid = (dir as NSString).lastPathComponent
            guard UUID(uuidString: uuid) != nil else { return nil }
            let fallback = ContainerIdentityResolver.fallbackIdentity(containerPath: dir)
            return InstalledApp(
                bundleID: fallback.bundleID,
                name: fallback.displayName,
                containerPath: dir,
                version: "",
                icon: nil
            )
        }
        log("browser: filesystem accepted \(apps.count)/\(dirs.count) app containers")
        return apps
    }

    static func inferredApp(
        for fallback: InstalledApp,
        knownAppsByBundleID: [String: InstalledApp],
        launchServicesIdentifiers: Set<String>
    ) -> InstalledApp? {
        guard UUID(uuidString: fallback.bundleID) != nil else { return fallback }
        guard isWithinOwnSandbox(fallback.containerPath) || hasPrivilegedContainerAccess() else {
            return nil
        }

        if let metadata = readContainerMetadata(containerPath: fallback.containerPath) {
            let bundleID = metadata.bundleID.trimmingCharacters(in: .whitespacesAndNewlines)
            if ContainerBundleCandidateResolver.isValidBundleIdentifier(bundleID),
               !bundleID.hasPrefix("systemgroup.") {
                let info = appInfoForBundleID(bundleID) as? [String: Any] ?? [:]
                let resolvedName = metadata.displayName.isEmpty
                    ? (info["name"] as? String ?? bundleID)
                    : metadata.displayName
                return InstalledApp(
                    bundleID: bundleID,
                    name: resolvedName,
                    containerPath: fallback.containerPath,
                    version: info["version"] as? String ?? "",
                    icon: info["icon"] as? UIImage
                )
            }
        }

        let fm = FileManager.default
        let libraryPath = (fallback.containerPath as NSString).appendingPathComponent("Library")
        let savedStatePath = (libraryPath as NSString).appendingPathComponent("Saved Application State")
        let preferencesPath = (libraryPath as NSString).appendingPathComponent("Preferences")
        let savedStates = (try? fm.contentsOfDirectory(atPath: savedStatePath)) ?? []
        let preferences = (try? fm.contentsOfDirectory(atPath: preferencesPath)) ?? []
        let strongCandidates = ContainerBundleCandidateResolver.candidates(
            savedStateNames: savedStates,
            preferenceFileNames: []
        )
        let candidates = ContainerBundleCandidateResolver.candidates(
            savedStateNames: savedStates,
            preferenceFileNames: preferences
        )

        func resolvedApp(from candidates: [String], source: String) -> InstalledApp? {
            for bundleID in candidates {
                if let known = knownAppsByBundleID[bundleID] {
                    return InstalledApp(
                        bundleID: bundleID,
                        name: known.name,
                        containerPath: fallback.containerPath,
                        version: known.version,
                        icon: known.icon
                    )
                }

                let info = appInfoForBundleID(bundleID) as? [String: Any] ?? [:]
                guard info["found"] as? Bool == true else { continue }
                return InstalledApp(
                    bundleID: bundleID,
                    name: info["name"] as? String ?? bundleID,
                    containerPath: fallback.containerPath,
                    version: info["version"] as? String ?? "",
                    icon: info["icon"] as? UIImage
                )
            }

            guard let bundleID = ContainerBundleCandidateResolver.confirmedCandidate(
                candidates: candidates,
                launchServicesIdentifiers: launchServicesIdentifiers
            ) else {
                return nil
            }
            let uuid = (fallback.containerPath as NSString).lastPathComponent
            log("browser: content+LaunchServices confirmed \(uuid) -> \(bundleID) source=\(source)")
            return InstalledApp(
                bundleID: bundleID,
                name: bundleID,
                containerPath: fallback.containerPath,
                version: "",
                icon: nil
            )
        }

        if let app = resolvedApp(from: candidates, source: "state/preferences") {
            return app
        }
        if let bundleID = strongCandidates.first {
            return InstalledApp(
                bundleID: bundleID,
                name: bundleID,
                containerPath: fallback.containerPath,
                version: "",
                icon: nil
            )
        }

        let artifactPaths = [
            (libraryPath as NSString).appendingPathComponent("SplashBoard/Snapshots"),
            (libraryPath as NSString).appendingPathComponent("Caches/Snapshots"),
            (libraryPath as NSString).appendingPathComponent("Cookies"),
            (libraryPath as NSString).appendingPathComponent("WebKit")
        ]
        let artifactNames = artifactPaths.flatMap {
            (try? fm.contentsOfDirectory(atPath: $0)) ?? []
        }
        let artifactCandidates = ContainerBundleCandidateResolver.candidates(
            savedStateNames: [],
            preferenceFileNames: [],
            artifactNames: artifactNames
        )
        if let app = resolvedApp(from: artifactCandidates, source: "artifacts") {
            return app
        }

        return nil
    }

    static func inferUnidentifiedApps(
        in apps: [InstalledApp],
        knownApps: [InstalledApp],
        launchServicesIdentifiers: Set<String> = []
    ) -> [InstalledApp] {
        guard !apps.isEmpty else { return [] }
        let knownByBundleID = Dictionary(
            knownApps.map { ($0.bundleID, $0) },
            uniquingKeysWith: { first, _ in first }
        )
        var inferredCount = 0
        var skippedRestrictedCount = 0
        let result = apps.map { app -> InstalledApp in
            guard UUID(uuidString: app.bundleID) != nil else { return app }
            guard let inferred = autoreleasepool(invoking: {
                inferredApp(
                    for: app,
                    knownAppsByBundleID: knownByBundleID,
                    launchServicesIdentifiers: launchServicesIdentifiers
                )
            }) else {
                skippedRestrictedCount += 1
                return app
            }
            inferredCount += 1
            if inferredCount <= 5 {
                log("browser: inferred \((app.containerPath as NSString).lastPathComponent) -> \(inferred.bundleID)")
            }
            return inferred
        }
        if inferredCount > 0 || skippedRestrictedCount > 0 {
            log("browser: inferred=\(inferredCount)/\(apps.count) skipped_restricted=\(skippedRestrictedCount)")
        }
        return result
    }

    // MARK: File browsing

    static func listFiles(at path: String) -> [FileEntry] {
        guard isWithinOwnSandbox(path) || hasPrivilegedContainerAccess() else {
            log("listFiles: sandbox protected path skipped (\(path))")
            return []
        }

        let fm = FileManager.default
        guard let items = try? fm.contentsOfDirectory(atPath: path) else {
            log("listFiles: unavailable for \(path) errno=\(errno)")
            return []
        }
        var entries: [FileEntry] = []
        for item in items {
            if item.hasPrefix(".") { continue }
            let full = (path as NSString).appendingPathComponent(item)
            guard let attributes = try? fm.attributesOfItem(atPath: full) else { continue }
            // Never expose symbolic links as folders/files in the browser: resolving a
            // directory link could navigate outside the selected application container.
            if let itemType = attributes[.type] as? FileAttributeType,
               itemType == .typeSymbolicLink {
                continue
            }
            var isDir: ObjCBool = false
            guard fm.fileExists(atPath: full, isDirectory: &isDir) else { continue }
            let size = isDir.boolValue
                ? -1
                : (attributes[.size] as? NSNumber)?.int64Value ?? 0
            entries.append(
                FileEntry(
                    name: item,
                    path: full,
                    isDirectory: isDir.boolValue,
                    size: size,
                    modifiedAt: attributes[.modificationDate] as? Date
                )
            )
        }
        return entries.sorted {
            if $0.isDirectory != $1.isDirectory { return $0.isDirectory }
            return $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending
        }
    }

    static func readTextFile(at path: String, limit: Int = 200_000) -> String {
        guard isWithinOwnSandbox(path) || hasPrivilegedContainerAccess() else {
            return "Sandbox restricted path."
        }
        guard let fileURL = validatedLocalFileURL(fromPath: path, isDirectory: false, requireExists: true),
              let data = try? Data(contentsOf: fileURL) else {
            return "Unable to read file."
        }
        let truncated = data.prefix(limit)
        if let text = String(data: truncated, encoding: .utf8) {
            return data.count > limit ? text + "\n… [truncated]" : text
        }
        if let text = String(data: truncated, encoding: .utf16) {
            return data.count > limit ? text + "\n… [truncated]" : text
        }
        return "Binary data (\(data.count) bytes) — not text."
    }
}
