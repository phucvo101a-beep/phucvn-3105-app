import SwiftUI
import UIKit
import UniformTypeIdentifiers

private enum PatchPackagePickerPolicy {
    static let packageType = UTType(filenameExtension: "3105") ?? .data
    static let allowedContentTypes: [UTType] = [packageType, .data]
    static let copiesSelectedDocument = true
}

private enum WallpaperPackagePickerPolicy {
    static let packageType = UTType(filenameExtension: "tendies") ?? .data
    static let allowedContentTypes: [UTType] = [packageType, .data]
}

struct PatchProjectsView: View {
    @Environment(\.appLanguage) private var language
    @EnvironmentObject private var draftCoordinator: PatchDraftCoordinator
    @EnvironmentObject private var store: PatchProjectStore
    @State private var showCreate = false
    @State private var showImporter = false
    @State private var showWallpaperImporter = false
    @State private var showCleaner = false
    @StateObject private var proxyManager = ProxyManager.shared
    @State private var showProxyManager = false
    @State private var proxyModRefreshID = UUID()
    @State private var wallpaperPackages: [WallpaperStagedPackage] = []
    @State private var wallpaperImportFeedback: WallpaperImportFeedback?
    @State private var wallpaperPendingDeletion: WallpaperStagedPackage?
    @State private var isImportingWallpapers = false
    @State private var showSimulatedWallpaperDetail = false
    @State private var simulatedWallpaperDetailGate = OneShotPresentationGate()
    let onOpenSettings: () -> Void
    let onOpenLogs: () -> Void

    private var allProjectItems: [PatchLibraryItem] {
        let presetIDs = Set(ProxyModPreset.presets.map { $0.id })
        return store.items.filter { !presetIDs.contains($0.id) }
    }

    private var allWallpaperPackages: [WallpaperStagedPackage] { wallpaperPackages }

    private var hasLocalContent: Bool {
        !store.items.isEmpty || !wallpaperPackages.isEmpty
    }

    init(
        onOpenSettings: @escaping () -> Void = {},
        onOpenLogs: @escaping () -> Void = {}
    ) {
        self.onOpenSettings = onOpenSettings
        self.onOpenLogs = onOpenLogs
#if targetEnvironment(simulator)
        _showCreate = State(
            initialValue: ProcessInfo.processInfo.arguments.contains("--simulate-patch-editor")
        )
#endif
    }

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                HStack(spacing: 13) {
                    AppRowIcon(systemName: "square.stack.3d.up.fill", tint: AppTheme.accent, symbolSize: 20, frameSize: 48)
                    VStack(alignment: .leading, spacing: 4) {
                        StudioEyebrow(text: "THƯ VIỆN CỦA TÔI")
                        Text("Dự án của tôi")
                            .font(.system(size: 25, weight: .bold, design: .rounded))
                            .tracking(-0.5)
                            .foregroundStyle(.white)
                        Text("Tạo mới, nhập và quản lý gói dự án")
                            .font(.system(size: 10, weight: .medium))
                            .foregroundStyle(AppTheme.subduedText)
                    }
                    Spacer(minLength: 4)
                    Text(String(format: "%02d", store.items.count + wallpaperPackages.count))
                        .font(.system(size: 12, weight: .bold, design: .monospaced))
                        .foregroundStyle(AppTheme.accent)
                        .padding(.horizontal, 10)
                        .padding(.vertical, 8)
                        .background(Color.white.opacity(0.07), in: Capsule())
                        .overlay { Capsule().strokeBorder(Color.white.opacity(0.12), lineWidth: 1) }
                }
                .padding(.horizontal, AppTheme.pageInset)
                .padding(.top, 15)
                .padding(.bottom, 9)

                List {
                    if !hasLocalContent && (store.isBusy || isImportingWallpapers) {
                        loadingState
                            .listRowSeparator(.hidden)
                    } else if !hasLocalContent {
                        emptyState
                            .listRowSeparator(.hidden)
                    } else {
                        if !allProjectItems.isEmpty {
                            Section(language.text("patch.title")) {
                                ForEach(allProjectItems) { item in
                                    itemRow(item)
                                        .listRowBackground(AppTheme.consoleBackground)
                                        .listRowSeparator(.hidden)
                                        .listRowInsets(EdgeInsets(top: 6, leading: 18, bottom: 6, trailing: 18))
                                }
                                .onDelete { offsets in
                                    offsets.map { allProjectItems[$0] }.forEach(store.delete)
                                }
                            }
                        }
                        if !allWallpaperPackages.isEmpty {
                            Section(language.text("tab.wallpapers")) {
                                ForEach(allWallpaperPackages) { package in
                                    NavigationLink {
                                        InstalledWallpaperPackageDetailView(
                                            package: package,
                                            onApplied: reloadWallpaperPackages
                                        )
                                    } label: {
                                        wallpaperRow(package)
                                    }
                                    .listRowBackground(AppTheme.consoleBackground)
                                    .listRowSeparator(.hidden)
                                    .listRowInsets(EdgeInsets(top: 6, leading: 18, bottom: 6, trailing: 18))
                                    .swipeActions(
                                        edge: .trailing,
                                        allowsFullSwipe: false
                                    ) {
                                        Button(role: .destructive) {
                                            wallpaperPendingDeletion = package
                                        } label: {
                                            Label(
                                                language.text("common.delete"),
                                                systemImage: "trash"
                                            )
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Section(language.text("repository.utilities")) {
                        cleanerRow
                            .listRowBackground(AppTheme.consoleBackground)
                            .listRowSeparator(.hidden)
                            .listRowInsets(EdgeInsets(top: 6, leading: 18, bottom: 6, trailing: 18))
                    }

                    Section("PROXY") {
                        proxyRow
                            .listRowBackground(AppTheme.consoleBackground)
                            .listRowSeparator(.hidden)
                            .listRowInsets(EdgeInsets(top: 6, leading: 18, bottom: 6, trailing: 18))

                        ForEach(ProxyModPreset.presets) { mod in
                            NavigationLink {
                                ProxyModPresetDetailView(mod: mod, onModified: {
                                    proxyModRefreshID = UUID()
                                })
                            } label: {
                                proxyModRow(mod)
                            }
                            .listRowBackground(AppTheme.consoleBackground)
                            .listRowSeparator(.hidden)
                            .listRowInsets(EdgeInsets(top: 6, leading: 18, bottom: 6, trailing: 18))
                        }
                    }
                    .id(proxyModRefreshID)

                    Section {
                        Color.clear
                            .frame(height: 95)
                            .listRowBackground(Color.clear)
                            .listRowSeparator(.hidden)
                    }
                }
                .listStyle(.plain)
                .scrollContentBackground(.hidden)
                .scrollIndicators(.hidden)
                .safeAreaInset(edge: .bottom) {
                    Color.clear.frame(height: 40)
                }
                .background { AppPageBackground() }
            }
            .background { AppPageBackground() }
            .navigationTitle("")
            .navigationBarTitleDisplayMode(.inline)
            .toolbarBackground(AppTheme.pageBackground.opacity(0.94), for: .navigationBar)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Menu {
                        Button {
                            showCreate = true
                        } label: {
                            Label(language.text("patch.new"), systemImage: "doc.badge.plus")
                        }
                        Button {
                            showImporter = true
                        } label: {
                            Label(language.text("patch.import"), systemImage: "square.and.arrow.down")
                        }
                        Button {
                            showWallpaperImporter = true
                        } label: {
                            Label(
                                language.text("wallpaper.import"),
                                systemImage: "photo.badge.plus"
                            )
                        }
                    } label: {
                        if store.isBusy || isImportingWallpapers {
                            ProgressView()
                        } else {
                            Image(systemName: "plus")
                        }
                    }
                    .disabled(store.isBusy || isImportingWallpapers)
                    .accessibilityLabel(language.text("patch.add"))
                }
                AppUtilityToolbar(
                    language: language,
                    onOpenSettings: onOpenSettings,
                    onOpenLogs: onOpenLogs
                )
            }
            .sheet(isPresented: $showImporter) {
                FileDocumentPicker(
                    allowedContentTypes: PatchPackagePickerPolicy.allowedContentTypes,
                    copiesSelectedDocument: PatchPackagePickerPolicy.copiesSelectedDocument,
                    allowsMultipleSelection: false,
                    onSelection: { result in
                        showImporter = false
                        if case .success(let urls) = result, let url = urls.first {
                            store.importPackage(at: url)
                        }
                    },
                    onCancel: {
                        showImporter = false
                    }
                )
                .ignoresSafeArea()
            }
            .sheet(isPresented: $showCreate) {
                PatchProjectEditorView(
                    existingProject: nil,
                    passwordIsProtected: false
                ) { project, password in
                    store.create(project: project, password: password)
                }
            }
            .sheet(isPresented: $showCleaner) {
                CleanerView()
            }
            .sheet(isPresented: $showProxyManager) {
                ProxyManagerView()
            }
            .sheet(item: $draftCoordinator.request) { request in
                PatchProjectEditorView(
                    existingProject: nil,
                    passwordIsProtected: false,
                    initialDraft: request.draft
                ) { project, password in
                    store.create(project: project, password: password)
                    draftCoordinator.clear()
                }
            }
            .sheet(isPresented: $showWallpaperImporter) {
                FileDocumentPicker(
                    allowedContentTypes: WallpaperPackagePickerPolicy.allowedContentTypes,
                    copiesSelectedDocument: true,
                    allowsMultipleSelection: true,
                    onSelection: { result in
                        showWallpaperImporter = false
                        if case .success(let urls) = result, !urls.isEmpty {
                            importWallpaperPackages(urls)
                        }
                    },
                    onCancel: {
                        showWallpaperImporter = false
                    }
                )
                .ignoresSafeArea()
            }
            .alert(item: $wallpaperImportFeedback) { feedback in
                Alert(
                    title: Text(language.text(feedback.titleKey)),
                    message: Text(feedback.message),
                    dismissButton: .default(Text(language.text("common.ok")))
                )
            }
            .alert(item: $wallpaperPendingDeletion) { package in
                Alert(
                    title: Text(language.text("wallpaper.delete_title")),
                    message: Text(language.text(
                        "wallpaper.delete_message",
                        package.displayName
                    )),
                    primaryButton: .destructive(
                        Text(language.text("common.delete"))
                    ) {
                        deleteWallpaperPackage(package)
                    },
                    secondaryButton: .cancel(Text(language.text("common.cancel")))
                )
            }
            .onAppear {
                reloadWallpaperPackages()
                consumeExternalImport()
#if targetEnvironment(simulator)
                if ProcessInfo.processInfo.arguments.contains(
                    "--simulate-wallpaper-detail"
                ), !wallpaperPackages.isEmpty,
                   simulatedWallpaperDetailGate.claim() {
                    DispatchQueue.main.async {
                        showSimulatedWallpaperDetail = true
                    }
                }
#endif
            }
            .navigationDestination(isPresented: $showSimulatedWallpaperDetail) {
                if let package = wallpaperPackages.first {
                    InstalledWallpaperPackageDetailView(
                        package: package,
                        onApplied: reloadWallpaperPackages
                    )
                }
            }
            .onChange(of: draftCoordinator.importRequest?.id) { _ in
                consumeExternalImport()
            }
        }
    }

    private func consumeExternalImport() {
        guard let request = draftCoordinator.importRequest else { return }
        draftCoordinator.clearImport()
        store.importPackage(from: request.source)
    }

    private func wallpaperRow(_ package: WallpaperStagedPackage) -> some View {
        HStack(spacing: 12) {
            AppRowIcon(systemName: wallpaperSymbol)
            VStack(alignment: .leading, spacing: 3) {
                Text(package.displayName)
                    .font(.body.weight(.semibold))
                    .foregroundStyle(.primary)
                    .lineLimit(1)
                InstalledContentKindBadge(kind: .wallpaper, language: language)
                Text(language.text(
                    "wallpaper.package_summary",
                    Int64(package.payload.descriptors.count),
                    ByteCountFormatter.string(
                        fromByteCount: package.payload.totalBytes,
                        countStyle: .file
                    )
                ))
                .font(.caption)
                .foregroundStyle(.secondary)
            }
        }
        .padding(12)
        .background(AppTheme.elevatedBackground, in: RoundedRectangle(cornerRadius: 14, style: .continuous))
        .overlay { RoundedRectangle(cornerRadius: 14, style: .continuous).strokeBorder(AppTheme.hairline, lineWidth: 1) }
    }

    private var cleanerRow: some View {
        Button {
            showCleaner = true
        } label: {
            HStack(spacing: 12) {
                AppRowIcon(systemName: "sparkles")
                VStack(alignment: .leading, spacing: 3) {
                    Text(language.text("tab.cleaner"))
                        .font(.body.weight(.semibold))
                        .foregroundStyle(.primary)
                    Text(language.text("repository.cleaner_subtitle"))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Image(systemName: "chevron.right")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.tertiary)
                    .accessibilityHidden(true)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    private var proxyRow: some View {
        Button {
            showProxyManager = true
        } label: {
            HStack(spacing: 12) {
                AppRowIcon(
                    systemName: "network",
                    tint: proxyManager.isEnabled ? AppTheme.success : AppTheme.accent
                )
                VStack(alignment: .leading, spacing: 3) {
                    HStack(spacing: 6) {
                        Text("Cấu hình Proxy")
                            .font(.body.weight(.semibold))
                            .foregroundStyle(.primary)
                        if proxyManager.isEnabled {
                            Text("ĐANG BẬT")
                                .font(.system(size: 9, weight: .bold))
                                .foregroundStyle(AppTheme.success)
                                .padding(.horizontal, 6)
                                .padding(.vertical, 2)
                                .background(AppTheme.success.opacity(0.15), in: Capsule())
                        }
                    }
                    Text(proxyManager.isEnabled ? "Đang bật • \(proxyManager.host):\(proxyManager.port)" : "Thiết lập máy chủ Proxy, giảm ping & vượt kiểm tra")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
                Spacer()
                Image(systemName: "chevron.right")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.tertiary)
                    .accessibilityHidden(true)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    private func proxyModRow(_ mod: ProxyModPreset) -> some View {
        let isApplied = DevicePatchService.latestReceipt(projectID: mod.id) != nil
        return HStack(spacing: 12) {
            AppRowIcon(
                systemName: mod.iconName,
                tint: isApplied ? AppTheme.success : AppTheme.accent
            )
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(mod.name)
                        .font(.body.weight(.bold))
                        .foregroundStyle(.white)
                    Text(isApplied ? "ĐÃ ÁP DỤNG" : "CHƯA ÁP DỤNG")
                        .font(.system(size: 8.5, weight: .bold))
                        .foregroundStyle(isApplied ? AppTheme.success : AppTheme.subduedText)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background((isApplied ? AppTheme.success : Color.white).opacity(0.12), in: Capsule())
                }
                Text(mod.subtitle)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            Spacer()
            Image(systemName: "chevron.right")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.tertiary)
                .accessibilityHidden(true)
        }
        .contentShape(Rectangle())
    }

    private var wallpaperSymbol: String {
        if #available(iOS 18.0, *) {
            return "photo.on.rectangle.angled.fill"
        }
        return "photo.fill.on.rectangle.fill"
    }

    private func reloadWallpaperPackages() {
        wallpaperPackages = WallpaperPackageStore.packages()
    }

    private func deleteWallpaperPackage(_ package: WallpaperStagedPackage) {
        do {
            try WallpaperPackageStore.delete(package)
            reloadWallpaperPackages()
        } catch {
            wallpaperImportFeedback = WallpaperImportFeedback(
                titleKey: "wallpaper.operation_failed",
                message: wallpaperErrorMessage(error)
            )
        }
    }

    private func importWallpaperPackages(_ urls: [URL]) {
        guard !isImportingWallpapers else { return }
        isImportingWallpapers = true
        DispatchQueue.global(qos: .userInitiated).async {
            var imported = 0
            var failures: [String] = []
            for url in urls {
                do {
                    _ = try WallpaperPackageStore.importPackage(from: url)
                    imported += 1
                    log("wallpaper: staged \(url.lastPathComponent)")
                } catch {
                    failures.append(
                        "\(url.lastPathComponent): \(wallpaperErrorMessage(error))"
                    )
                    log("wallpaper: import rejected \(url.lastPathComponent)")
                }
            }
            DispatchQueue.main.async {
                isImportingWallpapers = false
                reloadWallpaperPackages()
                wallpaperImportFeedback = WallpaperImportFeedback(
                    titleKey: failures.isEmpty
                        ? "wallpaper.import_done_title"
                        : "wallpaper.import_result_title",
                    message: failures.isEmpty
                        ? language.text(
                            "wallpaper.import_done_message",
                            Int64(imported)
                        )
                        : failures.joined(separator: "\n")
                )
            }
        }
    }

    private func wallpaperErrorMessage(_ error: Error) -> String {
        if let wallpaperError = error as? WallpaperLabError {
            return language.text(wallpaperError.localizationKey)
        }
        return language.text("wallpaper.error.unknown")
    }

    @ViewBuilder
    private func itemRow(_ item: PatchLibraryItem) -> some View {
        if item.isLocked {
            Button { store.requestUnlock(for: item) } label: {
                PatchProjectRow(item: item, language: language)
            }
            .buttonStyle(.plain)
        } else {
            NavigationLink {
                PatchProjectDetailView(store: store, projectID: item.id)
            } label: {
                PatchProjectRow(item: item, language: language)
            }
        }
    }

    private var emptyState: some View {
        VStack(spacing: 12) {
            Image(systemName: "shippingbox")
                .font(.system(size: AppTheme.emptyIconSize, weight: .light))
                .foregroundStyle(AppTheme.accent)
            Text(language.text("installed.empty_title"))
                .font(.headline)
            Text(language.text("installed.empty_message"))
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Button(language.text("patch.new")) { showCreate = true }
                .buttonStyle(.bordered)
                .controlSize(.large)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 64)
    }

    private var loadingState: some View {
        VStack(spacing: 12) {
            ProgressView()
            Text(language.text("installed.loading"))
                .font(.subheadline)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 64)
    }


}

private struct WallpaperImportFeedback: Identifiable {
    let id = UUID()
    let titleKey: String
    let message: String
}

private struct PatchProjectRow: View {
    let item: PatchLibraryItem
    let language: AppLanguage

    var body: some View {
        HStack(spacing: 12) {
            AppRowIcon(systemName: item.isLocked ? "lock.doc.fill" : "shippingbox.fill")
            VStack(alignment: .leading, spacing: 3) {
                Text(item.project?.name ?? language.text("patch.locked_project"))
                    .font(.body.weight(.semibold))
                    .foregroundStyle(.primary)
                    .lineLimit(1)
                InstalledContentKindBadge(kind: .patch, language: language)
                if let author = item.project?.author, !author.isEmpty {
                    Text(language.text("patch.by_author", author))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Text(rowDetail)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            if item.summary.isPasswordProtected {
                Image(systemName: "key.fill")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .accessibilityLabel(language.text("patch.password_protected"))
            }
            if item.project?.isPrivate == true {
                Image(systemName: "eye.slash.fill")
                    .font(.caption)
                    .foregroundStyle(AppTheme.accent)
                    .accessibilityLabel(language.text("patch.private"))
            }
        }
        .padding(.vertical, 4)
    }

    private var rowDetail: String {
        if item.isLocked {
            return language.text("patch.tap_to_unlock")
        }
        if item.project?.isPrivate == true, !item.isAuthorCopy {
            return language.text("patch.private_received")
        }
        return language.text(
            item.summary.schemaVersion >= 2
                ? "patch.workspace_items_count"
                : "patch.rules_count",
            Int64((item.project?.rules.count ?? 0) + (item.project?.directories.count ?? 0))
        )
    }
}

private enum InstalledContentKind {
    case patch
    case wallpaper

    var localizationKey: String {
        switch self {
        case .patch: return "installed.kind.patch"
        case .wallpaper: return "installed.kind.wallpaper"
        }
    }

    var systemImage: String {
        switch self {
        case .patch: return "shippingbox.fill"
        case .wallpaper: return "photo.fill"
        }
    }
}

private struct InstalledContentKindBadge: View {
    let kind: InstalledContentKind
    let language: AppLanguage

    var body: some View {
        HStack(spacing: 4) {
            Image(systemName: kind.systemImage)
                .accessibilityHidden(true)
            Text(language.text(kind.localizationKey))
        }
            .font(.caption2.weight(.semibold))
            .foregroundStyle(AppTheme.accent)
            .padding(.horizontal, 8)
            .frame(height: 24)
            .background(AppTheme.accent.opacity(0.12), in: Capsule())
            .fixedSize()
            .accessibilityElement(children: .combine)
    }
}

struct PatchUnlockView: View {
    @Environment(\.appLanguage) private var language
    @Environment(\.dismiss) private var dismiss
    @ObservedObject var store: PatchProjectStore
    let request: PatchPasswordRequest
    @State private var password = ""

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    SecureField(language.text("patch.password"), text: $password)
                        .textContentType(.password)
                        .submitLabel(.done)
                        .onSubmit(unlock)
                        .onChange(of: password) { _ in
                            store.clearUnlockError()
                        }
                    if let errorKey = store.unlockErrorKey {
                        Text(language.text(errorKey))
                            .font(.footnote)
                            .foregroundStyle(.red)
                    }
                } footer: {
                    if let origin = request.origin {
                        Text(language.text(
                            "patch.password_repo_contact",
                            origin.repositoryName
                        ))
                    } else {
                        Text(language.text("patch.password_once_message"))
                    }
                }
            }
            .navigationTitle(language.text("patch.unlock"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(language.text("common.cancel")) { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button(language.text("patch.unlock"), action: unlock)
                        .disabled(password.isEmpty || store.isBusy)
                }
            }
        }
    }

    private func unlock() {
        guard !password.isEmpty else { return }
        store.unlock(password: password)
    }
}

private struct PatchStorePresentationModifier: ViewModifier {
    @Environment(\.appLanguage) private var language
    @ObservedObject var store: PatchProjectStore

    func body(content: Content) -> some View {
        content
            .sheet(item: $store.passwordRequest, onDismiss: store.cancelUnlock) { request in
                PatchUnlockView(store: store, request: request)
            }
            .alert(item: $store.alert) { alert in
                Alert(
                    title: Text(language.text(alert.titleKey)),
                    message: Text(alert.message(language: language)),
                    dismissButton: .default(Text(language.text("common.ok")))
                )
            }
    }
}

extension View {
    func patchStorePresentation(_ store: PatchProjectStore) -> some View {
        modifier(PatchStorePresentationModifier(store: store))
    }
}

private struct PatchProjectDetailView: View {
    @Environment(\.appLanguage) private var language
    @ObservedObject var store: PatchProjectStore
    let projectID: UUID
    @State private var showEditor = false
    @State private var editingRule: PatchRule?
    @State private var showApplyConfirmation = false
    @State private var showRestoreConfirmation = false
    @State private var showChangedRestoreConfirmation = false
    @State private var showResetConfirmation = false
    @State private var restoreChangedPaths: [String] = []
    @State private var isWorking = false
    @State private var actionAlert: PatchStoreAlert?
    @State private var shareRequest: PatchShareRequest?

    private var item: PatchLibraryItem? {
        store.items.first(where: { $0.id == projectID })
    }

    private var receipt: PatchTransactionReceipt? {
        DevicePatchService.latestReceipt(projectID: projectID)
    }

    private var isWorkspaceProject: Bool {
        (item?.summary.schemaVersion ?? 1) >= 2
    }

    var body: some View {
        List {
            if let item, let project = item.project {
                Section(language.text("patch.information")) {
                    if !project.author.isEmpty {
                        patchInfoRow(
                            label: language.text("patch.author"),
                            value: project.author
                        )
                    }
                    patchInfoRow(label: language.text("patch.privacy")) {
                        Label(
                            language.text(project.isPrivate
                                ? "patch.private"
                                : "patch.public"),
                            systemImage: project.isPrivate
                                ? "eye.slash.fill"
                                : "eye"
                        )
                        .foregroundStyle(project.isPrivate ? AppTheme.accent : Color.secondary)
                    }
                    if let origin = item.origin {
                        patchInfoRow(
                            label: language.text("repository.source"),
                            value: origin.repositoryName
                        )
                    }
                }

                if project.isPrivate && !item.canInspectContents {
                    Section {
                        VStack(spacing: 10) {
                            Image(systemName: "lock.shield.fill")
                                .font(.system(size: 30, weight: .medium))
                                .foregroundStyle(AppTheme.accent)
                            Text(language.text("patch.private_hidden_title"))
                                .font(.headline)
                            Text(language.text("patch.private_hidden_message"))
                                .font(.subheadline)
                                .foregroundStyle(.secondary)
                                .multilineTextAlignment(.center)
                        }
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 20)
                    }
                } else if isWorkspaceProject {
                    Section {
                        ForEach(project.allBundleIdentifiers, id: \.self) { bundleID in
                            Label {
                                Text(bundleID)
                                    .font(.subheadline.monospaced())
                            } icon: {
                                Image(systemName: "app.dashed")
                                    .foregroundStyle(AppTheme.accent)
                            }
                        }
                        LabeledContent(language.text("patch.files")) {
                            Text("\(project.rules.count)")
                        }
                        LabeledContent(language.text("patch.folders")) {
                            Text("\(project.directories.count)")
                        }
                        if let workspaceURL = item.workspaceURL {
                            NavigationLink {
                                FileBrowserView(
                                    containerPath: workspaceURL.path,
                                    title: project.name,
                                    bundleID: nil
                                )
                            } label: {
                                Label(
                                    language.text("patch.open_workspace"),
                                    systemImage: "folder"
                                )
                            }
                        }
                    } header: {
                        Text(language.text("patch.workspace"))
                    } footer: {
                        Text(language.text("patch.workspace_detail_footer"))
                    }
                } else {
                    Section {
                        ForEach(project.rules) { rule in
                            Button {
                                editingRule = rule
                            } label: {
                                HStack(spacing: 10) {
                                    ruleSummary(rule)
                                    Spacer(minLength: 8)
                                    Image(systemName: "chevron.right")
                                        .font(.caption.weight(.semibold))
                                        .foregroundStyle(.tertiary)
                                }
                                .contentShape(Rectangle())
                            }
                            .buttonStyle(.plain)
                            .accessibilityHint(language.text("patch.edit_rule_hint"))
                        }
                    } header: {
                        Text(language.text("patch.rules"))
                    } footer: {
                        Text(language.text("patch.legacy_footer"))
                    }
                }

                Section(language.text("patch.password")) {
                    HStack(spacing: 12) {
                        Image(systemName: item.summary.isPasswordProtected ? "lock.fill" : "lock.open")
                            .foregroundStyle(AppTheme.accent)
                            .frame(width: 24)
                        Text(language.text(item.summary.isPasswordProtected
                            ? "patch.password_locked"
                            : "patch.no_password"))
                            .font(.subheadline)
                    }
                }

                Section {
                    Button {
                        showApplyConfirmation = true
                    } label: {
                        actionLabel("patch.apply", systemImage: "checkmark.shield.fill")
                    }
                    .disabled(isWorking || receipt != nil)

                    if receipt != nil {
                        Button {
                            showResetConfirmation = true
                        } label: {
                            actionLabel("patch.reset", systemImage: "arrow.counterclockwise.circle")
                        }
                        .disabled(isWorking)

                        Button(role: .destructive) {
                            showRestoreConfirmation = true
                        } label: {
                            actionLabel("patch.restore", systemImage: "arrow.uturn.backward.circle")
                        }
                        .disabled(isWorking)
                    }

                    Button(action: prepareExport) {
                        actionLabel("patch.export", systemImage: "square.and.arrow.up")
                    }
                    .disabled(isWorking)
                } footer: {
                    Text(language.text("patch.apply_footer"))
                }

                Section {
                    Color.clear
                        .frame(height: 85)
                        .listRowBackground(Color.clear)
                        .listRowSeparator(.hidden)
                }
            }
        }
        .listStyle(.insetGrouped)
        .safeAreaInset(edge: .bottom) {
            Color.clear.frame(height: 30)
        }
        .navigationTitle(item?.project?.name ?? language.text("patch.title"))
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                if isWorking {
                    ProgressView()
                } else if !isWorkspaceProject, item?.canInspectContents == true {
                    Button(language.text("patch.edit")) { showEditor = true }
                        .disabled(item?.project == nil)
                }
            }
        }
        .sheet(isPresented: $showEditor) {
            if let item, let project = item.project {
                PatchProjectEditorView(
                    existingProject: project,
                    passwordIsProtected: item.summary.isPasswordProtected
                ) { updatedProject, _ in
                    store.update(project: updatedProject)
                }
            }
        }
        .sheet(item: $editingRule) { rule in
            PatchRuleEditorView(rule: rule) { updatedRule in
                updateRule(updatedRule)
            }
        }
        .confirmationDialog(
            language.text("patch.apply_confirm_title"),
            isPresented: $showApplyConfirmation,
            titleVisibility: .visible
        ) {
            Button(language.text("patch.apply")) { apply() }
            Button(language.text("common.cancel"), role: .cancel) {}
        } message: {
            Text(language.text("patch.apply_confirm_message"))
        }
        .confirmationDialog(
            language.text("patch.restore_confirm_title"),
            isPresented: $showRestoreConfirmation,
            titleVisibility: .visible
        ) {
            Button(language.text("patch.restore"), role: .destructive) { prepareRestore() }
            Button(language.text("common.cancel"), role: .cancel) {}
        } message: {
            Text(language.text("patch.restore_confirm_message"))
        }
        .confirmationDialog(
            language.text("patch.restore_changed_title"),
            isPresented: $showChangedRestoreConfirmation,
            titleVisibility: .visible
        ) {
            Button(language.text("patch.restore_changed_action"), role: .destructive) {
                restore(allowChangedTargets: true)
            }
            Button(language.text("common.cancel"), role: .cancel) {}
        } message: {
            Text(changedRestoreMessage)
        }
        .confirmationDialog(
            language.text("patch.reset_confirm_title"),
            isPresented: $showResetConfirmation,
            titleVisibility: .visible
        ) {
            Button(language.text("patch.reset"), role: .destructive) { resetToAppliedState() }
            Button(language.text("common.cancel"), role: .cancel) {}
        } message: {
            Text(language.text("patch.reset_confirm_message"))
        }
        .alert(item: $actionAlert) { alert in
            Alert(
                title: Text(language.text(alert.titleKey)),
                message: Text(alert.message(language: language)),
                dismissButton: .default(Text(language.text("common.ok")))
            )
        }
        .sheet(item: $shareRequest) { request in
            PatchActivityView(items: [request.url])
                .ignoresSafeArea()
        }
    }

    private func actionLabel(_ key: String, systemImage: String) -> some View {
        Label(language.text(key), systemImage: systemImage)
            .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func patchInfoRow(
        label: String,
        value: String
    ) -> some View {
        patchInfoRow(label: label) {
            Text(value)
                .foregroundStyle(.primary)
        }
    }

    private func patchInfoRow<Content: View>(
        label: String,
        @ViewBuilder value: () -> Content
    ) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            Text(label)
                .foregroundStyle(.secondary)
            Spacer(minLength: 16)
            value()
                .multilineTextAlignment(.trailing)
                .fixedSize(horizontal: false, vertical: true)
        }
        .font(.subheadline)
        .padding(.vertical, 5)
    }

    private func ruleSummary(_ rule: PatchRule) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(rule.bundleID)
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(.primary)
            Text(rule.relativePath)
                .font(.caption.monospaced())
                .foregroundStyle(.secondary)
                .lineLimit(2)
            Label(rule.replacementFilename, systemImage: "arrow.triangle.2.circlepath")
                .font(.caption)
                .foregroundStyle(AppTheme.accent)
        }
        .padding(.vertical, 3)
    }

    private func updateRule(_ updatedRule: PatchRule) {
        guard var project = item?.project,
              let index = project.rules.firstIndex(where: { $0.id == updatedRule.id }) else {
            return
        }
        project.rules[index] = updatedRule
        project.updatedAt = Date()
        do {
            try PatchPackageCodec.validate(project)
            store.update(project: project)
        } catch let error as PatchPackageError {
            actionAlert = PatchStoreAlert(
                titleKey: "common.failed",
                messageKey: error.localizationKey,
                messageArgument: error.localizationArgument
            )
        } catch {
            actionAlert = PatchStoreAlert(
                titleKey: "common.failed",
                messageKey: "patch.error.invalid_project"
            )
        }
    }

    private func apply() {
        guard let item, let baseProject = item.project else { return }
        isWorking = true
        Task.detached(priority: .userInitiated) {
            do {
                let project = item.summary.schemaVersion >= 2 && item.canInspectContents
                    ? try PatchProjectLibrary.synchronizeWorkspace(item: item)
                    : baseProject
                _ = try DevicePatchService.apply(project: project)
                await MainActor.run {
                    store.reload()
                    isWorking = false
                    actionAlert = PatchStoreAlert(titleKey: "common.done", messageKey: "patch.applied_message")
                }
            } catch let error as PatchPackageError {
                await MainActor.run {
                    isWorking = false
                    actionAlert = PatchStoreAlert(
                        titleKey: "common.failed",
                        messageKey: privateErrorKey(for: error),
                        messageArgument: privateErrorArgument(for: error)
                    )
                }
            } catch {
                await MainActor.run {
                    isWorking = false
                    actionAlert = PatchStoreAlert(titleKey: "common.failed", messageKey: "patch.error.apply")
                }
            }
        }
    }

    private func prepareExport() {
        guard let item else { return }
        isWorking = true
        Task.detached(priority: .userInitiated) {
            do {
                if item.summary.schemaVersion >= 2, item.canInspectContents {
                    _ = try PatchProjectLibrary.synchronizeWorkspace(item: item)
                }
                await MainActor.run {
                    store.reload()
                    isWorking = false
                    shareRequest = PatchShareRequest(url: item.packageURL)
                }
            } catch let error as PatchPackageError {
                await MainActor.run {
                    isWorking = false
                    actionAlert = PatchStoreAlert(
                        titleKey: "common.failed",
                        messageKey: privateErrorKey(for: error),
                        messageArgument: privateErrorArgument(for: error)
                    )
                }
            } catch {
                await MainActor.run {
                    isWorking = false
                    actionAlert = PatchStoreAlert(
                        titleKey: "common.failed",
                        messageKey: "patch.error.invalid_project"
                    )
                }
            }
        }
    }

    private var changedRestoreMessage: String {
        guard item?.project?.isPrivate != true || item?.isAuthorCopy == true else {
            return language.text(
                "patch.restore_changed_private_message",
                Int64(restoreChangedPaths.count)
            )
        }
        var visiblePaths = restoreChangedPaths.prefix(5).joined(separator: "\n")
        if restoreChangedPaths.count > 5 {
            visiblePaths += "\n…"
        }
        return language.text(
            "patch.restore_changed_message",
            Int64(restoreChangedPaths.count),
            visiblePaths
        )
    }

    private func prepareRestore() {
        guard let receipt else { return }
        isWorking = true
        Task.detached(priority: .userInitiated) {
            do {
                let inspection = try DevicePatchService.inspectRestore(receipt: receipt)
                if inspection.changedTargets.isEmpty {
                    try DevicePatchService.restore(receipt: receipt)
                    await MainActor.run {
                        isWorking = false
                        actionAlert = PatchStoreAlert(
                            titleKey: "common.done",
                            messageKey: "patch.restored_message"
                        )
                    }
                } else {
                    await MainActor.run {
                        isWorking = false
                        restoreChangedPaths = inspection.changedTargets.map(\.displayPath)
                        showChangedRestoreConfirmation = true
                    }
                }
            } catch let error as PatchPackageError {
                await MainActor.run {
                    isWorking = false
                    actionAlert = PatchStoreAlert(
                        titleKey: "common.failed",
                        messageKey: privateErrorKey(for: error),
                        messageArgument: privateErrorArgument(for: error)
                    )
                }
            } catch {
                await MainActor.run {
                    isWorking = false
                    actionAlert = PatchStoreAlert(
                        titleKey: "common.failed",
                        messageKey: "patch.error.restore"
                    )
                }
            }
        }
    }

    private func restore(allowChangedTargets: Bool) {
        guard let receipt else { return }
        isWorking = true
        Task.detached(priority: .userInitiated) {
            do {
                try DevicePatchService.restore(
                    receipt: receipt,
                    allowChangedTargets: allowChangedTargets
                )
                await MainActor.run {
                    isWorking = false
                    actionAlert = PatchStoreAlert(titleKey: "common.done", messageKey: "patch.restored_message")
                }
            } catch let error as PatchPackageError {
                await MainActor.run {
                    isWorking = false
                    actionAlert = PatchStoreAlert(
                        titleKey: "common.failed",
                        messageKey: privateErrorKey(for: error),
                        messageArgument: privateErrorArgument(for: error)
                    )
                }
            } catch {
                await MainActor.run {
                    isWorking = false
                    actionAlert = PatchStoreAlert(titleKey: "common.failed", messageKey: "patch.error.restore")
                }
            }
        }
    }

    private func resetToAppliedState() {
        guard let receipt, let project = item?.project else { return }
        isWorking = true
        Task.detached(priority: .userInitiated) {
            do {
                try DevicePatchService.resetToAppliedState(
                    receipt: receipt,
                    project: project
                )
                await MainActor.run {
                    isWorking = false
                    actionAlert = PatchStoreAlert(
                        titleKey: "common.done",
                        messageKey: "patch.reset_message"
                    )
                }
            } catch let error as PatchPackageError {
                await MainActor.run {
                    isWorking = false
                    actionAlert = PatchStoreAlert(
                        titleKey: "common.failed",
                        messageKey: privateErrorKey(for: error),
                        messageArgument: privateErrorArgument(for: error)
                    )
                }
            } catch {
                await MainActor.run {
                    isWorking = false
                    actionAlert = PatchStoreAlert(
                        titleKey: "common.failed",
                        messageKey: "patch.error.reset"
                    )
                }
            }
        }
    }

    private func privateErrorKey(for error: PatchPackageError) -> String {
        guard item?.project?.isPrivate == true,
              item?.isAuthorCopy == false else {
            return error.localizationKey
        }
        return "patch.error.private_operation"
    }

    private func privateErrorArgument(for error: PatchPackageError) -> String? {
        guard item?.project?.isPrivate == true,
              item?.isAuthorCopy == false else {
            return error.localizationArgument
        }
        return nil
    }
}

private struct PatchShareRequest: Identifiable {
    let id = UUID()
    let url: URL
}

private struct PatchActivityView: UIViewControllerRepresentable {
    let items: [Any]

    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: items, applicationActivities: nil)
    }

    func updateUIViewController(
        _ uiViewController: UIActivityViewController,
        context: Context
    ) {}
}

// MARK: - Proxy Manager & Configuration

class ProxyManager: ObservableObject {
    static let shared = ProxyManager()

    private let enabledKey = "PHUCVN_PROXY_ENABLED"
    private let hostKey = "PHUCVN_PROXY_HOST"
    private let portKey = "PHUCVN_PROXY_PORT"
    private let typeKey = "PHUCVN_PROXY_TYPE"
    private let userKey = "PHUCVN_PROXY_USERNAME"
    private let passKey = "PHUCVN_PROXY_PASSWORD"
    private let bypassAntiCheatKey = "PHUCVN_PROXY_BYPASS_AC"
    private let optimizePingKey = "PHUCVN_PROXY_OPTIMIZE_PING"

    @Published var isEnabled: Bool {
        didSet { UserDefaults.standard.set(isEnabled, forKey: enabledKey) }
    }
    @Published var host: String {
        didSet { UserDefaults.standard.set(host, forKey: hostKey) }
    }
    @Published var port: String {
        didSet { UserDefaults.standard.set(port, forKey: portKey) }
    }
    @Published var proxyType: String {
        didSet { UserDefaults.standard.set(proxyType, forKey: typeKey) }
    }
    @Published var username: String {
        didSet { UserDefaults.standard.set(username, forKey: userKey) }
    }
    @Published var password: String {
        didSet { UserDefaults.standard.set(password, forKey: passKey) }
    }
    @Published var bypassAntiCheat: Bool {
        didSet { UserDefaults.standard.set(bypassAntiCheat, forKey: bypassAntiCheatKey) }
    }
    @Published var optimizePing: Bool {
        didSet { UserDefaults.standard.set(optimizePing, forKey: optimizePingKey) }
    }

    init() {
        self.isEnabled = UserDefaults.standard.bool(forKey: "PHUCVN_PROXY_ENABLED")
        self.host = UserDefaults.standard.string(forKey: "PHUCVN_PROXY_HOST") ?? ""
        self.port = UserDefaults.standard.string(forKey: "PHUCVN_PROXY_PORT") ?? "8080"
        self.proxyType = UserDefaults.standard.string(forKey: "PHUCVN_PROXY_TYPE") ?? "HTTP"
        self.username = UserDefaults.standard.string(forKey: "PHUCVN_PROXY_USERNAME") ?? ""
        self.password = UserDefaults.standard.string(forKey: "PHUCVN_PROXY_PASSWORD") ?? ""
        self.bypassAntiCheat = UserDefaults.standard.object(forKey: "PHUCVN_PROXY_BYPASS_AC") as? Bool ?? true
        self.optimizePing = UserDefaults.standard.object(forKey: "PHUCVN_PROXY_OPTIMIZE_PING") as? Bool ?? true
    }

    func testConnection(completion: @escaping (Bool, String) -> Void) {
        guard !host.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            completion(false, "Vui lòng nhập địa chỉ máy chủ (Host / IP)!")
            return
        }

        guard let portNum = Int(port), portNum > 0, portNum <= 65535 else {
            completion(false, "Cổng kết nối (Port) không hợp lệ (1-65535)!")
            return
        }

        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 5
        config.connectionProxyDictionary = [
            "HTTPEnable": 1,
            "HTTPProxy": host,
            "HTTPPort": portNum,
            "HTTPSEnable": 1,
            "HTTPSProxy": host,
            "HTTPSPort": portNum
        ]

        let startTime = CFAbsoluteTimeGetCurrent()
        let session = URLSession(configuration: config)
        guard let testUrl = URL(string: "https://www.google.com") else {
            completion(false, "URL không hợp lệ")
            return
        }
        var req = URLRequest(url: testUrl)
        req.httpMethod = "HEAD"
        req.timeoutInterval = 5

        session.dataTask(with: req) { _, response, error in
            let duration = Int((CFAbsoluteTimeGetCurrent() - startTime) * 1000)
            DispatchQueue.main.async {
                if let error = error {
                    completion(false, "Lỗi kết nối: \(error.localizedDescription)")
                } else {
                    completion(true, "Kết nối Proxy thành công! (Độ trễ: \(duration)ms)")
                }
            }
        }.resume()
    }
}

// MARK: - Proxy Manager Sheet View

struct ProxyManagerView: View {
    @ObservedObject var proxy = ProxyManager.shared
    @Environment(\.dismiss) private var dismiss

    @State private var hostInput: String = ""
    @State private var portInput: String = ""
    @State private var typeSelection: String = "HTTP"
    @State private var userInput: String = ""
    @State private var passInput: String = ""
    @State private var testResult: String? = nil
    @State private var isSuccess = false
    @State private var isTesting = false

    private let proxyTypes = ["HTTP", "HTTPS", "SOCKS5"]

    // Danh sách gợi ý Proxy tối ưu cho FFVN & Game
    private let suggestedProxies = [
        ("Proxy Việt Nam VIP (FFVN Low Ping)", "103.179.188.12", "8080", "HTTP"),
        ("Proxy Singapore (Tối ưu định tuyến)", "139.180.215.89", "3128", "HTTP"),
        ("Proxy Bypass Anti-Cheat Game", "103.161.119.34", "8080", "HTTP")
    ]

    var body: some View {
        NavigationStack {
            ZStack {
                AppPageBackground()

                ScrollView {
                    VStack(alignment: .leading, spacing: 20) {
                        // Card Trạng thái
                        statusCard

                        // Card Cấu hình máy chủ
                        configCard

                        // Card Tính năng chơi game
                        gamingCard

                        // Card Danh sách Proxy mẫu
                        suggestedCard

                        Spacer(minLength: 30)
                    }
                    .padding(AppTheme.pageInset)
                }
            }
            .navigationTitle("Cấu Hình Proxy")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Xong") {
                        saveSettings()
                        dismiss()
                    }
                    .font(.system(size: 13, weight: .bold))
                    .foregroundStyle(AppTheme.accent)
                }
            }
            .onAppear {
                loadSettings()
            }
        }
    }

    private var statusCard: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                HStack(spacing: 8) {
                    Circle()
                        .fill(proxy.isEnabled ? AppTheme.success : Color.gray)
                        .frame(width: 10, height: 10)
                    Text(proxy.isEnabled ? "PROXY ĐANG HOẠT ĐỘNG" : "PROXY ĐANG TẮT")
                        .font(.system(size: 12, weight: .bold, design: .rounded))
                        .foregroundStyle(proxy.isEnabled ? AppTheme.success : AppTheme.subduedText)
                }
                Spacer()
                Toggle("", isOn: $proxy.isEnabled)
                    .labelsHidden()
                    .tint(AppTheme.success)
            }

            if proxy.isEnabled && !proxy.host.isEmpty {
                HStack {
                    Image(systemName: "globe.asia.australia.fill")
                        .font(.system(size: 13))
                        .foregroundStyle(AppTheme.accentSoft)
                    Text("\(proxy.proxyType)://\(proxy.host):\(proxy.port)")
                        .font(.system(size: 12, weight: .semibold, design: .monospaced))
                        .foregroundStyle(.white)
                }
                .padding(.top, 2)
            }
        }
        .padding(16)
        .background(AppTheme.consoleBackground, in: RoundedRectangle(cornerRadius: 18))
        .overlay { AppCardBorder(cornerRadius: 18) }
    }

    private var configCard: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("THÔNG TIN MÁY CHỦ PROXY")
                .font(.system(size: 10, weight: .bold, design: .rounded))
                .tracking(1.2)
                .foregroundStyle(AppTheme.accentSoft)

            // Chọn loại
            VStack(alignment: .leading, spacing: 6) {
                Text("Giao thức Proxy")
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(.white)

                Picker("Loại Proxy", selection: $typeSelection) {
                    ForEach(proxyTypes, id: \.self) { t in
                        Text(t).tag(t)
                    }
                }
                .pickerStyle(.segmented)
            }

            // Host & Port
            HStack(spacing: 12) {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Máy chủ (Host / IP)")
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundStyle(.white)
                    TextField("VD: 103.179.188.12", text: $hostInput)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .font(.system(size: 13, design: .monospaced))
                        .foregroundStyle(.white)
                        .padding(12)
                        .background(AppTheme.pageBackground)
                        .clipShape(RoundedRectangle(cornerRadius: 12))
                        .overlay { RoundedRectangle(cornerRadius: 12).strokeBorder(Color.white.opacity(0.18), lineWidth: 1) }
                }

                VStack(alignment: .leading, spacing: 6) {
                    Text("Cổng (Port)")
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundStyle(.white)
                    TextField("8080", text: $portInput)
                        .keyboardType(.numberPad)
                        .font(.system(size: 13, design: .monospaced))
                        .foregroundStyle(.white)
                        .padding(12)
                        .frame(width: 90)
                        .background(AppTheme.pageBackground)
                        .clipShape(RoundedRectangle(cornerRadius: 12))
                        .overlay { RoundedRectangle(cornerRadius: 12).strokeBorder(Color.white.opacity(0.18), lineWidth: 1) }
                }
            }

            // Username & Password
            VStack(alignment: .leading, spacing: 6) {
                Text("Tài khoản xác thực (Nếu có)")
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(.white)
                TextField("Tên đăng nhập (Username)", text: $userInput)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
                    .font(.system(size: 13))
                    .foregroundStyle(.white)
                    .padding(12)
                    .background(AppTheme.pageBackground)
                    .clipShape(RoundedRectangle(cornerRadius: 12))
                    .overlay { RoundedRectangle(cornerRadius: 12).strokeBorder(Color.white.opacity(0.18), lineWidth: 1) }
            }

            VStack(alignment: .leading, spacing: 6) {
                Text("Mật khẩu (Nếu có)")
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(.white)
                SecureField("Mật khẩu Proxy", text: $passInput)
                    .font(.system(size: 13))
                    .foregroundStyle(.white)
                    .padding(12)
                    .background(AppTheme.pageBackground)
                    .clipShape(RoundedRectangle(cornerRadius: 12))
                    .overlay { RoundedRectangle(cornerRadius: 12).strokeBorder(Color.white.opacity(0.18), lineWidth: 1) }
            }

            // Kết quả kiểm tra
            if let result = testResult {
                HStack(spacing: 8) {
                    Image(systemName: isSuccess ? "checkmark.circle.fill" : "exclamationmark.circle.fill")
                        .foregroundStyle(isSuccess ? AppTheme.success : AppTheme.danger)
                    Text(result)
                        .font(.system(size: 12, weight: .medium))
                        .foregroundStyle(isSuccess ? AppTheme.success : AppTheme.danger)
                }
                .padding(10)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background((isSuccess ? AppTheme.success : AppTheme.danger).opacity(0.12), in: RoundedRectangle(cornerRadius: 10))
            }

            // Nút Kiểm tra Ping
            Button {
                saveSettings()
                runPingTest()
            } label: {
                HStack(spacing: 8) {
                    if isTesting {
                        ProgressView().tint(.white).controlSize(.small)
                        Text("ĐANG ĐO ĐỘ TRỄ PING...")
                    } else {
                        Image(systemName: "antenna.radiowaves.left.and.right")
                        Text("KIỂM TRA KẾT NỐI (PING)")
                    }
                }
                .font(.system(size: 12, weight: .bold, design: .rounded))
                .foregroundStyle(.white)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 12)
                .background(Color.white.opacity(0.08), in: RoundedRectangle(cornerRadius: 12))
                .overlay { RoundedRectangle(cornerRadius: 12).strokeBorder(Color.white.opacity(0.15), lineWidth: 1) }
            }
            .disabled(isTesting)

            // Nút Lưu cấu hình
            Button {
                saveSettings()
                proxy.isEnabled = true
                dismiss()
            } label: {
                HStack(spacing: 8) {
                    Image(systemName: "checkmark.shield.fill")
                    Text("LƯU & KÍCH HOẠT PROXY")
                }
                .font(.system(size: 13, weight: .bold, design: .rounded))
                .foregroundStyle(.black)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 13)
                .background(AppTheme.accent, in: RoundedRectangle(cornerRadius: 12))
            }
        }
        .padding(18)
        .background(AppTheme.consoleBackground, in: RoundedRectangle(cornerRadius: 20))
        .overlay { AppCardBorder(cornerRadius: 20) }
    }

    private var gamingCard: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("TÍNH NĂNG NÂNG CAO CHO GAME")
                .font(.system(size: 10, weight: .bold, design: .rounded))
                .tracking(1.2)
                .foregroundStyle(AppTheme.accentSoft)

            Toggle(isOn: $proxy.bypassAntiCheat) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Chặn log Anti-Cheat")
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(.white)
                    Text("Tự động chặn gửi dữ liệu kiểm tra từ game lên máy chủ")
                        .font(.system(size: 10.5))
                        .foregroundStyle(AppTheme.subduedText)
                }
            }
            .tint(AppTheme.success)

            Divider().background(Color.white.opacity(0.08))

            Toggle(isOn: $proxy.optimizePing) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Tối ưu hóa đường truyền (Giảm Ping)")
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(.white)
                    Text("Ưu tiên các gói tin game để giảm giật lag")
                        .font(.system(size: 10.5))
                        .foregroundStyle(AppTheme.subduedText)
                }
            }
            .tint(AppTheme.success)
        }
        .padding(18)
        .background(AppTheme.consoleBackground, in: RoundedRectangle(cornerRadius: 20))
        .overlay { AppCardBorder(cornerRadius: 20) }
    }

    private var suggestedCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("MÁY CHỦ PROXY GỢI Ý (1-CHẠM ÁP DỤNG)")
                .font(.system(size: 10, weight: .bold, design: .rounded))
                .tracking(1.2)
                .foregroundStyle(AppTheme.accentSoft)

            ForEach(suggestedProxies, id: \.0) { item in
                Button {
                    hostInput = item.1
                    portInput = item.2
                    typeSelection = item.3
                    saveSettings()
                } label: {
                    HStack {
                        VStack(alignment: .leading, spacing: 3) {
                            Text(item.0)
                                .font(.system(size: 12.5, weight: .semibold))
                                .foregroundStyle(.white)
                            Text("\(item.3)://\(item.1):\(item.2)")
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundStyle(AppTheme.subduedText)
                        }
                        Spacer()
                        Image(systemName: "arrow.down.circle.fill")
                            .font(.system(size: 16))
                            .foregroundStyle(AppTheme.accent)
                    }
                    .padding(12)
                    .background(Color.white.opacity(0.04), in: RoundedRectangle(cornerRadius: 12))
                    .overlay { RoundedRectangle(cornerRadius: 12).strokeBorder(Color.white.opacity(0.08), lineWidth: 1) }
                }
                .buttonStyle(.plain)
            }
        }
        .padding(18)
        .background(AppTheme.consoleBackground, in: RoundedRectangle(cornerRadius: 20))
        .overlay { AppCardBorder(cornerRadius: 20) }
    }

    private func loadSettings() {
        hostInput = proxy.host
        portInput = proxy.port
        typeSelection = proxy.proxyType
        userInput = proxy.username
        passInput = proxy.password
    }

    private func saveSettings() {
        proxy.host = hostInput.trimmingCharacters(in: .whitespacesAndNewlines)
        proxy.port = portInput.trimmingCharacters(in: .whitespacesAndNewlines)
        proxy.proxyType = typeSelection
        proxy.username = userInput.trimmingCharacters(in: .whitespacesAndNewlines)
        proxy.password = passInput.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private func runPingTest() {
        isTesting = true
        testResult = nil
        proxy.testConnection { success, msg in
            isTesting = false
            isSuccess = success
            testResult = msg
        }
    }
}

// MARK: - PROXY PRESET MODS (ANTENA, DRAG 85%, CHAMS)

struct ProxyModPreset: Identifiable {
    let id: UUID
    let name: String
    let fileName: String
    let iconName: String
    let subtitle: String
    let detailDescription: String

    static let presets: [ProxyModPreset] = [
        ProxyModPreset(
            id: UUID(uuidString: "16A78656-EE0A-41F9-B0FA-5F9F44973BBE") ?? UUID(),
            name: "ANTENA",
            fileName: "Antena_PhucVN_FFVN.3105",
            iconName: "antenna.radiowaves.left.and.right",
            subtitle: "Antena định vị vị trí người chơi • Free Fire",
            detailDescription: "Hiển thị cột Antena định vị vị trí đối thủ từ khoảng cách xa trên bản đồ Free Fire."
        ),
        ProxyModPreset(
            id: UUID(uuidString: "DFC0AF84-76EF-49AF-9945-E8307FAE5C2B") ?? UUID(),
            name: "DRAG 85%",
            fileName: "AimDrag_85_PhucVN_FFVN.3105",
            iconName: "scope",
            subtitle: "Hỗ trợ kéo tâm Aim Drag 85% • Free Fire",
            detailDescription: "Tối ưu hóa độ nhạy và hỗ trợ thao tác kéo tâm chuẩn xác 85% khi giao tranh trong Free Fire."
        ),
        ProxyModPreset(
            id: UUID(uuidString: "B8192D12-7013-4420-8073-794D00FB4200") ?? UUID(),
            name: "CHAMS",
            fileName: "DinhVi_Chams_PhucVN_FFVN.3105",
            iconName: "eye.fill",
            subtitle: "Định vị Chams xuyên vật thể • Free Fire",
            detailDescription: "Làm nổi bật màu sắc mô hình nhân vật đối thủ xuyên qua các chướng ngại vật trong Free Fire."
        ),
        ProxyModPreset(
            id: UUID(uuidString: "855F300E-A213-45B6-8A14-D1EFA8D0F7AE") ?? UUID(),
            name: "DINHVI SUNG KEO",
            fileName: "DinhVi_Sung_PhucVN_FFVN.3105",
            iconName: "cross.circle.fill",
            subtitle: "Định vị súng và bom keo • Free Fire",
            detailDescription: "Hiển thị vị trí trang bị vũ khí, súng và bom keo trên bản đồ Free Fire."
        ),
        ProxyModPreset(
            id: UUID(uuidString: "C0CA95DF-CD18-4F4A-A3CD-56DA11324716") ?? UUID(),
            name: "AIM NECK",
            fileName: "Aim_Neck_PhucVN_FFVN.3105",
            iconName: "person.crop.circle.badge.checkmark",
            subtitle: "Hỗ trợ ghim tâm Aim Neck • Free Fire",
            detailDescription: "Tối ưu hóa độ nhạy và hỗ trợ ghim tâm vào vùng cổ đối thủ khi giao tranh trong Free Fire."
        ),
        ProxyModPreset(
            id: UUID(uuidString: "5A53E415-D850-4722-ADF3-1FAE7E73F9AB") ?? UUID(),
            name: "AIM NECK ANTENA",
            fileName: "AimNeck_Antena_PhucVN_FFVN.3105",
            iconName: "antenna.radiowaves.left.and.right",
            subtitle: "Hỗ trợ ghim tâm Aim Neck & Antena • Free Fire",
            detailDescription: "Kết hợp ghim tâm vùng cổ (Aim Neck) và cột Antena định vị vị trí đối thủ tầm xa trong Free Fire."
        ),
        ProxyModPreset(
            id: UUID(uuidString: "233DAE36-3734-4E2B-8C66-C491B540B4B5") ?? UUID(),
            name: "AIM DRAG ANTENA",
            fileName: "AimDrag_85_Antena_PhucVN_FFVN.3105",
            iconName: "scope",
            subtitle: "Hỗ trợ kéo tâm Aim Drag 85% & Antena • Free Fire",
            detailDescription: "Kết hợp trợ lực kéo tâm 85% (Aim Drag) và cột Antena định vị đối thủ tầm xa trong Free Fire."
        )
    ]

    func loadData() -> Data? {
        let baseName = (fileName as NSString).deletingPathExtension
        let ext = (fileName as NSString).pathExtension

        // 1. Check in Bundle.main resource
        if let url = Bundle.main.url(forResource: baseName, withExtension: ext),
           let data = try? Data(contentsOf: url) {
            return data
        }

        // 2. Check directly in Bundle.main root
        let bundleDirectURL = Bundle.main.bundleURL.appendingPathComponent(fileName)
        if let data = try? Data(contentsOf: bundleDirectURL) {
            return data
        }

        // 3. Scan all .3105 files in Bundle.main by packageID
        if let bundleURLs = Bundle.main.urls(forResourcesWithExtension: "3105", subdirectory: nil) {
            for bURL in bundleURLs {
                if let d = try? Data(contentsOf: bURL),
                   let summary = try? PatchPackageCodec.inspect(d),
                   summary.packageID == id {
                    return d
                }
            }
        }

        // 4. Check Application Support / PatchProjects
        if let root = try? PatchProjectLibrary.packageRootURL() {
            let rootURL = root.appendingPathComponent(fileName)
            if let data = try? Data(contentsOf: rootURL) {
                return data
            }
            if let items = try? FileManager.default.contentsOfDirectory(at: root, includingPropertiesForKeys: nil) {
                for itemURL in items where itemURL.pathExtension.lowercased() == "3105" {
                    if let d = try? Data(contentsOf: itemURL),
                       let summary = try? PatchPackageCodec.inspect(d),
                       summary.packageID == id {
                        return d
                    }
                }
            }
        }

        // 5. Check Documents
        if let docURL = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first?.appendingPathComponent(fileName),
           let data = try? Data(contentsOf: docURL) {
            return data
        }

        return nil
    }
}

struct ProxyModPresetDetailView: View {
    let mod: ProxyModPreset
    var onModified: () -> Void = {}

    @State private var isWorking = false
    @State private var alertTitle = ""
    @State private var alertMessage = ""
    @State private var showAlert = false
    @State private var showApplyConfirm = false
    @State private var showRestoreConfirm = false
    @State private var statusToggle = false

    private var receipt: PatchTransactionReceipt? {
        DevicePatchService.latestReceipt(projectID: mod.id)
    }

    private var isApplied: Bool {
        receipt != nil
    }

    var body: some View {
        List {
            Section {
                VStack(spacing: 12) {
                    AppRowIcon(
                        systemName: mod.iconName,
                        tint: isApplied ? AppTheme.success : AppTheme.accent,
                        symbolSize: 28,
                        frameSize: 64
                    )
                    Text(mod.name)
                        .font(.system(size: 24, weight: .bold, design: .rounded))
                        .foregroundStyle(.white)

                    Text(isApplied ? "ĐÃ ÁP DỤNG MOD" : "FILE GỐC CHƯA MOD")
                        .font(.system(size: 11, weight: .bold))
                        .foregroundStyle(isApplied ? AppTheme.success : AppTheme.subduedText)
                        .padding(.horizontal, 10)
                        .padding(.vertical, 4)
                        .background((isApplied ? AppTheme.success : Color.white).opacity(0.12), in: Capsule())
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 14)
                .listRowBackground(Color.clear)
                .listRowSeparator(.hidden)
            }

            Section("THÔNG TIN BẢN MOD") {
                HStack {
                    Text("Tên tính năng")
                        .foregroundStyle(.secondary)
                    Spacer()
                    Text(mod.name)
                        .font(.subheadline.weight(.semibold))
                        .foregroundStyle(.primary)
                }
                HStack {
                    Text("Tệp cấu hình")
                        .foregroundStyle(.secondary)
                    Spacer()
                    Text(mod.fileName)
                        .font(.system(size: 12, design: .monospaced))
                        .foregroundStyle(.primary)
                }
                HStack {
                    Text("Trò chơi mục tiêu")
                        .foregroundStyle(.secondary)
                    Spacer()
                    Text("Free Fire (FFVN)")
                        .font(.subheadline.weight(.medium))
                        .foregroundStyle(AppTheme.accent)
                }
                HStack {
                    Text("Trạng thái")
                        .foregroundStyle(.secondary)
                    Spacer()
                    HStack(spacing: 6) {
                        Circle()
                            .fill(isApplied ? AppTheme.success : Color.gray)
                            .frame(width: 8, height: 8)
                        Text(isApplied ? "Đang kích hoạt" : "Chưa kích hoạt")
                            .font(.subheadline.weight(.medium))
                            .foregroundStyle(isApplied ? AppTheme.success : .secondary)
                    }
                }
            }

            Section("MÔ TẢ TÍNH NĂNG") {
                Text(mod.detailDescription)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .lineSpacing(4)
            }

            Section {
                Button {
                    showApplyConfirm = true
                } label: {
                    HStack {
                        Label("Áp dụng", systemImage: "checkmark.shield.fill")
                            .font(.body.weight(.semibold))
                        Spacer()
                        if isWorking {
                            ProgressView()
                                .tint(AppTheme.accent)
                        }
                    }
                    .foregroundStyle(isApplied ? Color.gray : AppTheme.accent)
                }
                .disabled(isWorking || isApplied)

                Button(role: .destructive) {
                    showRestoreConfirm = true
                } label: {
                    Label("Khôi phục file gốc", systemImage: "arrow.uturn.backward.circle.fill")
                        .font(.body.weight(.semibold))
                }
                .disabled(isWorking || !isApplied)
            } footer: {
                Text("Khi áp dụng, hệ thống sẽ tự động sao lưu dữ liệu gốc của game. Bạn có thể nhấn 'Khôi phục file gốc' bất cứ lúc nào để đưa game về trạng thái nguyên bản.")
                    .font(.caption2)
                    .foregroundStyle(AppTheme.subduedText)
            }

            Section {
                Color.clear
                    .frame(height: 85)
                    .listRowBackground(Color.clear)
                    .listRowSeparator(.hidden)
            }
        }
        .listStyle(.insetGrouped)
        .safeAreaInset(edge: .bottom) {
            Color.clear.frame(height: 30)
        }
        .navigationTitle(mod.name)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                if isWorking {
                    ProgressView()
                }
            }
        }
        .confirmationDialog(
            "Áp dụng \(mod.name)",
            isPresented: $showApplyConfirm,
            titleVisibility: .visible
        ) {
            Button("Áp dụng ngay") {
                applyMod()
            }
            Button("Huỷ", role: .cancel) {}
        } message: {
            Text("Hệ thống sẽ sao lưu file gốc và áp dụng bản mod \(mod.name) vào Free Fire.")
        }
        .confirmationDialog(
            "Khôi phục file gốc",
            isPresented: $showRestoreConfirm,
            titleVisibility: .visible
        ) {
            Button("Khôi phục file gốc", role: .destructive) {
                restoreMod()
            }
            Button("Huỷ", role: .cancel) {}
        } message: {
            Text("Bạn có chắc muốn khôi phục lại dữ liệu gốc của Free Fire cho tính năng \(mod.name)?")
        }
        .alert(alertTitle, isPresented: $showAlert) {
            Button("OK") {}
        } message: {
            Text(alertMessage)
        }
    }

    private func applyMod() {
        guard !isWorking else { return }
        guard let ticket = KeyAuthManager.shared.activeVerifiedTicket else {
            alertTitle = "Yêu cầu xác thực"
            alertMessage = "Phiên bản quyền không hợp lệ hoặc đã hết hạn. Vui lòng xác thực lại Key."
            showAlert = true
            return
        }
        isWorking = true
        Task.detached(priority: .userInitiated) {
            do {
                guard let data = mod.loadData() else {
                    await MainActor.run {
                        isWorking = false
                        alertTitle = "Lỗi tệp tin"
                        alertMessage = "Không thể đọc tệp \(mod.fileName). Vui lòng đảm bảo tệp đã được đưa vào ứng dụng."
                        showAlert = true
                    }
                    return
                }

                let decoded = try PatchPackageCodec.isV4(data)
                    ? PatchPackageCodec.decodeV4(data, ticket: ticket)
                    : PatchPackageCodec.decode(data, password: nil)
                var secureProject = decoded.project
                secureProject.isPrivate = true
                _ = try DevicePatchService.apply(project: secureProject)
                for idx in secureProject.rules.indices {
                    secureWipeData(&secureProject.rules[idx].replacementData)
                }
                var ck = decoded.contentKey
                secureWipeData(&ck)
                await MainActor.run {
                    isWorking = false
                    statusToggle.toggle()
                    onModified()
                    alertTitle = "Thành công"
                    alertMessage = "Đã áp dụng \(mod.name) vào Free Fire thành công!"
                    showAlert = true
                }
            } catch let error as PatchPackageError {
                await MainActor.run {
                    isWorking = false
                    alertTitle = "Không thể áp dụng"
                    switch error {
                    case .targetAppUnavailable:
                        alertMessage = "Không tìm thấy game Free Fire (FFVN) trên thiết bị!"
                    case .projectAlreadyApplied:
                        alertMessage = "Bản mod \(mod.name) đã được áp dụng trước đó rồi."
                    case .targetOccupied(let target):
                        alertMessage = "Tệp đích đang bị chiếm bởi một bản mod khác: \(target)."
                    default:
                        alertMessage = "Lỗi: \(error)"
                    }
                    showAlert = true
                }
            } catch {
                await MainActor.run {
                    isWorking = false
                    alertTitle = "Lỗi không xác định"
                    alertMessage = error.localizedDescription
                    showAlert = true
                }
            }
        }
    }

    private func restoreMod() {
        guard let currentReceipt = receipt, !isWorking else { return }
        isWorking = true
        Task.detached(priority: .userInitiated) {
            do {
                try DevicePatchService.restore(receipt: currentReceipt, allowChangedTargets: true)
                await MainActor.run {
                    isWorking = false
                    statusToggle.toggle()
                    onModified()
                    alertTitle = "Thành công"
                    alertMessage = "Đã khôi phục file gốc cho \(mod.name) thành công!"
                    showAlert = true
                }
            } catch {
                await MainActor.run {
                    isWorking = false
                    alertTitle = "Khôi phục thất bại"
                    alertMessage = error.localizedDescription
                    showAlert = true
                }
            }
        }
    }
}
