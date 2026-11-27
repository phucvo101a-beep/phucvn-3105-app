import SwiftUI
import UIKit

struct AppDataBrowserView: View {
    @Environment(\.appLanguage) private var language
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.horizontalSizeClass) private var horizontalSizeClass

    @State private var apps: [InstalledApp] = []
    @ObservedObject private var localDevBridge = LocalDevBridge.shared
    @State private var appSearchText = ""
    @State private var accessFilter: AppAccessFilter = .all
    @FocusState private var isAppSearchFocused: Bool
    @State private var isLoading = false
    @State private var isResolving = false
    @State private var errorMessage: String?
    @State private var hasLoaded = false
    @State private var workspaceURL: URL?
    @State private var patchesURL: URL?
    @State private var reloadGeneration = 0

    @Binding private var tabSession: FilesTabSession
    let isActive: Bool
    let onOpenSettings: () -> Void
    let onOpenLogs: () -> Void

    init(
        tabSession: Binding<FilesTabSession>,
        isActive: Bool = true,
        onOpenSettings: @escaping () -> Void = {},
        onOpenLogs: @escaping () -> Void = {}
    ) {
        _tabSession = tabSession
        self.isActive = isActive
        self.onOpenSettings = onOpenSettings
        self.onOpenLogs = onOpenLogs
    }

    private typealias AppAccessBadge = (title: String, icon: String, color: Color, isSandboxLocked: Bool)

    private var localDevAppByBundleID: [String: LocalDevApp] {
        var map: [String: LocalDevApp] = [:]
        map.reserveCapacity(localDevBridge.installedApps.count)
        for item in localDevBridge.installedApps where map[item.bundle_id] == nil {
            map[item.bundle_id] = item
        }
        return map
    }

    private func accessBadgeInfo(for app: InstalledApp, devLookup: [String: LocalDevApp]) -> AppAccessBadge {
        if let devApp = devLookup[app.bundleID] {
            return (devApp.accessBadgeTitle, devApp.accessBadgeIcon, devApp.accessBadgeColor, devApp.isSandboxLocked)
        }
        if ContainerStore.isWithinOwnSandbox(app.containerPath) {
            return ("Sandbox nội bộ", "checkmark.shield.fill", AppTheme.success, false)
        }
        if ContainerStore.hasPrivilegedContainerAccess() {
            return ("Toàn quyền Container", "lock.open.fill", .green, false)
        }
        return ("Bị khóa Sandbox", "lock.fill", .orange, true)
    }

    private var queryMatchedApps: [InstalledApp] {
        let query = appSearchText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !query.isEmpty else { return apps }
        let devLookup = localDevAppByBundleID

        return apps.filter { app in
            if app.displayName.localizedStandardContains(query)
                || app.bundleID.localizedStandardContains(query)
                || app.version.localizedStandardContains(query) {
                return true
            }
            return accessBadgeInfo(for: app, devLookup: devLookup).title.localizedStandardContains(query)
        }
    }

    private var filteredApps: [InstalledApp] {
        let matched = queryMatchedApps
        let devLookup = localDevAppByBundleID
        switch accessFilter {
        case .all:
            return matched
        case .accessible:
            return matched.filter { !accessBadgeInfo(for: $0, devLookup: devLookup).isSandboxLocked }
        case .sandboxLocked:
            return matched.filter { accessBadgeInfo(for: $0, devLookup: devLookup).isSandboxLocked }
        }
    }

    private var hasAppSearchQuery: Bool {
        !appSearchText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || accessFilter != .all
    }

    private var overlayState: AppBrowserOverlayState {
        if (isLoading || isResolving) && apps.isEmpty { return .loading }
        if apps.isEmpty { return .empty }
        return .none
    }

    private var interfaceAnimation: Animation? {
        reduceMotion ? nil : .easeOut(duration: 0.24)
    }

    var body: some View {
        navigationContent(tabID: tabSession.selectedTabID)
            .id(tabSession.selectedTabID)
    }

    private func navigationContent(tabID: UUID) -> some View {
        NavigationStack(path: navigationPath(for: tabID)) {
            appList
                .navigationTitle("")
                .navigationBarTitleDisplayMode(.inline)
                .toolbarBackground(AppTheme.pageBackground.opacity(0.96), for: .navigationBar)
                .toolbar {
                    ToolbarItem(placement: .navigationBarTrailing) {
                        FilesTabToolbarButton(session: $tabSession)
                    }
                    ToolbarItem(placement: .navigationBarTrailing) {
                        Button { reload() } label: {
                            if isResolving {
                                ProgressView()
                            } else {
                                Image(systemName: "arrow.clockwise")
                            }
                        }
                        .disabled(isResolving)
                        .accessibilityLabel(language.text("browser.retry"))
                    }
                    AppUtilityToolbar(
                        language: language,
                        onOpenSettings: onOpenSettings,
                        onOpenLogs: onOpenLogs
                    )
                }
                .onAppear {
                    if workspaceURL == nil {
                        workspaceURL = try? PatchWorkspaceService.documentsRootURL()
                        patchesURL = try? PatchWorkspaceService.patchesRootURL()
                    }
                    if !hasLoaded && (!localDevBridge.installedApps.isEmpty || localDevBridge.currentStatus.isLive) {
                        hasLoaded = true
                        reload()
                    }
                }
                .onChange(of: localDevBridge.currentStatus.isLive) { isLive in
                    if isLive && !isLoading && !isResolving && apps.count <= 1 {
                        hasLoaded = true
                        reload()
                    }
                }
                .navigationDestination(for: FileBrowserDestination.self) { destination in
                    if destination.startPath == destination.containerPath {
                        FileBrowserView(
                            containerPath: destination.containerPath,
                            title: destination.title,
                            bundleID: destination.bundleID,
                            filesTabSession: $tabSession
                        )
                    } else {
                        FileBrowserView(
                            containerPath: destination.containerPath,
                            startPath: destination.startPath,
                            title: destination.title,
                            bundleID: destination.bundleID,
                            filesTabSession: $tabSession
                        )
                    }
                }
        }
    }

    /// Write the complete value back through the Binding. This keeps each file tab's
    /// navigation stack in sync when a destination is pushed or popped.
    private func navigationPath(for tabID: UUID) -> Binding<[FileBrowserDestination]> {
        Binding(
            get: { tabSession.navigationPath(for: tabID) },
            set: { newPath in
                var updatedSession = tabSession
                updatedSession.setNavigationPath(newPath, for: tabID)
                tabSession = updatedSession
            }
        )
    }

    private var appList: some View {
        let devLookup = localDevAppByBundleID
        return ScrollView(showsIndicators: false) {
            LazyVStack(alignment: .leading, spacing: 13) {
                browserHero
                    .padding(.top, 9)
                    .padding(.bottom, 2)

                if horizontalSizeClass == .regular {
                    FilesTabStrip(session: $tabSession)
                        .padding(.bottom, 2)
                }

                // MARK: - Section 1: Independent Own-Sandbox & USB Diagnostics (always available)
                VStack(alignment: .leading, spacing: 2) {
                    Text("DỮ LIỆU NỘI BỘ & HỘP CÁT (SANDBOX)")
                        .font(.system(size: 10, weight: .heavy, design: .rounded))
                        .tracking(1.25)
                        .foregroundStyle(AppTheme.success)
                    Text("Luôn khả dụng qua API iOS chuẩn — độc lập hoàn toàn với LocalDev & Pairing")
                        .font(.system(size: 10, weight: .medium))
                        .foregroundStyle(AppTheme.subduedText)
                }
                .padding(.horizontal, 3)

                if let workspaceURL {
                    workspaceCard(workspaceURL)
                }

                patchesShortcutCard

                sandboxShortcutCard

                if let diagnosticsURL = ContainerStore.ownDiagnosticsURL {
                    diagnosticsShortcutCard(diagnosticsURL)
                }

                if !ContainerStore.hasPrivilegedContainerAccess() {
                    sandboxScopeNoticeCard
                }

                // MARK: - Section 2: Optional LocalDev / Pairing Tunnel Extension
                VStack(alignment: .leading, spacing: 2) {
                    Text("KẾT NỐI MỞ RỘNG LOCALDEV (TÙY CHỌN VPN / PAIRING)")
                        .font(.system(size: 10, weight: .heavy, design: .rounded))
                        .tracking(1.25)
                        .foregroundStyle(AppTheme.accentSoft)
                    Text("Chỉ cần khi duyệt Documents / container ngoài app; lỗi ở đây không ảnh hưởng Sandbox hay Nhật ký USB")
                        .font(.system(size: 10, weight: .medium))
                        .foregroundStyle(AppTheme.subduedText)
                }
                .padding(.horizontal, 3)
                .padding(.top, 8)

                LocalDevStatusCard()
                    .padding(.bottom, 2)

                VStack(alignment: .leading, spacing: 2) {
                    Text("TRUYỀN TỆP WI-FI LAN (3105 AIRLIFT)")
                        .font(.system(size: 10, weight: .heavy, design: .rounded))
                        .tracking(1.25)
                        .foregroundStyle(AppTheme.accentSoft)
                    Text("Gửi nhanh .ipa, .3105, Pairing từ trình duyệt PC và tải file đã trích xuất về máy tính")
                        .font(.system(size: 10, weight: .medium))
                        .foregroundStyle(AppTheme.subduedText)
                }
                .padding(.horizontal, 3)
                .padding(.top, 2)

                AirliftServerCard()
                    .padding(.bottom, 2)

                appDataScannerSection

                if !apps.isEmpty {
                    appSearchField
                        .padding(.top, 2)

                    appAccessFilterBar
                        .padding(.bottom, 2)

                    HStack(alignment: .lastTextBaseline) {
                        VStack(alignment: .leading, spacing: 3) {
                            Text(hasAppSearchQuery ? "KẾT QUẢ TÌM KIẾM & LỌC" : "ỨNG DỤNG & GAME ĐÃ PHÁT HIỆN")
                                .font(.system(size: 10, weight: .heavy, design: .rounded))
                                .tracking(1.25)
                                .foregroundStyle(AppTheme.accentSoft)
                            Text(hasAppSearchQuery
                                 ? language.text("browser.search_count", Int64(filteredApps.count), Int64(apps.count))
                                 : language.text("browser.apps_count", Int64(apps.count)))
                                .font(.system(size: 11, weight: .medium))
                                .foregroundStyle(AppTheme.subduedText)
                        }
                        Spacer()
                    }
                    .padding(.horizontal, 3)
                    .padding(.top, 4)

                    if filteredApps.isEmpty {
                        appSearchEmptyState
                    } else {
                        ForEach(filteredApps) { app in
                            appNavigationRow(app, badge: accessBadgeInfo(for: app, devLookup: devLookup))
                        }
                    }
                }

                // Generous bottom clearance so the floating StudioTabBar never covers the button or content
                Color.clear
                    .frame(height: 140)
            }
            .padding(.horizontal, AppTheme.pageInset)
            .padding(.bottom, 30)
            .frame(maxWidth: 760)
            .frame(maxWidth: .infinity)
        }
        .scrollDismissesKeyboard(.interactively)
        .background { AppPageBackground() }
        .compositingGroup()
    }

    private var browserHero: some View {
        ZStack(alignment: .topTrailing) {
            RoundedRectangle(cornerRadius: 27, style: .continuous)
                .fill(
                    LinearGradient(
                        colors: [
                            Color(red: 0.19, green: 0.22, blue: 0.28),
                            Color(red: 0.085, green: 0.105, blue: 0.14),
                            AppTheme.consoleBackground
                        ],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    )
                )

            VStack(alignment: .leading, spacing: 14) {
                HStack {
                    StudioEyebrow(text: "PHUCVN  /  DATA STUDIO")
                    Spacer(minLength: 8)
                    HStack(spacing: 6) {
                        Circle()
                            .fill(AppTheme.success)
                            .frame(width: 6, height: 6)
                        Text(apps.isEmpty ? "READY" : "LIVE")
                            .font(.system(size: 9, weight: .heavy, design: .monospaced))
                            .tracking(1.1)
                            .foregroundStyle(AppTheme.success)
                    }
                    .padding(.horizontal, 9)
                    .padding(.vertical, 6)
                    .background(AppTheme.success.opacity(0.10), in: Capsule())
                    .overlay { Capsule().strokeBorder(AppTheme.success.opacity(0.25), lineWidth: 1) }
                }

                HStack(alignment: .bottom, spacing: 12) {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Quản lý tệp")
                            .font(.system(size: 27, weight: .bold, design: .rounded))
                            .tracking(-0.75)
                            .foregroundStyle(.white)
                        Text("Truy cập tệp lưu trữ, bản vá và dữ liệu thiết bị.")
                            .font(.system(size: 11, weight: .medium))
                            .foregroundStyle(Color.white.opacity(0.70))
                            .lineLimit(2)
                    }
                    Spacer(minLength: 0)
                    VStack(alignment: .trailing, spacing: 2) {
                        Text(apps.isEmpty ? "120" : "\(apps.count)")
                            .font(.system(size: 28, weight: .black, design: .rounded))
                            .monospacedDigit()
                            .tracking(-1)
                            .foregroundStyle(AppTheme.accent)
                        Text(apps.isEmpty ? "FPS • TỆP" : "ỨNG DỤNG")
                            .font(.system(size: 8, weight: .bold, design: .rounded))
                            .tracking(1.1)
                            .foregroundStyle(AppTheme.subduedText)
                    }
                }
            }
            .padding(17)
        }
        .frame(minHeight: 124)
        .clipShape(RoundedRectangle(cornerRadius: 27, style: .continuous))
        .overlay { StudioGlassHighlight(cornerRadius: 27, intensity: 1.0) }
        .overlay { AppCardBorder(cornerRadius: 27) }
        .shadow(color: AppTheme.silverGlow.opacity(0.14), radius: 23, y: 10)
        .shadow(color: .black.opacity(0.24), radius: 12, y: 7)
        .compositingGroup()
    }

    private var appSearchField: some View {
        HStack(spacing: 11) {
            Image(systemName: "magnifyingglass")
                .font(.system(size: 15, weight: .semibold))
                .foregroundStyle(AppTheme.accentSoft)
                .accessibilityHidden(true)

            TextField(language.text("browser.search_apps_placeholder"), text: $appSearchText)
                .font(.system(size: 14, weight: .medium))
                .foregroundStyle(AppTheme.accent)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .submitLabel(.search)
                .focused($isAppSearchFocused)
                .accessibilityLabel(language.text("browser.search_apps_placeholder"))

            if !appSearchText.isEmpty {
                Button {
                    withAnimation(interfaceAnimation) { appSearchText = "" }
                } label: {
                    Image(systemName: "xmark.circle.fill")
                        .font(.system(size: 17, weight: .medium))
                        .foregroundStyle(AppTheme.subduedText)
                        .frame(width: 30, height: 34)
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityLabel(language.text("browser.clear_search"))
                .transition(.scale.combined(with: .opacity))
            }
        }
        .padding(.leading, 15)
        .padding(.trailing, 7)
        .frame(height: 51)
        .background {
            RoundedRectangle(cornerRadius: 17, style: .continuous)
                .fill(AppTheme.elevatedBackground.opacity(0.92))
                .overlay {
                    RoundedRectangle(cornerRadius: 17, style: .continuous)
                        .fill(
                            LinearGradient(
                                colors: [Color.white.opacity(0.065), .clear, Color.black.opacity(0.08)],
                                startPoint: .topLeading,
                                endPoint: .bottomTrailing
                            )
                        )
                }
        }
        .overlay { StudioGlassHighlight(cornerRadius: 17, intensity: 0.65) }
        .overlay {
            RoundedRectangle(cornerRadius: 17, style: .continuous)
                .strokeBorder(
                    isAppSearchFocused ? AppTheme.accentSoft.opacity(0.78) : Color.white.opacity(0.13),
                    lineWidth: isAppSearchFocused ? 1.3 : 1
                )
        }
        .shadow(
            color: isAppSearchFocused ? AppTheme.silverGlow.opacity(0.17) : .black.opacity(0.22),
            radius: isAppSearchFocused ? 17 : 12,
            y: 5
        )
        .animation(interfaceAnimation, value: appSearchText.isEmpty)
        .animation(interfaceAnimation, value: isAppSearchFocused)
    }

    private var patchesShortcutCard: some View {
        let validPatchesURL = patchesURL.flatMap {
            ContainerStore.validatedLocalFileURL(fromPath: $0.path, isDirectory: true)
        }
        let destination = validPatchesURL.map { url in
            FileBrowserDestination(
                containerPath: url.path,
                startPath: url.path,
                title: "Kho bản vá (.3105)",
                bundleID: nil
            )
        }

        return Button {
            if let destination {
                pushDestination(destination)
            }
        } label: {
            HStack(spacing: 13) {
                AppRowIcon(systemName: "archivebox.fill", tint: AppTheme.accentSoft, symbolSize: 19, frameSize: 45)
                VStack(alignment: .leading, spacing: 4) {
                    Text("Kho bản vá (.3105)")
                        .font(.system(size: 13, weight: .bold, design: .rounded))
                        .foregroundStyle(.white)
                    Text("Quản lý các gói bản vá đã trích xuất hoặc lưu trữ")
                        .font(.system(size: 10, weight: .medium))
                        .foregroundStyle(AppTheme.subduedText)
                }
                Spacer()
                Image(systemName: "arrow.up.right")
                    .font(.system(size: 11, weight: .bold))
                    .foregroundStyle(AppTheme.accentSoft)
                    .frame(width: 31, height: 31)
                    .background(AppTheme.accentSoft.opacity(0.10), in: Circle())
            }
            .padding(13)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(cardSurface(tint: AppTheme.accentSoft))
            .contentShape(RoundedRectangle(cornerRadius: 21, style: .continuous))
        }
        .buttonStyle(AppPressableStyle())
        .contextMenu {
            if let destination {
                openInNewTabButton(destination)
            }
        }
    }

    private var sandboxShortcutCard: some View {
        let validSandboxURL = ContainerStore.validatedLocalFileURL(
            fromPath: ContainerStore.ownSandboxRootURL.path,
            isDirectory: true
        )
        let destination = validSandboxURL.map { url in
            FileBrowserDestination(
                containerPath: url.path,
                startPath: url.path,
                title: "Hộp cát ứng dụng (Sandbox)",
                bundleID: ContainerStore.ownBundleID
            )
        }

        return Button {
            if let destination {
                pushDestination(destination)
            }
        } label: {
            HStack(spacing: 13) {
                AppRowIcon(systemName: "internaldrive.fill", tint: AppTheme.silverGlow, symbolSize: 19, frameSize: 45)
                VStack(alignment: .leading, spacing: 4) {
                    Text("Hộp cát ứng dụng (Sandbox)")
                        .font(.system(size: 13, weight: .bold, design: .rounded))
                        .foregroundStyle(.white)
                    Text("Duyệt Documents, Library & tmp hợp lệ qua API iOS")
                        .font(.system(size: 10, weight: .medium))
                        .foregroundStyle(AppTheme.subduedText)
                }
                Spacer()
                Image(systemName: "arrow.up.right")
                    .font(.system(size: 11, weight: .bold))
                    .foregroundStyle(AppTheme.silverGlow)
                    .frame(width: 31, height: 31)
                    .background(AppTheme.silverGlow.opacity(0.10), in: Circle())
            }
            .padding(13)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(cardSurface(tint: AppTheme.subduedText))
            .contentShape(RoundedRectangle(cornerRadius: 21, style: .continuous))
        }
        .buttonStyle(AppPressableStyle())
        .contextMenu {
            if let destination {
                openInNewTabButton(destination)
            }
        }
    }

    private func diagnosticsShortcutCard(_ url: URL) -> some View {
        let destination = FileBrowserDestination(
            containerPath: url.path,
            startPath: url.path,
            title: "Nhật ký & USB Diagnostics",
            bundleID: ContainerStore.ownBundleID
        )

        return Button {
            AppLog.shared.writeDiagnosticsSnapshot()
            pushDestination(destination)
        } label: {
            HStack(spacing: 13) {
                AppRowIcon(systemName: "cable.connector", tint: AppTheme.info, symbolSize: 19, frameSize: 45)
                VStack(alignment: .leading, spacing: 4) {
                    Text("Nhật ký & USB Diagnostics")
                        .font(.system(size: 13, weight: .bold, design: .rounded))
                        .foregroundStyle(.white)
                    Text("Thư mục Documents/3105-Diagnostics đọc trực tiếp qua USB")
                        .font(.system(size: 10, weight: .medium))
                        .foregroundStyle(AppTheme.subduedText)
                }
                Spacer()
                Image(systemName: "arrow.up.right")
                    .font(.system(size: 11, weight: .bold))
                    .foregroundStyle(AppTheme.info)
                    .frame(width: 31, height: 31)
                    .background(AppTheme.info.opacity(0.10), in: Circle())
            }
            .padding(13)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(cardSurface(tint: AppTheme.info))
            .contentShape(RoundedRectangle(cornerRadius: 21, style: .continuous))
        }
        .buttonStyle(AppPressableStyle())
        .contextMenu {
            openInNewTabButton(destination)
        }
    }

    private var appAccessFilterBar: some View {
        let devLookup = localDevAppByBundleID
        let matched = queryMatchedApps
        let accessibleCount = matched.filter { !accessBadgeInfo(for: $0, devLookup: devLookup).isSandboxLocked }.count
        let lockedCount = matched.count - accessibleCount

        return ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 8) {
                accessFilterChip(.all, title: "Tất cả", count: matched.count, tint: AppTheme.accent)
                accessFilterChip(.accessible, title: "Mở được", count: accessibleCount, tint: AppTheme.success)
                accessFilterChip(.sandboxLocked, title: "Khóa Sandbox", count: lockedCount, tint: .orange)
            }
            .padding(.horizontal, 2)
        }
    }

    private func accessFilterChip(
        _ filter: AppAccessFilter,
        title: String,
        count: Int,
        tint: Color
    ) -> some View {
        let isSelected = accessFilter == filter
        return Button {
            withAnimation(interfaceAnimation) {
                accessFilter = filter
            }
        } label: {
            HStack(spacing: 5) {
                Text(title)
                    .font(.system(size: 11, weight: .bold, design: .rounded))
                Text("\(count)")
                    .font(.system(size: 10, weight: .heavy, design: .monospaced))
                    .monospacedDigit()
                    .padding(.horizontal, 5)
                    .padding(.vertical, 1.5)
                    .background(
                        (isSelected ? Color.black.opacity(0.18) : Color.white.opacity(0.10)),
                        in: Capsule()
                    )
            }
            .foregroundStyle(isSelected ? Color.black : Color.white.opacity(0.88))
            .padding(.horizontal, 11)
            .padding(.vertical, 6)
            .background(
                isSelected ? tint : AppTheme.elevatedBackground.opacity(0.88),
                in: Capsule()
            )
            .overlay {
                Capsule().strokeBorder(isSelected ? tint : Color.white.opacity(0.12), lineWidth: 1)
            }
        }
        .buttonStyle(AppPressableStyle())
    }

    private var sandboxScopeNoticeCard: some View {
        HStack(alignment: .top, spacing: 11) {
            Image(systemName: "checkmark.shield.fill")
                .font(.system(size: 15, weight: .bold))
                .foregroundStyle(AppTheme.success)
                .padding(.top, 2)

            VStack(alignment: .leading, spacing: 4) {
                Text("iOS \(AppInfo.osVersion) · Chế độ Sandbox chuẩn (Non-JB)")
                    .font(.system(size: 12, weight: .bold, design: .rounded))
                    .foregroundStyle(.white)
                Text(
                    localDevBridge.currentStatus.isLive
                        ? "LocalDev đã kết nối: hiển thị toàn bộ ứng dụng & game User kèm nhãn quyền truy cập (Toàn quyền / Chỉ Documents / Bị khóa Sandbox)."
                        : "iOS non-JB chặn app đọc trực tiếp container app khác (đây là cơ chế bảo mật Sandbox, không phải lỗi phiên bản iOS). Hãy dùng Documents, 3105-Diagnostics qua USB hoặc bật LocalDev."
                )
                .font(.system(size: 10, weight: .medium))
                .foregroundStyle(AppTheme.subduedText)
                .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
        }
        .padding(13)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(cardSurface(tint: AppTheme.success))
    }

    private var appDataScannerSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 12) {
                AppRowIcon(systemName: "square.stack.3d.up.fill", tint: AppTheme.accentSoft, symbolSize: 17, frameSize: 42)
                VStack(alignment: .leading, spacing: 3) {
                    Text("Kho dữ liệu ứng dụng")
                        .font(.system(size: 13, weight: .bold, design: .rounded))
                        .foregroundStyle(.white)
                    Text(
                        !localDevBridge.isModuleEnabled
                            ? "LocalDev đang tắt — đang duyệt an toàn trong Hộp cát (Sandbox) của app"
                            : (apps.isEmpty ? "Quét toàn bộ ứng dụng & game User đã cài trên thiết bị" : "Đã phát hiện \(apps.count) ứng dụng & game trên thiết bị")
                    )
                        .font(.system(size: 10, weight: .medium))
                        .foregroundStyle(AppTheme.subduedText)
                }
                Spacer()
                Button {
                    reload()
                } label: {
                    if isLoading || isResolving {
                        ProgressView().controlSize(.mini).tint(AppTheme.accent)
                    } else {
                        Image(systemName: "arrow.clockwise")
                            .font(.system(size: 13, weight: .bold))
                            .foregroundStyle(AppTheme.accent)
                            .frame(width: 32, height: 32)
                            .background(AppTheme.accent.opacity(0.14), in: Circle())
                    }
                }
                .buttonStyle(AppPressableStyle())
                .disabled(isLoading || isResolving)
                .accessibilityLabel("Quét lại dữ liệu")
            }

            Button {
                reload()
            } label: {
                HStack(spacing: 7) {
                    if isLoading || isResolving {
                        ProgressView().controlSize(.mini).tint(.black)
                        Text("Đang quét dữ liệu...")
                            .font(.system(size: 12, weight: .bold))
                    } else {
                        Image(systemName: apps.isEmpty ? "arrow.triangle.2.circlepath" : "arrow.clockwise")
                            .font(.system(size: 12, weight: .bold))
                        Text(apps.isEmpty ? "Quét toàn bộ ứng dụng & game" : "Quét lại ứng dụng & game")
                            .font(.system(size: 12, weight: .bold))
                    }
                }
                .foregroundStyle(.black)
                .frame(maxWidth: .infinity)
                .frame(height: 38)
                .background(AppTheme.accent, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
            }
            .buttonStyle(AppPressableStyle())
            .disabled(isLoading || isResolving)
        }
        .padding(13)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(cardSurface(tint: AppTheme.accentSoft))
        .contentShape(RoundedRectangle(cornerRadius: 21, style: .continuous))
    }

    private func workspaceCard(_ url: URL) -> some View {
        let destination = FileBrowserDestination(
            containerPath: url.path,
            startPath: url.path,
            title: AppBrand.name,
            bundleID: nil
        )

        return Button {
            pushDestination(destination)
        } label: {
            HStack(spacing: 13) {
                AppRowIcon(systemName: "shippingbox.fill", tint: AppTheme.success, symbolSize: 19, frameSize: 45)
                VStack(alignment: .leading, spacing: 4) {
                    Text(AppBrand.name)
                        .font(.system(size: 13, weight: .bold, design: .rounded))
                        .foregroundStyle(.white)
                    Text(language.text("browser.workspace_subtitle"))
                        .font(.system(size: 10, weight: .medium))
                        .foregroundStyle(AppTheme.subduedText)
                }
                Spacer()
                Image(systemName: "arrow.up.right")
                    .font(.system(size: 11, weight: .bold))
                    .foregroundStyle(AppTheme.success)
                    .frame(width: 31, height: 31)
                    .background(AppTheme.success.opacity(0.10), in: Circle())
            }
            .padding(13)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(cardSurface(tint: AppTheme.success))
            .contentShape(RoundedRectangle(cornerRadius: 21, style: .continuous))
        }
        .buttonStyle(AppPressableStyle())
        .contextMenu {
            openInNewTabButton(destination)
        }
        .accessibilityLabel("Mở không gian dữ liệu \(AppBrand.name)")
    }

    @ViewBuilder
    private func appNavigationRow(_ app: InstalledApp, badge: AppAccessBadge) -> some View {
        let destination = FileBrowserDestination(
            containerPath: app.containerPath,
            startPath: app.containerPath,
            title: app.displayName,
            bundleID: app.bundleID
        )

        if app.containerPath.isEmpty {
            appCard(app, isAvailable: false, badge: badge)
                .accessibilityHint("Không tìm thấy đường dẫn dữ liệu của ứng dụng này")
        } else {
            Button {
                pushDestination(destination)
            } label: {
                appCard(app, isAvailable: true, badge: badge)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .contentShape(RoundedRectangle(cornerRadius: 21, style: .continuous))
            }
            .buttonStyle(AppPressableStyle())
            .contextMenu {
                openInNewTabButton(destination)
            }
            .accessibilityElement(children: .combine)
            .accessibilityHint("Chạm để mở dữ liệu ứng dụng")
        }
    }

    private func appCard(_ app: InstalledApp, isAvailable: Bool, badge: AppAccessBadge? = nil) -> some View {
        let resolvedBadge = badge ?? ("Bị khóa Sandbox", "lock.fill", Color.orange, true)
        let isLocked = !isAvailable || resolvedBadge.isSandboxLocked

        return HStack(spacing: 13) {
            BrowserAppIcon(app: app)
                .frame(width: 47, height: 47)
                .background(
                    LinearGradient(
                        colors: [Color.white.opacity(0.12), Color.white.opacity(0.035)],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    ),
                    in: RoundedRectangle(cornerRadius: 14, style: .continuous)
                )
                .overlay {
                    RoundedRectangle(cornerRadius: 14, style: .continuous)
                        .fill(LinearGradient(colors: [Color.white.opacity(0.11), .clear], startPoint: .topLeading, endPoint: .bottomTrailing))
                }
                .overlay {
                    RoundedRectangle(cornerRadius: 14, style: .continuous)
                        .strokeBorder(Color.white.opacity(0.17), lineWidth: 1)
                }
                .shadow(color: AppTheme.silverGlow.opacity(0.08), radius: 8, y: 3)

            VStack(alignment: .leading, spacing: 4) {
                Text(app.displayName)
                    .font(.system(size: 13, weight: .bold, design: .rounded))
                    .foregroundStyle(.white)
                    .lineLimit(dynamicTypeSize.isAccessibilitySize ? 2 : 1)
                    .minimumScaleFactor(0.86)

                Text(app.bundleID)
                    .font(.system(size: 9, weight: .medium, design: .monospaced))
                    .foregroundStyle(AppTheme.subduedText)
                    .lineLimit(1)
                    .truncationMode(.middle)

                HStack(spacing: 6) {
                    if !app.version.isEmpty {
                        Text("VERSION  \(app.version)")
                            .font(.system(size: 8, weight: .bold, design: .monospaced))
                            .tracking(0.45)
                            .foregroundStyle(AppTheme.accentSoft.opacity(0.86))
                            .lineLimit(1)
                    }

                    HStack(spacing: 3) {
                        Image(systemName: resolvedBadge.icon)
                            .font(.system(size: 7, weight: .bold))
                        Text(resolvedBadge.title)
                            .font(.system(size: 7.5, weight: .bold))
                    }
                    .foregroundStyle(resolvedBadge.color)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(resolvedBadge.color.opacity(0.14), in: Capsule())
                    .overlay {
                        Capsule().strokeBorder(resolvedBadge.color.opacity(0.28), lineWidth: 0.5)
                    }
                }
            }

            Spacer(minLength: 4)

            Image(systemName: isLocked ? "lock.fill" : "chevron.right")
                .font(.system(size: 11, weight: .bold))
                .foregroundStyle(!isAvailable ? AppTheme.subduedText : (isLocked ? Color.orange : AppTheme.accent))
                .frame(width: 31, height: 31)
                .background(Color.white.opacity(0.065), in: Circle())
                .overlay { Circle().strokeBorder(Color.white.opacity(0.10), lineWidth: 1) }
        }
        .padding(.horizontal, 13)
        .padding(.vertical, 12)
        .frame(minHeight: 76)
        .background(cardSurface(tint: isLocked ? Color.orange : AppTheme.accentSoft))
        .opacity(!isAvailable ? 0.58 : (isLocked ? 0.85 : 1))
    }

    private func cardSurface(tint: Color) -> some View {
        RoundedRectangle(cornerRadius: 21, style: .continuous)
            .fill(AppTheme.consoleBackground)
            .overlay {
                RoundedRectangle(cornerRadius: 21, style: .continuous)
                    .strokeBorder(Color.white.opacity(0.12), lineWidth: 1)
            }
            .shadow(color: .black.opacity(0.18), radius: 8, y: 4)
    }

    private var appSearchEmptyState: some View {
        let trimmedQuery = appSearchText.trimmingCharacters(in: .whitespacesAndNewlines)
        return VStack(spacing: 11) {
            Image(systemName: "magnifyingglass")
                .font(.system(size: 27, weight: .light))
                .foregroundStyle(AppTheme.accentSoft)
            Text(
                trimmedQuery.isEmpty
                    ? "Không có ứng dụng nào trong nhóm bộ lọc hiện tại."
                    : language.text("browser.search_apps_no_results", appSearchText)
            )
                .font(.system(size: 12, weight: .semibold))
                .foregroundStyle(AppTheme.subduedText)
                .multilineTextAlignment(.center)

            Button(trimmedQuery.isEmpty ? "Hiển thị tất cả" : language.text("browser.clear_search")) {
                withAnimation(interfaceAnimation) {
                    appSearchText = ""
                    accessFilter = .all
                }
            }
            .font(.system(size: 11, weight: .bold, design: .rounded))
            .foregroundStyle(AppTheme.pageBackground)
            .padding(.horizontal, 17)
            .padding(.vertical, 10)
            .background(
                LinearGradient(colors: [AppTheme.accent, AppTheme.accentSoft], startPoint: .topLeading, endPoint: .bottomTrailing),
                in: Capsule()
            )
            .buttonStyle(AppPressableStyle())
        }
        .frame(maxWidth: .infinity, minHeight: 170)
        .padding(20)
        .background(cardSurface(tint: AppTheme.accentSoft))
    }

    /// Push directly into the selected tab's path from a real Button action. This
    /// avoids relying on implicit NavigationLink path mutations inside a scrolling row.
    private func pushDestination(_ destination: FileBrowserDestination) {
        var updatedSession = tabSession
        let tabID = updatedSession.selectedTabID
        var path = updatedSession.navigationPath(for: tabID)
        path.append(destination)
        updatedSession.setNavigationPath(path, for: tabID)
        tabSession = updatedSession
    }

    private func openInNewTabButton(_ destination: FileBrowserDestination) -> some View {
        Button {
            var updatedSession = tabSession
            updatedSession.openTab(navigationPath: [destination])
            tabSession = updatedSession
        } label: {
            Label(language.text("browser.open_new_tab"), systemImage: "square.on.square")
        }
    }

    private var emptyView: some View {
        VStack(spacing: 15) {
            ZStack {
                Circle()
                    .fill(AppTheme.accentSoft.opacity(0.09))
                    .frame(width: 88, height: 88)
                Circle()
                    .strokeBorder(AppTheme.accentSoft.opacity(0.22), lineWidth: 1)
                    .frame(width: 88, height: 88)
                Image(systemName: "folder.badge.questionmark")
                    .font(.system(size: 29, weight: .light))
                    .foregroundStyle(AppTheme.accentSoft)
            }
            Text(errorMessage ?? language.text("browser.empty"))
                .font(.system(size: 13, weight: .medium))
                .foregroundStyle(AppTheme.subduedText)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 25)
            Button(language.text("browser.retry")) { reload() }
                .font(.system(size: 12, weight: .bold, design: .rounded))
                .foregroundStyle(AppTheme.pageBackground)
                .padding(.horizontal, 20)
                .padding(.vertical, 11)
                .background(AppTheme.accent, in: Capsule())
                .buttonStyle(AppPressableStyle())
        }
        .padding(24)
    }

    private func reload() {
        reloadGeneration += 1
        let requestID = reloadGeneration
        isLoading = true
        isResolving = true
        errorMessage = nil
        let emptyMessage = language.text("browser.empty")

        let finishWithApps: ([LocalDevApp]) -> Void = { localApps in
            DispatchQueue.global(qos: .userInitiated).async {
                let localDevApps: [InstalledApp] = localApps.map { lApp in
                    let preferredPath: String
                    if ContainerStore.isWithinOwnSandbox(lApp.container_path ?? "") ||
                        (ContainerStore.hasPrivilegedContainerAccess() && !(lApp.container_path ?? "").isEmpty) {
                        preferredPath = lApp.container_path ?? LocalDevVirtualPath.rootPath(bundleID: lApp.bundle_id)
                    } else {
                        preferredPath = LocalDevVirtualPath.rootPath(bundleID: lApp.bundle_id)
                    }
                    return InstalledApp(
                        bundleID: lApp.bundle_id,
                        name: lApp.display_name,
                        containerPath: preferredPath,
                        version: lApp.version,
                        icon: nil
                    )
                }

                guard ContainerStore.hasPrivilegedContainerAccess() else {
                    ContainerStore.logSandboxModeNoticeOnce(context: "browser")
                    let sandboxApps = AppDataCatalogMerger.merge(
                        identified: [ContainerStore.ownInstalledApp] + localDevApps,
                        fallback: [],
                        identifier: { $0.bundleID },
                        path: { $0.containerPath }
                    ).filter {
                        ContainerPresentationPolicy.shouldShow(bundleID: $0.bundleID)
                    }.sorted {
                        $0.displayName.localizedCaseInsensitiveCompare($1.displayName) == .orderedAscending
                    }

                    DispatchQueue.main.async {
                        guard requestID == reloadGeneration else { return }
                        apps = sandboxApps
                        isLoading = false
                        isResolving = false
                        if sandboxApps.isEmpty {
                            errorMessage = emptyMessage
                        }
                        AppLog.shared.writeDiagnosticsSnapshot()
                    }
                    return
                }

                let bundleMetadata = ContainerStore.applicationBundleMetadataCatalog()
                let apiApps = ContainerStore.applyingBundleMetadata(
                    to: ContainerStore.installedAppsFromAPI(),
                    catalog: bundleMetadata
                )
                let dynamicIdentifiers = ContainerStore.dynamicAppIdentifiers()
                let mcmApps = ContainerStore.installedAppsFromMCM(
                    identifiers: dynamicIdentifiers,
                    bundleMetadata: bundleMetadata
                )
                let filesystemApps = ContainerStore.containersFromFilesystem()
                let baseIdentifiedApps = mcmApps + apiApps + localDevApps
                var result = ContainerDiscoveryMerger.merge(
                    enumerated: filesystemApps,
                    identified: baseIdentifiedApps,
                    path: { $0.containerPath }
                )
                result.sort { $0.displayName.localizedCaseInsensitiveCompare($1.displayName) == .orderedAscending }

                let preliminary = result.filter {
                    ContainerPresentationPolicy.shouldShow(bundleID: $0.bundleID)
                }
                DispatchQueue.main.async {
                    guard requestID == reloadGeneration else { return }
                    apps = preliminary
                    isLoading = false
                }

                let launchServicesIdentifiers = ContainerStore.launchServicesStoreIdentifiers()
                let mhaIdentifiers = MHAIdentifierCatalog.identifiers(
                    dynamic: dynamicIdentifiers,
                    installed: apiApps.map(\.bundleID),
                    research: ContainerStore.researchAppIdentifiers,
                    custom: bundleMetadata.keys.sorted(),
                    launchServices: launchServicesIdentifiers
                )

                let mhaApps = ContainerStore.installedAppsFromMHACandidates(
                    identifiers: mhaIdentifiers,
                    bundleMetadata: bundleMetadata
                ) { discoveredApps in
                    var progressiveResult = AppDataCatalogMerger.merge(
                        identified: discoveredApps + baseIdentifiedApps,
                        fallback: [],
                        identifier: { $0.bundleID },
                        path: { $0.containerPath }
                    )
                    progressiveResult = progressiveResult.filter {
                        ContainerPresentationPolicy.shouldShow(bundleID: $0.bundleID)
                    }
                    progressiveResult.sort {
                        $0.displayName.localizedCaseInsensitiveCompare($1.displayName) == .orderedAscending
                    }
                    DispatchQueue.main.async {
                        guard requestID == reloadGeneration else { return }
                        apps = progressiveResult
                    }
                }

                let allKnownApps = mhaApps + baseIdentifiedApps
                let identifiedPaths = Set(allKnownApps.map {
                    ContainerDiscoveryMerger.canonicalPath($0.containerPath)
                })
                let unmatchedFilesystemApps = filesystemApps.filter {
                    !identifiedPaths.contains(ContainerDiscoveryMerger.canonicalPath($0.containerPath))
                }
                let inferredFilesystemApps = ContainerStore.inferUnidentifiedApps(
                    in: unmatchedFilesystemApps,
                    knownApps: allKnownApps,
                    launchServicesIdentifiers: Set(launchServicesIdentifiers)
                ).filter {
                    ContainerPresentationPolicy.shouldShow(bundleID: $0.bundleID)
                }
                result = AppDataCatalogMerger.merge(
                    identified: allKnownApps,
                    fallback: inferredFilesystemApps,
                    identifier: { $0.bundleID },
                    path: { $0.containerPath }
                )
                result = result.filter {
                    ContainerPresentationPolicy.shouldShow(bundleID: $0.bundleID)
                }
                result.sort { $0.displayName.localizedCaseInsensitiveCompare($1.displayName) == .orderedAscending }

                DispatchQueue.main.async {
                    guard requestID == reloadGeneration else { return }
                    apps = result
                    isLoading = false
                    isResolving = false
                    if result.isEmpty {
                        errorMessage = emptyMessage
                    }
                    AppLog.shared.writeDiagnosticsSnapshot()
                }
            }
        }

        if LocalDevBridge.shared.currentStatusSnapshot.isLive {
            LocalDevBridge.shared.scanApplications { scannedApps in
                guard requestID == reloadGeneration else { return }
                finishWithApps(scannedApps)
            }
        } else {
            // Keep own-Sandbox app discovery completely functional even if LocalDev/Pairing has failed.
            finishWithApps([])
        }
    }
}

private enum AppAccessFilter: String, CaseIterable, Identifiable {
    case all
    case accessible
    case sandboxLocked

    var id: String { rawValue }
}

private enum AppBrowserOverlayState: Equatable {
    case loading
    case empty
    case none
}

struct BrowserAppIcon: View {
    let app: InstalledApp
    @State private var resolvedIcon: UIImage?
    @State private var didRequestIcon = false

    init(app: InstalledApp) {
        self.app = app
        _resolvedIcon = State(initialValue: app.icon)
    }

    var body: some View {
        Group {
            if let resolvedIcon {
                Image(uiImage: resolvedIcon)
                    .resizable()
                    .scaledToFill()
            } else {
                Image(systemName: "app.fill")
                    .font(.system(size: 18, weight: .medium))
                    .foregroundStyle(AppTheme.accentSoft)
            }
        }
        .frame(width: AppTheme.appIconSize, height: AppTheme.appIconSize)
        .clipShape(RoundedRectangle(cornerRadius: 11, style: .continuous))
        .accessibilityHidden(true)
        .onAppear {
            guard resolvedIcon == nil, !didRequestIcon else { return }
            didRequestIcon = true
            let bundleID = app.bundleID
            DispatchQueue.global(qos: .utility).async {
                let icon = iconForBundleID(bundleID)
                DispatchQueue.main.async {
                    resolvedIcon = icon
                }
            }
        }
    }
}
