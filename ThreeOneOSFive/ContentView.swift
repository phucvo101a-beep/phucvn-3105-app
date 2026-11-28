import SwiftUI
import UIKit

struct ContentView: View {
    @Environment(\.appLanguage) private var language
    @Environment(\.horizontalSizeClass) private var horizontalSizeClass
    @EnvironmentObject private var patchDraftCoordinator: PatchDraftCoordinator
    @EnvironmentObject private var patchStore: PatchProjectStore
    @State private var tabNavigation: AppTabNavigationState
    @State private var activeUtilitySheet: RootUtilitySheet?

    init() {
#if targetEnvironment(simulator)
        let arguments = ProcessInfo.processInfo.arguments
        let initialTab: Int
        if arguments.contains("--simulate-installed-tab")
            || arguments.contains("--simulate-patch-tab") {
            initialTab = AppSection.installed.rawValue
        } else if arguments.contains("--simulate-files-tab") {
            initialTab = AppSection.files.rawValue
        } else {
            initialTab = AppSection.home.rawValue
        }
        _tabNavigation = State(initialValue: AppTabNavigationState(selectedTab: initialTab))
        _activeUtilitySheet = State(
            initialValue: arguments.contains("--simulate-settings") ? .settings : nil
        )
#else
        _tabNavigation = State(initialValue: AppTabNavigationState())
        _activeUtilitySheet = State(initialValue: nil)
#endif
    }

    var body: some View {
        Group {
            if horizontalSizeClass == .regular {
                regularLayout
            } else {
                compactLayout
            }
        }
        .tint(AppTheme.accent)
        .preferredColorScheme(.dark)
        .imageScale(.medium)
        .onChange(of: patchDraftCoordinator.request?.id) { requestID in
            if requestID != nil { selectSection(AppSection.installed.rawValue) }
        }
        .onChange(of: patchDraftCoordinator.importRequest?.id) { requestID in
            if requestID != nil { selectSection(AppSection.installed.rawValue) }
        }
        .onAppear {
            var updatedNavigation = tabNavigation
            updatedNavigation.reconcileSelection(with: featureVisibility)
            tabNavigation = updatedNavigation
        }
        .sheet(item: $activeUtilitySheet) { sheet in
            switch sheet {
            case .settings:
                SettingsView()
            case .logs:
                LogView()
            }
        }
    }

    private var compactLayout: some View {
        ZStack(alignment: .bottom) {
            AppPageBackground()
            ForEach(featureVisibility.visibleSections) { section in
                sectionContent(section)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .opacity(selectedVisibleSection == section ? 1 : 0)
                    .allowsHitTesting(selectedVisibleSection == section)
                    .accessibilityHidden(selectedVisibleSection != section)
                    .zIndex(selectedVisibleSection == section ? 1 : 0)
            }

            StudioTabBar(
                sections: featureVisibility.visibleSections,
                selectedTab: tabSelection
            )
            .zIndex(10)
        }
        .patchStorePresentation(patchStore)
    }

    private var regularLayout: some View {
        NavigationSplitView {
            List {
                ForEach(featureVisibility.visibleSections) { section in
                    Button {
                        withAnimation(.easeInOut(duration: 0.18)) {
                            selectSection(section.rawValue)
                        }
                    } label: {
                        Label(language.text(section.titleKey), systemImage: section.systemImage)
                            .fontWeight(section.rawValue == tabNavigation.selectedTab ? .semibold : .regular)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .listRowBackground(
                        section.rawValue == tabNavigation.selectedTab
                            ? AppTheme.accent.opacity(0.14)
                            : Color.clear
                    )
                    .accessibilityAddTraits(
                        section.rawValue == tabNavigation.selectedTab ? .isSelected : []
                    )
                }
            }
            .navigationTitle(AppBrand.name)
            .navigationSplitViewColumnWidth(min: 210, ideal: 240, max: 300)
        } detail: {
            sectionContent(selectedVisibleSection)
                .id(selectedVisibleSection.rawValue)
        }
        .navigationSplitViewStyle(.balanced)
        .patchStorePresentation(patchStore)
    }

    @ViewBuilder
    private func sectionContent(_ section: AppSection) -> some View {
        switch section {
        case .home:
            HomeDashboardView(
                isActive: selectedVisibleSection == .home,
                onSelectSection: { selectSection($0.rawValue) },
                onOpenSettings: openSettings,
                onOpenLogs: openLogs
            )
        case .installed:
            PatchProjectsView(
                onOpenSettings: openSettings,
                onOpenLogs: openLogs
            )
        case .files:
            AppDataBrowserView(
                tabSession: filesTabSession,
                isActive: selectedVisibleSection == .files,
                onOpenSettings: openSettings,
                onOpenLogs: openLogs
            )
        }
    }

    private var tabSelection: Binding<Int> {
        Binding(
            get: { tabNavigation.selectedTab },
            set: { selectSection($0) }
        )
    }

    private var filesTabSession: Binding<FilesTabSession> {
        Binding(
            get: { tabNavigation.filesTabs },
            set: { newSession in
                var updatedNavigation = tabNavigation
                updatedNavigation.setFilesTabs(newSession)
                tabNavigation = updatedNavigation
            }
        )
    }

    private func selectSection(_ newSelection: Int) {
        var updatedNavigation = tabNavigation
        updatedNavigation.select(newSelection)
        tabNavigation = updatedNavigation
    }

    private var featureVisibility: FeatureVisibility { FeatureVisibility() }

    private var selectedVisibleSection: AppSection {
        let selected = AppSection(rawValue: tabNavigation.selectedTab)
        return selected.flatMap {
            featureVisibility.isVisible($0) ? $0 : nil
        } ?? .home
    }

    private func openSettings() {
        activeUtilitySheet = .settings
    }

    private func openLogs() {
        activeUtilitySheet = .logs
    }
}

private enum RootUtilitySheet: String, Identifiable {
    case settings
    case logs

    var id: String { rawValue }
}

private struct StudioTabBar: View {
    @Environment(\.appLanguage) private var language
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Namespace private var selectionNamespace
    let sections: [AppSection]
    @Binding var selectedTab: Int

    var body: some View {
        HStack(spacing: 4) {
            ForEach(sections) { section in
                let isSelected = selectedTab == section.rawValue
                Button {
                    guard !isSelected else { return }
                    DevHaptics.light()
                    if reduceMotion {
                        selectedTab = section.rawValue
                    } else {
                        withAnimation(.spring(response: 0.28, dampingFraction: 0.76)) {
                            selectedTab = section.rawValue
                        }
                    }
                } label: {
                    VStack(spacing: 3) {
                        Image(systemName: section.systemImage)
                            .font(.system(size: 16, weight: isSelected ? .semibold : .medium))
                            .scaleEffect(isSelected ? 1.04 : 1.0)
                        Text(language.text(section.titleKey))
                            .font(.system(size: 9.5, weight: isSelected ? .bold : .medium, design: .rounded))
                            .lineLimit(1)
                            .minimumScaleFactor(0.8)
                    }
                    .foregroundStyle(isSelected ? Color.white : Color.white.opacity(0.42))
                    .frame(maxWidth: .infinity)
                    .frame(height: 50)
                    .overlay(alignment: .top) {
                        if isSelected {
                            Capsule()
                                .fill(Color.white.opacity(0.92))
                                .frame(width: 18, height: 2)
                                .shadow(color: Color.white.opacity(0.55), radius: 4, y: 1)
                                .padding(.top, 2)
                                .matchedGeometryEffect(id: "DOCK_TOP_BAR", in: selectionNamespace)
                        }
                    }
                    .background {
                        if isSelected {
                            Capsule()
                                .fill(Color.white.opacity(0.10))
                                .overlay {
                                    Capsule()
                                        .strokeBorder(
                                            LinearGradient(
                                                stops: [
                                                    .init(color: Color.white.opacity(0.22), location: 0),
                                                    .init(color: Color.white.opacity(0.03), location: 1)
                                                ],
                                                startPoint: .top,
                                                endPoint: .bottom
                                            ),
                                            lineWidth: 0.75
                                        )
                                }
                                .matchedGeometryEffect(id: "DOCK_GLASS_PILL", in: selectionNamespace)
                        }
                    }
                    .contentShape(Capsule())
                }
                .buttonStyle(TactileButtonStyle(cornerRadius: 25, pressedScale: 0.96, showRimHighlight: false))
                .accessibilityLabel(language.text(section.titleKey))
                .accessibilityAddTraits(isSelected ? .isSelected : [])
            }
        }
        .padding(.horizontal, 4)
        .padding(.vertical, 4)
        .frame(height: 58)
        .background {
            Capsule()
                .fill(.ultraThinMaterial)
                .overlay {
                    Capsule()
                        .fill(DevUIStyle.dockTint.opacity(0.75))
                }
                .overlay {
                    Capsule()
                        .strokeBorder(
                            LinearGradient(
                                stops: [
                                    .init(color: Color.white.opacity(0.20), location: 0.0),
                                    .init(color: Color.white.opacity(0.06), location: 0.45),
                                    .init(color: Color.white.opacity(0.02), location: 1.0)
                                ],
                                startPoint: .top,
                                endPoint: .bottom
                            ),
                            lineWidth: 0.75
                        )
                }
                .shadow(color: .black.opacity(0.55), radius: 18, y: 10)
        }
        .padding(.horizontal, 24)
        .padding(.top, 8)
        .padding(.bottom, 6)
        .background {
            LinearGradient(
                colors: [DevUIStyle.canvas.opacity(0), DevUIStyle.canvas.opacity(0.88)],
                startPoint: .top,
                endPoint: .bottom
            )
            .ignoresSafeArea(edges: .bottom)
            .allowsHitTesting(false)
        }
    }
}
