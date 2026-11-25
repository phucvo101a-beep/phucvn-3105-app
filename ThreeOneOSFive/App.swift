import SwiftUI

@main
struct ThreeOneOSFiveApp: App {
    @StateObject private var appState = AppState()
    @StateObject private var patchDraftCoordinator = PatchDraftCoordinator()
    @StateObject private var fileOperationCoordinator = FileOperationCoordinator()
    @StateObject private var patchStore = PatchProjectStore()
    @StateObject private var keyAuth = KeyAuthManager.shared
    @StateObject private var language = AppLanguageManager.shared
    @AppStorage("hasCompletedOnboarding") private var hasCompletedOnboarding = false
    @State private var showOnboarding = false
    @Environment(\.scenePhase) private var scenePhase

    init() {
        showOnboarding = !UserDefaults.standard.bool(forKey: "hasCompletedOnboarding")
        LocalDevBridge.shared.initialize()
    }

    var body: some Scene {
        WindowGroup {
            ZStack {
                switch keyAuth.gatePhase {
                case .checking:
                    SecurityCheckingView(message: keyAuth.statusMessage)
                        .transition(.opacity)
                case .serverClosed(let message):
                    SecurityLockoutView(
                        mode: .serverClosed(message: message),
                        onRetry: { keyAuth.bootstrapCheck() }
                    )
                    .transition(.opacity)
                case .deviceBanned(let reason, let hwid):
                    SecurityLockoutView(
                        mode: .deviceBanned(reason: reason, hwid: hwid),
                        onRetry: { keyAuth.bootstrapCheck() }
                    )
                    .transition(.opacity)
                case .forceUpdate(let minVer, let latestVer, let downloadURL, let message):
                    SecurityLockoutView(
                        mode: .forceUpdate(
                            minVersion: minVer,
                            latestVersion: latestVer,
                            downloadURL: downloadURL,
                            message: message
                        ),
                        onRetry: { keyAuth.bootstrapCheck() }
                    )
                    .transition(.opacity)
                case .tampered:
                    SecurityLockoutView(
                        mode: .tampered,
                        onRetry: { keyAuth.bootstrapCheck() }
                    )
                    .transition(.opacity)
                case .requiresKey:
                    KeyGatekeeperView(keyAuth: keyAuth)
                        .transition(.opacity)
                case .unlocked(let ticket):
                    if SecCoreBridge.shared.isActiveTicketValid(ticket) {
                        ContentView()
                            .environmentObject(appState)
                            .environmentObject(patchDraftCoordinator)
                            .environmentObject(fileOperationCoordinator)
                            .environmentObject(patchStore)
                            .environmentObject(language)
                            .preferredColorScheme(.dark)
                            .onOpenURL { url in
                                if url.pathExtension.lowercased() == "3105" {
                                    patchDraftCoordinator.handleIncomingFileURL(url)
                                } else if url.scheme == "threeoneosfive" {
                                    patchDraftCoordinator.handleIncomingLink(url)
                                } else if url.isFileURL {
                                    fileOperationCoordinator.handleIncomingFileURL(url)
                                }
                            }
                            .fullScreenCover(isPresented: $showOnboarding) {
                                OnboardingView {
                                    hasCompletedOnboarding = true
                                    showOnboarding = false
                                    appState.detectSupport()
                                }
                            }
                    } else {
                        KeyGatekeeperView(keyAuth: keyAuth)
                            .transition(.opacity)
                    }
                }
            }
            .preferredColorScheme(.dark)
            .onAppear {
                if !showOnboarding && keyAuth.activeVerifiedTicket != nil {
                    appState.detectSupport()
                }
            }
            .onChange(of: scenePhase) { phase in
                if phase == .active {
                    keyAuth.verifyLiveSessionOnForeground()
                    if !showOnboarding && keyAuth.activeVerifiedTicket != nil {
                        appState.detectSupport()
                    }
                }
            }
            .onChange(of: keyAuth.gatePhase) { phase in
                if case .unlocked(let t) = phase, SecCoreBridge.shared.isActiveTicketValid(t), !showOnboarding {
                    appState.detectSupport()
                }
            }
        }
    }
}
