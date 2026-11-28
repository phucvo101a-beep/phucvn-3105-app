import SwiftUI

struct HomeDashboardView: View {
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize
    @ObservedObject private var keyAuth = KeyAuthManager.shared
    @State private var showCleaner = false
    @State private var showWallpaper = false
    @State private var showKeyDetails = false

    let isActive: Bool
    let onSelectSection: (AppSection) -> Void
    let onOpenSettings: () -> Void
    let onOpenLogs: () -> Void

    private let columns = [
        GridItem(.flexible(), spacing: 12),
        GridItem(.flexible(), spacing: 12)
    ]

    var body: some View {
        NavigationStack {
            ScrollView(showsIndicators: false) {
                VStack(alignment: .leading, spacing: 14) {
                    heading
                    heroStatusCard
                    licenseStatusBar
                    quickAccess
                    maintenancePanel
                    footer
                }
                .frame(maxWidth: 760)
                .frame(maxWidth: .infinity)
                .padding(.horizontal, AppTheme.pageInset)
                .padding(.top, 10)
                .padding(.bottom, 28)
            }
            .scrollDismissesKeyboard(.immediately)
            .appTopSafeAreaBlur()
            .background { AppPageBackground() }
            .navigationTitle("")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar(.hidden, for: .navigationBar)
            .sheet(isPresented: $showCleaner) {
                CleanerView()
            }
            .sheet(isPresented: $showWallpaper) {
                WallpaperLabView(
                    onOpenSettings: onOpenSettings,
                    onOpenLogs: onOpenLogs
                )
            }
            .sheet(isPresented: $showKeyDetails) {
                KeyLicenseDetailView()
            }
        }
    }

    private var heading: some View {
        HStack(spacing: 12) {
            AppLogo(size: 42)

            VStack(alignment: .leading, spacing: 3) {
                Text(AppBrand.name)
                    .font(.system(size: 16, weight: .heavy, design: .rounded))
                    .tracking(-0.4)
                    .foregroundStyle(.white)
                    .lineLimit(1)
                    .minimumScaleFactor(0.78)

                Text("TRUNG TÂM ĐIỀU KHIỂN")
                    .font(.system(size: 9, weight: .bold, design: .rounded))
                    .tracking(1.55)
                    .foregroundStyle(AppTheme.subduedText)
            }

            Spacer(minLength: 0)

            Menu {
                Button(action: onOpenSettings) {
                    Label("Cài đặt", systemImage: "gearshape")
                }
                Button(action: onOpenLogs) {
                    Label("Nhật ký hoạt động", systemImage: "apple.terminal")
                }
            } label: {
                Image(systemName: "gearshape.fill")
                    .font(.system(size: 15, weight: .semibold))
                    .foregroundStyle(AppTheme.accent)
                    .frame(width: 40, height: 40)
                    .background(AppTheme.consoleBackground, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
                    .overlay {
                        RoundedRectangle(cornerRadius: 12, style: .continuous)
                            .strokeBorder(Color.white.opacity(0.14), lineWidth: 1)
                    }
            }
            .accessibilityLabel("Cài đặt và nhật ký")
        }
        .padding(.top, 2)
    }

    private var licenseStatusBar: some View {
        Button {
            showKeyDetails = true
        } label: {
            HStack(spacing: 10) {
                ZStack {
                    RoundedRectangle(cornerRadius: 12, style: .continuous)
                        .fill(AppTheme.accent.opacity(0.14))
                        .frame(width: 32, height: 32)
                    Image(systemName: "key.fill")
                        .font(.system(size: 13, weight: .bold))
                        .foregroundStyle(AppTheme.accent)
                }

                Text(keyAuth.currentKey.isEmpty ? "Chưa kích hoạt" : keyAuth.currentKey)
                    .font(.system(size: 11.5, weight: .bold, design: .monospaced))
                    .foregroundStyle(.white)
                    .lineLimit(1)
                    .truncationMode(.tail)

                Spacer(minLength: 4)

                Text(keyAuth.isPermanent ? "Vĩnh Viễn" : (keyAuth.remainingCountdownText.isEmpty ? "Đang kiểm tra" : keyAuth.remainingCountdownText))
                    .font(.system(size: 9.5, weight: .bold, design: .rounded))
                    .foregroundStyle(keyAuth.isPermanent ? AppTheme.accentSoft : (keyAuth.secondsRemaining < 3600 ? AppTheme.danger : AppTheme.success))
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                    .background(Color.white.opacity(0.07), in: Capsule())

                HStack(spacing: 3) {
                    Text("Xem")
                        .font(.system(size: 11, weight: .bold, design: .rounded))
                    Image(systemName: "chevron.right")
                        .font(.system(size: 10, weight: .semibold))
                }
                .foregroundStyle(AppTheme.accent)
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 10)
            .background(AppTheme.consoleBackground, in: RoundedRectangle(cornerRadius: 20, style: .continuous))
            .overlay { AppCardBorder(cornerRadius: 20) }
        }
        .buttonStyle(AppPressableStyle())
    }

    private var heroStatusCard: some View {
        Button(action: onOpenSettings) {
            ZStack(alignment: .topTrailing) {
                RoundedRectangle(cornerRadius: 20, style: .continuous)
                    .fill(
                        LinearGradient(
                            colors: [
                                Color(red: 0.19, green: 0.215, blue: 0.250),
                                Color(red: 0.11, green: 0.125, blue: 0.148),
                                Color(red: 0.052, green: 0.060, blue: 0.072)
                            ],
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        )
                    )

                VStack(alignment: .leading, spacing: 10) {
                    HStack {
                        StudioEyebrow(text: "KHÔNG GIAN QUẢN LÝ")
                        Spacer()
                        AppStatusPill(title: "SẴN SÀNG", tint: AppTheme.success)
                    }

                    Text("Kiểm soát thiết bị & dữ liệu")
                        .font(.system(size: dynamicTypeSize.isAccessibilitySize ? 19 : 21, weight: .bold, design: .rounded))
                        .tracking(-0.5)
                        .foregroundStyle(
                            LinearGradient(
                                colors: [Color.white, AppTheme.silverGlow, Color.white.opacity(0.85)],
                                startPoint: .topLeading,
                                endPoint: .bottomTrailing
                            )
                        )
                        .lineLimit(1)
                        .minimumScaleFactor(0.78)

                    HStack(spacing: 6) {
                        Image(systemName: "iphone.gen3")
                            .font(.system(size: 11, weight: .semibold))
                            .foregroundStyle(AppTheme.accentSoft)
                        Text("\(AppInfo.hardwareDisplayName) • iOS \(AppInfo.osVersion) (\(AppInfo.osBuild))")
                            .font(.system(size: 11, weight: .medium, design: .monospaced))
                            .foregroundStyle(AppTheme.subduedText)
                            .lineLimit(1)
                            .minimumScaleFactor(0.75)
                        Spacer(minLength: 4)
                        Image(systemName: "chevron.right")
                            .font(.system(size: 10, weight: .bold))
                            .foregroundStyle(AppTheme.accentSoft)
                    }
                }
                .padding(14)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .frame(minHeight: 112)
            .clipShape(RoundedRectangle(cornerRadius: 20, style: .continuous))
            .overlay { AppCardBorder(cornerRadius: 20) }
            .shadow(color: .black.opacity(0.22), radius: 10, y: 5)
        }
        .buttonStyle(AppPressableStyle())
        .accessibilityLabel("Thông tin thiết bị và phiên bản")
    }

    private var quickAccess: some View {
        VStack(alignment: .leading, spacing: 13) {
            StudioSectionHeading(title: "Công cụ chính", detail: "04 CÔNG CỤ")

            LazyVGrid(columns: columns, spacing: 12) {
                Button {
                    onSelectSection(.installed)
                } label: {
                    HomeToolCard(
                        symbol: "square.stack.3d.up.fill",
                        title: "Dự án của tôi",
                        detail: "Tạo và quản lý dự án",
                        tint: AppTheme.accent
                    )
                }
                .buttonStyle(AppPressableStyle())

                Button {
                    onSelectSection(.files)
                } label: {
                    HomeToolCard(
                        symbol: "folder.fill",
                        title: "Quản lý tệp",
                        detail: "Duyệt dữ liệu ứng dụng",
                        tint: AppTheme.info
                    )
                }
                .buttonStyle(AppPressableStyle())

                Button {
                    showCleaner = true
                } label: {
                    HomeToolCard(
                        symbol: "sparkles",
                        title: "Dọn dẹp",
                        detail: "Bảo trì bộ nhớ tạm",
                        tint: AppTheme.success
                    )
                }
                .buttonStyle(AppPressableStyle())

                if WallpaperFeatureSupportPolicy.isSupported(major: AppInfo.versionTuple.major) {
                    Button {
                        showWallpaper = true
                    } label: {
                        HomeToolCard(
                            symbol: "photo.on.rectangle.angled",
                            title: "Công cụ hình nền",
                            detail: "Quản lý gói hình nền",
                            tint: AppTheme.accentSoft
                        )
                    }
                    .buttonStyle(AppPressableStyle())
                } else {
                    Button(action: onOpenSettings) {
                        HomeToolCard(
                            symbol: "iphone.gen3",
                            title: "Thông tin thiết bị",
                            detail: "Phiên bản và trạng thái",
                            tint: AppTheme.accentSoft
                        )
                    }
                    .buttonStyle(AppPressableStyle())
                }
            }
        }
    }

    private var maintenancePanel: some View {
        Button {
            showCleaner = true
        } label: {
            HStack(spacing: 14) {
                AppRowIcon(
                    systemName: "shield.lefthalf.filled",
                    tint: AppTheme.success,
                    symbolSize: 20,
                    frameSize: 48
                )

                VStack(alignment: .leading, spacing: 4) {
                    Text("Dọn dẹp & bảo trì")
                        .font(.system(size: 14, weight: .bold, design: .rounded))
                        .foregroundStyle(.white)
                    Text("Quét bộ nhớ tạm trong phạm vi an toàn")
                        .font(.system(size: 10, weight: .medium))
                        .foregroundStyle(AppTheme.subduedText)
                        .lineLimit(2)
                }

                Spacer(minLength: 4)

                Image(systemName: "arrow.up.right")
                    .font(.system(size: 12, weight: .bold))
                    .foregroundStyle(AppTheme.accent)
                    .frame(width: 32, height: 32)
                    .background(Color.white.opacity(0.07), in: Circle())
            }
            .padding(13)
            .background(
                LinearGradient(
                    colors: [Color(red: 0.145, green: 0.165, blue: 0.195), AppTheme.consoleBackground],
                    startPoint: .topLeading,
                    endPoint: .bottomTrailing
                ),
                in: RoundedRectangle(cornerRadius: 20, style: .continuous)
            )
            .overlay { StudioGlassHighlight(cornerRadius: 20, intensity: 0.75) }
            .overlay { AppCardBorder(cornerRadius: 20) }
        }
        .buttonStyle(AppPressableStyle())
    }

    private var footer: some View {
        HStack(spacing: 8) {
            Capsule()
                .fill(AppTheme.accentSoft.opacity(0.45))
                .frame(width: 20, height: 2)
            Text("PHUCVN IPA DEV")
                .font(.system(size: 9, weight: .bold, design: .rounded))
                .tracking(1.6)
                .foregroundStyle(AppTheme.subduedText.opacity(0.7))
            Capsule()
                .fill(AppTheme.accentSoft.opacity(0.45))
                .frame(width: 20, height: 2)
        }
        .frame(maxWidth: .infinity)
        .padding(.top, 2)
    }
}

private struct HomeToolCard: View {
    let symbol: String
    let title: String
    let detail: String
    let tint: Color

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .top) {
                HomeToolSymbol(symbolName: symbol, tint: tint)
                Spacer(minLength: 0)
                Image(systemName: "arrow.up.right")
                    .font(.system(size: 10, weight: .bold))
                    .foregroundStyle(AppTheme.subduedText)
                    .frame(width: 26, height: 26)
                    .background(Color.white.opacity(0.055), in: Circle())
            }

            VStack(alignment: .leading, spacing: 3) {
                Text(title)
                    .font(.system(size: 13, weight: .bold, design: .rounded))
                    .tracking(-0.15)
                    .foregroundStyle(.white)
                    .lineLimit(1)
                    .minimumScaleFactor(0.82)
                Text(detail)
                    .font(.system(size: 9.5, weight: .medium))
                    .foregroundStyle(AppTheme.subduedText)
                    .lineLimit(2)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .frame(maxWidth: .infinity, minHeight: 96, alignment: .leading)
        .padding(12)
        .background(
            AppTheme.consoleBackground,
            in: RoundedRectangle(cornerRadius: 20, style: .continuous)
        )
        .overlay { AppCardBorder(cornerRadius: 20) }
        .shadow(color: .black.opacity(0.18), radius: 8, y: 4)
    }
}

private struct HomeToolSymbol: View {
    let symbolName: String
    let tint: Color

    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .fill(
                    LinearGradient(
                        colors: [tint.opacity(0.22), tint.opacity(0.07)],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    )
                )
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .strokeBorder(Color.white.opacity(0.18), lineWidth: 1)
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .fill(LinearGradient(colors: [Color.white.opacity(0.12), .clear], startPoint: .topLeading, endPoint: .bottomTrailing))
            Image(systemName: symbolName)
                .font(.system(size: 17, weight: .semibold))
                .foregroundStyle(tint)
                .shadow(color: tint.opacity(0.34), radius: 7, y: 1)
        }
        .frame(width: 38, height: 38)
        .shadow(color: tint.opacity(0.10), radius: 9, y: 3)
    }
}
