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
                .padding(.top, 8)
                .padding(.bottom, 92)
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
            AppLogo(size: 42, cornerRadius: 12)

            VStack(alignment: .leading, spacing: 2) {
                Text(AppBrand.name)
                    .font(.system(size: 16, weight: .bold, design: .rounded))
                    .tracking(-0.35)
                    .foregroundStyle(.white)
                    .lineLimit(1)
                    .minimumScaleFactor(0.78)

                Text("CONTROL CENTER")
                    .font(.system(size: 10, weight: .semibold, design: .monospaced))
                    .tracking(1.8)
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
                    .font(.system(size: 15, weight: .medium))
                    .foregroundStyle(.white.opacity(0.88))
                    .frame(width: 38, height: 38)
                    .background(.ultraThinMaterial, in: Circle())
                    .overlay { Circle().fill(DevUIStyle.cardElevated.opacity(0.62)) }
                    .overlay {
                        Circle()
                            .strokeBorder(
                                LinearGradient(
                                    stops: [
                                        .init(color: Color.white.opacity(0.18), location: 0),
                                        .init(color: Color.white.opacity(0.03), location: 1)
                                    ],
                                    startPoint: .top,
                                    endPoint: .bottom
                                ),
                                lineWidth: 0.75
                            )
                    }
            }
            .buttonStyle(TactileButtonStyle(cornerRadius: 19, showRimHighlight: false))
            .accessibilityLabel("Cài đặt và nhật ký")
        }
        .padding(.top, 2)
    }

    private var licenseStatusBar: some View {
        Button {
            DevHaptics.light()
            showKeyDetails = true
        } label: {
            HStack(spacing: 10) {
                Image(systemName: "key.fill")
                    .font(.system(size: 14, weight: .semibold))
                    .foregroundStyle(AppTheme.accent)
                    .shadow(color: AppTheme.accent.opacity(0.28), radius: 6, y: 1)

                Text(keyAuth.currentKey.isEmpty ? "Chưa kích hoạt" : keyAuth.currentKey)
                    .font(.system(size: 11.5, weight: .bold, design: .monospaced))
                    .foregroundStyle(.white)
                    .lineLimit(1)
                    .truncationMode(.tail)

                Spacer(minLength: 4)

                Text(keyAuth.isPermanent ? "VĨNH VIỄN" : (keyAuth.remainingCountdownText.isEmpty ? "ĐANG KIỂM TRA" : keyAuth.remainingCountdownText))
                    .font(.system(size: 9, weight: .bold, design: .monospaced))
                    .tracking(0.6)
                    .foregroundStyle(keyAuth.isPermanent ? AppTheme.accentSoft : (keyAuth.secondsRemaining < 3600 ? AppTheme.danger : AppTheme.success))
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                    .background(DevUIStyle.recessedSlot.opacity(0.85), in: Capsule())
                    .overlay { Capsule().strokeBorder(Color.white.opacity(0.08), lineWidth: 0.75) }

                HStack(spacing: 3) {
                    Text("Xem")
                        .font(.system(size: 11, weight: .semibold, design: .rounded))
                    Image(systemName: "chevron.right")
                        .font(.system(size: 9.5, weight: .bold))
                }
                .foregroundStyle(AppTheme.accentSoft)
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 11)
            .background(
                LinearGradient(
                    colors: [
                        Color(red: 20.0 / 255.0, green: 22.0 / 255.0, blue: 29.0 / 255.0),
                        Color(red: 12.0 / 255.0, green: 13.0 / 255.0, blue: 17.0 / 255.0)
                    ],
                    startPoint: .topLeading,
                    endPoint: .bottomTrailing
                ),
                in: RoundedRectangle(cornerRadius: 16, style: .continuous)
            )
            .overlay { SpecularRimBorder(cornerRadius: 16) }
            .shadow(color: .black.opacity(0.28), radius: 10, y: 4)
        }
        .buttonStyle(TactileButtonStyle(cornerRadius: 16))
    }

    private var heroStatusCard: some View {
        Button {
            DevHaptics.light()
            onOpenSettings()
        } label: {
            ZStack {
                DevUIStyle.cardBase
                DotMatrixBackground()
                CornerReticles()

                VStack(alignment: .leading, spacing: 12) {
                    HStack {
                        Text("SYSTEM TELEMETRY")
                            .font(.system(size: 9.5, weight: .bold, design: .monospaced))
                            .tracking(1.6)
                            .foregroundStyle(AppTheme.accentSoft)
                        Spacer()
                        AppStatusPill(title: "SẴN SÀNG", tint: AppTheme.success, usePulseLED: true)
                    }

                    Text("Kiểm soát thiết bị & dữ liệu")
                        .font(.system(size: dynamicTypeSize.isAccessibilitySize ? 19 : 21, weight: .bold, design: .rounded))
                        .tracking(-0.45)
                        .foregroundStyle(.white)
                        .lineLimit(1)
                        .minimumScaleFactor(0.78)

                    HStack(spacing: 8) {
                        HStack(spacing: 6) {
                            Image(systemName: "iphone.gen3")
                                .font(.system(size: 11, weight: .semibold))
                                .foregroundStyle(AppTheme.accentSoft)
                            Text(AppInfo.hardwareDisplayName)
                                .foregroundStyle(.white.opacity(0.92))
                            Text("|")
                                .foregroundStyle(Color.white.opacity(0.20))
                            Text("iOS \(AppInfo.osVersion)")
                                .foregroundStyle(AppTheme.accentSoft)
                            Text("|")
                                .foregroundStyle(Color.white.opacity(0.20))
                            Text(AppInfo.osBuild)
                                .foregroundStyle(AppTheme.subduedText)
                        }
                        .font(.system(size: 11, weight: .semibold, design: .monospaced))
                        .lineLimit(1)
                        .minimumScaleFactor(0.75)

                        Spacer(minLength: 4)

                        Image(systemName: "chevron.right")
                            .font(.system(size: 10, weight: .bold))
                            .foregroundStyle(AppTheme.subduedText)
                    }
                    .padding(.horizontal, 11)
                    .padding(.vertical, 8)
                    .background(DevUIStyle.recessedSlot, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
                    .overlay {
                        RoundedRectangle(cornerRadius: 10, style: .continuous)
                            .strokeBorder(Color.white.opacity(0.06), lineWidth: 0.75)
                    }
                }
                .padding(14)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .frame(minHeight: 118)
            .clipShape(RoundedRectangle(cornerRadius: 20, style: .continuous))
            .overlay { SpecularRimBorder(cornerRadius: 20) }
            .shadow(color: .black.opacity(0.32), radius: 14, y: 6)
        }
        .buttonStyle(TactileButtonStyle(cornerRadius: 20))
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
            DevHaptics.light()
            showCleaner = true
        } label: {
            HStack(spacing: 12) {
                Capsule()
                    .fill(AppTheme.success)
                    .frame(width: 2.5, height: 28)
                    .shadow(color: AppTheme.success.opacity(0.45), radius: 4)

                Image(systemName: "shield.lefthalf.filled")
                    .font(.system(size: 20, weight: .semibold))
                    .foregroundStyle(AppTheme.success)
                    .shadow(color: AppTheme.success.opacity(0.25), radius: 6, y: 1)

                VStack(alignment: .leading, spacing: 3) {
                    Text("Dọn dẹp & bảo trì")
                        .font(.system(size: 14, weight: .bold, design: .rounded))
                        .foregroundStyle(.white)
                    Text("Quét bộ nhớ tạm trong phạm vi an toàn")
                        .font(.system(size: 10.5, weight: .medium))
                        .foregroundStyle(AppTheme.subduedText)
                        .lineLimit(1)
                }

                Spacer(minLength: 4)

                Image(systemName: "arrow.up.right")
                    .font(.system(size: 11.5, weight: .semibold))
                    .foregroundStyle(AppTheme.subduedText.opacity(0.8))
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 13)
            .background(
                DevUIStyle.cardBase,
                in: RoundedRectangle(cornerRadius: 20, style: .continuous)
            )
            .overlay { SpecularRimBorder(cornerRadius: 20) }
            .shadow(color: .black.opacity(0.22), radius: 10, y: 4)
        }
        .buttonStyle(TactileButtonStyle(cornerRadius: 20))
    }

    private var footer: some View {
        HStack(spacing: 8) {
            Capsule()
                .fill(AppTheme.accentSoft.opacity(0.35))
                .frame(width: 20, height: 1.5)
            Text("PHUCVN IPA DEV")
                .font(.system(size: 9, weight: .bold, design: .monospaced))
                .tracking(1.6)
                .foregroundStyle(AppTheme.subduedText.opacity(0.6))
            Capsule()
                .fill(AppTheme.accentSoft.opacity(0.35))
                .frame(width: 20, height: 1.5)
        }
        .frame(maxWidth: .infinity)
        .padding(.top, 4)
    }
}

private struct HomeToolCard: View {
    let symbol: String
    let title: String
    let detail: String
    let tint: Color

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(alignment: .top) {
                Image(systemName: symbol)
                    .font(.system(size: 22, weight: .medium))
                    .foregroundStyle(tint)
                    .shadow(color: tint.opacity(0.25), radius: 7, y: 2)
                Spacer(minLength: 0)
                Image(systemName: "arrow.up.right")
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(AppTheme.subduedText.opacity(0.72))
            }

            Spacer(minLength: 0)

            VStack(alignment: .leading, spacing: 3) {
                Text(title)
                    .font(.system(size: 13.5, weight: .bold, design: .rounded))
                    .tracking(-0.15)
                    .foregroundStyle(.white)
                    .lineLimit(1)
                    .minimumScaleFactor(0.82)
                Text(detail)
                    .font(.system(size: 10, weight: .medium))
                    .foregroundStyle(AppTheme.subduedText)
                    .lineLimit(2)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .frame(maxWidth: .infinity, minHeight: 112, alignment: .leading)
        .padding(14)
        .background(alignment: .bottomTrailing) {
            Image(systemName: symbol)
                .font(.system(size: 56, weight: .bold))
                .foregroundStyle(Color.white.opacity(0.035))
                .rotationEffect(.degrees(-12))
                .offset(x: 10, y: 12)
                .allowsHitTesting(false)
        }
        .background(DevUIStyle.cardBase)
        .clipShape(RoundedRectangle(cornerRadius: 20, style: .continuous))
        .overlay { SpecularRimBorder(cornerRadius: 20) }
        .shadow(color: .black.opacity(0.24), radius: 10, y: 4)
    }
}
