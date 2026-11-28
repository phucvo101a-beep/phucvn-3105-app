import SwiftUI

struct SettingsView: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(\.appLanguage) private var language
    @EnvironmentObject private var appState: AppState
    @ObservedObject private var keyAuth = KeyAuthManager.shared
    @State private var copiedKey = false
    @State private var showKeyDetails = false

    var body: some View {
        NavigationStack {
            ScrollView(showsIndicators: false) {
                VStack(alignment: .leading, spacing: 14) {
                    pageHeading
                    deviceCard

                    SettingsGroup(title: "THÔNG TIN PHIÊN BẢN") {
                        SettingsValueRow(
                            symbol: "person.crop.circle.fill",
                            title: "Tác giả / Phát triển",
                            value: "PHUCVN"
                        )
                    }

                    SettingsGroup(title: "BẢN QUYỀN & MÁY CHỦ KEY") {
                        blackVIPPassHeader
                            .padding(.vertical, 6)

                        SettingsRowDivider()

                        HStack {
                            SettingsSymbol(symbol: "clock.badge.checkmark.fill", tint: keyAuth.isPermanent ? AppTheme.accent : (keyAuth.secondsRemaining < 3600 ? AppTheme.danger : AppTheme.success))
                            VStack(alignment: .leading, spacing: 2) {
                                Text("Thời hạn sử dụng")
                                    .font(.system(size: 13, weight: .bold, design: .rounded))
                                    .foregroundStyle(.white)
                                Text(keyAuth.remainingCountdownText.isEmpty ? (keyAuth.isPermanent ? "Vĩnh Viễn (Trọn đời)" : "Đang kiểm tra...") : keyAuth.remainingCountdownText)
                                    .font(.system(size: 11.5, weight: .bold, design: .rounded))
                                    .foregroundStyle(keyAuth.isPermanent ? AppTheme.accent : (keyAuth.secondsRemaining < 3600 ? AppTheme.danger : AppTheme.success))
                            }
                            Spacer()
                        }
                        .padding(.vertical, 4)

                        SettingsRowDivider()
                        SettingsValueRow(
                            symbol: "crown.fill",
                            title: "Cấp độ tài khoản",
                            value: keyAuth.role.uppercased() + " MEMBER"
                        )

                        SettingsRowDivider()
                        SettingsValueRow(
                            symbol: "iphone.gen3",
                            title: "Thiết bị liên kết",
                            value: keyAuth.deviceSlotsText.isEmpty ? "1 máy" : keyAuth.deviceSlotsText
                        )

                        SettingsRowDivider()
                        Button {
                            DevHaptics.light()
                            showKeyDetails = true
                        } label: {
                            HStack(spacing: 11) {
                                SettingsSymbol(symbol: "info.circle.fill", tint: AppTheme.accent)
                                Text("Xem chi tiết & Sao chép bản quyền")
                                    .font(.system(size: 13, weight: .bold, design: .rounded))
                                    .foregroundStyle(AppTheme.accent)
                                Spacer()
                                Image(systemName: "chevron.right")
                                    .font(.system(size: 11, weight: .semibold))
                                    .foregroundStyle(AppTheme.subduedText)
                            }
                            .padding(.vertical, 7)
                        }
                        .buttonStyle(TactileButtonStyle(cornerRadius: 12, showRimHighlight: false))

                        SettingsRowDivider()
                        Button {
                            DevHaptics.light()
                            keyAuth.unlinkKey()
                        } label: {
                            HStack(spacing: 11) {
                                SettingsSymbol(symbol: "rectangle.portrait.and.arrow.right", tint: AppTheme.danger)
                                Text("Hủy kích hoạt / Đổi Key mới")
                                    .font(.system(size: 13, weight: .bold, design: .rounded))
                                    .foregroundStyle(AppTheme.danger)
                                Spacer()
                            }
                            .padding(.vertical, 7)
                        }
                        .buttonStyle(TactileButtonStyle(cornerRadius: 12, showRimHighlight: false))
                    }

                    SettingsGroup(title: "TRẠNG THÁI HỆ THỐNG") {
                        HStack(spacing: 12) {
                            SettingsSymbol(symbol: "hammer.fill", tint: AppTheme.accent)
                            VStack(alignment: .leading, spacing: 4) {
                                Text("Chế độ nhà phát triển")
                                    .font(.system(size: 13, weight: .bold, design: .rounded))
                                    .foregroundStyle(.white)
                                Text("Được bật cố định. Không có tùy chọn tắt trong ứng dụng.")
                                    .font(.system(size: 10, weight: .medium))
                                    .foregroundStyle(AppTheme.subduedText)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                            Spacer(minLength: 5)
                            AppStatusPill(title: "LUÔN BẬT", tint: AppTheme.success, systemName: "lock.fill")
                        }
                        .padding(.vertical, 7)

                        SettingsRowDivider()

                        HStack(spacing: 12) {
                            SettingsSymbol(
                                symbol: "checkmark.shield.fill",
                                tint: appState.isSupported ? AppTheme.success : AppTheme.warning
                            )
                            VStack(alignment: .leading, spacing: 4) {
                                Text("Khả năng tương thích")
                                    .font(.system(size: 13, weight: .bold, design: .rounded))
                                    .foregroundStyle(.white)
                                Text("iOS \(AppInfo.osVersion) · \(AppInfo.osBuild)")
                                    .font(.system(size: 10, weight: .medium, design: .monospaced))
                                    .foregroundStyle(AppTheme.subduedText)
                            }
                            Spacer(minLength: 8)
                            Text(language.text(appState.isSupported ? "settings.supported" : "settings.unsupported"))
                                .font(.system(size: 9, weight: .heavy, design: .rounded))
                                .tracking(0.45)
                                .foregroundStyle(appState.isSupported ? AppTheme.success : AppTheme.warning)
                                .padding(.horizontal, 9)
                                .padding(.vertical, 7)
                                .background(
                                    (appState.isSupported ? AppTheme.success : AppTheme.warning).opacity(0.12),
                                    in: Capsule()
                                )
                        }
                        .padding(.vertical, 8)
                    }

                    SettingsGroup(title: "CÔNG CỤ VÀ BẢO TRÌ") {
                        NavigationLink {
                            CleanerView()
                        } label: {
                            SettingsNavigationRow(
                                symbol: "sparkles",
                                title: "Dọn dẹp & bảo trì",
                                detail: "Quét bộ nhớ đệm và tệp tạm an toàn"
                            )
                        }
                        .buttonStyle(.plain)

                        if WallpaperFeatureSupportPolicy.isSupported(major: AppInfo.versionTuple.major) {
                            SettingsRowDivider()
                            NavigationLink {
                                WallpaperResetSettingsView()
                            } label: {
                                SettingsNavigationRow(
                                    symbol: "arrow.counterclockwise",
                                    title: "Đặt lại hình nền",
                                    detail: language.text("wallpaper.reset_settings_footer")
                                )
                            }
                            .buttonStyle(.plain)
                        }
                    }

                    footer
                }
                .frame(maxWidth: 680)
                .frame(maxWidth: .infinity)
                .padding(.horizontal, AppTheme.pageInset)
                .padding(.top, 12)
                .padding(.bottom, 32)
            }
            .background { AppPageBackground() }
            .navigationTitle("Cài đặt")
            .navigationBarTitleDisplayMode(.inline)
            .toolbarBackground(AppTheme.pageBackground.opacity(0.92), for: .navigationBar)
            .toolbarBackground(.visible, for: .navigationBar)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Đóng") { dismiss() }
                        .font(.system(size: 13, weight: .semibold, design: .rounded))
                        .foregroundStyle(AppTheme.accent)
                }
            }
            .sheet(isPresented: $showKeyDetails) {
                KeyLicenseDetailView()
            }
        }
        .tint(AppTheme.accent)
    }

    private var blackVIPPassHeader: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                HStack(spacing: 6) {
                    Image(systemName: "key.fill")
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(AppTheme.silverGlow)
                        .shadow(color: AppTheme.silverGlow.opacity(0.35), radius: 6)
                    Text("BLACK VIP PASS")
                        .font(.system(size: 9.5, weight: .bold, design: .monospaced))
                        .tracking(1.6)
                        .foregroundStyle(AppTheme.accentSoft)
                }
                Spacer()
                Text(keyAuth.role.uppercased())
                    .font(.system(size: 9, weight: .bold, design: .monospaced))
                    .tracking(0.8)
                    .foregroundStyle(.white.opacity(0.9))
                    .padding(.horizontal, 8)
                    .padding(.vertical, 3)
                    .background(DevUIStyle.recessedSlot, in: Capsule())
                    .overlay { Capsule().strokeBorder(Color.white.opacity(0.14), lineWidth: 0.75) }
            }

            HStack(spacing: 10) {
                VStack(alignment: .leading, spacing: 3) {
                    Text("Mã Key bản quyền")
                        .font(.system(size: 10, weight: .medium))
                        .foregroundStyle(AppTheme.subduedText)
                    Text(keyAuth.currentKey.isEmpty ? "Chưa kích hoạt" : keyAuth.currentKey)
                        .font(.system(size: 13, weight: .bold, design: .monospaced))
                        .foregroundStyle(.white)
                        .lineLimit(1)
                        .minimumScaleFactor(0.8)
                }

                Spacer(minLength: 4)

                if !keyAuth.currentKey.isEmpty {
                    Button {
                        DevHaptics.light()
                        UIPasteboard.general.string = keyAuth.currentKey
                        withAnimation(.spring(response: 0.28, dampingFraction: 0.72)) {
                            copiedKey = true
                        }
                        DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
                            withAnimation(.easeOut(duration: 0.2)) {
                                copiedKey = false
                            }
                        }
                    } label: {
                        Image(systemName: copiedKey ? "checkmark.circle.fill" : "doc.on.doc")
                            .font(.system(size: 14, weight: .semibold))
                            .foregroundStyle(copiedKey ? AppTheme.success : .white.opacity(0.85))
                            .scaleEffect(copiedKey ? 1.12 : 1.0)
                            .frame(width: 32, height: 32)
                            .background(DevUIStyle.recessedSlot, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
                            .overlay { SpecularRimBorder(cornerRadius: 10, color: copiedKey ? AppTheme.success : .white, topOpacity: copiedKey ? 0.35 : 0.18) }
                    }
                    .buttonStyle(TactileButtonStyle(cornerRadius: 10, showRimHighlight: false))
                }
            }
        }
        .padding(13)
        .background {
            ZStack {
                LinearGradient(
                    colors: [
                        Color(red: 22.0 / 255.0, green: 24.0 / 255.0, blue: 32.0 / 255.0),
                        Color(red: 10.0 / 255.0, green: 11.0 / 255.0, blue: 15.0 / 255.0)
                    ],
                    startPoint: .topLeading,
                    endPoint: .bottomTrailing
                )
                DotMatrixBackground(opacity: 0.03)
            }
        }
        .clipShape(RoundedRectangle(cornerRadius: 15, style: .continuous))
        .overlay { SpecularRimBorder(cornerRadius: 15, topOpacity: 0.24, midOpacity: 0.06, bottomOpacity: 0.02) }
    }

    private var pageHeading: some View {
        HStack(spacing: 13) {
            AppLogo(size: 48, cornerRadius: 12)
            VStack(alignment: .leading, spacing: 3) {
                StudioEyebrow(text: "TÙY CHỈNH HỆ THỐNG")
                Text("Cài đặt")
                    .font(.system(size: 26, weight: .bold, design: .rounded))
                    .tracking(-0.55)
                    .foregroundStyle(.white)
                Text("Thông tin thiết bị và trạng thái vận hành")
                    .font(.system(size: 11, weight: .medium))
                    .foregroundStyle(AppTheme.subduedText)
            }
            Spacer(minLength: 0)
        }
    }

    private var deviceCard: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(alignment: .center, spacing: 13) {
                Image(systemName: "iphone.gen3")
                    .font(.system(size: 26, weight: .light))
                    .foregroundStyle(AppTheme.accent)
                    .shadow(color: AppTheme.accent.opacity(0.28), radius: 8, y: 2)
                    .frame(width: 32, height: 34)

                VStack(alignment: .leading, spacing: 3) {
                    StudioEyebrow(text: "THIẾT BỊ HIỆN TẠI")
                    Text(AppInfo.hardwareDisplayName)
                        .font(.system(size: 18, weight: .bold, design: .rounded))
                        .tracking(-0.3)
                        .foregroundStyle(.white)
                        .lineLimit(1)
                        .minimumScaleFactor(0.82)
                    Text("PHUCVN IPA DEV")
                        .font(.system(size: 11, weight: .semibold, design: .rounded))
                        .foregroundStyle(AppTheme.accentSoft)
                }
                Spacer(minLength: 4)
                Image(systemName: "checkmark.seal.fill")
                    .font(.system(size: 16, weight: .semibold))
                    .foregroundStyle(AppTheme.success)
                    .shadow(color: AppTheme.success.opacity(0.35), radius: 6)
            }

            HStack(spacing: 8) {
                SettingsMiniStat(label: "iOS", value: AppInfo.osVersion)
                SettingsMiniStat(label: "BUILD", value: AppInfo.osBuild)
                SettingsMiniStat(label: "APP", value: "v\(appVersion) (\(appBuild))")
            }
        }
        .padding(16)
        .background {
            ZStack {
                DevUIStyle.cardBase
                DotMatrixBackground(opacity: 0.03)
            }
        }
        .clipShape(RoundedRectangle(cornerRadius: 20, style: .continuous))
        .overlay { SpecularRimBorder(cornerRadius: 20) }
        .shadow(color: .black.opacity(0.32), radius: 18, y: 8)
    }

    private var footer: some View {
        VStack(spacing: 6) {
            Text("3105 × PHUCVN")
                .font(.system(size: 10, weight: .heavy, design: .rounded))
                .tracking(1.75)
                .foregroundStyle(AppTheme.accentSoft.opacity(0.8))
            Text("Giao diện quản lý thiết bị")
                .font(.system(size: 9, weight: .medium))
                .foregroundStyle(AppTheme.subduedText.opacity(0.7))
        }
        .frame(maxWidth: .infinity)
        .padding(.top, 2)
    }

    private var appVersion: String {
        Bundle.main.object(forInfoDictionaryKey: "AppReleaseDisplayVersion") as? String
            ?? Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String
            ?? "1.0"
    }

    private var appBuild: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "—"
    }
}

private struct SettingsGroup<Content: View>: View {
    let title: String
    let content: Content

    init(title: String, @ViewBuilder content: () -> Content) {
        self.title = title
        self.content = content()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(title)
                .font(.system(size: 9, weight: .heavy, design: .rounded))
                .tracking(1.55)
                .foregroundStyle(AppTheme.accentSoft)
                .padding(.horizontal, 3)

            VStack(spacing: 0) {
                content
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 8)
            .background {
                RoundedRectangle(cornerRadius: 20, style: .continuous)
                    .fill(DevUIStyle.cardBase)
            }
            .overlay { SpecularRimBorder(cornerRadius: 20) }
        }
    }
}

private struct SettingsMiniStat: View {
    let label: String
    let value: String

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(label)
                .font(.system(size: 8.5, weight: .bold, design: .rounded))
                .tracking(1.1)
                .foregroundStyle(AppTheme.subduedText)
            Text(value)
                .font(.system(size: 11, weight: .bold, design: .monospaced))
                .foregroundStyle(.white)
                .lineLimit(1)
                .minimumScaleFactor(0.75)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 10)
        .padding(.vertical, 8)
        .background(DevUIStyle.recessedSlot, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .strokeBorder(Color.white.opacity(0.07), lineWidth: 0.75)
        }
    }
}

private struct SettingsValueRow: View {
    let symbol: String
    let title: String
    let value: String

    var body: some View {
        HStack(spacing: 11) {
            SettingsSymbol(symbol: symbol, tint: AppTheme.accentSoft)
            Text(title)
                .font(.system(size: 12, weight: .semibold))
                .foregroundStyle(.white.opacity(0.92))
            Spacer(minLength: 8)
            Text(value)
                .font(.system(size: 10, weight: .semibold, design: .monospaced))
                .foregroundStyle(AppTheme.subduedText)
                .multilineTextAlignment(.trailing)
                .lineLimit(2)
                .textSelection(.enabled)
        }
        .padding(.vertical, 8)
    }
}

private struct SettingsNavigationRow: View {
    let symbol: String
    let title: String
    let detail: String

    var body: some View {
        HStack(spacing: 12) {
            SettingsSymbol(symbol: symbol, tint: AppTheme.accent)
            VStack(alignment: .leading, spacing: 4) {
                Text(title)
                    .font(.system(size: 12, weight: .bold, design: .rounded))
                    .foregroundStyle(.white)
                Text(detail)
                    .font(.system(size: 10, weight: .medium))
                    .foregroundStyle(AppTheme.subduedText)
                    .lineLimit(2)
            }
            Spacer(minLength: 8)
            Image(systemName: "chevron.right")
                .font(.system(size: 10, weight: .bold))
                .foregroundStyle(AppTheme.subduedText)
        }
        .padding(.vertical, 10)
        .contentShape(Rectangle())
    }
}

private struct SettingsSymbol: View {
    let symbol: String
    let tint: Color

    var body: some View {
        Image(systemName: symbol)
            .font(.system(size: 15, weight: .semibold))
            .foregroundStyle(tint)
            .shadow(color: tint.opacity(0.25), radius: 5, y: 1)
            .frame(width: 24, height: 24)
    }
}

private struct SettingsRowDivider: View {
    var body: some View {
        Rectangle()
            .fill(Color.white.opacity(0.08))
            .frame(height: 0.5)
            .padding(.leading, 35)
    }
}
