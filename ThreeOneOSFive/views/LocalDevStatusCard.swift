import SwiftUI
import UniformTypeIdentifiers

public struct LocalDevStatusCard: View {
    @ObservedObject private var bridge = LocalDevBridge.shared
    @State private var showFilePicker = false
    @State private var isChecking = false

    public init() {}

    private var statusColor: Color {
        switch bridge.currentStatus.code {
        case 1: return Color.green
        case 2: return Color.orange
        case 3: return Color.orange
        case 4: return Color.red
        case 5: return Color.red
        default: return Color.secondary
        }
    }

    private var statusIcon: String {
        switch bridge.currentStatus.code {
        case 1: return "checkmark.shield.fill"
        case 2: return "doc.badge.plus"
        case 3: return "network.badge.shield.half.filled"
        case 4: return "hand.raised.fill"
        case 5: return "exclamationmark.triangle.fill"
        default: return "questionmark.circle"
        }
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            // Header: Title & Live Badge
            HStack(spacing: 11) {
                Image(systemName: statusIcon)
                    .font(.system(size: 20, weight: .semibold))
                    .foregroundStyle(statusColor)
                    .shadow(color: statusColor.opacity(0.28), radius: 7, y: 1)

                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 6) {
                        Text("LOCALDEV KẾT NỐI")
                            .font(.system(size: 9.5, weight: .bold, design: .monospaced))
                            .tracking(1.2)
                            .foregroundStyle(AppTheme.subduedText)
                        PulseLED(color: statusColor, size: 5.5, isAnimated: bridge.currentStatus.code == 1)
                    }

                    Text(bridge.currentStatus.status)
                        .font(.system(size: 14, weight: .bold, design: .rounded))
                        .foregroundStyle(statusColor)
                }

                Spacer()

                Button {
                    DevHaptics.light()
                    isChecking = true
                    bridge.refreshStatus()
                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.6) {
                        isChecking = false
                    }
                } label: {
                    if isChecking {
                        ProgressView().controlSize(.mini).tint(AppTheme.accent)
                    } else {
                        Image(systemName: "arrow.clockwise")
                            .font(.system(size: 13, weight: .semibold))
                            .foregroundStyle(AppTheme.accentSoft)
                            .frame(width: 28, height: 28)
                    }
                }
                .buttonStyle(TactileButtonStyle(cornerRadius: 14, showRimHighlight: false))
                .accessibilityLabel("Kiểm tra lại kết nối")
            }

            // Description message
            Text(bridge.currentStatus.message)
                .font(.system(size: 11, weight: .medium))
                .foregroundStyle(Color.white.opacity(0.82))
                .fixedSize(horizontal: false, vertical: true)

            if let err = bridge.lastError, !err.isEmpty {
                HStack(alignment: .top, spacing: 6) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .font(.system(size: 10, weight: .bold))
                        .foregroundStyle(Color.orange)
                    Text(err)
                        .font(.system(size: 10, weight: .medium))
                        .foregroundStyle(Color.white)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .padding(.horizontal, 9)
                .padding(.vertical, 6)
                .background(Color.orange.opacity(0.14), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
            }

            if let udid = bridge.currentStatus.udid, !udid.isEmpty, bridge.currentStatus.isLive {
                HStack(spacing: 4) {
                    Text("UDID:")
                        .font(.system(size: 9, weight: .bold, design: .monospaced))
                        .foregroundStyle(AppTheme.subduedText)
                    Text(udid)
                        .font(.system(size: 9, weight: .semibold, design: .monospaced))
                        .foregroundStyle(Color.white.opacity(0.75))
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
            }

            // Action buttons
            VStack(spacing: 8) {
                HStack(spacing: 8) {
                    // Button: Jump directly into LocalDev App / VPN
                    Button {
                        DevHaptics.light()
                        bridge.openLocalDevVPNApp()
                    } label: {
                        HStack(spacing: 6) {
                            Image(systemName: "bolt.horizontal.fill")
                                .font(.system(size: 11, weight: .bold))
                            Text("Mở app LocalDev")
                                .font(.system(size: 11.5, weight: .bold))
                        }
                        .foregroundStyle(.black)
                        .padding(.horizontal, 10)
                        .padding(.vertical, 9)
                        .frame(maxWidth: .infinity)
                        .background(Color.white, in: RoundedRectangle(cornerRadius: 11, style: .continuous))
                    }
                    .buttonStyle(TactileButtonStyle(cornerRadius: 11, showRimHighlight: false))

                    // Button: Import Pairing File
                    Button {
                        DevHaptics.light()
                        showFilePicker = true
                    } label: {
                        HStack(spacing: 6) {
                            Image(systemName: bridge.currentStatus.code == 1 ? "checkmark.circle.fill" : "doc.badge.plus")
                                .font(.system(size: 11, weight: .bold))
                            Text(bridge.currentStatus.code == 1 ? "Đổi Pairing" : "Chọn Pairing")
                                .font(.system(size: 11.5, weight: .bold))
                        }
                        .foregroundStyle(.white)
                        .padding(.horizontal, 10)
                        .padding(.vertical, 9)
                        .frame(maxWidth: .infinity)
                        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 11, style: .continuous))
                        .overlay {
                            RoundedRectangle(cornerRadius: 11, style: .continuous)
                                .fill(DevUIStyle.cardElevated.opacity(0.75))
                        }
                        .overlay { SpecularRimBorder(cornerRadius: 11) }
                    }
                    .buttonStyle(TactileButtonStyle(cornerRadius: 11))
                }

                if bridge.currentStatus.code == 4 {
                    Button {
                        DevHaptics.light()
                        if let url = URL(string: UIApplication.openSettingsURLString) {
                            UIApplication.shared.open(url, options: [:], completionHandler: nil)
                        }
                    } label: {
                        Text("Cấp quyền Mạng cục bộ trong Cài Đặt")
                            .font(.system(size: 11, weight: .bold))
                            .foregroundStyle(.white)
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 7)
                            .background(Color.red.opacity(0.28), in: RoundedRectangle(cornerRadius: 11, style: .continuous))
                            .overlay { SpecularRimBorder(cornerRadius: 11, color: Color.red, topOpacity: 0.35, midOpacity: 0.10, bottomOpacity: 0.02) }
                    }
                    .buttonStyle(TactileButtonStyle(cornerRadius: 11))
                }
            }
        }
        .padding(14)
        .background {
            ZStack(alignment: .topLeading) {
                DevUIStyle.cardBase
                RadialGradient(
                    colors: [statusColor.opacity(0.12), .clear],
                    center: .topLeading,
                    startRadius: 4,
                    endRadius: 190
                )
            }
        }
        .clipShape(RoundedRectangle(cornerRadius: 20, style: .continuous))
        .overlay {
            SpecularRimBorder(
                cornerRadius: 20,
                color: statusColor,
                topOpacity: 0.36,
                midOpacity: 0.08,
                bottomOpacity: 0.02,
                lineWidth: 0.75
            )
        }
        .shadow(color: .black.opacity(0.26), radius: 12, y: 5)
        .sheet(isPresented: $showFilePicker) {
            FileDocumentPicker(
                allowedContentTypes: [
                    UTType.item,
                    UTType.data,
                    UTType.propertyList
                ],
                allowsMultipleSelection: false,
                onSelection: { result in
                    showFilePicker = false
                    switch result {
                    case .success(let urls):
                        if let url = urls.first {
                            _ = bridge.importPairingFile(from: url)
                        }
                    case .failure(let error):
                        bridge.lastError = error.localizedDescription
                    }
                },
                onCancel: {
                    showFilePicker = false
                }
            )
            .ignoresSafeArea()
        }
        .onAppear {
            bridge.refreshStatus()
        }
    }
}
