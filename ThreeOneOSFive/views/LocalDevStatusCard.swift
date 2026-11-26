import SwiftUI
import UniformTypeIdentifiers

public struct LocalDevStatusCard: View {
    @ObservedObject private var bridge = LocalDevBridge.shared
    @State private var showFilePicker = false

    public init() {}

    private var statusColor: Color {
        switch bridge.currentStatus.code {
        case 1: return Color.green
        case 2: return Color.orange
        case 3: return Color.orange
        case 4: return Color.red
        case 5: return Color.red
        case 6: return Color.yellow
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
        case 6: return "bolt.slash.fill"
        default: return "questionmark.circle"
        }
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            // Header: Title & Live Badge
            HStack(spacing: 10) {
                ZStack {
                    Circle()
                        .fill(statusColor.opacity(0.16))
                        .frame(width: 36, height: 36)
                    Image(systemName: statusIcon)
                        .font(.system(size: 16, weight: .bold))
                        .foregroundStyle(statusColor)
                }

                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 6) {
                        Text("LOCALDEV KẾT NỐI")
                            .font(.system(size: 10, weight: .heavy, design: .rounded))
                            .tracking(1.1)
                            .foregroundStyle(AppTheme.subduedText)
                        Circle()
                            .fill(statusColor)
                            .frame(width: 6, height: 6)
                    }

                    Text(bridge.currentStatus.status)
                        .font(.system(size: 14, weight: .bold, design: .rounded))
                        .foregroundStyle(statusColor)
                }

                Spacer()

                Button {
                    bridge.refreshStatus()
                } label: {
                    if bridge.isCheckingStatus {
                        ProgressView().controlSize(.mini).tint(AppTheme.accent)
                            .frame(width: 28, height: 28)
                    } else {
                        Image(systemName: "arrow.clockwise")
                            .font(.system(size: 13, weight: .bold))
                            .foregroundStyle(AppTheme.accent)
                            .frame(width: 28, height: 28)
                            .background(AppTheme.accent.opacity(0.12), in: Circle())
                    }
                }
                .disabled(bridge.isCheckingStatus)
                .buttonStyle(AppPressableStyle())
                .accessibilityLabel("Kiểm tra lại kết nối")
            }

            // Description message
            Text(bridge.currentStatus.message)
                .font(.system(size: 11, weight: .medium))
                .foregroundStyle(Color.white.opacity(0.85))
                .fixedSize(horizontal: false, vertical: true)

            if !bridge.currentStatus.isLive {
                HStack(alignment: .top, spacing: 6) {
                    Image(systemName: "checkmark.circle.fill")
                        .font(.system(size: 10, weight: .bold))
                        .foregroundStyle(AppTheme.success)
                    Text("Độc lập: Hộp cát Sandbox (Documents, Library, tmp), Kho bản vá & Nhật ký USB vẫn dùng bình thường.")
                        .font(.system(size: 10, weight: .medium))
                        .foregroundStyle(Color.white.opacity(0.75))
                        .fixedSize(horizontal: false, vertical: true)
                }
                .padding(.horizontal, 9)
                .padding(.vertical, 6)
                .background(AppTheme.success.opacity(0.10), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
            }

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
                .background(Color.orange.opacity(0.18), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
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
                        bridge.openLocalDevVPNApp()
                    } label: {
                        HStack(spacing: 6) {
                            Image(systemName: "bolt.horizontal.fill")
                                .font(.system(size: 11, weight: .bold))
                            Text("Mở app LocalDev")
                                .font(.system(size: 11, weight: .bold))
                        }
                        .foregroundStyle(.black)
                        .padding(.horizontal, 10)
                        .padding(.vertical, 9)
                        .frame(maxWidth: .infinity)
                        .background(AppTheme.accent, in: RoundedRectangle(cornerRadius: 11, style: .continuous))
                    }
                    .buttonStyle(AppPressableStyle())

                    // Button: Import Pairing File
                    Button {
                        showFilePicker = true
                    } label: {
                        HStack(spacing: 6) {
                            Image(systemName: bridge.currentStatus.code == 1 ? "checkmark.circle.fill" : "doc.badge.plus")
                                .font(.system(size: 11, weight: .bold))
                            Text(bridge.currentStatus.code == 2 ? "Chọn Pairing" : "Đổi Pairing")
                                .font(.system(size: 11, weight: .bold))
                        }
                        .foregroundStyle(.white)
                        .padding(.horizontal, 10)
                        .padding(.vertical, 9)
                        .frame(maxWidth: .infinity)
                        .background(AppTheme.elevatedBackground, in: RoundedRectangle(cornerRadius: 11, style: .continuous))
                        .overlay {
                            RoundedRectangle(cornerRadius: 11, style: .continuous)
                                .strokeBorder(Color.white.opacity(0.18), lineWidth: 1)
                        }
                    }
                    .buttonStyle(AppPressableStyle())
                }

                if bridge.currentStatus.code != LocalDevCode.missingPairing.rawValue {
                    Button {
                        bridge.clearSavedPairing()
                    } label: {
                        HStack(spacing: 5) {
                            Image(systemName: "trash")
                                .font(.system(size: 10, weight: .bold))
                            Text("Xóa Pairing đã lưu")
                                .font(.system(size: 10.5, weight: .semibold))
                        }
                        .foregroundStyle(Color.white.opacity(0.75))
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 6)
                        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 9, style: .continuous))
                    }
                    .disabled(bridge.isCheckingStatus)
                    .buttonStyle(AppPressableStyle())
                }

                if bridge.currentStatus.code == 4 {
                    Button {
                        if let url = URL(string: UIApplication.openSettingsURLString) {
                            UIApplication.shared.open(url, options: [:], completionHandler: nil)
                        }
                    } label: {
                        Text("Cấp quyền Mạng cục bộ trong Cài Đặt")
                            .font(.system(size: 11, weight: .bold))
                            .foregroundStyle(.white)
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 7)
                            .background(Color.red.opacity(0.3), in: RoundedRectangle(cornerRadius: 9, style: .continuous))
                    }
                    .buttonStyle(AppPressableStyle())
                }
            }
        }
        .padding(14)
        .background(
            RoundedRectangle(cornerRadius: 18, style: .continuous)
                .fill(AppTheme.consoleBackground.opacity(0.95))
        )
        .overlay {
            RoundedRectangle(cornerRadius: 18, style: .continuous)
                .strokeBorder(statusColor.opacity(0.35), lineWidth: 1)
        }
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
