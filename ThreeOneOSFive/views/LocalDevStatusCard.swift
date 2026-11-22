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
                            .font(.system(size: 13, weight: .bold))
                            .foregroundStyle(AppTheme.accent)
                            .frame(width: 28, height: 28)
                            .background(AppTheme.accent.opacity(0.12), in: Circle())
                    }
                }
                .buttonStyle(AppPressableStyle())
                .accessibilityLabel("Kiểm tra lại kết nối")
            }

            // Description message
            Text(bridge.currentStatus.message)
                .font(.system(size: 11, weight: .medium))
                .foregroundStyle(Color.white.opacity(0.85))
                .fixedSize(horizontal: false, vertical: true)

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

            // Action buttons depending on state
            HStack(spacing: 9) {
                Button {
                    showFilePicker = true
                } label: {
                    HStack(spacing: 6) {
                        Image(systemName: bridge.currentStatus.code == 1 ? "arrow.triangle.2.circlepath.doc.on.clipboard" : "doc.badge.plus")
                            .font(.system(size: 11, weight: .bold))
                        Text(bridge.currentStatus.code == 1 ? "Nạp Pairing mới" : "Chọn file Pairing (.mobiledevicepairing)")
                            .font(.system(size: 11, weight: .bold))
                    }
                    .foregroundStyle(.white)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 8)
                    .frame(maxWidth: .infinity)
                    .background(AppTheme.elevatedBackground, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
                    .overlay {
                        RoundedRectangle(cornerRadius: 10, style: .continuous)
                            .strokeBorder(Color.white.opacity(0.18), lineWidth: 1)
                    }
                }
                .buttonStyle(AppPressableStyle())

                if bridge.currentStatus.code == 4 {
                    Button {
                        if let url = URL(string: UIApplication.openSettingsURLString) {
                            UIApplication.shared.open(url)
                        }
                    } label: {
                        Text("Mở Cài Đặt")
                            .font(.system(size: 11, weight: .bold))
                            .foregroundStyle(.black)
                            .padding(.horizontal, 12)
                            .padding(.vertical, 8)
                            .background(Color.white, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
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
        .fileImporter(
            isPresented: $showFilePicker,
            allowedContentTypes: [
                UTType(filenameExtension: "mobiledevicepairing") ?? .data,
                UTType(filenameExtension: "plist") ?? .propertyList,
                .propertyList,
                .data
            ],
            allowsMultipleSelection: false
        ) { result in
            switch result {
            case .success(let urls):
                if let url = urls.first {
                    _ = bridge.importPairingFile(from: url)
                }
            case .failure(let error):
                bridge.lastError = error.localizedDescription
            }
        }
        .onAppear {
            bridge.refreshStatus()
        }
    }
}
