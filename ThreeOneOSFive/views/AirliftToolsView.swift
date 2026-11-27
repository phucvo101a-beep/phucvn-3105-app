import SwiftUI
import UIKit
import UniformTypeIdentifiers

struct AirliftServerCard: View {
    @ObservedObject private var server = AirliftLanServer.shared
    @State private var copiedAddress = false

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 11) {
                AppRowIcon(
                    systemName: "wifi.circle.fill",
                    tint: server.isRunning ? AppTheme.success : AppTheme.accentSoft,
                    symbolSize: 18,
                    frameSize: 40
                )

                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 6) {
                        Text("3105 Airlift (Wi-Fi LAN)")
                            .font(.system(size: 13, weight: .bold, design: .rounded))
                            .foregroundStyle(.white)
                        Text(server.isRunning ? "ONLINE" : "TẮT")
                            .font(.system(size: 8.5, weight: .heavy, design: .monospaced))
                            .foregroundStyle(server.isRunning ? AppTheme.success : AppTheme.subduedText)
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(
                                (server.isRunning ? AppTheme.success : Color.white).opacity(0.12),
                                in: Capsule()
                            )
                    }
                    Text(server.lastEventMessage)
                        .font(.system(size: 10, weight: .medium))
                        .foregroundStyle(AppTheme.subduedText)
                        .lineLimit(2)
                }

                Spacer(minLength: 6)

                Button {
                    server.toggle()
                } label: {
                    Text(server.isRunning ? "Tắt" : "Bật")
                        .font(.system(size: 11, weight: .bold, design: .rounded))
                        .foregroundStyle(server.isRunning ? Color.white : Color.black)
                        .padding(.horizontal, 13)
                        .padding(.vertical, 7)
                        .background(
                            server.isRunning ? Color.red.opacity(0.35) : AppTheme.accent,
                            in: Capsule()
                        )
                }
                .buttonStyle(AppPressableStyle())
            }

            if server.isRunning, let urlStr = server.serverURL {
                HStack(spacing: 8) {
                    Text(urlStr)
                        .font(.system(size: 12, weight: .bold, design: .monospaced))
                        .foregroundStyle(AppTheme.success)
                        .lineLimit(1)
                        .truncationMode(.middle)

                    Spacer(minLength: 4)

                    Button {
                        UIPasteboard.general.string = urlStr
                        copiedAddress = true
                        DispatchQueue.main.asyncAfter(deadline: .now() + 1.6) {
                            copiedAddress = false
                        }
                    } label: {
                        HStack(spacing: 4) {
                            Image(systemName: copiedAddress ? "checkmark" : "doc.on.doc")
                                .font(.system(size: 10, weight: .bold))
                            Text(copiedAddress ? "Đã chép" : "Chép URL")
                                .font(.system(size: 10.5, weight: .bold))
                        }
                        .foregroundStyle(.white)
                        .padding(.horizontal, 10)
                        .padding(.vertical, 5)
                        .background(Color.white.opacity(0.10), in: Capsule())
                    }
                    .buttonStyle(AppPressableStyle())
                }
                .padding(.horizontal, 10)
                .padding(.vertical, 8)
                .background(AppTheme.success.opacity(0.08), in: RoundedRectangle(cornerRadius: 11, style: .continuous))
                .overlay {
                    RoundedRectangle(cornerRadius: 11, style: .continuous)
                        .strokeBorder(AppTheme.success.opacity(0.28), lineWidth: 1)
                }

                Text("Mở địa chỉ trên ở trình duyệt PC cùng Wi-Fi để gửi .ipa / .3105 / Pairing hoặc tải ngược tệp từ Documents về máy tính.")
                    .font(.system(size: 9.5, weight: .medium))
                    .foregroundStyle(AppTheme.subduedText)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(13)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 20, style: .continuous)
                .fill(AppTheme.consoleBackground.opacity(0.95))
        )
        .overlay {
            RoundedRectangle(cornerRadius: 20, style: .continuous)
                .strokeBorder(
                    (server.isRunning ? AppTheme.success : Color.white).opacity(server.isRunning ? 0.35 : 0.12),
                    lineWidth: 1
                )
        }
    }
}

struct IpaFileSharingToolView: View {
    @Environment(\.dismiss) private var dismiss

    @State private var showPicker = false
    @State private var includeSampleEntitlements = true
    @State private var isProcessing = false
    @State private var statusText = "Chọn file .ipa (đã giải mã) để bật UIFileSharingEnabled và LSSupportsOpeningDocumentsInPlace trước khi ký chứng chỉ."
    @State private var result: IpaPatchResult?
    @State private var errorMessage: String?
    @State private var availableAirliftIpas: [URL] = []

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    VStack(alignment: .leading, spacing: 8) {
                        HStack(spacing: 10) {
                            AppRowIcon(systemName: "doc.badge.gearshape.fill", tint: AppTheme.accent, symbolSize: 18, frameSize: 42)
                            VStack(alignment: .leading, spacing: 2) {
                                Text("Mở khóa File Sharing cho IPA")
                                    .font(.system(size: 16, weight: .bold, design: .rounded))
                                    .foregroundStyle(.white)
                                Text("Chuẩn bị sẵn bản *-filesharing.ipa trước khi ký .p12 / .mobileprovision")
                                    .font(.system(size: 11, weight: .medium))
                                    .foregroundStyle(AppTheme.subduedText)
                            }
                        }

                        Toggle(isOn: $includeSampleEntitlements) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text("Tạo kèm Entitlements mẫu (get-task-allow)")
                                    .font(.system(size: 12.5, weight: .semibold))
                                    .foregroundStyle(.white)
                                Text("Xuất thêm file *-filesharing-entitlements.plist cạnh file .ipa để dùng khi ký")
                                    .font(.system(size: 10, weight: .medium))
                                    .foregroundStyle(AppTheme.subduedText)
                            }
                        }
                        .tint(AppTheme.accent)
                        .padding(.top, 4)
                    }
                    .padding(14)
                    .background(AppTheme.consoleBackground, in: RoundedRectangle(cornerRadius: 18, style: .continuous))
                    .overlay {
                        RoundedRectangle(cornerRadius: 18, style: .continuous)
                            .strokeBorder(Color.white.opacity(0.12), lineWidth: 1)
                    }

                    Button {
                        showPicker = true
                    } label: {
                        HStack(spacing: 8) {
                            if isProcessing {
                                ProgressView().controlSize(.small).tint(.black)
                            } else {
                                Image(systemName: "folder.badge.plus")
                                    .font(.system(size: 14, weight: .bold))
                            }
                            Text(isProcessing ? "Đang xử lý IPA..." : "Chọn file .ipa từ Tệp / iCloud")
                                .font(.system(size: 14, weight: .bold, design: .rounded))
                        }
                        .foregroundStyle(.black)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 13)
                        .background(AppTheme.accent, in: RoundedRectangle(cornerRadius: 14, style: .continuous))
                    }
                    .buttonStyle(AppPressableStyle())
                    .disabled(isProcessing)

                    if !availableAirliftIpas.isEmpty {
                        VStack(alignment: .leading, spacing: 8) {
                            Text("FILE .IPA TRONG DOCUMENTS / AIRLIFT")
                                .font(.system(size: 10, weight: .heavy, design: .rounded))
                                .tracking(1.1)
                                .foregroundStyle(AppTheme.accentSoft)

                            ForEach(availableAirliftIpas, id: \.path) { url in
                                Button {
                                    runPatch(at: url)
                                } label: {
                                    HStack(spacing: 10) {
                                        Image(systemName: "shippingbox.fill")
                                            .foregroundStyle(AppTheme.accent)
                                        Text(url.lastPathComponent)
                                            .font(.system(size: 12.5, weight: .semibold))
                                            .foregroundStyle(.white)
                                            .lineLimit(1)
                                        Spacer()
                                        Text("Vá ngay")
                                            .font(.system(size: 11, weight: .bold))
                                            .foregroundStyle(.black)
                                            .padding(.horizontal, 10)
                                            .padding(.vertical, 5)
                                            .background(AppTheme.accentSoft, in: Capsule())
                                    }
                                    .padding(11)
                                    .background(AppTheme.consoleBackground, in: RoundedRectangle(cornerRadius: 13, style: .continuous))
                                }
                                .buttonStyle(AppPressableStyle())
                                .disabled(isProcessing)
                            }
                        }
                    }

                    VStack(alignment: .leading, spacing: 8) {
                        Text("TRẠNG THÁI XỬ LÝ")
                            .font(.system(size: 10, weight: .heavy, design: .rounded))
                            .tracking(1.1)
                            .foregroundStyle(AppTheme.subduedText)

                        Text(errorMessage ?? statusText)
                            .font(.system(size: 12, weight: .medium))
                            .foregroundStyle(errorMessage != nil ? Color.orange : Color.white.opacity(0.9))
                            .fixedSize(horizontal: false, vertical: true)

                        if let result {
                            Divider().overlay(Color.white.opacity(0.1))
                            VStack(alignment: .leading, spacing: 4) {
                                Text("Ứng dụng: \(result.displayName) (\(result.version))")
                                Text("Bundle ID: \(result.bundleIdentifier)")
                                Text("Tệp xuất: Documents/\(result.outputIpaURL.lastPathComponent)")
                                Text("Dung lượng: \(ByteCountFormatter.string(fromByteCount: result.outputBytes, countStyle: .file)) · \(result.entryCount) mục")
                                if let entURL = result.sampleEntitlementsURL {
                                    Text("Entitlements mẫu: Documents/\(entURL.lastPathComponent)")
                                }
                            }
                            .font(.system(size: 11, weight: .medium, design: .monospaced))
                            .foregroundStyle(AppTheme.success)

                            ShareLink(item: result.outputIpaURL) {
                                HStack(spacing: 6) {
                                    Image(systemName: "square.and.arrow.up")
                                    Text("Chia sẻ / Ký IPA ngay")
                                }
                                .font(.system(size: 12.5, weight: .bold))
                                .foregroundStyle(.black)
                                .frame(maxWidth: .infinity)
                                .padding(.vertical, 10)
                                .background(AppTheme.success, in: RoundedRectangle(cornerRadius: 11, style: .continuous))
                            }
                            .padding(.top, 4)
                        }
                    }
                    .padding(14)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(AppTheme.consoleBackground, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
                }
                .padding(AppTheme.pageInset)
            }
            .background { AppPageBackground() }
            .navigationTitle("Chuẩn bị IPA File Sharing")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Đóng") { dismiss() }
                }
            }
            .onAppear {
                reloadAvailableIpas()
            }
            .sheet(isPresented: $showPicker) {
                FileDocumentPicker(
                    allowedContentTypes: [UTType(filenameExtension: "ipa") ?? .data, .zip, .data],
                    copiesSelectedDocument: true,
                    allowsMultipleSelection: false,
                    onSelection: { res in
                        showPicker = false
                        if case .success(let urls) = res, let url = urls.first {
                            runPatch(at: url)
                        }
                    },
                    onCancel: { showPicker = false }
                )
                .ignoresSafeArea()
            }
        }
    }

    private func reloadAvailableIpas() {
        var found: [URL] = []
        let fm = FileManager.default
        let candidateDirs = [
            try? AirliftLanServer.airliftInboxURL(fileManager: fm),
            try? PatchWorkspaceService.documentsRootURL(fileManager: fm)
        ].compactMap { $0 }

        for dir in candidateDirs {
            let children = (try? fm.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil)) ?? []
            for item in children where item.pathExtension.lowercased() == "ipa" && !item.lastPathComponent.hasSuffix("-filesharing.ipa") {
                if !found.contains(where: { $0.path == item.path }) {
                    found.append(item)
                }
            }
        }
        availableAirliftIpas = found
    }

    private func runPatch(at url: URL) {
        isProcessing = true
        errorMessage = nil
        result = nil
        statusText = "Đang chuẩn bị giải nén \(url.lastPathComponent)..."
        let includeEnt = includeSampleEntitlements

        DispatchQueue.global(qos: .userInitiated).async {
            let token = BackgroundKeepAliveManager.shared.beginWorkToken()
            defer { BackgroundKeepAliveManager.shared.endWorkToken(token) }

            do {
                let res = try IpaFileSharingPatcher.patchIPA(
                    at: url,
                    includeSampleGetTaskAllow: includeEnt,
                    progressHandler: { stepMsg in
                        DispatchQueue.main.async {
                            self.statusText = stepMsg
                        }
                    }
                )
                DispatchQueue.main.async {
                    self.isProcessing = false
                    self.result = res
                    self.statusText = "Hoàn tất! File sẵn sàng để ký bằng chứng chỉ (.p12 + .mobileprovision)."
                    NotificationCenter.default.post(name: .airliftFilesChanged, object: nil)
                }
            } catch {
                DispatchQueue.main.async {
                    self.isProcessing = false
                    self.errorMessage = error.localizedDescription
                }
            }
        }
    }
}
