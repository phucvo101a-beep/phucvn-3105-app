import SwiftUI
import UIKit

struct KeyValidationResult {
    let isValid: Bool
    let duration: String
    let expiryText: String
    let expiryDateString: String
    let role: String
}

class KeyAuthManager: ObservableObject {
    static let shared = KeyAuthManager()

    private let keyStorageKey = "PHUCVN_SAVED_LICENSE_KEY"
    private let expiryStorageKey = "PHUCVN_SAVED_LICENSE_EXPIRY"
    private let expiryTextStorageKey = "PHUCVN_SAVED_LICENSE_EXPIRY_TEXT"
    private let slotsStorageKey = "PHUCVN_SAVED_LICENSE_SLOTS"

    private let serverUrl = "https://20-10.store/api.php"

    @Published var isAuthorized: Bool = false
    @Published var currentKey: String = ""
    @Published var expiryText: String = ""
    @Published var deviceSlotsText: String = ""
    @Published var role: String = "VIP"
    @Published var errorMessage: String? = nil
    @Published var isVerifying: Bool = false
    @Published var expirationDate: Date? = nil
    @Published var remainingCountdownText: String = ""
    @Published var exactExpiryDateText: String = ""
    @Published var isPermanent: Bool = false
    @Published var secondsRemaining: Int = 0

    private var countdownTimer: Timer? = nil

    var deviceHWID: String {
        if let id = UIDevice.current.identifierForVendor?.uuidString {
            return id
        }
        return "IPHONE-3105-\(AppInfo.machineName)"
    }

    init() {
        let savedKey = UserDefaults.standard.string(forKey: "PHUCVN_SAVED_LICENSE_KEY") ?? ""
        let savedExpiryText = UserDefaults.standard.string(forKey: "PHUCVN_SAVED_LICENSE_EXPIRY_TEXT") ?? ""
        let savedExpiry = UserDefaults.standard.string(forKey: "PHUCVN_SAVED_LICENSE_EXPIRY") ?? ""
        let savedSlots = UserDefaults.standard.string(forKey: "PHUCVN_SAVED_LICENSE_SLOTS") ?? ""

        if !savedKey.isEmpty {
            self.currentKey = savedKey
            self.expiryText = savedExpiryText
            self.deviceSlotsText = savedSlots

            if !savedExpiry.isEmpty {
                configureExpiration(expiryString: savedExpiry)
                if !isPermanent, let expDate = expirationDate, expDate <= Date() {
                    self.isAuthorized = false
                    self.errorMessage = "Mã Key bản quyền đã hết hạn sử dụng! Vui lòng mua Key mới tại Shop phuciosvn.com."
                    return
                }
            }

            self.isAuthorized = true
            startCountdownTimer()
            verifyWithServer(key: savedKey, isSilent: true)
        }
    }

    func activate(key: String, completion: ((Bool) -> Void)? = nil) {
        let trimmedKey = key.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
        guard !trimmedKey.isEmpty else {
            self.errorMessage = "Vui lòng nhập mã Key bản quyền!"
            completion?(false)
            return
        }

        // Kiểm tra định dạng cấu trúc Key bản quyền PHUCVN
        let validation = validateKeyStructure(trimmedKey)
        guard validation.isValid else {
            self.errorMessage = "Mã Key không hợp lệ! Vui lòng mua Key chính hãng tại Shop: phuciosvn.com"
            completion?(false)
            return
        }

        self.isVerifying = true
        self.errorMessage = nil

        verifyWithServer(key: trimmedKey, validationFallback: validation, isSilent: false) { [weak self] success in
            self?.isVerifying = false
            completion?(success)
        }
    }

    func unlinkKey() {
        stopCountdownTimer()
        UserDefaults.standard.removeObject(forKey: keyStorageKey)
        UserDefaults.standard.removeObject(forKey: expiryStorageKey)
        UserDefaults.standard.removeObject(forKey: expiryTextStorageKey)
        UserDefaults.standard.removeObject(forKey: slotsStorageKey)
        self.currentKey = ""
        self.expiryText = ""
        self.deviceSlotsText = ""
        self.expirationDate = nil
        self.remainingCountdownText = ""
        self.exactExpiryDateText = ""
        self.isPermanent = false
        self.secondsRemaining = 0
        self.isAuthorized = false
        self.errorMessage = nil
    }

    func isMasterTestKey(_ key: String) -> Bool {
        let clean = key.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
        return clean == "PHUCVN-VIP-9999" ||
               clean == "PHUCVN-LIFE-TEST-0001" ||
               clean == "PHUCVN-30D-TEST-0001" ||
               clean == "PHUCVN-7D-TEST-0001" ||
               clean == "PHUCVN-1D-TEST-0001" ||
               clean == "PHUCVN-1H-TEST-0001"
    }

    private func verifyWithServer(
        key: String,
        validationFallback: KeyValidationResult? = nil,
        isSilent: Bool,
        completion: ((Bool) -> Void)? = nil
    ) {
        let fallbackInfo = validationFallback ?? validateKeyStructure(key)

        guard var urlComponents = URLComponents(string: serverUrl) else {
            fallbackOrError("Địa chỉ Server không hợp lệ!", fallback: fallbackInfo, isSilent: isSilent, completion: completion)
            return
        }

        var queryItems = urlComponents.queryItems ?? []
        if !queryItems.contains(where: { $0.name == "action" }) {
            queryItems.append(URLQueryItem(name: "action", value: "verify_key"))
            urlComponents.queryItems = queryItems
        }

        guard let targetUrl = urlComponents.url else {
            fallbackOrError("Không tạo được URL kết nối!", fallback: fallbackInfo, isSilent: isSilent, completion: completion)
            return
        }

        var request = URLRequest(url: targetUrl)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue(deviceHWID, forHTTPHeaderField: "X-Device-HWID")
        request.timeoutInterval = 7

        let body: [String: Any] = [
            "key": key,
            "hwid": deviceHWID
        ]
        request.httpBody = try? JSONSerialization.data(withJSONObject: body)

        URLSession.shared.dataTask(with: request) { [weak self] data, response, error in
            DispatchQueue.main.async {
                guard let self = self else { return }

                // Khi server chưa online hoặc mất kết nối mạng
                if error != nil {
                    // Chỉ cho phép Master Test Key offline fallback
                    if self.isMasterTestKey(key) && fallbackInfo.isValid {
                        self.saveSuccessfulLicense(
                            key: key,
                            expiry: fallbackInfo.expiryDateString,
                            expiryText: fallbackInfo.expiryText,
                            role: fallbackInfo.role
                        )
                        completion?(true)
                        return
                    }

                    if !isSilent {
                        self.handleVerificationError("Không thể kết nối đến máy chủ xác thực bản quyền! Vui lòng kiểm tra kết nối mạng internet.", isSilent: isSilent, completion: completion)
                    }
                    return
                }

                // Kiểm tra HTTP Status
                if let httpResp = response as? HTTPURLResponse, httpResp.statusCode >= 400 {
                    if self.isMasterTestKey(key) && fallbackInfo.isValid {
                        self.saveSuccessfulLicense(
                            key: key,
                            expiry: fallbackInfo.expiryDateString,
                            expiryText: fallbackInfo.expiryText,
                            role: fallbackInfo.role
                        )
                        completion?(true)
                        return
                    }

                    self.handleVerificationError("Không thể xác thực bản quyền với máy chủ. Vui lòng liên hệ Admin để được hỗ trợ!", isSilent: isSilent, completion: completion)
                    return
                }

                guard let data = data,
                      let json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
                    if self.isMasterTestKey(key) && fallbackInfo.isValid {
                        self.saveSuccessfulLicense(
                            key: key,
                            expiry: fallbackInfo.expiryDateString,
                            expiryText: fallbackInfo.expiryText,
                            role: fallbackInfo.role
                        )
                        completion?(true)
                        return
                    }
                    self.handleVerificationError("Phản hồi từ máy chủ không hợp lệ (không phải JSON)!", isSilent: isSilent, completion: completion)
                    return
                }

                let success = (json["success"] as? Bool) == true
                let valid = (json["valid"] as? Bool) == true

                if success && valid {
                    let expiry = (json["expiry"] as? String) ?? fallbackInfo.expiryDateString
                    let expiryText = (json["expiry_text"] as? String) ?? fallbackInfo.expiryText
                    let role = (json["role"] as? String) ?? fallbackInfo.role
                    let slots = (json["devices_label"] as? String) ?? ""

                    self.saveSuccessfulLicense(key: key, expiry: expiry, expiryText: expiryText, role: role, slotsText: slots)
                    completion?(true)
                } else {
                    let errorMsg = (json["error"] as? String) ?? (json["message"] as? String) ?? "Mã Key không hợp lệ hoặc đã hết hạn!"
                    if isSilent {
                        self.unlinkKey()
                    } else {
                        self.handleVerificationError(errorMsg, isSilent: isSilent, completion: completion)
                    }
                }
            }
        }.resume()
    }

    private func fallbackOrError(_ msg: String, fallback: KeyValidationResult, isSilent: Bool, completion: ((Bool) -> Void)?) {
        if isMasterTestKey(currentKey) && fallback.isValid {
            saveSuccessfulLicense(key: currentKey, expiry: fallback.expiryDateString, expiryText: fallback.expiryText, role: fallback.role)
            completion?(true)
        } else {
            handleVerificationError(msg, isSilent: isSilent, completion: completion)
        }
    }

    private func saveSuccessfulLicense(key: String, expiry: String, expiryText: String, role: String, slotsText: String = "") {
        UserDefaults.standard.set(key, forKey: keyStorageKey)
        UserDefaults.standard.set(expiry, forKey: expiryStorageKey)
        UserDefaults.standard.set(expiryText, forKey: expiryTextStorageKey)
        if !slotsText.isEmpty {
            UserDefaults.standard.set(slotsText, forKey: slotsStorageKey)
            self.deviceSlotsText = slotsText
        }

        self.currentKey = key
        self.expiryText = expiryText
        self.role = role
        self.isAuthorized = true
        self.errorMessage = nil

        configureExpiration(expiryString: expiry)
        startCountdownTimer()
    }

    func startCountdownTimer() {
        stopCountdownTimer()
        updateCountdown()

        countdownTimer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in
            DispatchQueue.main.async {
                self?.updateCountdown()
            }
        }
        if let t = countdownTimer {
            RunLoop.main.add(t, forMode: .common)
        }
    }

    func stopCountdownTimer() {
        countdownTimer?.invalidate()
        countdownTimer = nil
    }

    func updateCountdown() {
        guard isAuthorized else {
            stopCountdownTimer()
            return
        }

        if isPermanent {
            remainingCountdownText = "Vĩnh Viễn (Trọn đời)"
            exactExpiryDateText = "Không giới hạn thời gian"
            secondsRemaining = Int.max
            return
        }

        guard let exp = expirationDate else {
            remainingCountdownText = expiryText.isEmpty ? "Vĩnh Viễn" : expiryText
            return
        }

        let now = Date()
        let diff = exp.timeIntervalSince(now)

        if diff <= 0 {
            // Đã hết thời gian -> Kick khỏi app ngay lập tức!
            kickOutOfAppImmediately(reason: "Mã Key bản quyền của bạn đã hết hạn sử dụng! Bạn đã bị đưa về màn hình khóa.")
            return
        }

        let totalSec = Int(diff)
        secondsRemaining = totalSec
        let days = totalSec / 86400
        let hours = (totalSec % 86400) / 3600
        let minutes = (totalSec % 3600) / 60
        let seconds = totalSec % 60

        if days > 0 {
            remainingCountdownText = "\(days) ngày \(hours) giờ \(minutes) phút \(seconds) giây"
        } else if hours > 0 {
            remainingCountdownText = "\(hours) giờ \(minutes) phút \(seconds) giây"
        } else if minutes > 0 {
            remainingCountdownText = "\(minutes) phút \(seconds) giây"
        } else {
            remainingCountdownText = "\(seconds) giây"
        }
    }

    func checkExpirationNow() {
        guard isAuthorized, !isPermanent, let exp = expirationDate else { return }
        if exp <= Date() {
            kickOutOfAppImmediately(reason: "Mã Key bản quyền của bạn đã hết hạn sử dụng! Bạn đã bị đưa về màn hình khóa.")
        } else {
            updateCountdown()
        }
    }

    func kickOutOfAppImmediately(reason: String = "Mã Key bản quyền của bạn đã hết hạn sử dụng!") {
        stopCountdownTimer()
        UserDefaults.standard.removeObject(forKey: keyStorageKey)
        UserDefaults.standard.removeObject(forKey: expiryStorageKey)
        UserDefaults.standard.removeObject(forKey: expiryTextStorageKey)
        UserDefaults.standard.removeObject(forKey: slotsStorageKey)

        self.currentKey = ""
        self.expirationDate = nil
        self.remainingCountdownText = ""
        self.exactExpiryDateText = ""
        self.isPermanent = false
        self.secondsRemaining = 0
        self.errorMessage = reason

        withAnimation(.easeInOut(duration: 0.25)) {
            self.isAuthorized = false
        }
    }

    private func parseDate(_ str: String) -> Date? {
        let clean = str.trimmingCharacters(in: .whitespacesAndNewlines)
        if clean.isEmpty || clean.lowercased() == "permanent" { return nil }

        let formats = [
            "yyyy-MM-dd HH:mm:ss",
            "yyyy/MM/dd HH:mm:ss",
            "yyyy-MM-dd'T'HH:mm:ssZ",
            "yyyy-MM-dd'T'HH:mm:ss",
            "dd/MM/yyyy HH:mm:ss",
            "dd-MM-yyyy HH:mm:ss",
            "yyyy-MM-dd",
            "dd/MM/yyyy"
        ]

        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        for fmt in formats {
            formatter.dateFormat = fmt
            if let d = formatter.date(from: clean) {
                return d
            }
        }
        return nil
    }

    private func configureExpiration(expiryString: String) {
        let clean = expiryString.trimmingCharacters(in: .whitespacesAndNewlines)
        if clean.lowercased() == "permanent" || clean.lowercased().contains("vĩnh viễn") || clean.lowercased().contains("life") {
            self.isPermanent = true
            self.expirationDate = nil
            self.exactExpiryDateText = "Không thời hạn (Vĩnh Viễn)"
            self.remainingCountdownText = "Vĩnh Viễn (Trọn đời)"
            self.secondsRemaining = Int.max
        } else if let d = parseDate(clean) {
            self.isPermanent = false
            self.expirationDate = d
            let df = DateFormatter()
            df.dateFormat = "HH:mm:ss • dd/MM/yyyy"
            self.exactExpiryDateText = df.string(from: d)
            updateCountdown()
        } else {
            self.exactExpiryDateText = clean.isEmpty ? "Không xác định" : clean
        }
    }

    // Xác thực cấu trúc mã Key bản quyền chuẩn PHUCVN
    func validateKeyStructure(_ key: String) -> KeyValidationResult {
        let clean = key.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()

        // 1. Danh sách Master Keys
        if clean == "PHUCVN-LIFE-TEST-0001" || clean == "PHUCVN-VIP-9999" {
            return KeyValidationResult(isValid: true, duration: "permanent", expiryText: "Vĩnh Viễn", expiryDateString: "permanent", role: "VIP")
        }
        if clean == "PHUCVN-30D-TEST-0001" {
            let exp = Calendar.current.date(byAdding: .day, value: 30, to: Date()) ?? Date()
            return KeyValidationResult(isValid: true, duration: "30d", expiryText: "30 Ngày", expiryDateString: formatDate(exp), role: "VIP")
        }
        if clean == "PHUCVN-7D-TEST-0001" {
            let exp = Calendar.current.date(byAdding: .day, value: 7, to: Date()) ?? Date()
            return KeyValidationResult(isValid: true, duration: "7d", expiryText: "7 Ngày", expiryDateString: formatDate(exp), role: "VIP")
        }
        if clean == "PHUCVN-1D-TEST-0001" {
            let exp = Calendar.current.date(byAdding: .day, value: 1, to: Date()) ?? Date()
            return KeyValidationResult(isValid: true, duration: "1d", expiryText: "24 Giờ", expiryDateString: formatDate(exp), role: "VIP")
        }
        if clean == "PHUCVN-1H-TEST-0001" {
            let exp = Calendar.current.date(byAdding: .hour, value: 1, to: Date()) ?? Date()
            return KeyValidationResult(isValid: true, duration: "1h", expiryText: "1 Giờ", expiryDateString: formatDate(exp), role: "VIP")
        }

        // 2. Khớp định dạng sinh key tự động: PHUCVN-(LIFE|30D|7D|1D|1H|VIP)-[A-Z0-9]{3,8}-[A-Z0-9]{3,8}
        let pattern = "^PHUCVN-(LIFE|30D|7D|1D|1H|VIP)-[A-Z0-9]{3,8}-[A-Z0-9]{3,8}$"
        if let regex = try? NSRegularExpression(pattern: pattern, options: .caseInsensitive),
           let match = regex.firstMatch(in: clean, range: NSRange(clean.startIndex..., in: clean)),
           let typeRange = Range(match.range(at: 1), in: clean) {
            let type = String(clean[typeRange])
            switch type {
            case "LIFE", "VIP":
                return KeyValidationResult(isValid: true, duration: "permanent", expiryText: "Vĩnh Viễn", expiryDateString: "permanent", role: "VIP")
            case "30D":
                let exp = Calendar.current.date(byAdding: .day, value: 30, to: Date()) ?? Date()
                return KeyValidationResult(isValid: true, duration: "30d", expiryText: "30 Ngày", expiryDateString: formatDate(exp), role: "VIP")
            case "7D":
                let exp = Calendar.current.date(byAdding: .day, value: 7, to: Date()) ?? Date()
                return KeyValidationResult(isValid: true, duration: "7d", expiryText: "7 Ngày", expiryDateString: formatDate(exp), role: "VIP")
            case "1D":
                let exp = Calendar.current.date(byAdding: .day, value: 1, to: Date()) ?? Date()
                return KeyValidationResult(isValid: true, duration: "1d", expiryText: "24 Giờ", expiryDateString: formatDate(exp), role: "VIP")
            case "1H":
                let exp = Calendar.current.date(byAdding: .hour, value: 1, to: Date()) ?? Date()
                return KeyValidationResult(isValid: true, duration: "1h", expiryText: "1 Giờ", expiryDateString: formatDate(exp), role: "VIP")
            default:
                break
            }
        }

        return KeyValidationResult(isValid: false, duration: "", expiryText: "", expiryDateString: "", role: "")
    }

    private func formatDate(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return formatter.string(from: date)
    }

    private func handleVerificationError(_ msg: String, isSilent: Bool, completion: ((Bool) -> Void)?) {
        if !isSilent {
            self.errorMessage = msg
        }
        completion?(false)
    }
}

struct KeyGatekeeperView: View {
    @ObservedObject var keyAuth = KeyAuthManager.shared
    @State private var inputKey: String = ""
    @State private var copiedHWID = false

    var body: some View {
        ZStack {
            AppPageBackground()

            ScrollView(showsIndicators: false) {
                VStack(spacing: 24) {
                    // Logo & Branding Header
                    VStack(spacing: 12) {
                        AppLogo(size: 72)

                        Text(AppBrand.name)
                            .font(.system(size: 26, weight: .heavy, design: .rounded))
                            .foregroundStyle(.white)

                        Text("XÁC THỰC BẢN QUYỀN HỆ THỐNG")
                            .font(.system(size: 10, weight: .bold, design: .rounded))
                            .tracking(2.0)
                            .foregroundStyle(AppTheme.accentSoft)
                    }
                    .padding(.top, 36)

                    // Card nhập Key
                    VStack(alignment: .leading, spacing: 18) {
                        HStack {
                            Image(systemName: "key.fill")
                                .font(.system(size: 14, weight: .bold))
                                .foregroundStyle(AppTheme.accent)
                            Text("NHẬP MÃ LICENSE KEY")
                                .font(.system(size: 11, weight: .bold, design: .rounded))
                                .tracking(1.2)
                                .foregroundStyle(AppTheme.accentSoft)
                            Spacer()
                        }

                        // Input field
                        HStack(spacing: 10) {
                            TextField("VD: PHUCVN-LIFE-XXXX-XXXX", text: $inputKey)
                                .autocorrectionDisabled()
                                .textInputAutocapitalization(.characters)
                                .font(.system(size: 15, weight: .semibold, design: .monospaced))
                                .foregroundStyle(.white)
                                .padding(.horizontal, 14)
                                .padding(.vertical, 14)
                                .background(AppTheme.pageBackground)
                                .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
                                .overlay {
                                    RoundedRectangle(cornerRadius: 14, style: .continuous)
                                        .strokeBorder(Color.white.opacity(0.18), lineWidth: 1)
                                }

                            Button {
                                if let paste = UIPasteboard.general.string {
                                    inputKey = paste.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
                                }
                            } label: {
                                Image(systemName: "doc.on.clipboard.fill")
                                    .font(.system(size: 16, weight: .bold))
                                    .foregroundStyle(AppTheme.accent)
                                    .frame(width: 48, height: 48)
                                    .background(AppTheme.pageBackground)
                                    .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
                                    .overlay {
                                        RoundedRectangle(cornerRadius: 14, style: .continuous)
                                            .strokeBorder(Color.white.opacity(0.18), lineWidth: 1)
                                    }
                            }
                        }

                        // Error message
                        if let error = keyAuth.errorMessage {
                            HStack(alignment: .top, spacing: 8) {
                                Image(systemName: "exclamationmark.triangle.fill")
                                    .foregroundStyle(AppTheme.danger)
                                    .font(.system(size: 13))
                                Text(error)
                                    .font(.system(size: 12, weight: .medium))
                                    .foregroundStyle(AppTheme.danger)
                            }
                            .padding(10)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(AppTheme.danger.opacity(0.12), in: RoundedRectangle(cornerRadius: 10))
                        }

                        // Submit Button
                        Button {
                            keyAuth.activate(key: inputKey)
                        } label: {
                            HStack(spacing: 8) {
                                if keyAuth.isVerifying {
                                    ProgressView()
                                        .tint(.black)
                                        .controlSize(.small)
                                    Text("ĐANG KIỂM TRA...")
                                        .font(.system(size: 13, weight: .bold, design: .rounded))
                                } else {
                                    Image(systemName: "checkmark.shield.fill")
                                        .font(.system(size: 14, weight: .bold))
                                    Text("KÍCH HOẠT VÀ TIẾP TỤC")
                                        .font(.system(size: 13, weight: .bold, design: .rounded))
                                }
                            }
                            .foregroundStyle(.black)
                            .frame(maxWidth: .infinity)
                            .frame(height: 50)
                            .background(AppTheme.accent, in: RoundedRectangle(cornerRadius: 14, style: .continuous))
                        }
                        .disabled(keyAuth.isVerifying)
                        .buttonStyle(AppPressableStyle())
                    }
                    .padding(20)
                    .background(AppTheme.consoleBackground, in: RoundedRectangle(cornerRadius: 24, style: .continuous))
                    .overlay { AppCardBorder(cornerRadius: 24) }
                    .shadow(color: .black.opacity(0.25), radius: 15, y: 7)

                    // Device Info HWID Card
                    HStack {
                        VStack(alignment: .leading, spacing: 3) {
                            Text("MÃ THIẾT BỊ (HWID)")
                                .font(.system(size: 9, weight: .bold))
                                .tracking(1.0)
                                .foregroundStyle(AppTheme.subduedText)
                            Text(keyAuth.deviceHWID)
                                .font(.system(size: 11, weight: .medium, design: .monospaced))
                                .foregroundStyle(.white)
                                .lineLimit(1)
                                .truncationMode(.middle)
                        }
                        Spacer()
                        Button {
                            UIPasteboard.general.string = keyAuth.deviceHWID
                            copiedHWID = true
                            DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
                                copiedHWID = false
                            }
                        } label: {
                            Image(systemName: copiedHWID ? "checkmark.circle.fill" : "doc.on.doc")
                                .font(.system(size: 13, weight: .bold))
                                .foregroundStyle(copiedHWID ? AppTheme.success : AppTheme.accentSoft)
                                .frame(width: 34, height: 34)
                                .background(Color.white.opacity(0.06), in: Circle())
                        }
                    }
                    .padding(14)
                    .background(AppTheme.consoleBackground, in: RoundedRectangle(cornerRadius: 16))
                    .overlay { AppCardBorder(cornerRadius: 16) }

                    // Link vào Shop mua Key: https://phuciosvn.com/
                    Link(destination: URL(string: "https://phuciosvn.com/")!) {
                        HStack(spacing: 8) {
                            Image(systemName: "cart.fill")
                                .font(.system(size: 13, weight: .bold))
                            Text("Chưa có Key? Mua Key tại Shop ngay")
                                .font(.system(size: 12, weight: .bold, design: .rounded))
                        }
                        .foregroundStyle(AppTheme.accent)
                        .padding(.vertical, 12)
                        .padding(.horizontal, 22)
                        .background(Color.white.opacity(0.06), in: Capsule())
                        .overlay {
                            Capsule().strokeBorder(AppTheme.accent.opacity(0.35), lineWidth: 1)
                        }
                    }
                    .padding(.top, 4)

                    Spacer(minLength: 30)
                }
                .padding(.horizontal, AppTheme.pageInset)
            }
        }
    }
}

// MARK: - Màn hình Chi Tiết Bản Quyền & Thời Gian Còn Lại
struct KeyLicenseDetailView: View {
    @Environment(\.dismiss) private var dismiss
    @ObservedObject var keyAuth = KeyAuthManager.shared
    @State private var copiedKey = false
    @State private var copiedHWID = false

    var body: some View {
        NavigationStack {
            ZStack {
                AppPageBackground()

                ScrollView(showsIndicators: false) {
                    VStack(spacing: 20) {
                        // Header Logo & Cấp độ
                        VStack(spacing: 8) {
                            ZStack {
                                Circle()
                                    .fill(
                                        LinearGradient(
                                            colors: [AppTheme.accent, Color.purple],
                                            startPoint: .topLeading,
                                            endPoint: .bottomTrailing
                                        )
                                    )
                                    .frame(width: 64, height: 64)
                                    .shadow(color: AppTheme.accent.opacity(0.4), radius: 12)

                                Image(systemName: "crown.fill")
                                    .font(.system(size: 26, weight: .bold))
                                    .foregroundStyle(.white)
                            }
                            .padding(.top, 10)

                            Text("BẢN QUYỀN 3105 x PHUCVN")
                                .font(.system(size: 18, weight: .heavy, design: .rounded))
                                .foregroundStyle(.white)

                            Text(keyAuth.role.uppercased() + " MEMBER")
                                .font(.system(size: 10, weight: .bold, design: .rounded))
                                .tracking(1.4)
                                .foregroundStyle(AppTheme.accentSoft)
                        }

                        // Đồng Hồ Đếm Ngược Trực Tiếp (Giờ - Phút - Giây)
                        VStack(spacing: 8) {
                            Text(keyAuth.isPermanent ? "TRẠNG THÁI BẢN QUYỀN" : "THỜI GIAN SỬ DỤNG CÒN LẠI")
                                .font(.system(size: 10, weight: .heavy, design: .rounded))
                                .tracking(1.2)
                                .foregroundStyle(AppTheme.subduedText)

                            Text(keyAuth.remainingCountdownText.isEmpty ? (keyAuth.isPermanent ? "Vĩnh Viễn (Trọn đời)" : "Đang kiểm tra...") : keyAuth.remainingCountdownText)
                                .font(.system(size: 18, weight: .heavy, design: .rounded))
                                .foregroundStyle(keyAuth.isPermanent ? AppTheme.accent : (keyAuth.secondsRemaining < 3600 ? AppTheme.danger : AppTheme.success))
                                .multilineTextAlignment(.center)
                                .padding(.horizontal, 10)

                            if !keyAuth.exactExpiryDateText.isEmpty {
                                HStack(spacing: 5) {
                                    Image(systemName: "calendar.badge.clock")
                                        .font(.system(size: 11))
                                    Text("Hết hạn lúc: \(keyAuth.exactExpiryDateText)")
                                        .font(.system(size: 11, weight: .medium))
                                }
                                .foregroundStyle(AppTheme.subduedText)
                            }
                        }
                        .padding(18)
                        .frame(maxWidth: .infinity)
                        .background(AppTheme.consoleBackground, in: RoundedRectangle(cornerRadius: 20, style: .continuous))
                        .overlay { AppCardBorder(cornerRadius: 20) }

                        // Thông tin Mã Key & Thiết Bị Liên Kết
                        VStack(alignment: .leading, spacing: 14) {
                            // Hàng Key
                            VStack(alignment: .leading, spacing: 6) {
                                Text("MÃ KEY ĐANG KÍCH HOẠT")
                                    .font(.system(size: 10, weight: .bold))
                                    .tracking(0.8)
                                    .foregroundStyle(AppTheme.subduedText)

                                HStack {
                                    Text(keyAuth.currentKey.isEmpty ? "Chưa có key" : keyAuth.currentKey)
                                        .font(.system(size: 13.5, weight: .bold, design: .monospaced))
                                        .foregroundStyle(.white)
                                        .lineLimit(1)
                                        .minimumScaleFactor(0.8)

                                    Spacer()

                                    Button {
                                        UIPasteboard.general.string = keyAuth.currentKey
                                        copiedKey = true
                                        DispatchQueue.main.asyncAfter(deadline: .now() + 2) { copiedKey = false }
                                    } label: {
                                        HStack(spacing: 4) {
                                            Image(systemName: copiedKey ? "checkmark" : "doc.on.doc")
                                            Text(copiedKey ? "Đã chép" : "Sao chép")
                                        }
                                        .font(.system(size: 11, weight: .bold))
                                        .foregroundStyle(copiedKey ? AppTheme.success : AppTheme.accent)
                                        .padding(.horizontal, 10)
                                        .padding(.vertical, 6)
                                        .background(Color.white.opacity(0.08), in: Capsule())
                                    }
                                }
                                .padding(12)
                                .background(AppTheme.pageBackground, in: RoundedRectangle(cornerRadius: 12))
                            }

                            // Giới hạn máy & Hạng
                            HStack {
                                VStack(alignment: .leading, spacing: 3) {
                                    Text("GIỚI HẠN THIẾT BỊ")
                                        .font(.system(size: 10, weight: .bold))
                                        .tracking(0.8)
                                        .foregroundStyle(AppTheme.subduedText)
                                    Text(keyAuth.deviceSlotsText.isEmpty ? "1 máy" : keyAuth.deviceSlotsText)
                                        .font(.system(size: 12.5, weight: .semibold))
                                        .foregroundStyle(.white)
                                }
                                Spacer()
                                VStack(alignment: .trailing, spacing: 3) {
                                    Text("GÓI BẢN QUYỀN")
                                        .font(.system(size: 10, weight: .bold))
                                        .tracking(0.8)
                                        .foregroundStyle(AppTheme.subduedText)
                                    Text(keyAuth.role.uppercased())
                                        .font(.system(size: 12.5, weight: .bold))
                                        .foregroundStyle(AppTheme.accent)
                                }
                            }
                            .padding(12)
                            .background(AppTheme.pageBackground, in: RoundedRectangle(cornerRadius: 12))

                            // HWID
                            VStack(alignment: .leading, spacing: 6) {
                                Text("MÃ THIẾT BỊ NÀY (HWID)")
                                    .font(.system(size: 10, weight: .bold))
                                    .tracking(0.8)
                                    .foregroundStyle(AppTheme.subduedText)

                                HStack {
                                    Text(keyAuth.deviceHWID)
                                        .font(.system(size: 11, weight: .medium, design: .monospaced))
                                        .foregroundStyle(.white.opacity(0.85))
                                        .lineLimit(1)
                                        .truncationMode(.middle)

                                    Spacer()

                                    Button {
                                        UIPasteboard.general.string = keyAuth.deviceHWID
                                        copiedHWID = true
                                        DispatchQueue.main.asyncAfter(deadline: .now() + 2) { copiedHWID = false }
                                    } label: {
                                        Image(systemName: copiedHWID ? "checkmark.circle.fill" : "doc.on.doc")
                                            .font(.system(size: 12, weight: .bold))
                                            .foregroundStyle(copiedHWID ? AppTheme.success : AppTheme.subduedText)
                                            .frame(width: 28, height: 28)
                                    }
                                }
                                .padding(10)
                                .background(AppTheme.pageBackground, in: RoundedRectangle(cornerRadius: 12))
                            }
                        }
                        .padding(18)
                        .background(AppTheme.consoleBackground, in: RoundedRectangle(cornerRadius: 20))
                        .overlay { AppCardBorder(cornerRadius: 20) }

                        // Các nút hành động
                        VStack(spacing: 12) {
                            Link(destination: URL(string: "https://phuciosvn.com/")!) {
                                HStack(spacing: 8) {
                                    Image(systemName: "cart.fill")
                                    Text("Gia Hạn / Mua Key Tại Shop phuciosvn.com")
                                }
                                .font(.system(size: 12.5, weight: .bold, design: .rounded))
                                .foregroundStyle(AppTheme.accent)
                                .frame(maxWidth: .infinity)
                                .frame(height: 46)
                                .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 14))
                                .overlay {
                                    RoundedRectangle(cornerRadius: 14)
                                        .strokeBorder(AppTheme.accent.opacity(0.35), lineWidth: 1)
                                }
                            }

                            Button(role: .destructive) {
                                dismiss()
                                DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) {
                                    keyAuth.unlinkKey()
                                }
                            } label: {
                                HStack(spacing: 6) {
                                    Image(systemName: "rectangle.portrait.and.arrow.right")
                                    Text("Đổi Key Khác / Đăng Xuất")
                                }
                                .font(.system(size: 12.5, weight: .bold, design: .rounded))
                                .foregroundStyle(AppTheme.danger)
                                .frame(maxWidth: .infinity)
                                .frame(height: 44)
                            }
                        }
                        .padding(.top, 4)
                    }
                    .padding(20)
                }
            }
            .navigationTitle("Thông Tin Bản Quyền")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Đóng") {
                        dismiss()
                    }
                    .font(.system(size: 14, weight: .semibold))
                    .foregroundStyle(AppTheme.accent)
                }
            }
        }
    }
}
