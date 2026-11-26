# Hướng dẫn đọc Log Real-Time & Kiểm tra dữ liệu 3105 qua USB trên Windows (iOS Non-JB)

## 1. Điều kiện chuẩn bị trên PC Windows
1. Cài driver USB của Apple (cài **Apple Devices** từ Microsoft Store hoặc **iTunes** bản chính thức để có `Apple Mobile Device Service`).
2. Cài Python 3.10+ và `pymobiledevice3`:
   ```powershell
   python -m pip install -U pymobiledevice3
   ```
3. Cắm iPhone vào PC qua cáp USB, mở khóa iPhone và bấm **Tin cậy máy tính này (Trust This Computer)**.

## 2. Cấu hình đã tích hợp sẵn trong app 3105
- **`Info.plist`**: Đã bật `UIFileSharingEnabled = true` và `LSSupportsOpeningDocumentsInPlace = true` giúp Windows và dịch vụ `com.apple.mobile.house_arrest` (`VendDocuments`) đọc/ghi trực tiếp thư mục `Documents/` của app trên iOS non-JB (kể cả iOS 27.x).
- **`Utils.swift` (`AppLog`)**:
  - Tự động phát toàn bộ log `[3105]` qua Apple Unified Logging (`os.Logger`) để xem real-time qua USB.
  - Đồng bộ ghi song song vào `Documents/3105-Diagnostics/session-latest.log` (xoay vòng 512 KB) và `Documents/3105-Diagnostics/environment.json` (đã lọc bỏ mọi thông tin nhạy cảm/key/ticket).
- **`LocalDevBridge.swift`**: Tự động dò `.mobiledevicepairing` trong `Documents/` và `Documents/Inbox/`.

## 3. Các lệnh kiểm tra nhanh bằng `scripts/usb_inspect.py`

### Kiểm tra kết nối USB, phiên bản iOS & quyền File Sharing
```powershell
python scripts/usb_inspect.py info
```

### Đọc log real-time qua USB (lọc sẵn `[3105]`, `LocalDev`, `sandbox`)
```powershell
python scripts/usb_inspect.py logs
# Hoặc lưu ra file để phân tích:
python scripts/usb_inspect.py logs -o usb_live.log
```

### Đọc/tải toàn bộ log & chẩn đoán từ `Documents/3105-Diagnostics` qua USB
```powershell
python scripts/usb_inspect.py pull
# Hoặc tải cả thư mục Documents (bao gồm Patches):
python scripts/usb_inspect.py pull --all-docs
```

### Chạy chẩn đoán tổng hợp (Doctor)
```powershell
python scripts/usb_inspect.py doctor
```

### Đẩy file ghép nối `.mobiledevicepairing` vào `Documents/` của app qua USB
```powershell
python scripts/usb_inspect.py push-pairing
```

## 4. Dùng lệnh `pymobiledevice3` trực tiếp (nếu muốn)
- Xem syslog real-time:
  ```powershell
  pymobiledevice3 syslog live -m "[3105]"
  ```
- Mở shell AFC vào thư mục `Documents` của app (thay `<BUNDLE_ID>` bằng Bundle ID thực tế khi ký IPA):
  ```powershell
  pymobiledevice3 apps afc --documents <BUNDLE_ID>
  ```
- Tải nhanh file log từ `Documents/3105-Diagnostics`:
  ```powershell
  pymobiledevice3 apps pull --documents <BUNDLE_ID> /Documents/3105-Diagnostics .\usb_diag
  ```
