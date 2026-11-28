# PHUCVN IPA DEV

Phiên bản tùy biến của **ThreeOneOSFive (3105)** dành cho iOS bởi **PHUCVN**.

- **Server Key Admin**: `https://20-10.store/admin.php?tab=keysTab`
- **GitHub Repository**: `https://github.com/phucvo101a-beep/phucvn-3105-app`

## Tự động Build IPA trên GitHub Actions (qua GitHub Desktop)

Dự án đã được tích hợp sẵn GitHub Actions workflow tại `.github/workflows/build.yml`.

### Cách kích hoạt build:
1. Mở thư mục repo trong **GitHub Desktop** (`c:\Users\Admin\Downloads\phucvn-3105\phucvn-3105`), commit và **Push origin** lên nhánh `main` hoặc `master` để GitHub Actions tự động kích hoạt tiến trình build.
2. Hoặc kích hoạt thủ công trong mục **Actions** -> Chọn workflow **Build PHUCVN IPA DEV** -> Nhấn **Run workflow**.

### Tải file IPA sau khi build:
1. Chạy `Build_IPA.bat` hoặc vào tab **Actions** / mục **Releases** trên GitHub repository.
2. Tải về file `phucvn-ipa-dev-unsigned.ipa`.
3. Cài đặt file IPA này vào iPhone/iPad thông qua TrollStore, AltStore, Sideloadly hoặc Scarlet.
