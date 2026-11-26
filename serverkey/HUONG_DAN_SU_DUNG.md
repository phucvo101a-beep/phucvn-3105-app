# HỆ THỐNG MÁY CHỦ BẢN QUYỀN KEY & XÁC THỰC - PHUCVN STUDIO
Dành riêng cho ứng dụng iOS **3105 x PHUCVN**

---

## 1. TỔNG QUAN & GIẢI THÍCH 2 VẤN ĐỀ QUAN TRỌNG

### ❓ Vấn đề 1: Vì sao 1 Key trước đây lại xài được trên nhiều thiết bị?
- **Nguyên nhân**: Trên app iOS có cơ chế *Offline Fallback*. Khi app không kết nối được tới Server (hoặc link server bị trả về lỗi `404 Not Found` do chưa up đúng file), app tự động kiểm tra cú pháp Key cục bộ theo Regex. Nếu đúng cú pháp `PHUCVN-...`, app sẽ tự động mở khóa offline cho người dùng.
- Do đó, khi link server bị 404, bất kỳ máy iPhone nào nhập Key đó đều được app tự động duyệt qua offline -> dẫn đến tình trạng 1 key xài được trên vô số máy!
- **Khắc phục**: Chúng tôi đã cập nhật app: chỉ có các mã Master Test Key (`PHUCVN-*-TEST-*`) mới được phép offline. Mọi Key bản quyền thương mại khác bắt buộc phải kết nối thành công và xác thực qua Server mới được duyệt.

### ❓ Vấn đề 2: Vì sao Key nhập trên app rồi mà trên Server Hosting vẫn báo "Chưa dùng"?
- **Nguyên nhân chính**: App gửi request đến Server nhưng bị lỗi `404 Not Found` (Ví dụ app đang gọi đến `https://phuciosvn.com/serverkey/api.php` nhưng trên hosting file này chưa có ở đường dẫn đó hoặc tên miền chưa trỏ đúng thư mục).
- Vì request bị 404 nên **mã Key chưa bao giờ chạm tới được mã nguồn PHP trên hosting** -> Server không nhận được request nên không thể lưu trạng thái `is_used = true` -> Trên Admin hosting vẫn hiển thị "Chưa dùng"!
- **Nguyên nhân phụ (Phân quyền Hosting)**: Nếu hosting đã nhận được request nhưng thư mục `data/` chưa được cấp quyền ghi (`chmod 777` hoặc `chmod 755`), file `keys.json` sẽ không lưu được dữ liệu mới.

---

## 2. TÍNH NĂNG MỚI: TÙY CHỈNH SỐ LƯỢNG THIẾT BỊ CHO TỪNG KEY
Hệ thống hiện đã hỗ trợ đầy đủ quản lý đa thiết bị:
1. **Tùy chỉnh số thiết bị tối đa (`max_devices`)**:
   - Khi tạo Key trong Admin, bạn có thể chọn:
     - `1 Thiết bị` (Gói chuẩn 1 máy iPhone/iPad)
     - `2 Thiết bị` (Gói dùng chung 2 máy)
     - `3 Thiết bị`, `5 Thiết bị`, `10 Thiết bị`
     - `Không giới hạn thiết bị` (Vô hạn máy)
2. **Quản lý thiết bị chi tiết trong trang Quản Trị (`admin.php`)**:
   - Hiển thị số lượng thiết bị đang dùng: ví dụ `1/1`, `2/3`, `0/1` hoặc `Vô hạn`.
   - Xem chi tiết từng thiết bị: Mã HWID, ngày giờ kích hoạt, địa chỉ IP.
   - **Nút "Xóa" (Kick máy)**: Có thể ngắt kết nối một thiết bị bất kỳ để nhường slot cho máy khác.
   - **Nút "Đổi máy / Reset thiết bị"**: Xóa toàn bộ máy đang liên kết để cấp mới mà không làm mất thời hạn của Key.
   - **Chỉnh sửa số máy tối đa trực tiếp**: Tăng hoặc giảm slot thiết bị của Key bất kỳ lúc nào mà không cần tạo Key mới.
3. **Cài đặt Máy chủ ngay trên App iOS**:
   - Trên màn hình nhập Key, bấm nút **"Máy chủ" (icon bánh răng)** ở góc trên để:
     - Xem và đổi link Server phù hợp với hosting của bạn.
     - Bấm nút **"KIỂM TRA KẾT NỐI (PING)"** để kiểm tra ngay xem hosting có đang phản hồi `200 OK` hay đang bị `404 Not Found`.

---

## 3. DANH SÁCH MÃ KEY TEST CÓ SẴN
| Mã Key | Loại Thời Hạn | Thiết Bị Tối Đa | Cấp Độ | Trạng Thái |
| :--- | :--- | :--- | :--- | :--- |
| `PHUCVN-LIFE-TEST-0001` | Vĩnh Viễn | 1 Máy | VIP | Sẵn sàng sử dụng |
| `PHUCVN-30D-TEST-0001` | 30 Ngày | 1 Máy | VIP | Sẵn sàng sử dụng |
| `PHUCVN-7D-TEST-0001` | 7 Ngày | 1 Máy | VIP | Sẵn sàng sử dụng |
| `PHUCVN-1D-TEST-0001` | 1 Ngày | 1 Máy | VIP | Sẵn sàng sử dụng |
| `PHUCVN-1H-TEST-0001` | 1 Giờ | 1 Máy | VIP | Sẵn sàng sử dụng |

---

## 4. HƯỚNG DẪN TRIỂN KHAI LÊN HOSTING CHUẨN XÁC

### Bước 1: Nén và tải file lên Hosting
1. Nén toàn bộ nội dung thư mục `serverkey/` thành file zip.
2. Đăng nhập cPanel / DirectAdmin / CyberPanel:
   - **Cách 1 (Nếu muốn truy cập theo dạng `https://domain.com/serverkey/api.php`)**:
     Tạo thư mục `serverkey` bên trong `public_html` rồi tải file zip vào đó và giải nén.
   - **Cách 2 (Nếu muốn truy cập trực tiếp `https://domain.com/api.php`)**:
     Giải nén trực tiếp vào thư mục gốc `public_html`.

### Bước 2: Phân quyền thư mục `data/` (Bắt buộc)
1. Trong File Manager của hosting, nhấp chuột phải vào thư mục `data/` -> Chọn **Change Permissions (Phân quyền)**.
2. Tích chọn đủ quyền: **Read, Write, Execute** (Giá trị phân quyền là `755` hoặc `777`).
3. Làm tương tự với file `data/keys.json` (phân quyền `666` hoặc `777`) để PHP có quyền cập nhật trạng thái "Đã dùng" và lưu danh sách HWID thiết bị.

### Bước 3: Đăng nhập Quản Trị Admin
- Link: `https://domain-cua-ban.com/admin.php` (hoặc `https://domain-cua-ban.com/serverkey/admin.php`)
- Tài khoản quản trị mặc định: `phucvn`
- Mật khẩu quản trị mặc định: `1231234aZ@1`

### Bước 4: Kiểm tra và Nhập Link Server trên App iOS
1. Mở ứng dụng iOS. Ở màn hình nhập Key, nhấn nút **"Máy chủ"** góc trên.
2. Nhập chính xác đường dẫn đến file `api.php`:
   - Ví dụ: `https://phuciosvn.com/serverkey/api.php` hoặc `https://phuciosvn.com/api.php`.
3. Bấm **"KIỂM TRA KẾT NỐI (PING)"**:
   - Nếu hiện: `✅ Máy chủ hoạt động tốt (HTTP 200 OK)` -> Bấm **"LƯU ĐỊA CHỈ SERVER"**.
   - Nếu hiện `404 Not Found` -> Kiểm tra lại thư mục đã upload trên hosting.
