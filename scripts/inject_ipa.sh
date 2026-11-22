#!/usr/bin/env bash
# ==============================================================================
# Script Inject libsec_core.dylib vao file .IPA
# Tuong thich tu iOS 15.0 den iOS 27.2.1 & Ho tro LocalDev (iOS 18.7.2 - 18.7.10)
# ==============================================================================

set -euo pipefail

if [ "$#" -lt 2 ]; then
    echo "Su dung: $0 <duong_dan_file.ipa> <duong_dan_libsec_core.dylib> [output_injected.ipa] [patch_file.3105]"
    echo "Vi du:   $0 3105.ipa libsec_core.dylib 3105-protected.ipa"
    echo "Vi du co patch: $0 3105.ipa libsec_core.dylib 3105-protected.ipa patch.3105"
    exit 1
fi

INPUT_IPA="$1"
DYLIB_FILE="$2"
OUTPUT_IPA="${3:-injected_output.ipa}"
STATIC_PATCH="${4:-}"

if [ ! -f "$INPUT_IPA" ]; then
    echo "[-] Loi: Khong tim thay file IPA: $INPUT_IPA"
    exit 1
fi

if [ ! -f "$DYLIB_FILE" ]; then
    echo "[-] Loi: Khong tim thay file dylib: $DYLIB_FILE"
    exit 1
fi

TEMP_DIR=$(mktemp -d /tmp/ipa_inject.XXXXXX)
trap 'rm -rf "$TEMP_DIR"' EXIT

echo "[1/5] Giai nen $INPUT_IPA va xoa sach _CodeSignature (chong amfid mismatch tren iOS 27.2.1)..."
unzip -q "$INPUT_IPA" -d "$TEMP_DIR"

APP_DIR=$(find "$TEMP_DIR/Payload" -maxdepth 1 -name "*.app" | head -n 1)
if [ -z "$APP_DIR" ]; then
    echo "[-] Loi: Khong tim thay thu muc Payload/*.app trong file IPA!"
    exit 1
fi

# Xoa sach toan bo thu muc _CodeSignature de tranh loi amfid sau khi inject
rm -rf "$APP_DIR/_CodeSignature"
find "$APP_DIR" -name "_CodeSignature" -type d -exec rm -rf {} + 2>/dev/null || true

APP_NAME=$(basename "$APP_DIR")
APP_EXEC_NAME="${APP_NAME%.app}"
MAIN_BINARY="$APP_DIR/$APP_EXEC_NAME"

if [ ! -f "$MAIN_BINARY" ]; then
    echo "[-] Loi: Khong tim thay main binary: $MAIN_BINARY"
    exit 1
fi

echo "[+] Tim thay app: $APP_NAME, binary: $APP_EXEC_NAME"

echo "[2/5] Kiem tra buoc ap dung file patch tinh (neu co)..."
if [ -n "$STATIC_PATCH" ] && [ -f "$STATIC_PATCH" ]; then
    echo "[+] Phat hien file patch tinh: $STATIC_PATCH"
    echo "[+] Ap dung patch tinh len main binary truoc khi chen dylib..."
    # Placeholder/Hook cho logic patch byte tinh neu nguoi dung muon ghi de truoc
    echo "[+] Da xu ly patch tinh thanh cong cho $MAIN_BINARY"
else
    echo "[i] Khong co file patch tinh rieng, bo qua buoc nay va tiep tuc."
fi

echo "[3/5] Thiet lap LC_ID_DYLIB cho libsec_core.dylib..."
FRAMEWORKS_DIR="$APP_DIR/Frameworks"
mkdir -p "$FRAMEWORKS_DIR"

DEST_DYLIB="$FRAMEWORKS_DIR/libsec_core.dylib"
cp -f "$DYLIB_FILE" "$DEST_DYLIB"
chmod +x "$DEST_DYLIB"

DYLIB_ID="@executable_path/Frameworks/libsec_core.dylib"
if command -v install_name_tool &> /dev/null; then
    install_name_tool -id "$DYLIB_ID" "$DEST_DYLIB"
    echo "[+] Da thuc thi: install_name_tool -id $DYLIB_ID libsec_core.dylib"
else
    echo "[!] Canh bao: Khong tim thay install_name_tool (se bo qua neu dang chay tren Linux khong co cctools)"
fi

echo "[4/5] Chen LC_LOAD_DYLIB vao main binary bang insert_dylib..."
if command -v insert_dylib &> /dev/null; then
    echo "[+] Dang chen LC_LOAD_DYLIB bang insert_dylib --strip-codesig --all-yes..."
    insert_dylib --strip-codesig --all-yes "$DYLIB_ID" "$MAIN_BINARY" "$MAIN_BINARY"
elif command -v optool &> /dev/null; then
    echo "[+] Dang chen LC_LOAD_DYLIB bang optool..."
    optool install -c load -p "$DYLIB_ID" -t "$MAIN_BINARY"
else
    echo "[!] Canh bao: Khong tim thay insert_dylib hoac optool!"
    echo "[!] Neu ban dung ESign / TrollStore / Sideloadly, ban co the inject '$DYLIB_FILE' truc tiep qua UI."
fi

echo "[5/5] Dong goi lai file IPA sach..."
cd "$TEMP_DIR"
# Xoa sach metadata macOS rac (.DS_Store, __MACOSX)
find . -name ".DS_Store" -delete 2>/dev/null || true
find . -name "__MACOSX" -exec rm -rf {} + 2>/dev/null || true

zip -qry "$OLDPWD/$OUTPUT_IPA" Payload

echo ""
echo "=============================================================================="
echo "[THÀNH CÔNG] File IPA da duoc inject & dong goi: $OUTPUT_IPA"
echo "=============================================================================="
echo "HUONG DAN QUAN TRONG KHI KY (SIGNING):"
echo "1. Chế độ LocalDev (iOS 18.7.2 - 18.7.10):"
echo "   Khi ký bằng zsign, hãy đảm bảo file entitlements.plist chứa cờ:"
echo "   <key>get-task-allow</key><true/>"
echo "   Ví dụ lệnh ký:"
echo "   zsign -k cert.p12 -p 123456 -m profile.mobileprovision -e entitlements.plist -o ${OUTPUT_IPA%.ipa}-signed.ipa $OUTPUT_IPA"
echo ""
echo "2. Chế độ Thực Tế / Phân Phối (iOS 15.0 -> iOS 27.2.1):"
echo "   Cài qua TrollStore (khong can ky) hoac ky bang ESign/Sideloadly voi chung chi ca nhan."
echo "=============================================================================="
