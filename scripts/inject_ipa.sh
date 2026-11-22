#!/usr/bin/env bash
# ==============================================================================
# Script Inject libsec_core.dylib vao file .IPA
# Su dung tren macOS hoac Linux/WSL co cai dat optool / insert_dylib
# ==============================================================================

set -euo pipefail

if [ "$#" -lt 2 ]; then
    echo "Su dung: $0 <duong_dan_file.ipa> <duong_dan_libsec_core.dylib> [output_injected.ipa]"
    echo "Vi du:   $0 3105.ipa libsec_core.dylib 3105-protected.ipa"
    exit 1
fi

INPUT_IPA="$1"
DYLIB_FILE="$2"
OUTPUT_IPA="${3:-injected_output.ipa}"

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

echo "[+] Dang giai nen $INPUT_IPA vao thu muc tam..."
unzip -q "$INPUT_IPA" -d "$TEMP_DIR"

APP_DIR=$(find "$TEMP_DIR/Payload" -maxdepth 1 -name "*.app" | head -n 1)
if [ -z "$APP_DIR" ]; then
    echo "[-] Loi: Khong tim thay thu muc Payload/*.app trong file IPA!"
    exit 1
fi

APP_NAME=$(basename "$APP_DIR")
APP_EXEC_NAME="${APP_NAME%.app}"
MAIN_BINARY="$APP_DIR/$APP_EXEC_NAME"

if [ ! -f "$MAIN_BINARY" ]; then
    echo "[-] Loi: Khong tim thay main binary: $MAIN_BINARY"
    exit 1
fi

echo "[+] Tim thay app: $APP_NAME, binary: $APP_EXEC_NAME"

# Tao thu muc Frameworks neu chua co
FRAMEWORKS_DIR="$APP_DIR/Frameworks"
mkdir -p "$FRAMEWORKS_DIR"

# Copy dylib vao Frameworks
DEST_DYLIB="$FRAMEWORKS_DIR/libsec_core.dylib"
cp -f "$DYLIB_FILE" "$DEST_DYLIB"
chmod +x "$DEST_DYLIB"

echo "[+] Da copy libsec_core.dylib vao $FRAMEWORKS_DIR"

# Inject LC_LOAD_DYLIB vao binary
DYLIB_LOAD_PATH="@executable_path/Frameworks/libsec_core.dylib"

if command -v insert_dylib &> /dev/null; then
    echo "[+] Dang chen LC_LOAD_DYLIB bang insert_dylib..."
    insert_dylib --inplace --all-yes "$DYLIB_LOAD_PATH" "$MAIN_BINARY"
elif command -v optool &> /dev/null; then
    echo "[+] Dang chen LC_LOAD_DYLIB bang optool..."
    optool install -c load -p "$DYLIB_LOAD_PATH" -t "$MAIN_BINARY"
else
    echo "[!] Canh bao: Khong tim thay optool hoac insert_dylib tren he thong!"
    echo "[!] Neu ban dung ESign / TrollStore / Sideloadly, ban co the chon tinh nang 'Inject Dylib' truc tiep tren giao dien app de chen '$DYLIB_FILE'."
fi

# Dong goi lai IPA
echo "[+] Dang nen lai file IPA..."
cd "$TEMP_DIR"
zip -qry "$OLDPWD/$OUTPUT_IPA" Payload

echo "[OK] Dong goi thanh cong: $OUTPUT_IPA"
echo "Huong dan tiep theo:"
echo "1. Cai dat file '$OUTPUT_IPA' qua TrollStore (khong can sign) hoac ESign/Sideloadly (ky bang chung chi ca nhan)."
echo "2. Khi mo app, libsec_core se tu dong khoi chay truoc tien qua constructor de khoa may & bao ve ban quyen."
