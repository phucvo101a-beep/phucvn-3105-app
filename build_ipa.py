# -*- coding: utf-8 -*-
import sys
import os
import time
import subprocess
import plistlib
import zipfile
from pathlib import Path

REQUIRED_BONJOUR_SERVICES = (
    "_apple-mobdev2._tcp",
    "_remotepairing._tcp",
    "_lockdown._tcp",
    "_localdev._tcp",
    "_3105airlift._tcp",
    "_remotepairing-pairable-host._tcp",
)
REQUIRED_BACKGROUND_MODES = ("audio",)

# Setup colorama for Windows terminal
try:
    import colorama
    from colorama import Fore, Style
    colorama.init(autoreset=True)
    GREEN = Fore.GREEN
    YELLOW = Fore.YELLOW
    CYAN = Fore.CYAN
    RED = Fore.RED
    RESET = Style.RESET_ALL
    BOLD = Style.BRIGHT
except Exception:
    GREEN = YELLOW = CYAN = RED = RESET = BOLD = ""

try:
    import requests
    USE_REQUESTS = True
except Exception:
    import urllib.request
    import json
    USE_REQUESTS = False

REPO_OWNER = "phucvoipa"
REPO_NAME = "phucvn-3105"
API_BASE = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}"
RELEASE_URL = f"https://github.com/{REPO_OWNER}/{REPO_NAME}/releases/download/latest/3105-x-phucvn-unsigned.ipa"
HEADERS = {"User-Agent": "BuildIPATool/1.0"}

def print_banner():
    print(f"{CYAN}{BOLD}=" * 60)
    print(f"{GREEN}{BOLD}       3105 x PHUCVN - TỰ ĐỘNG THEO DÕI & TẢI BUILD IPA")
    print(f"{CYAN}       Kho lưu trữ: https://github.com/{REPO_OWNER}/{REPO_NAME}")
    print(f"{CYAN}{BOLD}=" * 60 + f"{RESET}\n")

def get_latest_run():
    url = f"{API_BASE}/actions/runs?per_page=1"
    try:
        if USE_REQUESTS:
            res = requests.get(url, headers=HEADERS, timeout=10)
            if res.status_code == 200:
                runs = res.json().get("workflow_runs", [])
                if runs:
                    return runs[0]
            elif res.status_code == 403:
                # Rate limit exceeded for unauthenticated IP
                return {"rate_limited": True}
        else:
            req = urllib.request.Request(url, headers=HEADERS)
            try:
                with urllib.request.urlopen(req, timeout=10) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    runs = data.get("workflow_runs", [])
                    if runs:
                        return runs[0]
            except urllib.error.HTTPError as e:
                if e.code == 403:
                    return {"rate_limited": True}
    except Exception as e:
        print(f"{RED}[!] Lỗi khi lấy thông tin build: {e}{RESET}")
    return None

def validate_info_plist_dict(plist_data: dict, source_label: str) -> bool:
    """Verify NSLocalNetworkUsageDescription, required NSBonjourServices, and UIBackgroundModes are intact."""
    desc = str(plist_data.get("NSLocalNetworkUsageDescription", "")).strip()
    bonjour = plist_data.get("NSBonjourServices", [])
    if not isinstance(bonjour, list):
        bonjour = []
    bg_modes = plist_data.get("UIBackgroundModes", [])
    if not isinstance(bg_modes, list):
        bg_modes = []
    missing_services = [svc for svc in REQUIRED_BONJOUR_SERVICES if svc not in bonjour]
    missing_bg = [m for m in REQUIRED_BACKGROUND_MODES if m not in bg_modes]
    if not desc or missing_services or missing_bg:
        print(f"{RED}[!] {source_label} thiếu cấu hình Mạng cục bộ / Chạy ngầm:{RESET}")
        if not desc:
            print(f"{RED}    - Thiếu key NSLocalNetworkUsageDescription{RESET}")
        if missing_services:
            print(f"{RED}    - Thiếu NSBonjourServices: {', '.join(missing_services)}{RESET}")
        if missing_bg:
            print(f"{RED}    - Thiếu UIBackgroundModes: {', '.join(missing_bg)}{RESET}")
        return False
    print(f"{GREEN}[OK] {source_label} giữ đủ NSLocalNetworkUsageDescription, {len(REQUIRED_BONJOUR_SERVICES)} NSBonjourServices & UIBackgroundModes(audio){RESET}")
    return True


def verify_local_source_info_plist() -> None:
    local_plist = Path(__file__).resolve().parent / "ThreeOneOSFive" / "Info.plist"
    if not local_plist.is_file():
        return
    try:
        with local_plist.open("rb") as f:
            plist_data = plistlib.load(f)
        validate_info_plist_dict(plist_data, "ThreeOneOSFive/Info.plist")
    except Exception as e:
        print(f"{YELLOW}[!] Không thể kiểm tra ThreeOneOSFive/Info.plist: {e}{RESET}")


def verify_ipa_local_network_plist(ipa_path: Path) -> bool:
    """Inspect packaged/downloaded IPA without mutating Info.plist to ensure local-network keys survive."""
    try:
        with zipfile.ZipFile(ipa_path, "r") as zf:
            info_candidates = [
                name for name in zf.namelist()
                if name.startswith("Payload/") and name.endswith(".app/Info.plist")
            ]
            if not info_candidates:
                print(f"{YELLOW}[!] Không tìm thấy Payload/*.app/Info.plist trong {ipa_path.name}{RESET}")
                return False
            with zf.open(info_candidates[0], "r") as pf:
                plist_data = plistlib.load(pf)
            return validate_info_plist_dict(plist_data, f"{ipa_path.name}:{info_candidates[0]}")
    except Exception as e:
        print(f"{YELLOW}[!] Lỗi kiểm tra Info.plist trong IPA: {e}{RESET}")
        return False


def download_file(url, target_path):
    print(f"{CYAN}[+] Đang tải file IPA từ Release...{RESET}")
    try:
        if USE_REQUESTS:
            res = requests.get(url, headers=HEADERS, stream=True, timeout=30)
            if res.status_code == 200:
                total_size = int(res.headers.get("content-length", 0))
                downloaded = 0
                with open(target_path, "wb") as f:
                    for chunk in res.iter_content(chunk_size=1024 * 64):
                        if chunk:
                            f.write(chunk)
                            downloaded += len(chunk)
                            if total_size > 0:
                                percent = int((downloaded / total_size) * 100)
                                bar = "#" * (percent // 4) + "-" * (25 - (percent // 4))
                                mb_done = downloaded / (1024 * 1024)
                                mb_total = total_size / (1024 * 1024)
                                print(f"\r    [{bar}] {percent}% ({mb_done:.1f}MB / {mb_total:.1f}MB)", end="", flush=True)
                print(f"\n{GREEN}[OK] Tải file IPA thành công!{RESET}")
                verify_ipa_local_network_plist(Path(target_path))
                return True
            elif res.status_code == 404:
                print(f"\n{YELLOW}[!] Bản Release chưa sẵn sàng, đang chuyển sang link Actions...{RESET}")
                return False
    except Exception as e:
        print(f"\n{RED}[!] Lỗi tải file: {e}{RESET}")
    return False

def open_folder(path):
    try:
        if sys.platform == "win32":
            subprocess.run(["explorer", "/select,", str(path)])
        else:
            os.system(f"open '{path.parent}'")
    except Exception:
        pass

def main():
    print_banner()
    verify_local_source_info_plist()

    print(f"{YELLOW}[+] Đang kiểm tra tiến trình build trên GitHub Actions...{RESET}")
    last_run = get_latest_run()
    if last_run and last_run.get("rate_limited"):
        print(f"{YELLOW}[!] GitHub API tạm giới hạn lượt truy vấn ẩn danh.{RESET}")
        print(f"{CYAN}[*] Bạn có thể theo dõi trực tiếp trên web: https://github.com/{REPO_OWNER}/{REPO_NAME}/actions{RESET}")
        print(f"{GREEN}[*] Đang thử kiểm tra xem bản Release IPA đã có chưa...{RESET}")
        downloads_dir = Path(os.environ.get("USERPROFILE", ".")) / "Downloads"
        target_ipa = downloads_dir / "3105-x-phucvn-unsigned.ipa"
        if download_file(RELEASE_URL, target_ipa):
            print(f"\n{GREEN}{BOLD}[VỊ TRÍ FILE IPA]: {target_ipa}{RESET}")
            open_folder(target_ipa)
        else:
            import webbrowser
            webbrowser.open(f"https://github.com/{REPO_OWNER}/{REPO_NAME}/actions")
        input("\nNhấn Enter để thoát...")
        return

    if not last_run:
        print(f"{RED}[!] Không tìm thấy lượt build nào. Vui lòng đảm bảo bạn đã push code lên GitHub.{RESET}")
        input("\nNhấn Enter để thoát...")
        return

    run_id = last_run.get("id")
    run_number = last_run.get("run_number")
    html_url = last_run.get("html_url")
    commit_msg = last_run.get("head_commit", {}).get("message", "N/A").strip().split("\n")[0]

    print(f"{BOLD}[*] Lượt chạy: #{run_number} (ID: {run_id})")
    print(f"[*] Commit: {commit_msg}")
    print(f"[*] Đường dẫn: {html_url}{RESET}")
    print("-" * 60)

    start_time = time.time()
    last_status = None

    while True:
        run = get_latest_run()
        if not run:
            time.sleep(5)
            continue

        status = run.get("status")
        conclusion = run.get("conclusion")
        elapsed = int(time.time() - start_time)
        mins, secs = divmod(elapsed, 60)
        time_str = f"{mins:02d}:{secs:02d}"

        if status != last_status:
            print(f"\n{CYAN}[Trạng thái: {status.upper()}]{RESET} (Thời gian theo dõi: {time_str})")
            last_status = status

        if status == "completed":
            print(f"\n" + "=" * 60)
            if conclusion == "success":
                print(f"{GREEN}{BOLD}>>> CHÚC MỪNG! ĐÃ BUILD THÀNH CÔNG FILE IPA! <<< {RESET}")
                print("=" * 60)

                downloads_dir = Path(os.environ.get("USERPROFILE", ".")) / "Downloads"
                target_ipa = downloads_dir / "3105-x-phucvn-unsigned.ipa"

                success = download_file(RELEASE_URL, target_ipa)
                if success:
                    print(f"\n{GREEN}{BOLD}[VỊ TRÍ FILE IPA]: {target_ipa}{RESET}")
                    open_folder(target_ipa)
                else:
                    print(f"\n{CYAN}[+] Đang mở trang tải về trên trình duyệt: {html_url}{RESET}")
                    import webbrowser
                    webbrowser.open(html_url)
            else:
                print(f"{RED}{BOLD}[!] Quá trình build kết thúc với trạng thái: {conclusion.upper()}{RESET}")
                print(f"{YELLOW}[!] Bạn có thể xem log chi tiết tại: {html_url}{RESET}")
                import webbrowser
                webbrowser.open(html_url)
            break
        elif status == "queued":
            print(f"\r{YELLOW}[Đang xếp hàng chờ máy Mac khả dụng...] Thời gian: {time_str}  {RESET}", end="", flush=True)
        elif status == "in_progress":
            print(f"\r{GREEN}[ĐANG BIÊN DỊCH VÀ ĐÓNG GÓI IPA TRÊN MACOS...] Thời gian: {time_str}  {RESET}", end="", flush=True)
        else:
            print(f"\r[{status}] Thời gian: {time_str}  ", end="", flush=True)

        time.sleep(6)

    print("\n" + "=" * 60)
    input("Nhấn Enter để thoát...")

if __name__ == "__main__":
    main()
