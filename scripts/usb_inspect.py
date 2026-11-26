#!/usr/bin/env python3
"""
3105 x PHUCVN — Windows USB Inspection, Real-Time Log & Diagnostics Tool
Works on non-jailbroken iOS 16–27.x over USB (usbmuxd + House Arrest VendDocuments + OsTrace/Syslog).

Requirements:
    pip install pymobiledevice3
    Apple Devices / iTunes (for Apple Mobile Device USB Driver on Windows)
"""

import argparse
import asyncio
import json
import os
import plistlib
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    from pymobiledevice3 import usbmux
    from pymobiledevice3.exceptions import PyMobileDevice3Exception
    from pymobiledevice3.lockdown import create_using_usbmux
    from pymobiledevice3.services.house_arrest import HouseArrestService
    from pymobiledevice3.services.installation_proxy import InstallationProxyService
    from pymobiledevice3.services.os_trace import OsTraceService
    from pymobiledevice3.services.syslog import SyslogService
except ImportError as exc:
    print(
        "[!] Thieu thu vien pymobiledevice3. Hay cai dat bang lenh:\n"
        "    python -m pip install -U pymobiledevice3\n"
        f"    Chi tiet: {exc}",
        file=sys.stderr,
    )
    sys.exit(1)

DEFAULT_BUNDLE_IDS = (
    "com.apple.mobile.MobileHouseArrest",
    "com.phucvn.3105",
)


def _safe_text(obj: Any) -> str:
    if isinstance(obj, bytes):
        return obj.decode("utf-8", errors="replace")
    return str(obj)


async def connect_usb_lockdown(udid: Optional[str] = None):
    devices = await usbmux.list_devices()
    usb_devices = [d for d in devices if getattr(d, "is_usb", True)]
    if not usb_devices:
        raise RuntimeError(
            "Khong tim thay iPhone qua cong USB.\n"
            "  - Kiem tra cap USB & mo khoa man hinh iPhone.\n"
            "  - Nhan 'Tin cay may tinh nay' (Trust This Computer) tren iPhone.\n"
            "  - Dam bao da cai Apple Devices / iTunes tren Windows (Apple Mobile Device Service)."
        )

    target_udid = udid or usb_devices[0].serial
    lockdown = await create_using_usbmux(serial=target_udid, autopair=True)
    return lockdown


async def detect_3105_app(
    lockdown, preferred_bundle_id: Optional[str] = None
) -> Tuple[Optional[str], Dict[str, Any]]:
    proxy = InstallationProxyService(lockdown)
    apps = await proxy.get_apps(application_type="User")

    if preferred_bundle_id and preferred_bundle_id in apps:
        return preferred_bundle_id, apps[preferred_bundle_id]

    for bid in DEFAULT_BUNDLE_IDS:
        if bid in apps:
            return bid, apps[bid]

    for bid, meta in apps.items():
        name = str(meta.get("CFBundleDisplayName") or meta.get("CFBundleName") or "").lower()
        if "3105" in name or "phucvn" in name:
            return bid, meta

    return preferred_bundle_id or DEFAULT_BUNDLE_IDS[0], {}


async def open_house_arrest_documents(
    lockdown, bundle_id: str, prefer_full_container: bool = False
) -> Tuple[HouseArrestService, str]:
    """
    Opens House Arrest over USB cleanly:
    - If prefer_full_container is True (for dev-signed get-task-allow apps), tries VendContainer first,
      then falls back gracefully to VendDocuments (UIFileSharingEnabled = true).
    - Otherwise uses VendDocuments directly so non-JB iOS 27.x never hits container access errors.
    """
    if prefer_full_container:
        try:
            svc = await HouseArrestService.create(lockdown, bundle_id=bundle_id, documents_only=False)
            return svc, "VendContainer"
        except PyMobileDevice3Exception:
            pass

    svc = await HouseArrestService.create(lockdown, bundle_id=bundle_id, documents_only=True)
    return svc, "VendDocuments"


def _documents_prefix(mode: str) -> str:
    # VendDocuments roots at container root with /Documents accessible
    return "/Documents"


async def cmd_info(args: argparse.Namespace) -> int:
    lockdown = await connect_usb_lockdown(args.udid)
    try:
        vals = lockdown.all_values
        print("=== THONG TIN IPHONE QUA USB ===")
        print(f"UDID           : {vals.get('UniqueDeviceID', lockdown.udid)}")
        print(f"Ten thiet bi   : {vals.get('DeviceName', 'Unknown')}")
        print(f"iOS Version    : {vals.get('ProductVersion', 'Unknown')} ({vals.get('BuildVersion', '')})")
        print(f"Model          : {vals.get('ProductType', 'Unknown')} / {vals.get('HardwareModel', '')}")

        bundle_id, meta = await detect_3105_app(lockdown, args.bundle_id)
        print("\n=== THONG TIN APP 3105 ===")
        if meta:
            ent = meta.get("Entitlements") or {}
            get_task_allow = bool(ent.get("get-task-allow", False))
            file_sharing = bool(meta.get("UIFileSharingEnabled", False))
            open_in_place = bool(meta.get("LSSupportsOpeningDocumentsInPlace", False))
            print(f"Bundle ID      : {bundle_id}")
            print(f"Ten hien thi   : {meta.get('CFBundleDisplayName') or meta.get('CFBundleName')}")
            print(f"Phien ban      : {meta.get('CFBundleShortVersionString')} ({meta.get('CFBundleVersion')})")
            print(f"File Sharing   : {file_sharing} (UIFileSharingEnabled)")
            print(f"Open In Place  : {open_in_place} (LSSupportsOpeningDocumentsInPlace)")
            print(f"Dev Signed     : {get_task_allow} (get-task-allow)")
        else:
            print(f"[!] Khong tim thay app 3105 (bundle_id={bundle_id}) trong danh sach app User.")
        return 0
    finally:
        await lockdown.close()


async def _stream_os_trace(
    lockdown, filters: List[str], process_filter: Optional[str], out_fp, show_all: bool
) -> None:
    svc = OsTraceService(lockdown)
    async for entry in svc.syslog():
        proc = _safe_text(getattr(entry, "process", "") or "")
        msg = _safe_text(getattr(entry, "message", "") or "")
        subsys = _safe_text(getattr(entry, "subsystem", "") or "")
        ts = _safe_text(getattr(entry, "timestamp", "") or datetime.now().isoformat())
        line = f"[{ts}] [{proc}] ({subsys}) {msg}"

        if not show_all:
            proc_hit = bool(process_filter and process_filter.lower() in proc.lower())
            text_hit = any(f.lower() in line.lower() for f in filters)
            if not (proc_hit or text_hit):
                continue

        print(line, flush=True)
        if out_fp is not None:
            out_fp.write(line + "\n")
            out_fp.flush()


async def _stream_legacy_syslog(
    lockdown, filters: List[str], process_filter: Optional[str], out_fp, show_all: bool
) -> None:
    svc = SyslogService(lockdown)
    async for raw in svc.watch():
        line = _safe_text(raw).rstrip("\r\n")
        if not show_all:
            proc_hit = bool(process_filter and process_filter.lower() in line.lower())
            text_hit = any(f.lower() in line.lower() for f in filters)
            if not (proc_hit or text_hit):
                continue
        print(line, flush=True)
        if out_fp is not None:
            out_fp.write(line + "\n")
            out_fp.flush()


async def cmd_logs(args: argparse.Namespace) -> int:
    lockdown = await connect_usb_lockdown(args.udid)
    out_fp = None
    try:
        bundle_id, meta = await detect_3105_app(lockdown, args.bundle_id)
        exec_name = str(meta.get("CFBundleExecutable") or "3105")
        filters = args.match or ["[3105]", "3105", "bad_query", "sandbox", "LocalDev", bundle_id or ""]
        filters = [f for f in filters if f]

        if args.out:
            out_path = Path(args.out)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_fp = out_path.open("a", encoding="utf-8")

        print(
            f"[*] Dang doc log real-time qua USB (UDID={lockdown.udid}, process={exec_name})...\n"
            f"[*] Nhan Ctrl+C de dung.",
            flush=True,
        )
        try:
            await _stream_os_trace(lockdown, filters, exec_name, out_fp, args.all)
        except PyMobileDevice3Exception:
            print("[i] Chuyen sang kenh syslog_relay du phong...", flush=True)
            await _stream_legacy_syslog(lockdown, filters, exec_name, out_fp, args.all)
        return 0
    except KeyboardInterrupt:
        print("\n[*] Da dung doc log.")
        return 0
    finally:
        if out_fp is not None:
            out_fp.close()
        await lockdown.close()


async def _pull_documents_tree(
    svc: HouseArrestService, remote_dir: str, local_dir: Path
) -> List[Path]:
    pulled: List[Path] = []
    local_dir.mkdir(parents=True, exist_ok=True)
    try:
        names = await svc.listdir(remote_dir)
    except PyMobileDevice3Exception:
        return pulled

    for name in names:
        if name in (".", ".."):
            continue
        remote_item = f"{remote_dir.rstrip('/')}/{name}"
        local_item = local_dir / name
        try:
            st = await svc.stat(remote_item)
        except PyMobileDevice3Exception:
            continue

        if st.get("st_ifmt") == "S_IFDIR":
            pulled.extend(await _pull_documents_tree(svc, remote_item, local_item))
        else:
            data = await svc.get_file_contents(remote_item)
            local_item.write_bytes(data)
            pulled.append(local_item)
    return pulled


async def cmd_pull(args: argparse.Namespace) -> int:
    lockdown = await connect_usb_lockdown(args.udid)
    try:
        bundle_id, meta = await detect_3105_app(lockdown, args.bundle_id)
        if not bundle_id:
            print("[!] Khong xac dinh duoc Bundle ID cua app 3105.", file=sys.stderr)
            return 1

        ent = meta.get("Entitlements") or {}
        is_dev = bool(ent.get("get-task-allow", False))
        svc, mode = await open_house_arrest_documents(
            lockdown, bundle_id, prefer_full_container=(args.full_container or is_dev)
        )
        try:
            root = _documents_prefix(mode)
            target_remote = root if args.all_docs else f"{root}/3105-Diagnostics"
            dest = Path(args.dest or f"usb_diagnostics/{lockdown.udid}")
            print(f"[*] Ket noi House Arrest ({mode}) -> {bundle_id}:{target_remote}")
            pulled = await _pull_documents_tree(svc, target_remote, dest)
            if not pulled:
                print(
                    "[!] Chua co tep trong 3105-Diagnostics. "
                    "Hay mo app 3105 tren iPhone it nhat 1 lan sau khi cap nhat."
                )
                return 0
            print(f"[OK] Da tai {len(pulled)} tep ve: {dest.resolve()}")
            for path in pulled:
                print(f"     - {path}")
            return 0
        finally:
            await svc.close()
    finally:
        await lockdown.close()


async def cmd_doctor(args: argparse.Namespace) -> int:
    lockdown = await connect_usb_lockdown(args.udid)
    try:
        vals = lockdown.all_values
        ios_ver = vals.get("ProductVersion", "Unknown")
        ios_build = vals.get("BuildVersion", "Unknown")
        bundle_id, meta = await detect_3105_app(lockdown, args.bundle_id)
        print(f"=== 3105 USB DOCTOR ===\nDevice: {vals.get('DeviceName')} | iOS {ios_ver} ({ios_build})")

        if not meta:
            print(f"[FAIL] App 3105 ({bundle_id}) chua duoc cai dat tren iPhone.")
            return 1

        file_sharing = bool(meta.get("UIFileSharingEnabled", False))
        print(f"App   : {bundle_id} v{meta.get('CFBundleShortVersionString')} | UIFileSharingEnabled={file_sharing}")
        if not file_sharing:
            print("[WARN] UIFileSharingEnabled chua bat — khong the doc Documents qua VendDocuments.")

        ent = meta.get("Entitlements") or {}
        svc, mode = await open_house_arrest_documents(
            lockdown, bundle_id, prefer_full_container=bool(ent.get("get-task-allow", False))
        )
        try:
            diag_dir = Path(args.dest or f"usb_diagnostics/{lockdown.udid}")
            pulled = await _pull_documents_tree(svc, "/Documents/3105-Diagnostics", diag_dir)
            env_file = diag_dir / "environment.json"
            log_file = diag_dir / "session-latest.log"

            if env_file.is_file():
                env_data = json.loads(env_file.read_text(encoding="utf-8"))
                print("\n--- environment.json ---")
                for k in ("ios_version", "ios_build", "access_mode", "privileged_container_access", "localdev_status", "sandbox_home"):
                    print(f"  {k}: {env_data.get(k)}")
            else:
                print("\n[!] Chua tim thay environment.json trong Documents/3105-Diagnostics.")

            if log_file.is_file():
                lines = log_file.read_text(encoding="utf-8", errors="replace").splitlines()
                bad_lines = [
                    ln for ln in lines
                    if re.search(r"\[bad_query\]|daemon returned no result|metadata=unavailable", ln)
                ]
                print(f"\n--- session-latest.log ({len(lines)} dong) ---")
                if bad_lines:
                    print(f"[WARN] Phat hien {len(bad_lines)} dong loi container/traversal cu:")
                    for ln in bad_lines[-10:]:
                        print(f"  {ln}")
                else:
                    print("[PASS] Khong co loi [bad_query] / denied? / unresolved nao trong log!")
                print("\n10 dong log gan nhat:")
                for ln in lines[-10:]:
                    print(f"  {ln}")
            elif pulled:
                print(f"[INFO] Da tai {len(pulled)} tep diagnostics.")
            return 0
        finally:
            await svc.close()
    finally:
        await lockdown.close()


async def cmd_push_pairing(args: argparse.Namespace) -> int:
    lockdown = await connect_usb_lockdown(args.udid)
    try:
        bundle_id, _ = await detect_3105_app(lockdown, args.bundle_id)
        if not bundle_id:
            print("[!] Khong tim thay app 3105 tren iPhone.", file=sys.stderr)
            return 1

        if args.pairing_file:
            pairing_path = Path(args.pairing_file)
            if not pairing_path.is_file():
                print(f"[!] Khong tim thay file: {pairing_path}", file=sys.stderr)
                return 1
            raw_bytes = pairing_path.read_bytes()
        else:
            record = await lockdown.fetch_pair_record()
            if not record:
                print("[!] Khong doc duoc pair record tu lockdown tren Windows.", file=sys.stderr)
                return 1
            record = dict(record)
            record.setdefault("UDID", lockdown.udid)
            raw_bytes = plistlib.dumps(record, fmt=plistlib.FMT_XML)

        svc, mode = await open_house_arrest_documents(lockdown, bundle_id, prefer_full_container=False)
        try:
            remote_target = f"/Documents/{lockdown.udid}.mobiledevicepairing"
            await svc.set_file_contents(remote_target, raw_bytes)
            print(f"[OK] Da ghi file pairing vao {bundle_id}:{remote_target} ({mode})")
            print("[i] Mo lai app 3105 -> LocalDevBridge se tu dong nap file nay.")
            return 0
        finally:
            await svc.close()
    finally:
        await lockdown.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="3105 x PHUCVN — Windows USB Inspection & Real-Time Log Tool (Non-JB iOS 16–27.x)"
    )
    parser.add_argument("--udid", help="UDID thiet bi iOS (mac dinh chon iPhone USB dau tien)")
    parser.add_argument("--bundle-id", help="Bundle ID cua app 3105 neu da doi khi sign lai")

    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("info", help="Kiem tra ket noi USB, iOS version va trang thai File Sharing cua app")

    p_logs = sub.add_parser("logs", help="Doc log real-time qua USB (OsTrace / Syslog)")
    p_logs.add_argument("--all", action="store_true", help="Hien thi tat ca syslog he thong (khong loc)")
    p_logs.add_argument("-m", "--match", action="append", help="Bo loc chuoi bo sung (co the lap lai)")
    p_logs.add_argument("-o", "--out", help="Luu log stream ra tep tren PC")

    p_pull = sub.add_parser("pull", help="Tai Documents/3105-Diagnostics (hoac toan bo Documents) qua USB")
    p_pull.add_argument("--dest", help="Thu muc luu tren Windows PC")
    p_pull.add_argument("--all-docs", action="store_true", help="Tai toan bo thu muc Documents (gom Patches)")
    p_pull.add_argument("--full-container", action="store_true", help="Thu VendContainer truoc neu app dev-signed")

    p_doc = sub.add_parser("doctor", help="Kiem tra tong hop thiet bi + log + environment.json qua USB")
    p_doc.add_argument("--dest", help="Thu muc luu tam diagnostics")

    p_pair = sub.add_parser("push-pairing", help="Day file .mobiledevicepairing vao Documents app qua USB")
    p_pair.add_argument("--pairing-file", help="Duong dan file .mobiledevicepairing co san (bo trong de tu lay tu Windows)")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    dispatch = {
        "info": cmd_info,
        "logs": cmd_logs,
        "pull": cmd_pull,
        "doctor": cmd_doctor,
        "push-pairing": cmd_push_pairing,
    }
    try:
        return asyncio.run(dispatch[args.command](args))
    except Exception as exc:
        print(f"[!] Loi: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
