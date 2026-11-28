#!/usr/bin/env python3
"""
Comprehensive 5-Scenario Zero-Trust Security Verification Suite for Tobi Aim 3105.
Runs natively on Python 3.12 stdlib AND optionally cross-tests live compiled
`serverkey_core` (--rust-bin) or `php` (--php-bin) engines when present.
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Dict, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import build_serverkey
import macho_hash
import obfuscate_build
import pack_3105
import v3_crypto


def compare_semver(a: str, b: str) -> int:
    def parse(s: str):
        clean = s.strip().lstrip("vV").split("-")[0].split("+")[0]
        parts = [int("".join(c for c in p if c.isdigit()) or "0") for p in clean.split(".")]
        while len(parts) < 3:
            parts.append(0)
        return parts

    pa, pb = parse(a), parse(b)
    return -1 if pa < pb else (1 if pa > pb else 0)


class InProcessV3Server:
    """Exact Python reference mirror of serverkey_core & CoreEngine.php V3 semantics."""

    BUNDLED = [
        "AIM BODY FFVN (1).3105",
        "Aim_Neck_TobiAim_FFVN.3105",
        "AimDrag_85_Antena_TobiAim_FFVN.3105",
        "AimDrag_85_TobiAim_FFVN.3105",
        "AimNeck_Antena_TobiAim_FFVN.3105",
        "Antena_TobiAim_FFVN.3105",
        "DinhVi_Chams_TobiAim_FFVN.3105",
        "DinhVi_Sung_TobiAim_FFVN.3105",
        "MODSKIN FFVN PHUCVN (1).3105",
        "MODSKIN FFVN PHUCVN (2).3105",
        "MODSKIN FFVN PHUCVN (3).3105",
        "MODSKIN FFVN PHUCVN (4).3105",
        "MODSKIN FFVN PHUCVN (5).3105",
    ]

    def __init__(self, data_dir: Path, secrets_map: Dict[str, str]):
        self.data_dir = data_dir
        self.x_priv = bytes.fromhex(secrets_map["SERVER_X25519_PRIV_HEX"])
        self.ed_seed = bytes.fromhex(secrets_map["SERVER_ED25519_PRIV_HEX"])
        self.pepper = secrets_map["PRE_SHARED_PEPPER"].encode("utf-8")
        self.bundle_master = bytes.fromhex(secrets_map["BUNDLE_PATCH_MASTER_KEY_HEX"])
        self.ci_secret = secrets_map["CI_SYNC_SECRET"].encode("utf-8")

        self.settings = {
            "server_open": True,
            "system_paused": False,
            "server_closed_message": "Server tạm đóng bảo trì.",
            "force_update": False,
            "min_required_version": "2.1.0",
            "latest_version": "2.1.0",
            "download_url": "https://tobivn.chickenkiller.com/download/3105-latest.ipa",
            "update_message": "Vui lòng cập nhật phiên bản mới!",
            "enforce_binary_hash": True,
            "preset_policies": {},
            "packages": {},
        }
        self.keys = []
        self.manifests = []
        self.nonces = {}
        self.rate_buckets = {}

    def ci_register(self, pkg: str, ver: str, bld: str, app_hash: str, sec_hash: str) -> dict:
        self.manifests.append(
            {
                "package_id": pkg,
                "version": ver,
                "build": bld,
                "app_hash": app_hash.lower(),
                "sec_hash": sec_hash.lower(),
                "active": True,
                "revoked": False,
            }
        )
        return {"ok": True}

    def process_v3(self, req: dict, now: Optional[int] = None) -> Tuple[int, dict]:
        now = now if now is not None else int(time.time())
        op = req.get("op", "")
        pkg = req.get("pkg", "")
        ver = req.get("ver", "")
        bld = req.get("bld", "")
        nonce_hex = req.get("nonce", "")
        ts = int(req.get("ts", 0))
        c_pub_hex = req.get("c_pub", "")
        fp = req.get("fp", "")
        ct_b64 = req.get("ct", "")
        ip = req.get("client_ip", "127.0.0.1")

        if req.get("v") != 3 or op not in ("preflight", "activate", "heartbeat"):
            return 400, {"error": "Unsupported op"}
        if abs(now - ts) > 180:
            return 403, {"error": "Timestamp skew"}

        # Rate limit check per device fp (35 / 60s)
        b = self.rate_buckets.setdefault(fp, {"start": now, "count": 0})
        if now - b["start"] >= 60:
            b["start"], b["count"] = now, 1
        else:
            b["count"] += 1
            if b["count"] > 35:
                return 429, {"error": "Rate limit exceeded"}

        if nonce_hex in self.nonces:
            return 403, {"error": "Replay nonce rejected"}
        self.nonces[nonce_hex] = now + 600

        req_nonce = bytes.fromhex(nonce_hex)
        c_pub = bytes.fromhex(c_pub_hex)
        shared = v3_crypto.x25519_shared(self.x_priv, c_pub)
        req_key = v3_crypto.hkdf_sha256(shared, self.pepper, b"3105-V3-REQ", 32)
        req_aad = f"V3REQ|3|{op}|{pkg}|{ver}|{bld}|{fp}|{nonce_hex}|{ts}".encode("utf-8")

        try:
            pt = v3_crypto.xchacha20_poly1305_decrypt(req_key, req_nonce, base64.b64decode(ct_b64), req_aad)
        except Exception:
            return 403, {"error": "AEAD decrypt failed"}

        inner = json.loads(pt.decode("utf-8"))
        if inner["op"] != op or inner["pkg"] != pkg or inner["ver"] != ver or int(inner["ts"]) != ts:
            return 403, {"error": "Envelope mismatch"}
        lic_key = inner.get("key", "")
        exp_proof = hmac.new(self.pepper, req_aad + b"|" + lic_key.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(exp_proof, inner.get("client_proof", "")):
            return 403, {"error": "Client proof invalid"}

        pkg_pol = self.settings["packages"].get(pkg, {})
        global_open = self.settings["server_open"] and not self.settings["system_paused"]
        server_open = global_open and pkg_pol.get("server_open", True)
        closed_msg = (
            self.settings["server_closed_message"]
            if not global_open
            else pkg_pol.get("server_closed_message", self.settings["server_closed_message"])
        )
        min_ver = pkg_pol.get("min_required_version", self.settings["min_required_version"])
        latest_ver = pkg_pol.get("latest_version", self.settings["latest_version"])
        dl_url = pkg_pol.get("download_url", self.settings["download_url"])
        force_up = pkg_pol.get("force_update", self.settings["force_update"])

        def respond(status, code, open_flag, update_flag, msg, eph=None, bkeys=None, lic=None, pstatuses=None):
            s_ts = int(time.time())
            s_nonce = os.urandom(24)
            s_nonce_hex = s_nonce.hex()
            res_aad = f"V3RES|3|{op}|{pkg}|{ver}|{fp}|{nonce_hex}|{s_nonce_hex}|{s_ts}|{code}".encode("utf-8")
            payload = {
                "status": status,
                "code": code,
                "op": op,
                "server_open": open_flag,
                "force_update": update_flag,
                "min_version": min_ver,
                "latest_version": latest_ver,
                "download_url": dl_url,
                "message": msg,
                "req_nonce": nonce_hex,
                "s_nonce": s_nonce_hex,
                "s_ts": s_ts,
                "ephemeral_session_key": eph,
                "session_token": hashlib.sha256(eph.encode()).hexdigest() if eph else None,
                "bundle_keys": bkeys or {},
                "preset_statuses": pstatuses or {},
                "license": lic or {"valid": False},
            }
            res_key = v3_crypto.hkdf_sha256(shared, self.pepper, b"3105-V3-RES|" + req_nonce, 32)
            ct = v3_crypto.xchacha20_poly1305_encrypt(res_key, s_nonce, json.dumps(payload).encode("utf-8"), res_aad)
            ct_hash = hashlib.sha256(ct).digest()
            sig_msg = b"3105-V3-SIG|" + res_aad + b"|" + ct_hash
            sig = v3_crypto.ed25519_sign(self.ed_seed, sig_msg)
            return 200, {
                "v": 3,
                "op": op,
                "pkg": pkg,
                "ver": ver,
                "fp": fp,
                "req_nonce": nonce_hex,
                "s_nonce": s_nonce_hex,
                "s_ts": s_ts,
                "code": code,
                "ct": base64.b64encode(ct).decode("ascii"),
                "sig": sig.hex(),
            }

        # 1. Kill-Switch
        if not server_open:
            return respond("server_closed", "SERVER_CLOSED", False, False, closed_msg)

        # 1b. Device HWID Ban Check
        ban_rec = next((b for b in getattr(self, "banned_devices", []) if b.get("active") and b.get("hwid", "").lower() == fp.lower()), None)
        if ban_rec:
            r_txt = ban_rec.get("reason", "").strip()
            msg = f"Thiết bị này đã bị khóa vĩnh viễn. Lý do: {r_txt}" if r_txt else "Thiết bị bị cấm truy cập."
            return respond("device_banned", "DEVICE_BANNED", True, False, msg)

        # 2. Tamper & Hash Manifest Check
        if int(inner.get("tamper_flags", 0)) != 0:
            return respond("denied", "TAMPER_DETECTED", True, False, "Tamper flags detected")

        app_h = inner.get("app_hash", "").lower()
        sec_h = inner.get("sec_hash", "").lower()
        matched = next(
            (m for m in self.manifests if m["package_id"] == pkg and m["app_hash"] == app_h and m["sec_hash"] == sec_h),
            None,
        )
        if self.settings["enforce_binary_hash"] or self.manifests:
            if not matched or matched["revoked"] or not matched["active"]:
                return respond("denied", "TAMPER_DETECTED", True, False, "Binary integrity mismatch")
            if compare_semver(ver, matched["version"]) != 0:
                return respond("denied", "TAMPER_DETECTED", True, False, "Manifest version spoof mismatch")
            auth_ver = matched["version"]
        else:
            auth_ver = ver

        # 3. Force Update Check
        if compare_semver(auth_ver, min_ver) < 0 or (force_up and compare_semver(auth_ver, latest_ver) < 0):
            return respond("force_update", "FORCE_UPDATE", True, True, self.settings["update_message"])

        pstatuses = {}
        ppol = self.settings.get("preset_policies", {})
        for fn in self.BUNDLED:
            bid_hex = v3_crypto.derive_bundle_id(fn).hex()
            cfg = ppol.get(fn, {}) if isinstance(ppol, dict) else {}
            st = "maintenance" if str(cfg.get("status", "stable")).lower() == "maintenance" else "stable"
            msg = str(cfg.get("message", "")).strip()
            pstatuses[bid_hex] = {"bundle_id": bid_hex, "file_name": fn, "label": fn, "status": st, "message": msg}

        if op == "preflight":
            return respond("ok", "OK", True, False, "Ready", pstatuses=pstatuses)

        # 4. License Validation
        rec = next((k for k in self.keys if k["key"].upper() == lic_key.strip().upper()), None)
        if not rec:
            return respond("denied", "INVALID_KEY", True, False, "Key invalid")
        if rec.get("status", "active") != "active":
            return respond("denied", "KEY_REVOKED", True, False, "Key revoked")
        if rec["is_used"] and rec.get("expiry_ts", 0) > 0 and now >= rec["expiry_ts"]:
            return respond("denied", "KEY_EXPIRED", True, False, "Key expired")
        if not rec["is_used"]:
            dur = {"1h": 3600, "1d": 86400, "7d": 7 * 86400, "30d": 30 * 86400}.get(rec["duration"], 0)
            rec["expiry_ts"] = (now + dur) if dur else 0
            rec["is_used"] = True
        devs = rec.setdefault("devices", [])
        if fp not in devs:
            if len(devs) >= rec.get("max_devices", 1) > 0:
                return respond("denied", "DEVICE_LIMIT", True, False, "Device limit")
            devs.append(fp)

        bkeys = {}
        for fn in self.BUNDLED:
            bid = v3_crypto.derive_bundle_id(fn)
            if pstatuses.get(bid.hex(), {}).get("status") == "maintenance":
                continue
            bkeys[bid.hex()] = v3_crypto.derive_bundle_key(self.bundle_master, bid).hex()

        eph = os.urandom(32).hex()
        return respond(
            "ok",
            "OK",
            True,
            False,
            "Authorized",
            eph=eph,
            bkeys=bkeys,
            lic={"valid": True, "expiry_ts": rec["expiry_ts"], "is_permanent": rec["duration"] == "permanent"},
            pstatuses=pstatuses,
        )


def client_build_and_decrypt(
    server_x_pub: bytes,
    server_ed_pub: bytes,
    pepper: bytes,
    op: str,
    pkg: str,
    ver: str,
    bld: str,
    fp: str,
    app_hash: str,
    sec_hash: str,
    license_key: str,
    transport,
    tamper_flags: int = 0,
    ts_override: Optional[int] = None,
) -> Tuple[int, dict, Optional[dict]]:
    """Simulates exact `sec_core` + `SecCoreBridge.swift` V3 client behavior."""
    c_priv = os.urandom(32)
    c_pub = v3_crypto.x25519_public_key(c_priv)
    shared = v3_crypto.x25519_shared(c_priv, server_x_pub)
    req_nonce = os.urandom(24)
    nonce_hex = req_nonce.hex()
    ts = ts_override if ts_override is not None else int(time.time())

    req_aad = f"V3REQ|3|{op}|{pkg}|{ver}|{bld}|{fp}|{nonce_hex}|{ts}".encode("utf-8")
    req_key = v3_crypto.hkdf_sha256(shared, pepper, b"3105-V3-REQ", 32)
    proof = hmac.new(pepper, req_aad + b"|" + license_key.encode("utf-8"), hashlib.sha256).hexdigest()

    inner = {
        "op": op,
        "key": license_key,
        "pkg": pkg,
        "ver": ver,
        "bld": bld,
        "app_hash": app_hash,
        "sec_hash": sec_hash,
        "tamper_flags": tamper_flags,
        "client_proof": proof,
        "ts": ts,
    }
    ct = v3_crypto.xchacha20_poly1305_encrypt(req_key, req_nonce, json.dumps(inner).encode("utf-8"), req_aad)
    env = {
        "v": 3,
        "op": op,
        "pkg": pkg,
        "ver": ver,
        "bld": bld,
        "nonce": nonce_hex,
        "ts": ts,
        "c_pub": c_pub.hex(),
        "fp": fp,
        "ct": base64.b64encode(ct).decode("ascii"),
    }
    status, resp_env = transport(env)
    if status != 200:
        return status, resp_env, None

    # Client verifies Ed25519 BEFORE AEAD decrypt
    res_aad = (
        f"V3RES|3|{resp_env['op']}|{resp_env['pkg']}|{resp_env['ver']}|"
        f"{resp_env['fp']}|{resp_env['req_nonce']}|{resp_env['s_nonce']}|{resp_env['s_ts']}|{resp_env['code']}"
    ).encode("utf-8")
    ct_raw = base64.b64decode(resp_env["ct"])
    sig_msg = b"3105-V3-SIG|" + res_aad + b"|" + hashlib.sha256(ct_raw).digest()
    if not v3_crypto.ed25519_verify(server_ed_pub, sig_msg, bytes.fromhex(resp_env["sig"])):
        raise ValueError("Ed25519 signature invalid")
    if resp_env["req_nonce"] != nonce_hex:
        raise ValueError("Response req_nonce mismatch")

    res_key = v3_crypto.hkdf_sha256(shared, pepper, b"3105-V3-RES|" + req_nonce, 32)
    pt = v3_crypto.xchacha20_poly1305_decrypt(res_key, bytes.fromhex(resp_env["s_nonce"]), ct_raw, res_aad)
    return 200, env, json.loads(pt.decode("utf-8"))


def build_synthetic_macho(text_bytes: bytes, marker: bytes) -> bytes:
    """Constructs a minimal valid 64-bit Mach-O file with __TEXT,__text and __DATA,__sechash."""
    page = 4096
    text_padded = text_bytes.ljust(page, b"\x00")
    data_payload = (marker + b"\x00" * 64).ljust(page, b"\x00")

    def seg_cmd(name: str, vmaddr: int, fileoff: int, filesize: int, sects: list) -> bytes:
        hdr = struct.pack(
            "<II16sQQQQiiII",
            0x19,  # LC_SEGMENT_64
            72 + 80 * len(sects),
            name.encode("ascii").ljust(16, b"\x00"),
            vmaddr,
            filesize,
            fileoff,
            filesize,
            5,
            5,
            len(sects),
            0,
        )
        sec_buf = b""
        for sname, saddr, ssize, soff in sects:
            sec_buf += struct.pack(
                "<16s16sQQIIIIIIII",
                sname.encode("ascii").ljust(16, b"\x00"),
                name.encode("ascii").ljust(16, b"\x00"),
                saddr,
                ssize,
                soff,
                4,
                0,
                0,
                0,
                0,
                0,
                0,
            )
        return hdr + sec_buf

    lc1 = seg_cmd("__TEXT", 0x100000000, 0, page * 2, [("__text", 0x100001000, len(text_bytes), page)])
    lc2 = seg_cmd("__DATA", 0x100002000, page * 2, page, [("__sechash", 0x100002000, 80, page * 2)])
    cmds = lc1 + lc2
    mh = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 6, 2, len(cmds), 0, 0)
    header_padded = (mh + cmds).ljust(page, b"\x00")
    return header_padded + text_padded + data_payload


class SecuritySuiteTests(unittest.TestCase):
    RUST_BIN: Optional[Path] = None

    @classmethod
    def setUpClass(cls):
        cls.tmpdir = Path(tempfile.mkdtemp(prefix="p3105_suite_"))
        cls.x_priv = os.urandom(32)
        cls.x_pub = v3_crypto.x25519_public_key(cls.x_priv)
        cls.ed_seed = os.urandom(32)
        cls.ed_pub = v3_crypto.ed25519_public_key(cls.ed_seed)
        cls.pepper = os.urandom(32).hex()
        cls.bundle_master = os.urandom(32)
        cls.ci_secret = os.urandom(32).hex()

        cls.secrets_map = {
            "SERVER_X25519_PRIV_HEX": cls.x_priv.hex(),
            "SERVER_ED25519_PRIV_HEX": cls.ed_seed.hex(),
            "PRE_SHARED_PEPPER": cls.pepper,
            "BUNDLE_PATCH_MASTER_KEY_HEX": cls.bundle_master.hex(),
            "CI_SYNC_SECRET": cls.ci_secret,
        }

        cls.pkg = "com.apple.mobile.MobileHouseArrest"
        cls.fp_main = hashlib.sha256(b"IPHONE-DEVICE-1").hexdigest()
        cls.fp_other = hashlib.sha256(b"IPHONE-DEVICE-2").hexdigest()
        cls.app_hash_v21 = hashlib.sha256(b"3105-ARM64-TEXT-V2.1.0").hexdigest()
        cls.sec_hash_v21 = hashlib.sha256(b"SEC-DYLIB-TEXT-V2.1.0").hexdigest()
        cls.app_hash_v20 = hashlib.sha256(b"3105-ARM64-TEXT-V2.0.0").hexdigest()
        cls.sec_hash_v20 = hashlib.sha256(b"SEC-DYLIB-TEXT-V2.0.0").hexdigest()

        # Run real build-time obfuscation on an isolated copy of the workspace
        cls.stage = cls.tmpdir / "stage"
        shutil.copytree(
            REPO_ROOT,
            cls.stage,
            ignore=shutil.ignore_patterns(".git", "dist", "serverkey_core", "tests"),
        )
        cls.obf_report = obfuscate_build.run_obfuscation(
            workspace=cls.stage,
            x25519_pub_hex=cls.x_pub.hex(),
            ed25519_pub_hex=cls.ed_pub.hex(),
            pepper=cls.pepper,
            bundle_master_hex=cls.bundle_master.hex(),
            spki_primary_hex=hashlib.sha256(b"pin1").hexdigest(),
            spki_backup_hex=hashlib.sha256(b"pin2").hexdigest(),
            api_host="tobivn.chickenkiller.com",
            api_path="/api/v3",
            strict=True,
        )

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def _new_server(self) -> InProcessV3Server:
        srv = InProcessV3Server(self.tmpdir / "data", self.secrets_map)
        srv.banned_devices = []
        srv.ci_register(self.pkg, "2.1.0", "9", self.app_hash_v21, self.sec_hash_v21)
        srv.ci_register(self.pkg, "2.0", "8", self.app_hash_v20, self.sec_hash_v20)
        srv.keys.append(
            {
                "key": "TOBIAIM-30D-VALID-0001",
                "duration": "30d",
                "status": "active",
                "is_used": False,
                "max_devices": 1,
                "devices": [],
            }
        )
        srv.keys.append(
            {
                "key": "TOBIAIM-BANNED-0002",
                "duration": "permanent",
                "status": "revoked",
                "is_used": False,
                "max_devices": 1,
                "devices": [],
            }
        )
        return srv

    # -----------------------------------------------------------------------
    # SCENARIO 1: Client Obfuscation, Symbol Renaming, V4 Packing & Mach-O Seal
    # -----------------------------------------------------------------------
    def test_01_ci_obfuscation_packing_and_macho_seal(self):
        v4_tag = bytes.fromhex(self.obf_report["v4_tag_hex"])
        self.assertGreaterEqual(len(self.obf_report["packed_3105"]), 26)
        self.assertGreater(self.obf_report["swift_strings_encrypted"], 15)

        # Verify ALL staged .3105 files lost legacy headers & publicContentKey
        for p in list(self.stage.glob("*.3105")) + list((self.stage / "ThreeOneOSFive").rglob("*.3105")):
            raw = p.read_bytes()
            self.assertEqual(raw[:4], v4_tag, f"{p.name} missing V4 tag")
            self.assertNotIn(b"3105PATCH", raw)
            self.assertNotIn(b"bplist00", raw)
            self.assertNotIn(b"publicContentKey", raw)

        # Verify Rust C-ABI symbol renaming synced cleanly with Swift
        swift_cfg = (self.stage / "ThreeOneOSFive" / "helpers" / "GeneratedSecurityConfig.swift").read_text("utf-8")
        rs_lib = (self.stage / "sec_core" / "src" / "lib.rs").read_text("utf-8")
        self.assertIn("export_name =", rs_lib)
        self.assertNotIn("KeyAuthManager", (self.stage / "ThreeOneOSFive" / "App.swift").read_text("utf-8"))
        self.assertNotIn("https://phuciosvn.com", (self.stage / "ThreeOneOSFive" / "views" / "KeyGatekeeperView.swift").read_text("utf-8"))
        self.assertNotIn("https://tobivn.chickenkiller.com", (self.stage / "ThreeOneOSFive" / "views" / "KeyGatekeeperView.swift").read_text("utf-8"))
        self.assertIn("{ _d([", swift_cfg)
        self.assertIn(
            "GeneratedSecurityConfig._d(",
            (self.stage / "ThreeOneOSFive" / "views" / "KeyGatekeeperView.swift").read_text("utf-8"),
        )
        self.assertIn(
            "GeneratedSecurityConfig._d(",
            (self.stage / "ThreeOneOSFive" / "helpers" / "LocalDevBridge.swift").read_text("utf-8"),
        )
        # Ensure string obfuscation preserved balanced braces/parens across all transformed Swift files
        for rel_sw in obfuscate_build.SWIFT_STRING_TARGET_FILES:
            sw_txt = (self.stage / rel_sw).read_text("utf-8")
            self.assertEqual(sw_txt.count("{"), sw_txt.count("}"), f"Unbalanced braces in {rel_sw}")
            self.assertEqual(sw_txt.count("("), sw_txt.count(")"), f"Unbalanced parens in {rel_sw}")

        # Verify synthetic Mach-O sealing zeroes marker & preserves __TEXT hash
        marker = bytes.fromhex(self.obf_report["seal_marker_hex"])
        macho_path = self.tmpdir / "libsec_test.dylib"
        macho_path.write_bytes(build_synthetic_macho(b"\xc0\x03\x5f\xd6" * 64, marker))
        sealed_hash = macho_hash.seal_sec_core_dylib(macho_path, self.obf_report["seal_marker_hex"])
        sealed_blob = macho_path.read_bytes()
        self.assertNotIn(marker, sealed_blob)
        off_data = 8192  # 2 * 4096
        mask = sealed_blob[off_data + 16 : off_data + 48]
        masked_digest = sealed_blob[off_data + 48 : off_data + 80]
        unmasked = bytes(m ^ d for m, d in zip(mask, masked_digest)).hex()
        self.assertEqual(unmasked, sealed_hash)

        # Verify patching 1 byte in __TEXT breaks integrity check
        patched = bytearray(sealed_blob)
        patched[4096] ^= 0xFF
        patched_path = self.tmpdir / "libsec_patched.dylib"
        patched_path.write_bytes(bytes(patched))
        self.assertNotEqual(macho_hash.compute_text_sha256(patched_path), sealed_hash)

        # Verify hardened serverkey distribution excludes live secrets and packs CoreEngine.php
        dist_srv = self.tmpdir / "dist_serverkey"
        build_serverkey.package_serverkey(REPO_ROOT / "serverkey", dist_srv)
        packed_core = (dist_srv / "lib" / "CoreEngine.php").read_text("utf-8")
        self.assertIn("gzuncompress", packed_core)
        self.assertNotIn("sodium_crypto_scalarmult", packed_core)
        self.assertFalse((dist_srv / ".env").exists())
        self.assertTrue((dist_srv / "data" / "banned_devices.json").exists())

        # Verify non-secret fingerprints & whitespace-trimmed pepper in run_obfuscation
        report_json = json.dumps(self.obf_report)
        self.assertTrue(self.obf_report["strict_mode"])
        self.assertEqual(self.obf_report["pepper_len"], len(self.pepper))
        self.assertEqual(
            self.obf_report["pepper_fp"],
            hashlib.sha256(b"FP|" + self.pepper.encode("utf-8")).hexdigest()[:8],
        )
        self.assertEqual(
            self.obf_report["x25519_pub_fp"],
            hashlib.sha256(b"FP|" + self.x_pub.hex().encode("utf-8")).hexdigest()[:8],
        )
        self.assertNotIn(self.pepper, report_json)
        self.assertNotIn(self.x_pub.hex(), report_json)
        self.assertNotIn(self.ed_pub.hex(), report_json)
        self.assertNotIn(self.bundle_master.hex(), report_json)

        trim_stage = self.tmpdir / "stage_trim"
        shutil.copytree(
            REPO_ROOT,
            trim_stage,
            ignore=shutil.ignore_patterns(".git", "dist", "serverkey", "serverkey_core", "tests", "*.3105"),
        )
        trim_report = obfuscate_build.run_obfuscation(
            workspace=trim_stage,
            x25519_pub_hex=f" {self.x_pub.hex()}\n",
            ed25519_pub_hex=self.ed_pub.hex(),
            pepper=f"  {self.pepper}\r\n ",
            bundle_master_hex=self.bundle_master.hex(),
            api_host=" tobivn.chickenkiller.com ",
            api_path=" /api/v3 ",
            strict=True,
        )
        self.assertEqual(trim_report["pepper_len"], len(self.pepper))
        self.assertEqual(trim_report["pepper_fp"], self.obf_report["pepper_fp"])
        self.assertEqual(trim_report["api_host"], "tobivn.chickenkiller.com")
        self.assertEqual(trim_report["api_path"], "/api/v3")
        gen_rs = (trim_stage / "sec_core" / "src" / "generated_secrets.rs").read_text("utf-8")
        self.assertIn(f"pub const PEPPER_LEN: usize = {len(self.pepper)};", gen_rs)
        with self.assertRaises(ValueError):
            obfuscate_build.run_obfuscation(
                workspace=trim_stage,
                x25519_pub_hex=self.x_pub.hex(),
                ed25519_pub_hex=self.ed_pub.hex(),
                pepper="   \r\n",
                bundle_master_hex=self.bundle_master.hex(),
            )

    # -----------------------------------------------------------------------
    # SCENARIO 2: Server Kill-Switch (Closed -> Lock; Re-open -> Normal)
    # -----------------------------------------------------------------------
    def test_02_server_kill_switch_global_and_per_app(self):
        srv = self._new_server()

        # Close server globally
        srv.settings["server_open"] = False
        srv.settings["server_closed_message"] = "Server đang bảo trì định kỳ!"

        for op in ("preflight", "activate"):
            st, _, dec = client_build_and_decrypt(
                self.x_pub, self.ed_pub, self.pepper.encode(),
                op, self.pkg, "2.1.0", "9", self.fp_main,
                self.app_hash_v21, self.sec_hash_v21, "TOBIAIM-30D-VALID-0001", srv.process_v3
            )
            self.assertEqual(st, 200)
            self.assertEqual(dec["code"], "SERVER_CLOSED")
            self.assertFalse(dec["server_open"])
            self.assertIsNone(dec["ephemeral_session_key"])
            self.assertEqual(dec["bundle_keys"], {})
            self.assertEqual(dec["message"], "Server đang bảo trì định kỳ!")

        # Open globally, close per-package only
        srv.settings["server_open"] = True
        srv.settings["packages"][self.pkg] = {
            "server_open": False,
            "server_closed_message": "Gói 3105 tạm khóa!",
        }
        _, _, dec = client_build_and_decrypt(
            self.x_pub, self.ed_pub, self.pepper.encode(),
            "activate", self.pkg, "2.1.0", "9", self.fp_main,
            self.app_hash_v21, self.sec_hash_v21, "TOBIAIM-30D-VALID-0001", srv.process_v3
        )
        self.assertEqual(dec["code"], "SERVER_CLOSED")
        self.assertIsNone(dec["ephemeral_session_key"])
        self.assertEqual(dec["message"], "Gói 3105 tạm khóa!")

        # Re-open package -> normal activation works!
        srv.settings["packages"][self.pkg]["server_open"] = True
        _, _, dec_ok = client_build_and_decrypt(
            self.x_pub, self.ed_pub, self.pepper.encode(),
            "activate", self.pkg, "2.1.0", "9", self.fp_main,
            self.app_hash_v21, self.sec_hash_v21, "TOBIAIM-30D-VALID-0001", srv.process_v3
        )
        self.assertEqual(dec_ok["code"], "OK")
        self.assertTrue(dec_ok["server_open"])
        self.assertIsNotNone(dec_ok["ephemeral_session_key"])

    # -----------------------------------------------------------------------
    # SCENARIO 3: Open Server + New Version + Valid Key -> Full V4 RAM Decrypt
    # -----------------------------------------------------------------------
    def test_03_valid_user_new_app_full_v4_decrypt_and_device_limit(self):
        srv = self._new_server()

        _, _, dec = client_build_and_decrypt(
            self.x_pub, self.ed_pub, self.pepper.encode(),
            "activate", self.pkg, "2.1.0", "9", self.fp_main,
            self.app_hash_v21, self.sec_hash_v21, "TOBIAIM-30D-VALID-0001", srv.process_v3
        )
        self.assertEqual(dec["code"], "OK")
        self.assertTrue(dec["license"]["valid"])
        self.assertGreater(dec["license"]["expiry_ts"], int(time.time()) + 29 * 86400)

        # Decrypt REAL packed V4 presets using server-returned bundle_keys
        v4_tag = bytes.fromhex(self.obf_report["v4_tag_hex"])
        for preset_name in ("Aim_Neck_TobiAim_FFVN.3105", "AIM BODY FFVN (1).3105", "MODSKIN FFVN PHUCVN (1).3105"):
            v4_file = (self.stage / preset_name).read_bytes()
            bid_hex = v4_file[4:20].hex()
            self.assertIn(bid_hex, dec["bundle_keys"], f"Missing bundle_key for {preset_name}")

            bundle_key = bytes.fromhex(dec["bundle_keys"][bid_hex])
            decrypted_json = pack_3105.unpack_v4_bytes(v4_file, bundle_key, expected_tag4=v4_tag)
            decoded_payload = json.loads(decrypted_json.decode("utf-8"))
            self.assertTrue(decoded_payload["project"]["isPrivate"])
            self.assertGreater(len(decoded_payload["project"]["rules"]), 0)

            # Compare decrypted rule digest against original repository V1 .3105
            orig_legacy = pack_3105.decode_legacy_3105((REPO_ROOT / preset_name).read_bytes())
            self.assertEqual(
                decoded_payload["project"]["rules"][0]["replacementData"],
                orig_legacy["project"]["rules"][0]["replacementData"],
            )

        # Second device blocked cleanly (max_devices=1)
        _, _, dec2 = client_build_and_decrypt(
            self.x_pub, self.ed_pub, self.pepper.encode(),
            "activate", self.pkg, "2.1.0", "9", self.fp_other,
            self.app_hash_v21, self.sec_hash_v21, "TOBIAIM-30D-VALID-0001", srv.process_v3
        )
        self.assertEqual(dec2["code"], "DEVICE_LIMIT")
        self.assertIsNone(dec2["ephemeral_session_key"])

    # -----------------------------------------------------------------------
    # SCENARIO 4: Force Update (Old Version Denied + Spoofed Version Rejected)
    # -----------------------------------------------------------------------
    def test_04_force_update_old_version_and_anti_version_spoof(self):
        srv = self._new_server()
        srv.settings["force_update"] = True
        srv.settings["min_required_version"] = "2.1.0"
        srv.settings["latest_version"] = "2.1.0"
        srv.settings["download_url"] = "https://tobivn.chickenkiller.com/new.ipa"

        # Old version 2.0 gets FORCE_UPDATE + link, NO keys even with valid license key
        _, _, dec = client_build_and_decrypt(
            self.x_pub, self.ed_pub, self.pepper.encode(),
            "activate", self.pkg, "2.0", "8", self.fp_main,
            self.app_hash_v20, self.sec_hash_v20, "TOBIAIM-30D-VALID-0001", srv.process_v3
        )
        self.assertEqual(dec["code"], "FORCE_UPDATE")
        self.assertTrue(dec["force_update"])
        self.assertEqual(dec["download_url"], "https://tobivn.chickenkiller.com/new.ipa")
        self.assertIsNone(dec["ephemeral_session_key"])
        self.assertEqual(dec["bundle_keys"], {})

        # Attacker edits Info.plist of v2.0 binary to claim "2.1.0" -> caught by manifest hash binding!
        _, _, dec_spoof = client_build_and_decrypt(
            self.x_pub, self.ed_pub, self.pepper.encode(),
            "activate", self.pkg, "2.1.0", "9", self.fp_main,
            self.app_hash_v20, self.sec_hash_v20, "TOBIAIM-30D-VALID-0001", srv.process_v3
        )
        self.assertEqual(dec_spoof["code"], "TAMPER_DETECTED")
        self.assertIsNone(dec_spoof["ephemeral_session_key"])

    # -----------------------------------------------------------------------
    # SCENARIO 5: Anti-Crack ("No Key", Binary Patch, Fake Response, Replay, AAD)
    # -----------------------------------------------------------------------
    def test_05_attack_resistance_no_key_fake_response_replay_tamper(self):
        srv = self._new_server()

        # 5a. "No key" / UI patch: cannot decrypt V4 .3105 without valid server-derived bundle_key
        v4_tag = bytes.fromhex(self.obf_report["v4_tag_hex"])
        v4_file = (self.stage / "Antena_TobiAim_FFVN.3105").read_bytes()
        with self.assertRaises(ValueError):
            pack_3105.unpack_v4_bytes(v4_file, os.urandom(32), expected_tag4=v4_tag)

        # 5b. Fake server response MITM / wrong Ed25519 signature rejected before trusting status
        captured = {}

        def mitm_fake_sig(env):
            st, r = srv.process_v3(env)
            captured["last_req"] = env
            rogue_ed = os.urandom(32)
            # Forge Ed25519 signature
            r["sig"] = os.urandom(64).hex()
            return st, r

        with self.assertRaises(ValueError):
            client_build_and_decrypt(
                self.x_pub, self.ed_pub, self.pepper.encode(),
                "preflight", self.pkg, "2.1.0", "9", self.fp_main,
                self.app_hash_v21, self.sec_hash_v21, "", mitm_fake_sig
            )

        # 5c. Mutating outer AAD header (`ver` or `code`) invalidates signature/AEAD
        def mitm_tamper_code(env):
            st, r = srv.process_v3(env)
            r["code"] = "HACKED"
            return st, r

        with self.assertRaises(ValueError):
            client_build_and_decrypt(
                self.x_pub, self.ed_pub, self.pepper.encode(),
                "preflight", self.pkg, "2.1.0", "9", self.fp_main,
                self.app_hash_v21, self.sec_hash_v21, "", mitm_tamper_code
            )

        # 5d. Replay exact previous request packet -> rejected 403
        st_replay, err_replay = srv.process_v3(captured["last_req"])
        self.assertEqual(st_replay, 403)
        self.assertIn("Replay", err_replay["error"])

        # 5e. Patched client binary hash or client tamper_flags != 0 -> TAMPER_DETECTED, NO keys
        _, _, dec_patched = client_build_and_decrypt(
            self.x_pub, self.ed_pub, self.pepper.encode(),
            "activate", self.pkg, "2.1.0", "9", self.fp_main,
            hashlib.sha256(b"CRACKED-NOP-PATCH").hexdigest(), self.sec_hash_v21,
            "TOBIAIM-30D-VALID-0001", srv.process_v3
        )
        self.assertEqual(dec_patched["code"], "TAMPER_DETECTED")
        self.assertIsNone(dec_patched["ephemeral_session_key"])

        _, _, dec_flags = client_build_and_decrypt(
            self.x_pub, self.ed_pub, self.pepper.encode(),
            "activate", self.pkg, "2.1.0", "9", self.fp_main,
            self.app_hash_v21, self.sec_hash_v21,
            "TOBIAIM-30D-VALID-0001", srv.process_v3, tamper_flags=0x40
        )
        self.assertEqual(dec_flags["code"], "TAMPER_DETECTED")

        # 5f. Optional live Rust binary verification (runs automatically in Linux CI)
        if self.RUST_BIN and self.RUST_BIN.exists():
            data_dir = self.tmpdir / "rust_data"
            data_dir.mkdir(parents=True, exist_ok=True)
            (data_dir / "settings.json").write_text(json.dumps(srv.settings), "utf-8")
            (data_dir / "keys.json").write_text(json.dumps(srv.keys), "utf-8")
            (data_dir / "build_manifests.json").write_text(json.dumps(srv.manifests), "utf-8")
            (data_dir / "banned_devices.json").write_text("[]", "utf-8")
            env_file = self.tmpdir / "rust.env"
            env_file.write_text(
                "\n".join(f"{k}={v}" for k, v in self.secrets_map.items()) + f"\nSERVERKEY_DATA_DIR={data_dir}\n",
                "utf-8",
            )

            def rust_exec(req_env):
                sub_env = dict(os.environ)
                sub_env["SERVERKEY_ENV_FILE"] = str(env_file)
                cmd_in = json.dumps({"action": "v3", "payload": req_env})
                proc = subprocess.run(
                    [str(self.RUST_BIN), "--exec"],
                    input=cmd_in,
                    text=True,
                    capture_output=True,
                    env=sub_env,
                    check=True,
                )
                out = json.loads(proc.stdout)
                return int(out["http_status"]), out["body"]

            st_r, _, dec_r = client_build_and_decrypt(
                self.x_pub, self.ed_pub, self.pepper.encode(),
                "activate", self.pkg, "2.1.0", "9", self.fp_main,
                self.app_hash_v21, self.sec_hash_v21, "TOBIAIM-30D-VALID-0001", rust_exec
            )
            self.assertEqual(st_r, 200)
            self.assertEqual(dec_r["code"], "OK")
            self.assertIn(hashlib.sha256(b"BUNDLE|Aim_Neck_TobiAim_FFVN.3105").digest()[:16].hex(), dec_r["bundle_keys"])

    # -----------------------------------------------------------------------
    # SCENARIO 6: Device HWID Ban & Unban Enforcement
    # -----------------------------------------------------------------------
    def test_06_device_hwid_ban_and_unban(self):
        srv = self._new_server()
        srv.keys.append(
            {
                "key": "TOBIAIM-30D-FRESH-9999",
                "duration": "30d",
                "status": "active",
                "is_used": False,
                "max_devices": 1,
                "devices": [],
            }
        )

        # 1. Valid user activates on fp_main first
        _, _, dec1 = client_build_and_decrypt(
            self.x_pub, self.ed_pub, self.pepper.encode(),
            "activate", self.pkg, "2.1.0", "9", self.fp_main,
            self.app_hash_v21, self.sec_hash_v21, "TOBIAIM-30D-VALID-0001", srv.process_v3
        )
        self.assertEqual(dec1["code"], "OK")

        # 2. Admin bans fp_main HWID on Server Key
        srv.banned_devices.append(
            {
                "hwid": self.fp_main.upper(),
                "reason": "Phát hiện share key & thử hook binary",
                "active": True,
                "source_key": "TOBIAIM-30D-VALID-0001",
            }
        )

        # Preflight immediately locks out banned device
        _, _, dec_pre = client_build_and_decrypt(
            self.x_pub, self.ed_pub, self.pepper.encode(),
            "preflight", self.pkg, "2.1.0", "9", self.fp_main,
            self.app_hash_v21, self.sec_hash_v21, "", srv.process_v3
        )
        self.assertEqual(dec_pre["code"], "DEVICE_BANNED")
        self.assertEqual(dec_pre["status"], "device_banned")
        self.assertIn("share key", dec_pre["message"])
        self.assertIsNone(dec_pre["ephemeral_session_key"])
        self.assertEqual(dec_pre["bundle_keys"], {})

        # Active session heartbeat revoked immediately
        _, _, dec_hb = client_build_and_decrypt(
            self.x_pub, self.ed_pub, self.pepper.encode(),
            "heartbeat", self.pkg, "2.1.0", "9", self.fp_main,
            self.app_hash_v21, self.sec_hash_v21, "TOBIAIM-30D-VALID-0001", srv.process_v3
        )
        self.assertEqual(dec_hb["code"], "DEVICE_BANNED")
        self.assertIsNone(dec_hb["ephemeral_session_key"])

        # Attempting a completely new unused valid key fails AND must not mark that new key used
        _, _, dec_new = client_build_and_decrypt(
            self.x_pub, self.ed_pub, self.pepper.encode(),
            "activate", self.pkg, "2.1.0", "9", self.fp_main,
            self.app_hash_v21, self.sec_hash_v21, "TOBIAIM-30D-FRESH-9999", srv.process_v3
        )
        self.assertEqual(dec_new["code"], "DEVICE_BANNED")
        fresh_rec = next(k for k in srv.keys if k["key"] == "TOBIAIM-30D-FRESH-9999")
        self.assertFalse(fresh_rec["is_used"])

        # Unbanned device fp_other continues working normally
        _, _, dec_other = client_build_and_decrypt(
            self.x_pub, self.ed_pub, self.pepper.encode(),
            "activate", self.pkg, "2.1.0", "9", self.fp_other,
            self.app_hash_v21, self.sec_hash_v21, "TOBIAIM-30D-FRESH-9999", srv.process_v3
        )
        self.assertEqual(dec_other["code"], "OK")
        self.assertIsNotNone(dec_other["ephemeral_session_key"])

        # 3. Admin unbans fp_main -> fp_main regains access smoothly
        srv.banned_devices.clear()
        _, _, dec_unban = client_build_and_decrypt(
            self.x_pub, self.ed_pub, self.pepper.encode(),
            "activate", self.pkg, "2.1.0", "9", self.fp_main,
            self.app_hash_v21, self.sec_hash_v21, "TOBIAIM-30D-VALID-0001", srv.process_v3
        )
        self.assertEqual(dec_unban["code"], "OK")
        self.assertIsNotNone(dec_unban["ephemeral_session_key"])

    # -----------------------------------------------------------------------
    # SCENARIO 7: Server Key Account 1-Device HWID & Single-Session Lock
    # -----------------------------------------------------------------------
    def test_07_serverkey_single_device_account_login(self):
        cfg_text = (REPO_ROOT / "serverkey" / "config.php").read_text(encoding="utf-8")
        admin_text = (REPO_ROOT / "serverkey" / "admin.php").read_text(encoding="utf-8")
        for sym in (
            "resolveClientDeviceIdentity",
            "authenticateAndBindAdminAccount",
            "verifyCurrentAdminSession",
            "logoutAdminSession",
        ):
            self.assertIn(sym, cfg_text)
        self.assertIn("authenticateAndBindAdminAccount", admin_text)
        self.assertIn("verifyCurrentAdminSession", admin_text)
        self.assertIn("kick_user_session", admin_text)
        self.assertIn("adminDeviceFp", admin_text)

        # Deterministic Python verification mirroring config.php HMAC cookie + HWID binding
        secret = hashlib.sha256(b"TOBIAIM-DEV-COOKIE|unit-test-pepper").digest()

        def ua_family(ua: str) -> str:
            u = ua.lower()
            os_name = "iPhone" if "iphone" in u else ("Windows" if "windows" in u else "UnknownOS")
            br = "Safari" if "safari" in u and "chrome" not in u else ("Chrome" if "chrome" in u else "Browser")
            return f"{os_name}|{br}"

        def make_cookie(dev_id: str, ua: str) -> str:
            fam = ua_family(ua)
            sig = hmac.new(secret, f"DEVCOOKIE|{dev_id}|{fam}".encode(), hashlib.sha256).hexdigest()
            return f"{dev_id}.{sig}"

        def resolve_hwid(cookie_val: str, ua: str, client_fp: str) -> Optional[str]:
            fam = ua_family(ua)
            if "." not in cookie_val:
                return None
            dev_id, sig = cookie_val.split(".", 1)
            exp = hmac.new(secret, f"DEVCOOKIE|{dev_id}|{fam}".encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(exp, sig):
                return None
            fp_hash = hashlib.sha256(f"FP|{client_fp}|{fam}".encode()).hexdigest()
            return "DEV-" + hashlib.sha256(f"ACCT-HWID-V1|{dev_id}|{fp_hash}".encode()).hexdigest()[:28].upper()

        ua_a = "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/130.0.0.0"
        ua_b = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Safari/604.1"
        hwid_a = resolve_hwid(make_cookie("a" * 32, ua_a), ua_a, "local-a|Win32|1920x1080")
        hwid_b = resolve_hwid(make_cookie("b" * 32, ua_b), ua_b, "local-b|iPhone|390x844")
        # Stolen cookie onto Device B must fail HMAC (different OS/browser) and yield different HWID
        self.assertIsNone(resolve_hwid(make_cookie("a" * 32, ua_a), ua_b, "local-b|iPhone|390x844"))
        self.assertNotEqual(hwid_a, hwid_b)
        # Same cookie copied onto another Windows Chrome machine with different local fp fails HWID match
        hwid_a_stolen = resolve_hwid(make_cookie("a" * 32, ua_a), ua_a, "local-stolen|Win32|1366x768")
        self.assertNotEqual(hwid_a, hwid_a_stolen)

        # If PHP CLI is installed (e.g. GitHub Actions ubuntu-latest), run full live PHP test!
        php_bin = shutil.which("php")
        if php_bin:
            with tempfile.TemporaryDirectory() as tmpdir:
                data_dir = Path(tmpdir) / "data"
                data_dir.mkdir(parents=True, exist_ok=True)
                pw_script = (REPO_ROOT / "serverkey" / "config.php").as_posix()
                php_code = r'''
                    putenv("SERVERKEY_DATA_DIR=" . $argv[1]);
                    putenv("PRE_SHARED_PEPPER=unit-test-pepper-1234567890");
                    require $argv[2];
                    $users = [[
                        "id" => "u1",
                        "username" => "qdaimmo",
                        "password" => hashUserPassword("Pass@123456"),
                        "role" => "admin",
                        "hwid" => "",
                        "device_fp_hash" => "",
                        "device_label" => "",
                        "active_session_token" => "",
                        "active_ua_hash" => "",
                        "is_active" => true,
                        "expiry_date" => "permanent",
                        "last_login" => null,
                        "last_ip" => "",
                        "is_hwid_blocked" => false,
                    ]];
                    saveUsers($users);
                    $settings = getSettings();

                    // Device A first login
                    $_SERVER["HTTP_USER_AGENT"] = "Mozilla/5.0 (Windows NT 10.0) Chrome/130.0.0.0";
                    $_COOKIE = [];
                    $devA = resolveClientDeviceIdentity("fp-pc-a", false);
                    $resA1 = authenticateAndBindAdminAccount("qdaimmo", "Pass@123456", $settings, $devA, "1.1.1.1");
                    if (empty($resA1["ok"]) || empty($resA1["bound_now"])) { fwrite(STDERR, "A1 failed\n"); exit(1); }

                    // Re-resolve using issued cookie from A -> matches bound HWID on subsequent login
                    $devA2 = resolveClientDeviceIdentity("fp-pc-a", false);
                    $resA2 = authenticateAndBindAdminAccount("qdaimmo", "Pass@123456", $settings, $devA2, "1.1.1.1");
                    if (empty($resA2["ok"]) || $resA2["hwid"] !== $resA1["hwid"]) { fwrite(STDERR, "A2 failed\n"); exit(2); }

                    // Session verification passes for newest token, rejects older replaced token
                    $_SESSION = [
                        "admin_logged_in" => true,
                        "admin_current_user" => "qdaimmo",
                        "admin_is_master" => false,
                        "admin_session_token" => $resA1["session_token"],
                        "admin_device_hwid" => $resA1["hwid"],
                        "admin_device_fp_hash" => $resA1["fp_hash"],
                        "admin_ua_hash" => $resA1["ua_hash"],
                    ];
                    $vOld = verifyCurrentAdminSession($settings, $devA2);
                    if (!empty($vOld["valid"])) { fwrite(STDERR, "Old session accepted\n"); exit(3); }
                    $_SESSION["admin_session_token"] = $resA2["session_token"];
                    $vNew = verifyCurrentAdminSession($settings, $devA2);
                    if (empty($vNew["valid"])) { fwrite(STDERR, "New session rejected: " . $vNew["reason"] . "\n"); exit(4); }

                    // Device B attempts login with valid password -> MUST BE REJECTED (HWID_MISMATCH)
                    $_SERVER["HTTP_USER_AGENT"] = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0) Safari/604.1";
                    $_COOKIE = [];
                    $devB = resolveClientDeviceIdentity("fp-iphone-b", false);
                    $resB = authenticateAndBindAdminAccount("qdaimmo", "Pass@123456", $settings, $devB, "2.2.2.2");
                    if (!empty($resB["ok"]) || ($resB["code"] ?? "") !== "HWID_MISMATCH") { fwrite(STDERR, "B was not blocked!\n"); exit(5); }

                    // Reset HWID -> Device A session invalid immediately, Device B can now bind once
                    withLockedJson(USERS_FILE, [], function(&$list, &$dirty) {
                        $list[0]["hwid"] = "";
                        $list[0]["active_session_token"] = "";
                        $dirty = true;
                        return true;
                    });
                    $_SERVER["HTTP_USER_AGENT"] = "Mozilla/5.0 (Windows NT 10.0) Chrome/130.0.0.0";
                    if (!empty(verifyCurrentAdminSession($settings, $devA2)["valid"])) { fwrite(STDERR, "A stayed valid after reset!\n"); exit(6); }

                    $_SERVER["HTTP_USER_AGENT"] = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0) Safari/604.1";
                    $resB2 = authenticateAndBindAdminAccount("qdaimmo", "Pass@123456", $settings, $devB, "2.2.2.2");
                    if (empty($resB2["ok"])) { fwrite(STDERR, "B2 failed after reset\n"); exit(7); }

                    // Now Device A is locked out!
                    $_SERVER["HTTP_USER_AGENT"] = "Mozilla/5.0 (Windows NT 10.0) Chrome/130.0.0.0";
                    $resA3 = authenticateAndBindAdminAccount("qdaimmo", "Pass@123456", $settings, $devA2, "1.1.1.1");
                    if (!empty($resA3["ok"]) || ($resA3["code"] ?? "") !== "HWID_MISMATCH") { fwrite(STDERR, "A3 was not blocked after B bound!\n"); exit(8); }

                    // Banning Device B HWID blocks login even if HWID matches
                    banDeviceHwid($resB2["hwid"], "test ban", "admin", "");
                    $_SERVER["HTTP_USER_AGENT"] = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0) Safari/604.1";
                    $resB3 = authenticateAndBindAdminAccount("qdaimmo", "Pass@123456", $settings, $devB, "2.2.2.2");
                    if (!empty($resB3["ok"]) || ($resB3["code"] ?? "") !== "DEVICE_BANNED") { fwrite(STDERR, "Banned B not blocked\n"); exit(9); }
                    echo "PHP_SINGLE_DEVICE_OK\n";
                '''
                proc = subprocess.run(
                    [php_bin, "-r", php_code, str(data_dir), pw_script],
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(proc.returncode, 0, f"PHP test failed: {proc.stderr} {proc.stdout}")
                self.assertIn("PHP_SINGLE_DEVICE_OK", proc.stdout)

    # -----------------------------------------------------------------------
    # SCENARIO 8: .htaccess V3 Route Order + iOS Launch Hang/Timeout Safeguards
    # -----------------------------------------------------------------------
    def test_08_htaccess_route_order_and_ios_timeout_safeguards(self):
        htaccess = (REPO_ROOT / "serverkey" / ".htaccess").read_text(encoding="utf-8")
        v3_pos = htaccess.find("RewriteRule ^api/v3/?$")
        deny_pos = htaccess.find("RewriteRule ^(data|lib|api)/")
        self.assertGreater(v3_pos, -1)
        self.assertGreater(deny_pos, -1)
        self.assertLess(v3_pos, deny_pos, "^api/v3/?$ must precede ^(data|lib|api)/ deny rule")

        app_swift = (REPO_ROOT / "ThreeOneOSFive" / "App.swift").read_text(encoding="utf-8")
        self.assertIn("SecurityGateRootView", app_swift)
        self.assertIn("startBootstrapIfNeeded()", app_swift)
        self.assertIn(".connectionError(let message)", app_swift)
        self.assertIn("@StateObject private var keyAuth = KeyAuthManager.shared", app_swift)

        self.assertIn("case .tampered(let message):", app_swift)

        gate_swift = (REPO_ROOT / "ThreeOneOSFive" / "views" / "KeyGatekeeperView.swift").read_text(encoding="utf-8")
        self.assertIn("bootstrapGeneration", gate_swift)
        self.assertIn("activationGeneration", gate_swift)
        self.assertIn("asyncAfter(deadline:", gate_swift)
        self.assertIn("handleCheckingTimeoutFallback", gate_swift)
        self.assertIn("checkingElapsedSeconds", gate_swift)
        self.assertIn("case connectionError(message: String)", gate_swift)
        bootstrap_block = gate_swift.split("func bootstrapCheck(", 1)[1].split("func activateKey(", 1)[0]
        self.assertIn("case .preflightOpen(_, _, let presetStatuses):", bootstrap_block)
        self.assertNotIn("self.errorMessage = msg\n                        self.gatePhase = .requiresKey", bootstrap_block)

        sec_bridge = (REPO_ROOT / "ThreeOneOSFive" / "helpers" / "SecCoreBridge.swift").read_text(encoding="utf-8")
        self.assertIn("case cryptoError(message: String)", sec_bridge)
        self.assertIn('if code == "TAMPER_DETECTED"', sec_bridge)
        self.assertIn("sentPkg == localPkg", sec_bridge)

        ld_swift = (REPO_ROOT / "ThreeOneOSFive" / "helpers" / "LocalDevBridge.swift").read_text(encoding="utf-8")
        self.assertIn("isCoreInitialized", ld_swift)
        self.assertIn("DispatchQueue.global(qos: .utility).async", ld_swift)

        net_rs = (REPO_ROOT / "sec_core" / "src" / "network.rs").read_text(encoding="utf-8")
        self.assertIn("resolve_addrs_with_timeout", net_rs)
        self.assertIn("read_http_response", net_rs)
        self.assertIn("decode_chunked_parts", net_rs)
        self.assertIn("is_ipv4()", net_rs)
        self.assertNotIn("read_to_end(", net_rs)

        lib_rs = (REPO_ROOT / "sec_core" / "src" / "lib.rs").read_text(encoding="utf-8")
        self.assertIn("ExchangeFailure", lib_rs)
        self.assertIn("CRYPTO_ERROR", lib_rs)

        # Verify sec_core dlsym extern clash, unsafe FFI obfuscation & ios_ui dead_code remediation
        anti_hook_rs = (REPO_ROOT / "sec_core" / "src" / "anti_hook.rs").read_text(encoding="utf-8")
        self.assertIn("libc::dlsym(libc::RTLD_DEFAULT", anti_hook_rs)
        self.assertIn("libc::getenv(", anti_hook_rs)
        self.assertNotIn("fn dlsym(", anti_hook_rs)
        self.assertIn("pub unsafe fn is_trampoline_hooked", anti_hook_rs)
        self.assertNotIn("0x1400_0000", anti_hook_rs)
        anti_debug_rs = (REPO_ROOT / "sec_core" / "src" / "anti_debug.rs").read_text(encoding="utf-8")
        self.assertNotIn("CS_VALID", anti_debug_rs)
        self.assertIn("#[used]", lib_rs)

        # Verify ALL exported C-ABI symbols (both safe and unsafe) were obfuscated in stage copy
        staged_lib = (self.stage / "sec_core" / "src" / "lib.rs").read_text(encoding="utf-8")
        staged_ffi = (self.stage / "sec_core" / "src" / "localdev" / "ffi.rs").read_text(encoding="utf-8")
        for sym in obfuscate_build.SEC_CABI_SYMBOLS:
            self.assertRegex(staged_lib, rf'#\[export_name = "_x[0-9a-f]+"\]\s*pub (?:unsafe )?extern "C" fn {sym}\b')
        for sym in obfuscate_build.LOCALDEV_CABI_SYMBOLS:
            self.assertRegex(staged_ffi, rf'#\[export_name = "_x[0-9a-f]+"\]\s*pub (?:unsafe )?extern "C" fn {sym}\b')

        ios_ui_rs = (REPO_ROOT / "sec_core" / "src" / "ios_ui.rs").read_text(encoding="utf-8")
        self.assertNotIn("on_submit", ios_ui_rs)
        self.assertNotIn("ActivationUiContext", ios_ui_rs)
        self.assertNotIn("fn dlsym(", ios_ui_rs)

        core_php = (REPO_ROOT / "serverkey" / "lib" / "CoreEngine.php").read_text(encoding="utf-8")
        self.assertIn("sodium_memzero", core_php)
        self.assertIn("__destruct", core_php)
        self.assertIn("ip_kf:", core_php)
        cfg_php = (REPO_ROOT / "serverkey" / "config.php").read_text(encoding="utf-8")
        self.assertIn("pbkdf2_sha256:", cfg_php)
        self.assertIn("$envHash !== '' ? $envHash", cfg_php)

        build_yml = (REPO_ROOT / ".github" / "workflows" / "build.yml").read_text(encoding="utf-8")
        self.assertIn("macho_hash.py\" verify-seal", build_yml)
        self.assertNotIn("if: env.SEC_CI_SYNC_URL", build_yml)
        # SwiftUI/Combine @Published requires runtime reflection metadata; stripping it freezes UI updates
        self.assertNotIn("SWIFT_REFLECTION_METADATA_LEVEL=none", build_yml)
        pbxproj = (REPO_ROOT / "ThreeOneOSFive.xcodeproj" / "project.pbxproj").read_text(encoding="utf-8")
        self.assertNotIn("SWIFT_REFLECTION_METADATA_LEVEL = none", pbxproj)

        # End-to-end synthetic 64-bit Mach-O binary containing __TEXT,__text and __DATA,__sechash
        marker = os.urandom(16)
        text_code = b"\xC0\x03\x5F\xD6" * 8
        sechash_buf = marker + (b"\x00" * 64)
        text_off = 512
        data_off = 512 + len(text_code)
        hdr = struct.pack("<IiiIIIII", macho_hash.MH_MAGIC_64, macho_hash.CPU_TYPE_ARM64, 0, 6, 2, 72 + 80 + 72 + 80, 0, 0)
        seg_text = struct.pack("<II16sQQQQiiII", macho_hash.LC_SEGMENT_64, 152, b"__TEXT".ljust(16, b"\x00"), 0, len(text_code), text_off, len(text_code), 5, 5, 1, 0)
        sec_text = struct.pack("<16s16sQQIIIIIIII", b"__text".ljust(16, b"\x00"), b"__TEXT".ljust(16, b"\x00"), 0, len(text_code), text_off, 2, 0, 0, 0, 0, 0, 0)
        seg_data = struct.pack("<II16sQQQQiiII", macho_hash.LC_SEGMENT_64, 152, b"__DATA".ljust(16, b"\x00"), 0, len(sechash_buf), data_off, len(sechash_buf), 3, 3, 1, 0)
        sec_data = struct.pack("<16s16sQQIIIIIIII", b"__sechash".ljust(16, b"\x00"), b"__DATA".ljust(16, b"\x00"), 0, len(sechash_buf), data_off, 2, 0, 0, 0, 0, 0, 0)
        synth_blob = (hdr + seg_text + sec_text + seg_data + sec_data).ljust(text_off, b"\x00") + text_code + sechash_buf
        synth_path = self.tmpdir / "libsec_core_synth.dylib"
        synth_path.write_bytes(synth_blob)
        sealed_hash = macho_hash.seal_sec_core_dylib(synth_path, marker.hex())
        verified_hash = macho_hash.verify_sec_core_seal(synth_path)
        self.assertEqual(sealed_hash, verified_hash)
        self.assertEqual(sealed_hash, hashlib.sha256(text_code).hexdigest())

    # -----------------------------------------------------------------------
    # SCENARIO 9: Per-Preset Stable / Maintenance Control (Server + Client)
    # -----------------------------------------------------------------------
    def test_09_preset_maintenance_and_stable_controls(self):
        srv = self._new_server()
        srv.keys.append(
            {
                "key": "TOBIAIM-PRESET-0001",
                "duration": "30d",
                "status": "active",
                "is_used": False,
                "max_devices": 1,
                "devices": [],
            }
        )
        aim_bid = v3_crypto.derive_bundle_id("AIM BODY FFVN (1).3105").hex()
        antena_bid = v3_crypto.derive_bundle_id("Antena_TobiAim_FFVN.3105").hex()

        # Put AIM BODY into maintenance on Server Key while keeping Antena stable
        srv.settings["preset_policies"] = {
            "AIM BODY FFVN (1).3105": {
                "status": "maintenance",
                "message": "Đang cập nhật AIM BODY theo bản mới.",
            },
            "Antena_TobiAim_FFVN.3105": {"status": "stable", "message": ""},
        }

        st, _, dec_maint = client_build_and_decrypt(
            self.x_pub, self.ed_pub, self.pepper.encode(),
            "activate", self.pkg, "2.1.0", "9", self.fp_main,
            self.app_hash_v21, self.sec_hash_v21, "TOBIAIM-PRESET-0001", srv.process_v3,
        )
        self.assertEqual(st, 200)
        self.assertEqual(dec_maint["preset_statuses"][aim_bid]["status"], "maintenance")
        self.assertEqual(dec_maint["preset_statuses"][aim_bid]["message"], "Đang cập nhật AIM BODY theo bản mới.")
        self.assertEqual(dec_maint["preset_statuses"][antena_bid]["status"], "stable")
        self.assertNotIn(aim_bid, dec_maint["bundle_keys"])
        self.assertIn(antena_bid, dec_maint["bundle_keys"])

        # Restore AIM BODY to stable -> bundle key returns & V4 container decrypts cleanly
        srv.settings["preset_policies"]["AIM BODY FFVN (1).3105"] = {"status": "stable", "message": ""}
        st2, _, dec_stable = client_build_and_decrypt(
            self.x_pub, self.ed_pub, self.pepper.encode(),
            "heartbeat", self.pkg, "2.1.0", "9", self.fp_main,
            self.app_hash_v21, self.sec_hash_v21, "TOBIAIM-PRESET-0001", srv.process_v3,
        )
        self.assertEqual(st2, 200)
        self.assertEqual(dec_stable["preset_statuses"][aim_bid]["status"], "stable")
        self.assertIn(aim_bid, dec_stable["bundle_keys"])

        # Cross-verify PHP/Swift/Rust parity markers
        core_php = (REPO_ROOT / "serverkey" / "lib" / "CoreEngine.php").read_text("utf-8")
        admin_php = (REPO_ROOT / "serverkey" / "admin.php").read_text("utf-8")
        bridge_sw = (REPO_ROOT / "ThreeOneOSFive" / "helpers" / "SecCoreBridge.swift").read_text("utf-8")
        proj_sw = (REPO_ROOT / "ThreeOneOSFive" / "views" / "PatchProjectsView.swift").read_text("utf-8")
        self.assertIn("resolvePresetPolicies", core_php)
        self.assertIn("'preset_statuses'", core_php)
        self.assertIn("require_once __DIR__ . '/lib/CoreEngine.php';", admin_php)
        self.assertIn("save_preset_policies", admin_php)
        self.assertIn("V3PresetStatus", bridge_sw)
        self.assertIn("ĐANG BẢO TRÌ", proj_sw)
        self.assertIn("ĐANG ỔN ĐỊNH", proj_sw)
        self.assertIn('case aim = "AIM"\n    case chams = "CHAMS"\n    case modskin = "MODSKIN"', proj_sw)
        self.assertIn('name: "MODSKIN 1"', proj_sw)
        self.assertIn('name: "MODSKIN 5"', proj_sw)
        self.assertIn("MODSKIN FFVN PHUCVN (5).3105", core_php)
        self.assertNotIn("isMaintenance ? .secondary", proj_sw)
        self.assertNotIn(": .secondary)", proj_sw)


def main():
    parser = argparse.ArgumentParser(description="Run 3105 5-Scenario Security Test Suite")
    parser.add_argument("--rust-bin", type=Path, default=None)
    args, remaining = parser.parse_known_args()
    if args.rust_bin:
        SecuritySuiteTests.RUST_BIN = args.rust_bin
    runner = unittest.TextTestRunner(verbosity=2)
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(SecuritySuiteTests)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()
