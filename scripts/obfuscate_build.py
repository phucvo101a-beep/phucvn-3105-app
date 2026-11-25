#!/usr/bin/env python3
"""
CI Build-Time Obfuscation & Secret Injection Pipeline (runs on staging copy ONLY):
1. Generates per-build XOR-split cryptographic material (`generated_secrets.rs` & `GeneratedSecurityConfig.swift`)
2. Generates randomized per-build C-ABI symbol names synced across Rust & Swift `dlsym`
3. Encrypts sensitive plain Swift literals into stack-only `_d([..], mask: ..)` calls
4. Renames internal Swift security class/struct identifiers consistently across target `.swift` files
5. Packs all `.3105` resources into encrypted V4 containers (removing `3105PATCH`/`bplist00` headers)
"""

import argparse
import os
import re
import secrets
import sys
from pathlib import Path
from typing import Dict, List

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import pack_3105

SEC_CABI_SYMBOLS = [
    "sec_core_preflight",
    "sec_core_activate",
    "sec_core_heartbeat",
    "sec_core_decrypt_v4",
    "sec_core_verify_ticket",
    "sec_core_wipe_session",
    "sec_core_device_fp",
    "sec_core_tamper_detected",
    "sec_core_free_string",
    "sec_core_free_bytes",
]

LOCALDEV_CABI_SYMBOLS = [
    "localdev_init",
    "localdev_import_pairing",
    "localdev_status",
    "localdev_scan_apps",
    "localdev_list_dir",
    "localdev_read_file",
    "localdev_write_file",
    "localdev_free_string",
    "localdev_free_bytes",
]

SWIFT_INTERNAL_SECURITY_TYPES = [
    "KeyAuthManager",
    "SecurityGatePhase",
    "SecCoreBridge",
    "RuntimeSessionTicket",
    "V3LicenseSummary",
    "V3GateOutcome",
    "KeychainLicenseVault",
    "SecureBytes",
    "secureWipeData",
    "SemVerComparator",
    "SecurityCheckingView",
    "SecurityLockoutView",
    "SecurityGateRootView",
]

SWIFT_STRING_TARGET_FILES = [
    "ThreeOneOSFive/helpers/SecCoreBridge.swift",
    "ThreeOneOSFive/helpers/SecureMemory.swift",
    "ThreeOneOSFive/helpers/PatchPackageCodec.swift",
    "ThreeOneOSFive/helpers/LocalDevBridge.swift",
    "ThreeOneOSFive/views/KeyGatekeeperView.swift",
]

SENSITIVE_SWIFT_PATTERNS = (
    "20-10.store",
    "phuciosvn.com",
    "api.php",
    "/api/",
    "com.phucvn",
    "com.apple.mobile",
    "Frameworks/libsec_core",
    "@executable_path",
    "@rpath/",
    "libsec_core",
    "DYLD_INSERT_LIBRARIES",
    "FRIDA_HOST",
    "_MSSafeMode",
    "3105-V3-SIG",
    "V3RES|3|",
    "SERVER_CLOSED",
    "DEVICE_BANNED",
    "FORCE_UPDATE",
    "TAMPER_DETECTED",
    "TICKET_REJECTED",
    "NETWORK_ERROR",
    "PHUCVN-",
    "3105PATCH",
    "bplist00",
    "saved_key",
)


def _split_xor(secret: bytes) -> tuple[bytes, bytes]:
    a = secrets.token_bytes(len(secret))
    b = bytes(x ^ y for x, y in zip(secret, a))
    return a, b


def _fmt_rust_arr(data: bytes) -> str:
    return "[" + ", ".join(f"0x{b:02X}" for b in data) + "]"


def _fmt_swift_arr(data: bytes) -> str:
    return "[" + ", ".join(f"0x{b:02X}" for b in data) + "]"


def _encode_bytes_xor(raw: bytes, mask: int) -> bytes:
    return bytes(b ^ mask for b in raw)


def _obfuscate_swift_strings(text: str) -> tuple[str, int]:
    """
    Safely replaces matching plain double-quoted Swift string literals with stack-decoded
    `GeneratedSecurityConfig._d([...], mask: 0x..)` calls without corrupting comments,
    multiline strings, interpolated strings `\\(...)`, or `case`/`@`/`import` declarations.
    """
    out = []
    i = 0
    n = len(text)
    replaced = 0

    while i < n:
        ch = text[i]
        # Skip line comment
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            end = text.find("\n", i)
            end = n if end == -1 else end + 1
            out.append(text[i:end])
            i = end
            continue
        # Skip block comment
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            end = text.find("*/", i + 2)
            end = n if end == -1 else end + 2
            out.append(text[i:end])
            i = end
            continue
        # Skip triple-quoted string literals
        if text[i : i + 3] == '"""':
            end = text.find('"""', i + 3)
            end = n if end == -1 else end + 3
            out.append(text[i:end])
            i = end
            continue

        if ch == '"':
            # Inspect current line prefix to skip case/import/@/# declarations
            line_start = text.rfind("\n", 0, i) + 1
            line_prefix = text[line_start:i]
            trimmed_prefix = line_prefix.lstrip()

            j = i + 1
            decoded_chars = bytearray()
            has_interp = False
            ok = True
            while j < n:
                c = text[j]
                if c == '"':
                    break
                if c == "\n":
                    ok = False
                    break
                if c == "\\":
                    if j + 1 >= n:
                        ok = False
                        break
                    nxt = text[j + 1]
                    if nxt == "(":
                        has_interp = True
                        ok = False
                        break
                    esc_map = {"n": 10, "r": 13, "t": 9, '"': 34, "\\": 92, "0": 0}
                    if nxt in esc_map:
                        decoded_chars.append(esc_map[nxt])
                        j += 2
                        continue
                    ok = False
                    break
                decoded_chars.extend(c.encode("utf-8"))
                j += 1

            if ok and j < n and not has_interp:
                lit = decoded_chars.decode("utf-8", errors="ignore")
                should_skip_context = (
                    trimmed_prefix.startswith("@")
                    or trimmed_prefix.startswith("#")
                    or trimmed_prefix.startswith("case ")
                    or trimmed_prefix.startswith("import ")
                    or "typealias" in line_prefix
                    or "LocalizedStringKey" in line_prefix
                    or trimmed_prefix.startswith("static let sym")
                )
                prev_non_ws = trimmed_prefix.rstrip()[-1:] if trimmed_prefix.rstrip() else ""
                is_expr = prev_non_ws in ("=", "(", ":", ",", "[", "+", "?", "!") or bool(re.search(r"\breturn\s+$", line_prefix))
                if (
                    not should_skip_context
                    and is_expr
                    and any(pat in lit for pat in SENSITIVE_SWIFT_PATTERNS)
                ):
                    mask = secrets.randbelow(254) + 1
                    enc = [b ^ mask for b in bytes(decoded_chars)]
                    arr = ", ".join(f"0x{b:02X}" for b in enc)
                    out.append(f"GeneratedSecurityConfig._d([{arr}], mask: 0x{mask:02X})")
                    replaced += 1
                    i = j + 1
                    continue

            # Keep original string unmodified
            out.append(text[i : min(j + 1, n)])
            i = min(j + 1, n)
            continue

        out.append(ch)
        i += 1

    return "".join(out), replaced


def run_obfuscation(
    workspace: Path,
    x25519_pub_hex: str,
    ed25519_pub_hex: str,
    pepper: str,
    bundle_master_hex: str,
    spki_primary_hex: str = "00" * 32,
    spki_backup_hex: str = "00" * 32,
    api_host: str = "20-10.store",
    api_path: str = "/api/v3",
    strict: bool = True,
) -> Dict:
    """Executes all obfuscation & sealing transforms in-place on `workspace` copy."""
    x_pub = bytes.fromhex(x25519_pub_hex.strip())
    ed_pub = bytes.fromhex(ed25519_pub_hex.strip())
    pep_bytes = pepper.encode("utf-8")
    b_master = bytes.fromhex(bundle_master_hex.strip())
    pin1 = bytes.fromhex(spki_primary_hex.strip())
    pin2 = bytes.fromhex(spki_backup_hex.strip())
    require_pin = pin1 != b"\x00" * 32 or pin2 != b"\x00" * 32

    if len(x_pub) != 32 or len(ed_pub) != 32 or len(b_master) != 32 or not (1 <= len(pep_bytes) <= 64):
        raise ValueError("Invalid secret lengths supplied to obfuscate_build")

    # 1. Per-build random parameters
    seal_marker = secrets.token_bytes(16)
    v4_tag = secrets.token_bytes(4)
    opaque_seed = secrets.randbits(64) | 1

    x_a, x_b = _split_xor(x_pub)
    ed_a, ed_b = _split_xor(ed_pub)
    pep_padded = pep_bytes.ljust(64, b"\x00")
    pep_a, pep_b = _split_xor(pep_padded)
    p1_a, p1_b = _split_xor(pin1)
    p2_a, p2_b = _split_xor(pin2)
    t4_a, t4_b = _split_xor(v4_tag)

    host_mask = secrets.randbelow(254) + 1
    path_mask = secrets.randbelow(254) + 1
    host_enc = _encode_bytes_xor(api_host.encode("utf-8"), host_mask)
    path_enc = _encode_bytes_xor(api_path.encode("utf-8"), path_mask)

    # 2. Per-build random C-ABI symbol names
    c_sym_map: Dict[str, str] = {}
    for s in SEC_CABI_SYMBOLS + LOCALDEV_CABI_SYMBOLS:
        c_sym_map[s] = f"_x{secrets.token_hex(6)}"

    # 3. Rewrite sec_core/src/generated_secrets.rs
    seal_arr = list(seal_marker) + [0] * 64
    rs_secrets = f"""// AUTO-GENERATED PER-BUILD SECURITY MATERIAL (DO NOT COMMIT)
pub const SEAL_REQUIRED: bool = {"true" if strict else "false"};
pub const REQUIRE_SPKI_PIN: bool = {"true" if require_pin else "false"};
pub const OPAQUE_SEED: u64 = 0x{opaque_seed:016X};

pub const X25519_SHARE_A: [u8; 32] = {_fmt_rust_arr(x_a)};
pub const X25519_SHARE_B: [u8; 32] = {_fmt_rust_arr(x_b)};

pub const ED25519_SHARE_A: [u8; 32] = {_fmt_rust_arr(ed_a)};
pub const ED25519_SHARE_B: [u8; 32] = {_fmt_rust_arr(ed_b)};

pub const PEPPER_LEN: usize = {len(pep_bytes)};
pub const PEPPER_SHARE_A: [u8; 64] = {_fmt_rust_arr(pep_a)};
pub const PEPPER_SHARE_B: [u8; 64] = {_fmt_rust_arr(pep_b)};

pub const SPKI_PRIMARY_A: [u8; 32] = {_fmt_rust_arr(p1_a)};
pub const SPKI_PRIMARY_B: [u8; 32] = {_fmt_rust_arr(p1_b)};

pub const SPKI_BACKUP_A: [u8; 32] = {_fmt_rust_arr(p2_a)};
pub const SPKI_BACKUP_B: [u8; 32] = {_fmt_rust_arr(p2_b)};

pub const V4_FORMAT_TAG: [u8; 4] = {_fmt_rust_arr(v4_tag)};

pub const API_HOST_MASK: u8 = 0x{host_mask:02X};
pub const API_HOST_ENC: &[u8] = &{_fmt_rust_arr(host_enc)};

pub const API_PATH_MASK: u8 = 0x{path_mask:02X};
pub const API_PATH_ENC: &[u8] = &{_fmt_rust_arr(path_enc)};

#[used]
#[cfg_attr(target_vendor = "apple", link_section = "__DATA,__sechash")]
pub static mut SEC_SELF_SEAL: [u8; 80] = {_fmt_rust_arr(bytes(seal_arr))};
"""
    (workspace / "sec_core" / "src" / "generated_secrets.rs").write_text(rs_secrets, encoding="utf-8")

    # 4. Rewrite Rust C-ABI symbol names via #[export_name = ...] (internal function names remain clean)
    for rs_rel in ("sec_core/src/lib.rs", "sec_core/src/localdev/ffi.rs"):
        rs_path = workspace / rs_rel
        rs_txt = rs_path.read_text(encoding="utf-8")
        for orig_sym, obf_sym in c_sym_map.items():
            rs_txt = re.sub(
                rf'#\[no_mangle\]\s*(pub extern "C" fn {re.escape(orig_sym)}\b)',
                rf'#[export_name = "{obf_sym}"]\n\1',
                rs_txt,
            )
        rs_path.write_text(rs_txt, encoding="utf-8")

    # Sync LocalDevBridge dlsym calls to obfuscated stack-decoded C symbols
    ld_bridge = workspace / "ThreeOneOSFive" / "helpers" / "LocalDevBridge.swift"
    if ld_bridge.exists():
        ld_txt = ld_bridge.read_text(encoding="utf-8")
        for orig_sym in LOCALDEV_CABI_SYMBOLS:
            obf_sym = c_sym_map[orig_sym]
            m_byte = secrets.randbelow(254) + 1
            enc_bytes = ", ".join(f"0x{(b ^ m_byte):02X}" for b in obf_sym.encode("utf-8"))
            ld_txt = ld_txt.replace(
                f'"{orig_sym}"',
                f'GeneratedSecurityConfig._d([{enc_bytes}], mask: 0x{m_byte:02X})',
            )
        ld_bridge.write_text(ld_txt, encoding="utf-8")

    # 5. Rewrite GeneratedSecurityConfig.swift with obfuscated shares & randomized C symbols
    lm_a, lm_b = _split_xor(b"3105PATCH\x00")
    def _sym_prop(prop_name: str, sym_key: str) -> str:
        val = c_sym_map[sym_key].encode("utf-8")
        m_byte = secrets.randbelow(254) + 1
        arr = ", ".join(f"0x{(b ^ m_byte):02X}" for b in val)
        return f'    static var {prop_name}: String {{ _d([{arr}], mask: 0x{m_byte:02X}) }}'

    swift_cfg = f"""import Darwin
import Foundation

enum GeneratedSecurityConfig {{
    static let enforceStrictCrypto: Bool = {"true" if strict else "false"}
    static let opaqueSeed: UInt64 = 0x{opaque_seed:016X}

    static let ed25519ShareA: [UInt8] = {_fmt_swift_arr(ed_a)}
    static let ed25519ShareB: [UInt8] = {_fmt_swift_arr(ed_b)}

    static let v4TagA: [UInt8] = {_fmt_swift_arr(t4_a)}
    static let v4TagB: [UInt8] = {_fmt_swift_arr(t4_b)}

    static let legacyMagicA: [UInt8] = {_fmt_swift_arr(lm_a)}
    static let legacyMagicB: [UInt8] = {_fmt_swift_arr(lm_b)}

{_sym_prop('symPreflight', 'sec_core_preflight')}
{_sym_prop('symActivate', 'sec_core_activate')}
{_sym_prop('symHeartbeat', 'sec_core_heartbeat')}
{_sym_prop('symDecryptV4', 'sec_core_decrypt_v4')}
{_sym_prop('symVerifyTicket', 'sec_core_verify_ticket')}
{_sym_prop('symWipeSession', 'sec_core_wipe_session')}
{_sym_prop('symDeviceFP', 'sec_core_device_fp')}
{_sym_prop('symTamperDetected', 'sec_core_tamper_detected')}
{_sym_prop('symFreeString', 'sec_core_free_string')}
{_sym_prop('symFreeBytes', 'sec_core_free_bytes')}

    static func serverEd25519PublicKeyData() -> Data {{
        var out = Data(count: 32)
        for i in 0..<32 {{
            out[i] = ed25519ShareA[i] ^ ed25519ShareB[i]
        }}
        return out
    }}

    static func v4FormatTag() -> Data {{
        var out = Data(count: 4)
        for i in 0..<4 {{
            out[i] = v4TagA[i] ^ v4TagB[i]
        }}
        return out
    }}

    static func legacyMagicData() -> Data {{
        var out = Data(count: 10)
        for i in 0..<10 {{
            out[i] = legacyMagicA[i] ^ legacyMagicB[i]
        }}
        return out
    }}

    @inline(never)
    static func _d(_ encoded: [UInt8], mask: UInt8) -> String {{
        var bytes = encoded.map {{ $0 ^ mask }}
        defer {{
            bytes.withUnsafeMutableBytes {{ buf in
                if let base = buf.baseAddress {{
                    p3105_secure_zero(base, buf.count)
                }}
            }}
        }}
        return String(bytes: bytes, encoding: .utf8) ?? ""
    }}
}}
"""
    (workspace / "ThreeOneOSFive" / "helpers" / "GeneratedSecurityConfig.swift").write_text(
        swift_cfg, encoding="utf-8"
    )

    # 6. Swift String Encryption + Whole-Word Symbol Obfuscation across target Swift files
    swift_str_count = 0
    for rel in SWIFT_STRING_TARGET_FILES:
        fpath = workspace / rel
        if fpath.exists():
            orig = fpath.read_text(encoding="utf-8")
            obf, cnt = _obfuscate_swift_strings(orig)
            swift_str_count += cnt
            fpath.write_text(obf, encoding="utf-8")

    swift_sym_map = {name: f"_K{secrets.token_hex(5)}" for name in SWIFT_INTERNAL_SECURITY_TYPES}
    swift_regex = re.compile(r"\b(" + "|".join(re.escape(k) for k in swift_sym_map) + r")\b")
    for sw_file in (workspace / "ThreeOneOSFive").rglob("*.swift"):
        txt = sw_file.read_text(encoding="utf-8")
        new_txt = swift_regex.sub(lambda m: swift_sym_map[m.group(1)], txt)
        if new_txt != txt:
            sw_file.write_text(new_txt, encoding="utf-8")

    # 7. Encrypt ALL bundled .3105 files into V4 (removing plaintext headers)
    packed_files: List[str] = []
    for p3105 in list(workspace.glob("*.3105")) + list((workspace / "ThreeOneOSFive").rglob("*.3105")):
        bid = pack_3105.pack_file(p3105, p3105, b_master, v4_tag)
        packed_files.append(f"{p3105.relative_to(workspace)}:{bid}")

    return {
        "seal_marker_hex": seal_marker.hex(),
        "v4_tag_hex": v4_tag.hex(),
        "c_symbols_renamed": len(c_sym_map),
        "swift_types_renamed": len(swift_sym_map),
        "swift_strings_encrypted": swift_str_count,
        "packed_3105": packed_files,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Obfuscate staging workspace before Xcode/Cargo build")
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--x25519-pub", default=os.environ.get("SEC_SERVER_X25519_PUB", ""))
    parser.add_argument("--ed25519-pub", default=os.environ.get("SEC_SERVER_ED25519_PUB", ""))
    parser.add_argument("--pepper", default=os.environ.get("SEC_PEPPER", ""))
    parser.add_argument("--bundle-master", default=os.environ.get("SEC_BUNDLE_MASTER_KEY", ""))
    parser.add_argument("--spki-primary", default=os.environ.get("SEC_SPKI_PIN_PRIMARY", "") or ("00" * 32))
    parser.add_argument("--spki-backup", default=os.environ.get("SEC_SPKI_PIN_BACKUP", "") or ("00" * 32))
    parser.add_argument("--api-host", default=os.environ.get("SEC_API_HOST", "") or "20-10.store")
    parser.add_argument("--api-path", default=os.environ.get("SEC_API_PATH", "") or "/api/v3")
    parser.add_argument("--non-strict", action="store_true")
    parser.add_argument("--marker-out", type=Path, default=None)
    args = parser.parse_args()

    res = run_obfuscation(
        workspace=args.workspace,
        x25519_pub_hex=args.x25519_pub,
        ed25519_pub_hex=args.ed25519_pub,
        pepper=args.pepper,
        bundle_master_hex=args.bundle_master,
        spki_primary_hex=args.spki_primary,
        spki_backup_hex=args.spki_backup,
        api_host=args.api_host,
        api_path=args.api_path,
        strict=not args.non_strict,
    )
    if args.marker_out:
        args.marker_out.write_text(res["seal_marker_hex"], encoding="utf-8")
    import json

    print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
