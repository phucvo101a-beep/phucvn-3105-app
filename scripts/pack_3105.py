#!/usr/bin/env python3
"""
V4 Encrypted Asset Packer for `.3105` patch packages.
Converts legacy V1-V3 `.3105` archives into chunked XChaCha20-Poly1305 containers
with zero plaintext headers (`3105PATCH`, `bplist00`) or embedded keys.
Requires server-derived `BUNDLE_PATCH_MASTER_KEY` (via HKDF per-bundle key) to open in RAM.
"""

import argparse
import base64
import datetime
import hashlib
import json
import os
import plistlib
import struct
import uuid
from pathlib import Path
from typing import Dict, Tuple

import v3_crypto

DEFAULT_CHUNK_SIZE = 65536


def _json_safe(value):
    if isinstance(value, bytes):
        return base64.b64encode(value).decode("ascii")
    if isinstance(value, datetime.datetime):
        dt = value if value.tzinfo is not None else value.replace(tzinfo=datetime.timezone.utc)
        return dt.timestamp()
    if isinstance(value, uuid.UUID):
        return str(value).upper()
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_json_safe(v) for v in value]
    return value


def decode_legacy_3105(raw: bytes) -> Dict:
    """Decrypts a V1-V3 `.3105` unpassworded binary plist into normalized JSON-ready dict."""
    idx = raw.find(b"bplist00")
    if idx == -1 or idx > 32:
        raise ValueError("Not a legacy bplist00 .3105 archive")
    env = plistlib.loads(raw[idx:])
    pkg_id = env["packageID"]
    if isinstance(pkg_id, bytes):
        pkg_id = str(uuid.UUID(bytes=pkg_id)).upper()
    else:
        pkg_id = str(pkg_id).upper()
    content_key = env.get("publicContentKey")
    if not content_key or len(content_key) != 32:
        raise ValueError("Missing publicContentKey in legacy archive")

    ver = int(env.get("schemaVersion", 1))
    ct = env["encryptedPayload"]
    plaintext = None
    for candidate_ver in (ver, 3, 2, 1):
        aad = f"3105PATCH/v{candidate_ver}/payload/{pkg_id}".encode("utf-8")
        try:
            plaintext = v3_crypto.aes256_gcm_decrypt_combined(ct, content_key, aad)
            break
        except ValueError:
            continue
    if plaintext is None:
        plaintext = v3_crypto.aes256_gcm_decrypt_combined(ct, content_key, b"")

    obj = plistlib.loads(plaintext)
    if "project" in obj:
        proj = obj["project"]
        digests = obj.get("replacementDigests", {})
    else:
        proj = obj
        digests = {}

    proj["isPrivate"] = True
    for rule in proj.get("rules", []):
        rid = str(rule["id"]).upper()
        if rid not in digests:
            digests[rid] = hashlib.sha256(rule.get("replacementData", b"")).digest()

    return _json_safe({"project": proj, "replacementDigests": digests})


def pack_v4_bytes(
    payload_json_bytes: bytes,
    bundle_name: str,
    master_key32: bytes,
    tag4: bytes = b"\x9d\x7a\x41\xe3",
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> Tuple[bytes, str]:
    """Packs plaintext JSON payload into chunked XChaCha20-Poly1305 V4 container."""
    if len(tag4) != 4 or len(master_key32) != 32:
        raise ValueError("Invalid V4 tag or master key length")

    bundle_id = v3_crypto.derive_bundle_id(bundle_name)
    bundle_id_hex = bundle_id.hex()
    bundle_key = v3_crypto.derive_bundle_key(master_key32, bundle_id)
    base_nonce = os.urandom(24)

    chunks = [
        payload_json_bytes[i : i + chunk_size]
        for i in range(0, max(1, len(payload_json_bytes)), chunk_size)
    ]
    out = bytearray()
    out.extend(tag4)
    out.extend(bundle_id)
    out.extend(struct.pack("<I", len(chunks)))
    out.extend(base_nonce)

    tag_hex = tag4.hex()
    for idx, pt_chunk in enumerate(chunks):
        c_nonce = bytearray(base_nonce)
        c_nonce[20] ^= idx & 0xFF
        c_nonce[21] ^= (idx >> 8) & 0xFF
        c_nonce[22] ^= (idx >> 16) & 0xFF
        c_nonce[23] ^= (idx >> 24) & 0xFF
        aad = f"V4C|{bundle_id_hex}|{idx}|{tag_hex}".encode("utf-8")
        ct_chunk = v3_crypto.xchacha20_poly1305_encrypt(bundle_key, bytes(c_nonce), pt_chunk, aad)
        out.extend(struct.pack("<I", len(ct_chunk)))
        out.extend(ct_chunk)

    return bytes(out), bundle_id_hex


def unpack_v4_bytes(
    container: bytes,
    bundle_key32: bytes,
    expected_tag4: bytes = b"\x9d\x7a\x41\xe3",
) -> bytes:
    """Decrypts a V4 `.3105` container chunk-by-chunk using its 32-byte bundle_key."""
    if len(container) < 48 or container[:4] != expected_tag4:
        raise ValueError("Invalid V4 tag or truncated header")
    bundle_id = container[4:20]
    chunk_count = struct.unpack_from("<I", container, 20)[0]
    base_nonce = container[24:48]
    bundle_id_hex = bundle_id.hex()
    tag_hex = expected_tag4.hex()

    pos = 48
    out = bytearray()
    for idx in range(chunk_count):
        ct_len = struct.unpack_from("<I", container, pos)[0]
        pos += 4
        ct_chunk = container[pos : pos + ct_len]
        pos += ct_len
        c_nonce = bytearray(base_nonce)
        c_nonce[20] ^= idx & 0xFF
        c_nonce[21] ^= (idx >> 8) & 0xFF
        c_nonce[22] ^= (idx >> 16) & 0xFF
        c_nonce[23] ^= (idx >> 24) & 0xFF
        aad = f"V4C|{bundle_id_hex}|{idx}|{tag_hex}".encode("utf-8")
        out.extend(v3_crypto.xchacha20_poly1305_decrypt(bundle_key32, bytes(c_nonce), ct_chunk, aad))
    return bytes(out)


def pack_file(src: Path, dst: Path, master_key32: bytes, tag4: bytes) -> str:
    raw = src.read_bytes()
    # Skip if already V4 packed
    if len(raw) >= 48 and raw[:4] == tag4:
        dst.write_bytes(raw)
        return raw[4:20].hex()
    payload_obj = decode_legacy_3105(raw)
    payload_bytes = json.dumps(payload_obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    v4_bytes, bid_hex = pack_v4_bytes(payload_bytes, src.name, master_key32, tag4=tag4)
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(v4_bytes)
    return bid_hex


def main() -> None:
    parser = argparse.ArgumentParser(description="Pack .3105 assets into encrypted V4 format")
    parser.add_argument("--master-key-hex", required=True)
    parser.add_argument("--tag-hex", default="9d7a41e3")
    parser.add_argument("files", nargs="+", type=Path)
    args = parser.parse_args()

    master_key = bytes.fromhex(args.master_key_hex.strip())
    tag4 = bytes.fromhex(args.tag_hex.strip())
    for path in args.files:
        if path.is_file() and path.suffix == ".3105":
            bid = pack_file(path, path, master_key, tag4)
            print(f"Packed V4: {path.name} -> bundle_id={bid} ({path.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
