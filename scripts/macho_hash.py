#!/usr/bin/env python3
"""
64-bit Mach-O & Universal (FAT) binary parser for computing `__TEXT,__text` SHA-256 hashes
and sealing `libsec_core.dylib`'s `__DATA` section with the post-strip self-integrity hash.
Pure Python standard library (zero external dependencies).
"""

import argparse
import hashlib
import os
import struct
from pathlib import Path
from typing import Optional, Tuple

FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA
MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19
CPU_TYPE_ARM64 = 0x0100000C


def _find_arm64_slice(blob: bytes) -> Tuple[int, int]:
    """Returns (slice_offset, slice_size) for thin or FAT Mach-O favoring ARM64."""
    if len(blob) < 32:
        raise ValueError("File too small to be a Mach-O binary")
    magic_be = struct.unpack_from(">I", blob, 0)[0]
    if magic_be == FAT_MAGIC:
        nfat = struct.unpack_from(">I", blob, 4)[0]
        off = 8
        for _ in range(nfat):
            cputype, _cpusub, offset, size, _align = struct.unpack_from(">iiIII", blob, off)
            if cputype == CPU_TYPE_ARM64:
                return offset, size
            off += 20
        # Fallback to first slice if non-ARM64
        _, _, offset, size, _ = struct.unpack_from(">iiIII", blob, 8)
        return offset, size
    magic_le = struct.unpack_from("<I", blob, 0)[0]
    if magic_le == MH_MAGIC_64:
        return 0, len(blob)
    raise ValueError(f"Unsupported binary magic: 0x{magic_le:08x}")


def _iter_segments_64(blob: bytes, slice_off: int):
    magic, _cputype, _cpusub, _filetype, ncmds, _sizeofcmds, _flags, _res = struct.unpack_from(
        "<IiiIIIII", blob, slice_off
    )
    if magic != MH_MAGIC_64:
        raise ValueError("Not a 64-bit Mach-O slice")
    cmd_off = slice_off + 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", blob, cmd_off)
        if cmd == LC_SEGMENT_64:
            segname_raw, vmaddr, vmsize, fileoff, filesize, _maxp, _initp, nsects, _flags = struct.unpack_from(
                "<16sQQQQiiII", blob, cmd_off + 8
            )
            segname = segname_raw.split(b"\x00", 1)[0].decode("ascii", errors="ignore")
            sections = []
            sect_off = cmd_off + 72
            for _s in range(nsects):
                sname_raw, seg_raw, addr, size, offset, align, reloff, nreloc, flags, r1, r2, r3 = struct.unpack_from(
                    "<16s16sQQIIIIIIII", blob, sect_off
                )
                sname = sname_raw.split(b"\x00", 1)[0].decode("ascii", errors="ignore")
                sections.append((sname, slice_off + offset, size))
                sect_off += 80
            yield segname, slice_off + fileoff, filesize, sections
        cmd_off += cmdsize


def compute_text_sha256(path: Path) -> str:
    """Computes SHA-256 hex digest of the `__TEXT,__text` section of a Mach-O binary."""
    blob = path.read_bytes()
    slice_off, _ = _find_arm64_slice(blob)
    for segname, _seg_off, _seg_sz, sections in _iter_segments_64(blob, slice_off):
        if segname == "__TEXT":
            for sname, s_off, s_size in sections:
                if sname == "__text":
                    return hashlib.sha256(blob[s_off : s_off + s_size]).hexdigest()
    raise ValueError(f"__TEXT,__text section not found in {path}")


def seal_sec_core_dylib(path: Path, marker_hex: str) -> str:
    """
    Computes post-strip `__TEXT,__text` SHA-256 of `libsec_core.dylib`, locates `marker_hex` inside
    `__DATA`, zeroes the marker, and writes `(mask32 || text_hash32 ^ mask32)` right behind it.
    """
    marker = bytes.fromhex(marker_hex)
    if len(marker) != 16:
        raise ValueError("marker_hex must be 16 bytes (32 hex chars)")
    blob = bytearray(path.read_bytes())
    text_hash_hex = compute_text_sha256(path)
    text_hash = bytes.fromhex(text_hash_hex)

    slice_off, _ = _find_arm64_slice(blob)
    found_pos: Optional[int] = None
    for segname, seg_off, seg_sz, _sections in _iter_segments_64(blob, slice_off):
        if segname.startswith("__DATA"):
            pos = blob.find(marker, seg_off, seg_off + seg_sz)
            if pos != -1:
                found_pos = pos
                break
    if found_pos is None:
        raise ValueError("Self-seal marker not found inside __DATA segment of dylib")

    mask = os.urandom(32)
    masked_hash = bytes(h ^ m for h, m in zip(text_hash, mask))
    # Clear marker + write mask32 + masked_hash32 (total 80 bytes = 16 + 32 + 32)
    blob[found_pos : found_pos + 16] = b"\x00" * 16
    blob[found_pos + 16 : found_pos + 48] = mask
    blob[found_pos + 48 : found_pos + 80] = masked_hash
    path.write_bytes(bytes(blob))

    # Re-verify __TEXT hash remained unchanged
    after_hash = compute_text_sha256(path)
    if after_hash != text_hash_hex:
        raise RuntimeError("__TEXT hash shifted unexpectedly after sealing __DATA!")
    return text_hash_hex


def main() -> None:
    parser = argparse.ArgumentParser(description="Mach-O __TEXT hash & self-seal utility")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_hash = sub.add_parser("hash", help="Print __TEXT,__text SHA-256")
    p_hash.add_argument("binary", type=Path)

    p_seal = sub.add_parser("seal", help="Seal libsec_core.dylib __DATA,__sechash post-strip")
    p_seal.add_argument("dylib", type=Path)
    p_seal.add_argument("--marker-hex", required=True)

    args = parser.parse_args()
    if args.cmd == "hash":
        print(compute_text_sha256(args.binary))
    elif args.cmd == "seal":
        h = seal_sec_core_dylib(args.dylib, args.marker_hex)
        print(h)


if __name__ == "__main__":
    main()
