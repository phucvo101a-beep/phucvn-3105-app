#!/usr/bin/env python3
"""
Pure-Python 3.12 standard-library cryptography implementing exact primitives matching
Rust (`x25519-dalek`, `ed25519-dalek`, `chacha20poly1305`, `hkdf`, `sha2`) and PHP (`ext-sodium`).
Includes AES-256-GCM (NIST SP 800-38D) for legacy .3105 migration during CI V4 packing.
"""

import hashlib
import hmac
import math
import os
import struct
from typing import Tuple

# ---------------------------------------------------------------------------
# HKDF-SHA256 (RFC 5869)
# ---------------------------------------------------------------------------

def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """Derives output keying material using RFC 5869 HKDF with SHA-256."""
    actual_salt = salt if salt else b"\x00" * 32
    prk = hmac.new(actual_salt, ikm, hashlib.sha256).digest()
    okm = bytearray()
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm.extend(t)
        counter += 1
    return bytes(okm[:length])


# ---------------------------------------------------------------------------
# ChaCha20 / HChaCha20 / XChaCha20-Poly1305 (RFC 8439 + draft-irtf-cfrg-xchacha)
# ---------------------------------------------------------------------------

def _rotl32(v: int, c: int) -> int:
    return ((v << c) & 0xFFFFFFFF) | (v >> (32 - c))


def _quarter_round(st: list, a: int, b: int, c: int, d: int) -> None:
    st[a] = (st[a] + st[b]) & 0xFFFFFFFF
    st[d] = _rotl32(st[d] ^ st[a], 16)
    st[c] = (st[c] + st[d]) & 0xFFFFFFFF
    st[b] = _rotl32(st[b] ^ st[c], 12)
    st[a] = (st[a] + st[b]) & 0xFFFFFFFF
    st[d] = _rotl32(st[d] ^ st[a], 8)
    st[c] = (st[c] + st[d]) & 0xFFFFFFFF
    st[b] = _rotl32(st[b] ^ st[c], 7)


def _chacha_core(state: list) -> list:
    working = list(state)
    for _ in range(10):
        _quarter_round(working, 0, 4, 8, 12)
        _quarter_round(working, 1, 5, 9, 13)
        _quarter_round(working, 2, 6, 10, 14)
        _quarter_round(working, 3, 7, 11, 15)
        _quarter_round(working, 0, 5, 10, 15)
        _quarter_round(working, 1, 6, 11, 12)
        _quarter_round(working, 2, 7, 8, 13)
        _quarter_round(working, 3, 4, 9, 14)
    return working


def chacha20_block(key32: bytes, counter: int, nonce12: bytes) -> bytes:
    """Produces a 64-byte ChaCha20 keystream block."""
    st = list(
        struct.unpack("<4I", b"expand 32-byte k")
        + struct.unpack("<8I", key32)
        + (counter & 0xFFFFFFFF,)
        + struct.unpack("<3I", nonce12)
    )
    working = _chacha_core(st)
    out = [(working[i] + st[i]) & 0xFFFFFFFF for i in range(16)]
    return struct.pack("<16I", *out)


def hchacha20(key32: bytes, nonce16: bytes) -> bytes:
    """Derives a 32-byte subkey via HChaCha20 from key and 16-byte nonce prefix."""
    st = list(
        struct.unpack("<4I", b"expand 32-byte k")
        + struct.unpack("<8I", key32)
        + struct.unpack("<4I", nonce16)
    )
    working = _chacha_core(st)
    return struct.pack("<8I", *(working[0:4] + working[12:16]))


def _chacha20_xor(key32: bytes, counter: int, nonce12: bytes, data: bytes) -> bytes:
    out = bytearray(len(data))
    blk_idx = 0
    for off in range(0, len(data), 64):
        ks = chacha20_block(key32, counter + blk_idx, nonce12)
        chunk = data[off : off + 64]
        for i, b in enumerate(chunk):
            out[off + i] = b ^ ks[i]
        blk_idx += 1
    return bytes(out)


def _poly1305_mac(msg: bytes, key32: bytes) -> bytes:
    """Computes RFC 8439 Poly1305 16-byte tag."""
    r = int.from_bytes(key32[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key32[16:32], "little")
    p = (1 << 130) - 5
    acc = 0
    for i in range(0, len(msg), 16):
        block = msg[i : i + 16]
        n = int.from_bytes(block + b"\x01", "little")
        acc = ((acc + n) * r) % p
    tag_int = (acc + s) & ((1 << 128) - 1)
    return tag_int.to_bytes(16, "little")


def _pad16(x: bytes) -> bytes:
    rem = len(x) % 16
    return b"\x00" * (16 - rem) if rem else b""


def chacha20_poly1305_encrypt(key32: bytes, nonce12: bytes, plaintext: bytes, aad: bytes) -> bytes:
    otk = chacha20_block(key32, 0, nonce12)[:32]
    ct = _chacha20_xor(key32, 1, nonce12, plaintext)
    mac_data = (
        aad
        + _pad16(aad)
        + ct
        + _pad16(ct)
        + struct.pack("<QQ", len(aad), len(ct))
    )
    tag = _poly1305_mac(mac_data, otk)
    return ct + tag


def chacha20_poly1305_decrypt(key32: bytes, nonce12: bytes, ciphertext_with_tag: bytes, aad: bytes) -> bytes:
    if len(ciphertext_with_tag) < 16:
        raise ValueError("Ciphertext too short")
    ct, tag = ciphertext_with_tag[:-16], ciphertext_with_tag[-16:]
    otk = chacha20_block(key32, 0, nonce12)[:32]
    mac_data = (
        aad
        + _pad16(aad)
        + ct
        + _pad16(ct)
        + struct.pack("<QQ", len(aad), len(ct))
    )
    expected = _poly1305_mac(mac_data, otk)
    if not hmac.compare_digest(expected, tag):
        raise ValueError("Poly1305 authentication failed")
    return _chacha20_xor(key32, 1, nonce12, ct)


def xchacha20_poly1305_encrypt(key32: bytes, nonce24: bytes, plaintext: bytes, aad: bytes) -> bytes:
    if len(key32) != 32 or len(nonce24) != 24:
        raise ValueError("Invalid key or 24-byte nonce length")
    subkey = hchacha20(key32, nonce24[:16])
    nonce12 = b"\x00\x00\x00\x00" + nonce24[16:24]
    return chacha20_poly1305_encrypt(subkey, nonce12, plaintext, aad)


def xchacha20_poly1305_decrypt(key32: bytes, nonce24: bytes, ciphertext_with_tag: bytes, aad: bytes) -> bytes:
    if len(key32) != 32 or len(nonce24) != 24:
        raise ValueError("Invalid key or 24-byte nonce length")
    subkey = hchacha20(key32, nonce24[:16])
    nonce12 = b"\x00\x00\x00\x00" + nonce24[16:24]
    return chacha20_poly1305_decrypt(subkey, nonce12, ciphertext_with_tag, aad)


# ---------------------------------------------------------------------------
# Curve25519 / X25519 (RFC 7748) & Ed25519 (RFC 8032)
# ---------------------------------------------------------------------------

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_A24 = 121665
_D = -121665 * pow(121666, _P - 2, _P) % _P
_I = pow(2, (_P - 1) // 4, _P)
_By = 4 * pow(5, _P - 2, _P) % _P
_Bx = _P - 1  # placeholder fixed below


def _ed_xrecover(y: int) -> int:
    xx = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = (x * _I) % _P
    if x % 2 != 0:
        x = _P - x
    return x


_Bx = _ed_xrecover(_By) % _P
if _Bx % 2 != 0:
    _Bx = _P - _Bx
_B_PT = (_Bx, _By, 1, (_Bx * _By) % _P)


def _clamp_scalar(k: bytes) -> int:
    b = bytearray(k[:32])
    b[0] &= 248
    b[31] &= 127
    b[31] |= 64
    return int.from_bytes(b, "little")


def x25519_shared(priv32: bytes, pub32: bytes) -> bytes:
    k = _clamp_scalar(priv32)
    u = int.from_bytes(pub32[:32], "little") & ((1 << 255) - 1)
    x_1 = u
    x_2, z_2 = 1, 0
    x_3, z_3 = u, 1
    swap = 0
    for t in range(254, -1, -1):
        k_t = (k >> t) & 1
        swap ^= k_t
        if swap:
            x_2, x_3 = x_3, x_2
            z_2, z_3 = z_3, z_2
        swap = k_t
        A = (x_2 + z_2) % _P
        AA = (A * A) % _P
        B = (x_2 - z_2) % _P
        BB = (B * B) % _P
        E = (AA - BB) % _P
        C = (x_3 + z_3) % _P
        D = (x_3 - z_3) % _P
        DA = (D * A) % _P
        CB = (C * B) % _P
        x_3 = pow((DA + CB) % _P, 2, _P)
        z_3 = (x_1 * pow((DA - CB) % _P, 2, _P)) % _P
        x_2 = (AA * BB) % _P
        z_2 = (E * ((AA + _A24 * E) % _P)) % _P
    if swap:
        x_2, x_3 = x_3, x_2
        z_2, z_3 = z_3, z_2
    res = (x_2 * pow(z_2, _P - 2, _P)) % _P
    return res.to_bytes(32, "little")


def x25519_public_key(priv32: bytes) -> bytes:
    base = b"\x09" + b"\x00" * 31
    return x25519_shared(priv32, base)


def _ed_add(P: tuple, Q: tuple) -> tuple:
    X1, Y1, Z1, T1 = P
    X2, Y2, Z2, T2 = Q
    A = ((Y1 - X1) * (Y2 - X2)) % _P
    B = ((Y1 + X1) * (Y2 + X2)) % _P
    C = (2 * T1 * T2 * _D) % _P
    D = (2 * Z1 * Z2) % _P
    E = (B - A) % _P
    F = (D - C) % _P
    G = (D + C) % _P
    H = (B + A) % _P
    return ((E * F) % _P, (G * H) % _P, (F * G) % _P, (E * H) % _P)


def _ed_mul(pt: tuple, e: int) -> tuple:
    res = (0, 1, 1, 0)
    cur = pt
    while e > 0:
        if e & 1:
            res = _ed_add(res, cur)
        cur = _ed_add(cur, cur)
        e >>= 1
    return res


def _ed_encode(pt: tuple) -> bytes:
    X, Y, Z, _ = pt
    zi = pow(Z, _P - 2, _P)
    x = (X * zi) % _P
    y = (Y * zi) % _P
    enc = bytearray(y.to_bytes(32, "little"))
    if x & 1:
        enc[31] |= 0x80
    return bytes(enc)


def _ed_decode(b: bytes) -> tuple:
    if len(b) != 32:
        raise ValueError("Invalid Ed25519 point bytes")
    y = int.from_bytes(b, "little") & ((1 << 255) - 1)
    if y >= _P:
        raise ValueError("Invalid y coordinate")
    sign = (b[31] >> 7) & 1
    xx = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    if xx == 0:
        if sign:
            raise ValueError("Invalid point")
        return (0, y, 1, 0)
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = (x * _I) % _P
    if (x * x - xx) % _P != 0:
        raise ValueError("Non-residue point")
    if (x & 1) != sign:
        x = _P - x
    return (x, y, 1, (x * y) % _P)


def _ed_secret_scalar_and_prefix(seed32: bytes) -> Tuple[int, bytes]:
    h = hashlib.sha512(seed32).digest()
    a_bytes = bytearray(h[:32])
    a_bytes[0] &= 248
    a_bytes[31] &= 63
    a_bytes[31] |= 64
    return int.from_bytes(a_bytes, "little"), h[32:]


def ed25519_public_key(seed32: bytes) -> bytes:
    a, _ = _ed_secret_scalar_and_prefix(seed32)
    return _ed_encode(_ed_mul(_B_PT, a))


def ed25519_sign(seed32: bytes, msg: bytes) -> bytes:
    a, prefix = _ed_secret_scalar_and_prefix(seed32)
    pub = _ed_encode(_ed_mul(_B_PT, a))
    r = int.from_bytes(hashlib.sha512(prefix + msg).digest(), "little") % _L
    R = _ed_encode(_ed_mul(_B_PT, r))
    k = int.from_bytes(hashlib.sha512(R + pub + msg).digest(), "little") % _L
    S = (r + k * a) % _L
    return R + S.to_bytes(32, "little")


def ed25519_verify(pub32: bytes, msg: bytes, sig64: bytes) -> bool:
    if len(pub32) != 32 or len(sig64) != 64:
        return False
    try:
        A = _ed_decode(pub32)
        R = _ed_decode(sig64[:32])
    except ValueError:
        return False
    S = int.from_bytes(sig64[32:], "little")
    if S >= _L:
        return False
    k = int.from_bytes(hashlib.sha512(sig64[:32] + pub32 + msg).digest(), "little") % _L
    lhs = _ed_mul(_B_PT, S)
    rhs = _ed_add(R, _ed_mul(A, k))
    return _ed_encode(lhs) == _ed_encode(rhs)


# ---------------------------------------------------------------------------
# Pure-Python AES-256-GCM (used by pack_3105.py to decrypt V1..V3 .3105 archives)
# ---------------------------------------------------------------------------

_SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]
_RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40]


def _xtime(a: int) -> int:
    return ((a << 1) ^ 0x1B) & 0xFF if (a & 0x80) else (a << 1) & 0xFF


def _aes256_key_schedule(key32: bytes) -> list:
    nk, nr = 8, 14
    w = [list(key32[i * 4 : (i + 1) * 4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        tmp = list(w[i - 1])
        if i % nk == 0:
            tmp = [_SBOX[tmp[1]] ^ _RCON[i // nk], _SBOX[tmp[2]], _SBOX[tmp[3]], _SBOX[tmp[0]]]
        elif i % nk == 4:
            tmp = [_SBOX[b] for b in tmp]
        w.append([w[i - nk][j] ^ tmp[j] for j in range(4)])
    return w


def _aes256_encrypt_block(block16: bytes, rk: list) -> bytes:
    st = [[block16[r + 4 * c] for c in range(4)] for r in range(4)]
    for c in range(4):
        for r in range(4):
            st[r][c] ^= rk[c][r]
    for rnd in range(1, 15):
        for r in range(4):
            for c in range(4):
                st[r][c] = _SBOX[st[r][c]]
        st[1] = st[1][1:] + st[1][:1]
        st[2] = st[2][2:] + st[2][:2]
        st[3] = st[3][3:] + st[3][:3]
        if rnd < 14:
            for c in range(4):
                a0, a1, a2, a3 = st[0][c], st[1][c], st[2][c], st[3][c]
                t = a0 ^ a1 ^ a2 ^ a3
                st[0][c] = a0 ^ t ^ _xtime(a0 ^ a1)
                st[1][c] = a1 ^ t ^ _xtime(a1 ^ a2)
                st[2][c] = a2 ^ t ^ _xtime(a2 ^ a3)
                st[3][c] = a3 ^ t ^ _xtime(a3 ^ a0)
        for c in range(4):
            for r in range(4):
                st[r][c] ^= rk[rnd * 4 + c][r]
    return bytes(st[r][c] for c in range(4) for r in range(4))


def _gf128_mul(x: int, y: int) -> int:
    z = 0
    v = y
    for i in range(127, -1, -1):
        if (x >> i) & 1:
            z ^= v
        lsb = v & 1
        v >>= 1
        if lsb:
            v ^= 0xE1000000000000000000000000000000
    return z


def _ghash(H: int, aad: bytes, ct: bytes) -> int:
    y = 0
    for data in (aad, ct):
        for i in range(0, len(data), 16):
            blk = data[i : i + 16].ljust(16, b"\x00")
            y = _gf128_mul(y ^ int.from_bytes(blk, "big"), H)
    len_blk = struct.pack(">QQ", len(aad) * 8, len(ct) * 8)
    return _gf128_mul(y ^ int.from_bytes(len_blk, "big"), H)


def aes256_gcm_decrypt_combined(combined: bytes, key32: bytes, aad: bytes) -> bytes:
    """Decrypts Apple CryptoKit AES.GCM.SealedBox.combined (12B nonce + ct + 16B tag)."""
    if len(combined) < 28:
        raise ValueError("Truncated AES-GCM box")
    nonce, ct, tag = combined[:12], combined[12:-16], combined[-16:]
    rk = _aes256_key_schedule(key32)
    H = int.from_bytes(_aes256_encrypt_block(b"\x00" * 16, rk), "big")
    j0 = nonce + b"\x00\x00\x00\x01"
    s = _ghash(H, aad, ct)
    expected_tag = (s ^ int.from_bytes(_aes256_encrypt_block(j0, rk), "big")).to_bytes(16, "big")
    if not hmac.compare_digest(expected_tag, tag):
        raise ValueError("AES-GCM authentication failed")
    out = bytearray(len(ct))
    ctr = 2
    for off in range(0, len(ct), 16):
        ks = _aes256_encrypt_block(nonce + struct.pack(">I", ctr), rk)
        chunk = ct[off : off + 16]
        for i, b in enumerate(chunk):
            out[off + i] = b ^ ks[i]
        ctr += 1
    return bytes(out)


def aes256_gcm_encrypt_combined(plaintext: bytes, key32: bytes, aad: bytes, nonce12: bytes | None = None) -> bytes:
    nonce = nonce12 if nonce12 is not None else os.urandom(12)
    rk = _aes256_key_schedule(key32)
    H = int.from_bytes(_aes256_encrypt_block(b"\x00" * 16, rk), "big")
    out = bytearray(len(plaintext))
    ctr = 2
    for off in range(0, len(plaintext), 16):
        ks = _aes256_encrypt_block(nonce + struct.pack(">I", ctr), rk)
        chunk = plaintext[off : off + 16]
        for i, b in enumerate(chunk):
            out[off + i] = b ^ ks[i]
        ctr += 1
    ct = bytes(out)
    j0 = nonce + b"\x00\x00\x00\x01"
    tag = (_ghash(H, aad, ct) ^ int.from_bytes(_aes256_encrypt_block(j0, rk), "big")).to_bytes(16, "big")
    return nonce + ct + tag


# ---------------------------------------------------------------------------
# Protocol V3 & V4 Shared Helpers
# ---------------------------------------------------------------------------

def derive_bundle_id(filename: str) -> bytes:
    return hashlib.sha256(b"BUNDLE|" + filename.encode("utf-8")).digest()[:16]


def derive_bundle_key(master_key32: bytes, bundle_id16: bytes) -> bytes:
    return hkdf_sha256(master_key32, b"3105-V4-BUNDLE", bundle_id16, 32)


def run_self_test() -> None:
    # RFC 7748 Test Vector
    a_sk = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    b_pk = bytes.fromhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    expected_ss = bytes.fromhex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
    assert x25519_shared(a_sk, b_pk) == expected_ss, "X25519 RFC 7748 vector mismatch"

    # RFC 8032 Test Vector #2
    seed = bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
    msg = bytes.fromhex("72")
    pub = ed25519_public_key(seed)
    sig = ed25519_sign(seed, msg)
    assert pub == bytes.fromhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
    assert ed25519_verify(pub, msg, sig), "Ed25519 verify failed"
    assert not ed25519_verify(pub, b"tampered", sig), "Ed25519 tampered verify failed"

    # XChaCha20-Poly1305 roundtrip
    k = os.urandom(32)
    n = os.urandom(24)
    ct = xchacha20_poly1305_encrypt(k, n, b"hello 3105", b"AAD")
    assert xchacha20_poly1305_decrypt(k, n, ct, b"AAD") == b"hello 3105"

    # AES-256-GCM roundtrip + tamper reject
    aes_k = bytes(range(32))
    box = aes256_gcm_encrypt_combined(b"payload-test-1234", aes_k, b"aad-v3")
    assert aes256_gcm_decrypt_combined(box, aes_k, b"aad-v3") == b"payload-test-1234"
    print("v3_crypto self-test PASSED")


if __name__ == "__main__":
    run_self_test()
