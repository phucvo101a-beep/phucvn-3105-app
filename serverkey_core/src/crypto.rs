use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::{Signer, SigningKey};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};
use zeroize::{Zeroize, Zeroizing};

/// Pure RFC 2104 HMAC-SHA256 helper (avoids hmac crate trait mismatch).
pub fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut k_block = [0u8; 64];
    if key.len() > 64 {
        let h = Sha256::digest(key);
        k_block[..32].copy_from_slice(&h);
    } else {
        k_block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k_block[i];
        opad[i] ^= k_block[i];
    }
    let mut inner = Sha256::new();
    inner.update(&ipad);
    for p in parts {
        inner.update(p);
    }
    let inner_hash = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&inner_hash);
    let digest = outer.finalize();
    k_block.zeroize();
    ipad.zeroize();
    opad.zeroize();
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_slice());
    out
}

/// Official 3105 bundled preset filenames mapped deterministically to V4 bundle IDs.
pub const BUNDLED_PRESET_FILENAMES: &[&str] = &[
    "AIM BODY FFVN (1).3105",
    "Aim_Neck_PhucVN_FFVN.3105",
    "AimDrag_85_Antena_PhucVN_FFVN.3105",
    "AimDrag_85_PhucVN_FFVN.3105",
    "AimNeck_Antena_PhucVN_FFVN.3105",
    "Antena_PhucVN_FFVN.3105",
    "DinhVi_Chams_PhucVN_FFVN.3105",
    "DinhVi_Sung_PhucVN_FFVN.3105",
];

/// Cryptographic keys held in memory by the server engine.
#[derive(Clone)]
pub struct ServerKeyMaterial {
    pub x25519_priv: Zeroizing<[u8; 32]>,
    pub ed25519_priv: Zeroizing<[u8; 32]>,
    pub pepper: Zeroizing<Vec<u8>>,
    pub bundle_master_key: Zeroizing<[u8; 32]>,
    pub ci_sync_secret: Zeroizing<Vec<u8>>,
    pub internal_ipc_secret: Zeroizing<Vec<u8>>,
}

impl ServerKeyMaterial {
    /// Parses required secrets from a key/value environment map.
    pub fn from_env_map(env: &std::collections::HashMap<String, String>) -> Result<Self, String> {
        let x25519_hex = env
            .get("SERVER_X25519_PRIV_HEX")
            .ok_or("Missing SERVER_X25519_PRIV_HEX")?;
        let ed25519_hex = env
            .get("SERVER_ED25519_PRIV_HEX")
            .ok_or("Missing SERVER_ED25519_PRIV_HEX")?;
        let pepper_str = env
            .get("PRE_SHARED_PEPPER")
            .ok_or("Missing PRE_SHARED_PEPPER")?;
        let bundle_hex = env
            .get("BUNDLE_PATCH_MASTER_KEY_HEX")
            .ok_or("Missing BUNDLE_PATCH_MASTER_KEY_HEX")?;
        let ci_secret = env.get("CI_SYNC_SECRET").cloned().unwrap_or_default();
        let ipc_secret = env
            .get("RUST_CORE_IPC_SECRET")
            .cloned()
            .unwrap_or_default();

        Ok(Self {
            x25519_priv: Zeroizing::new(decode_hex_32(x25519_hex, "SERVER_X25519_PRIV_HEX")?),
            ed25519_priv: Zeroizing::new(decode_hex_32(ed25519_hex, "SERVER_ED25519_PRIV_HEX")?),
            pepper: Zeroizing::new(pepper_str.as_bytes().to_vec()),
            bundle_master_key: Zeroizing::new(decode_hex_32(
                bundle_hex,
                "BUNDLE_PATCH_MASTER_KEY_HEX",
            )?),
            ci_sync_secret: Zeroizing::new(ci_secret.into_bytes()),
            internal_ipc_secret: Zeroizing::new(ipc_secret.into_bytes()),
        })
    }
}

pub fn decode_hex_32(hex_str: &str, name: &str) -> Result<[u8; 32], String> {
    let raw = hex::decode(hex_str.trim()).map_err(|_| format!("Invalid hex for {name}"))?;
    if raw.len() != 32 {
        return Err(format!("{name} must be 32 bytes"));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

pub fn decode_hex_24(hex_str: &str, name: &str) -> Result<[u8; 24], String> {
    let raw = hex::decode(hex_str.trim()).map_err(|_| format!("Invalid hex for {name}"))?;
    if raw.len() != 24 {
        return Err(format!("{name} must be 24 bytes"));
    }
    let mut out = [0u8; 24];
    out.copy_from_slice(&raw);
    Ok(out)
}

pub fn random_nonce_24() -> ([u8; 24], String) {
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    (nonce, hex::encode(nonce))
}

/// Builds deterministic AAD string for V3 client requests.
pub fn build_req_aad(
    v: u32,
    op: &str,
    pkg: &str,
    ver: &str,
    bld: &str,
    fp: &str,
    nonce_hex: &str,
    ts: i64,
) -> String {
    format!("V3REQ|{v}|{op}|{pkg}|{ver}|{bld}|{fp}|{nonce_hex}|{ts}")
}

/// Builds deterministic AAD string for V3 server responses.
pub fn build_res_aad(
    op: &str,
    pkg: &str,
    ver: &str,
    fp: &str,
    req_nonce_hex: &str,
    s_nonce_hex: &str,
    s_ts: i64,
    code: &str,
) -> String {
    format!("V3RES|3|{op}|{pkg}|{ver}|{fp}|{req_nonce_hex}|{s_nonce_hex}|{s_ts}|{code}")
}

/// Computes shared ECDH secret between server static X25519 private key and client ephemeral public key.
pub fn compute_shared_secret(
    server_priv: &[u8; 32],
    client_pub_bytes: &[u8; 32],
) -> Zeroizing<[u8; 32]> {
    let mut priv_copy = *server_priv;
    let secret = X25519Secret::from(priv_copy);
    priv_copy.zeroize();
    let client_pub = X25519Public::from(*client_pub_bytes);
    Zeroizing::new(*secret.diffie_hellman(&client_pub).as_bytes())
}

/// Derives 32-byte symmetric request/response AEAD key via HKDF-SHA256.
pub fn derive_v3_key(
    shared: &[u8; 32],
    pepper: &[u8],
    info: &[u8],
) -> Result<Zeroizing<[u8; 32]>, String> {
    let hk = Hkdf::<Sha256>::new(Some(pepper), shared);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(info, okm.as_mut())
        .map_err(|_| "HKDF expand failed".to_string())?;
    Ok(okm)
}

/// Decrypts V3 request ciphertext with XChaCha20-Poly1305 and strict REQ_AAD.
pub fn decrypt_request_v3(
    key: &[u8; 32],
    nonce24: &[u8; 24],
    aad: &str,
    ct_b64: &str,
) -> Result<Vec<u8>, String> {
    let ct = B64
        .decode(ct_b64.trim())
        .map_err(|_| "Malformed base64 ciphertext".to_string())?;
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| "AEAD key length error".to_string())?;
    cipher
        .decrypt(
            XNonce::from_slice(nonce24),
            Payload {
                msg: &ct,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| "AEAD request authentication failed".to_string())
}

/// Verifies client HMAC proof tying REQ_AAD and optional key material to PRE_SHARED_PEPPER.
pub fn verify_client_proof(
    pepper: &[u8],
    req_aad: &str,
    license_key: &str,
    provided_hex: &str,
) -> bool {
    let Ok(provided) = hex::decode(provided_hex.trim()) else {
        return false;
    };
    let expected = hmac_sha256(pepper, &[req_aad.as_bytes(), b"|", license_key.as_bytes()]);
    provided.len() == expected.len() && bool::from(provided.as_slice().ct_eq(&expected[..]))
}

/// Encrypts response JSON with caller-supplied s_nonce24 and signs RES_AAD || "|" || sha256(ct) with Ed25519.
pub fn seal_and_sign_response_v3(
    keys: &ServerKeyMaterial,
    shared: &[u8; 32],
    req_nonce24: &[u8; 24],
    s_nonce24: &[u8; 24],
    res_aad: &str,
    plaintext_json: &[u8],
) -> Result<(String, String), String> {
    let mut info = Vec::with_capacity(12 + 24);
    info.extend_from_slice(b"3105-V3-RES|");
    info.extend_from_slice(req_nonce24);
    let res_key = derive_v3_key(shared, &keys.pepper, &info)?;

    let cipher = XChaCha20Poly1305::new_from_slice(&*res_key)
        .map_err(|_| "AEAD key length error".to_string())?;
    let ct = cipher
        .encrypt(
            XNonce::from_slice(s_nonce24),
            Payload {
                msg: plaintext_json,
                aad: res_aad.as_bytes(),
            },
        )
        .map_err(|_| "Response AEAD encrypt failed".to_string())?;

    let ct_hash = Sha256::digest(&ct);
    let mut sig_msg = Vec::with_capacity(12 + res_aad.len() + 1 + 32);
    sig_msg.extend_from_slice(b"3105-V3-SIG|");
    sig_msg.extend_from_slice(res_aad.as_bytes());
    sig_msg.push(b'|');
    sig_msg.extend_from_slice(&ct_hash);

    let mut ed_bytes = *keys.ed25519_priv;
    let signing_key = SigningKey::from_bytes(&ed_bytes);
    ed_bytes.zeroize();
    let signature = signing_key.sign(&sig_msg);

    Ok((B64.encode(&ct), hex::encode(signature.to_bytes())))
}

/// Derives deterministic 16-byte bundle ID hex (32 chars) from a preset filename.
pub fn derive_bundle_id_hex(filename: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"BUNDLE|");
    hasher.update(filename.as_bytes());
    let digest = hasher.finalize();
    hex::encode(&digest[..16])
}

/// Derives per-bundle V4 decryption key from BUNDLE_PATCH_MASTER_KEY via HKDF-SHA256.
pub fn derive_bundle_key_hex(
    master_key: &[u8; 32],
    bundle_id_hex: &str,
) -> Result<String, String> {
    let id_bytes = hex::decode(bundle_id_hex).map_err(|_| "Invalid bundle_id hex".to_string())?;
    let hk = Hkdf::<Sha256>::new(Some(b"3105-V4-BUNDLE"), master_key);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(&id_bytes, out.as_mut())
        .map_err(|_| "Bundle HKDF failed".to_string())?;
    Ok(hex::encode(&*out))
}

/// Derives map of all bundled V4 keys for authorized sessions.
pub fn derive_all_bundle_keys(
    master_key: &[u8; 32],
) -> Result<std::collections::BTreeMap<String, String>, String> {
    let mut map = std::collections::BTreeMap::new();
    for &fname in BUNDLED_PRESET_FILENAMES {
        let bid = derive_bundle_id_hex(fname);
        let bkey = derive_bundle_key_hex(master_key, &bid)?;
        map.insert(bid, bkey);
    }
    Ok(map)
}

/// Generates random 32-byte hex secret (e.g. ephemeral session key or nonce).
pub fn random_hex_32() -> String {
    let mut buf = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(buf.as_mut());
    hex::encode(&*buf)
}

/// Verifies CI HMAC signature for build hash manifest synchronization.
pub fn verify_hmac_hex(secret: &[u8], payload: &[u8], sig_hex: &str) -> bool {
    if secret.is_empty() {
        return false;
    }
    let Ok(provided) = hex::decode(sig_hex.trim()) else {
        return false;
    };
    let expected = hmac_sha256(secret, &[payload]);
    provided.len() == expected.len() && bool::from(provided.as_slice().ct_eq(&expected[..]))
}

/// Computes SHA-256 hex digest of UTF-8 input.
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}
