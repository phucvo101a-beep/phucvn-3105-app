use crate::secrets;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hkdf::Hkdf;
use obfstr::obfstr;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

/// Computes RFC 2104 HMAC-SHA256 cleanly without trait resolution ambiguity.
pub fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut k_block = Zeroizing::new([0u8; 64]);
    if key.len() > 64 {
        let digest = Sha256::digest(key);
        k_block[..32].copy_from_slice(&digest);
    } else {
        k_block[..key.len()].copy_from_slice(key);
    }
    let mut i_pad = Zeroizing::new([0x36u8; 64]);
    let mut o_pad = Zeroizing::new([0x5Cu8; 64]);
    for i in 0..64 {
        i_pad[i] ^= k_block[i];
        o_pad[i] ^= k_block[i];
    }
    let mut inner = Sha256::new();
    inner.update(&*i_pad);
    for p in parts {
        inner.update(p);
    }
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(&*o_pad);
    outer.update(inner_hash);
    let out_digest = outer.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&out_digest);
    out
}

#[derive(Debug, Deserialize)]
pub struct OuterV3Response {
    pub v: u32,
    pub op: String,
    pub pkg: String,
    pub ver: String,
    pub fp: String,
    pub req_nonce: String,
    pub s_nonce: String,
    pub s_ts: i64,
    pub code: String,
    pub ct: String,
    pub sig: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LicenseInfo {
    #[serde(default)]
    pub valid: bool,
    #[serde(default)]
    pub key_masked: String,
    #[serde(default)]
    pub expiry: String,
    #[serde(default)]
    pub expiry_ts: i64,
    #[serde(default)]
    pub remaining_seconds: i64,
    #[serde(default)]
    pub is_permanent: bool,
    #[serde(default)]
    pub role: String,
    #[serde(default)]
    pub used_devices: usize,
    #[serde(default)]
    pub max_devices: u32,
}

#[derive(Debug, Deserialize)]
pub struct DecryptedV3Payload {
    pub status: String,
    pub code: String,
    pub op: String,
    pub server_open: bool,
    pub force_update: bool,
    pub min_version: String,
    pub latest_version: String,
    pub download_url: String,
    pub message: String,
    pub req_nonce: String,
    pub s_nonce: String,
    pub s_ts: i64,
    pub ephemeral_session_key: Option<String>,
    pub session_token: Option<String>,
    #[serde(default)]
    pub bundle_keys: BTreeMap<String, String>,
    #[serde(default)]
    pub license: LicenseInfo,
}

pub struct EncryptedExchangePacket {
    pub outer_json: String,
    pub shared_secret: Zeroizing<[u8; 32]>,
    pub req_nonce_hex: String,
    pub req_nonce_bytes: [u8; 24],
    pub op: String,
    pub pkg: String,
    pub ver: String,
    pub fp: String,
}

pub fn now_unix_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Builds signed, AAD-bound V3 encrypted request using ephemeral X25519 ECDH + HKDF-SHA256 + XChaCha20-Poly1305.
pub fn build_v3_request(
    op: &str,
    pkg: &str,
    ver: &str,
    bld: &str,
    fp: &str,
    app_hash: &str,
    sec_hash: &str,
    tamper_flags: u32,
    license_key: &str,
) -> Result<EncryptedExchangePacket, String> {
    let mut c_priv_bytes = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(c_priv_bytes.as_mut());
    let c_priv = x25519_dalek::StaticSecret::from(*c_priv_bytes);
    let c_pub = x25519_dalek::PublicKey::from(&c_priv);

    let s_pub_bytes = secrets::server_x25519_pub();
    let s_pub = x25519_dalek::PublicKey::from(*s_pub_bytes);
    let shared = Zeroizing::new(*c_priv.diffie_hellman(&s_pub).as_bytes());

    let mut req_nonce = [0u8; 24];
    OsRng.fill_bytes(&mut req_nonce);
    let nonce_hex = hex::encode(req_nonce);
    let ts = now_unix_secs();

    let req_aad = format!("V3REQ|3|{op}|{pkg}|{ver}|{bld}|{fp}|{nonce_hex}|{ts}");
    let pepper = secrets::pre_shared_pepper();

    let hk = Hkdf::<Sha256>::new(Some(pepper.as_slice()), shared.as_ref());
    let mut req_key = Zeroizing::new([0u8; 32]);
    let info_req = obfstr!("3105-V3-REQ").to_string();
    hk.expand(info_req.as_bytes(), req_key.as_mut())
        .map_err(|_| obfstr!("HKDF fail").to_string())?;

    let proof_mac = hmac_sha256(
        pepper.as_slice(),
        &[req_aad.as_bytes(), b"|", license_key.as_bytes()],
    );
    let proof_hex = hex::encode(proof_mac);

    let inner = serde_json::json!({
        "op": op,
        "key": license_key,
        "pkg": pkg,
        "ver": ver,
        "bld": bld,
        "app_hash": app_hash,
        "sec_hash": sec_hash,
        "tamper_flags": tamper_flags,
        "client_proof": proof_hex,
        "ts": ts,
    });
    let pt_bytes = Zeroizing::new(serde_json::to_vec(&inner).map_err(|_| "Encode fail")?);

    let cipher = XChaCha20Poly1305::new_from_slice(&*req_key)
        .map_err(|_| obfstr!("Key init fail").to_string())?;
    let ct = cipher
        .encrypt(
            chacha20poly1305::XNonce::from_slice(&req_nonce),
            Payload {
                msg: &pt_bytes,
                aad: req_aad.as_bytes(),
            },
        )
        .map_err(|_| obfstr!("Encrypt fail").to_string())?;

    let outer = serde_json::json!({
        "v": 3,
        "op": op,
        "pkg": pkg,
        "ver": ver,
        "bld": bld,
        "nonce": nonce_hex,
        "ts": ts,
        "c_pub": hex::encode(c_pub.as_bytes()),
        "fp": fp,
        "ct": B64.encode(&ct),
    });

    Ok(EncryptedExchangePacket {
        outer_json: outer.to_string(),
        shared_secret: shared,
        req_nonce_hex: nonce_hex,
        req_nonce_bytes: req_nonce,
        op: op.to_string(),
        pkg: pkg.to_string(),
        ver: ver.to_string(),
        fp: fp.to_string(),
    })
}

/// Verifies Ed25519 signature over RES_AAD + ct hash BEFORE AEAD decrypting V3 server response.
pub fn verify_and_decrypt_v3_response(
    pkt: &EncryptedExchangePacket,
    raw_response: &str,
) -> Result<(DecryptedV3Payload, String), String> {
    let outer: OuterV3Response = serde_json::from_str(raw_response)
        .map_err(|_| obfstr!("Malformed V3 response envelope").to_string())?;

    if outer.v != 3
        || outer.op != pkt.op
        || outer.pkg != pkt.pkg
        || outer.ver != pkt.ver
        || outer.fp != pkt.fp
        || !outer.req_nonce.eq_ignore_ascii_case(&pkt.req_nonce_hex)
    {
        return Err(obfstr!("Response envelope binding mismatch").to_string());
    }

    let now = now_unix_secs();
    if (now - outer.s_ts).abs() > 300 {
        return Err(obfstr!("Response timestamp stale").to_string());
    }

    let s_nonce_raw = hex::decode(outer.s_nonce.trim())
        .map_err(|_| obfstr!("Malformed server nonce").to_string())?;
    if s_nonce_raw.len() != 24 {
        return Err(obfstr!("Invalid server nonce size").to_string());
    }

    let ct = B64
        .decode(outer.ct.trim())
        .map_err(|_| obfstr!("Malformed server ct").to_string())?;

    let res_aad = format!(
        "V3RES|3|{}|{}|{}|{}|{}|{}|{}|{}",
        outer.op,
        outer.pkg,
        outer.ver,
        outer.fp,
        outer.req_nonce,
        outer.s_nonce,
        outer.s_ts,
        outer.code
    );

    // 1. Verify Ed25519 signature BEFORE touching plaintext
    let ct_hash = Sha256::digest(&ct);
    let sig_pfx = obfstr!("3105-V3-SIG|").to_string();
    let mut sig_msg = Vec::with_capacity(sig_pfx.len() + res_aad.len() + 1 + 32);
    sig_msg.extend_from_slice(sig_pfx.as_bytes());
    sig_msg.extend_from_slice(res_aad.as_bytes());
    sig_msg.push(b'|');
    sig_msg.extend_from_slice(&ct_hash);

    let sig_raw = hex::decode(outer.sig.trim())
        .map_err(|_| obfstr!("Malformed Ed25519 sig").to_string())?;
    let sig_arr: [u8; 64] = sig_raw
        .try_into()
        .map_err(|_| obfstr!("Invalid Ed25519 sig length").to_string())?;
    let sig = Signature::from_bytes(&sig_arr);

    let ed_pub_bytes = secrets::server_ed25519_pub();
    let vk = VerifyingKey::from_bytes(&*ed_pub_bytes)
        .map_err(|_| obfstr!("Invalid server Ed25519 key").to_string())?;
    vk.verify(&sig_msg, &sig)
        .map_err(|_| obfstr!("Server signature forgery detected!").to_string())?;

    // 2. Derive response key bound to request nonce and decrypt AEAD
    let pepper = secrets::pre_shared_pepper();
    let hk = Hkdf::<Sha256>::new(Some(pepper.as_slice()), pkt.shared_secret.as_ref());
    let res_pfx = obfstr!("3105-V3-RES|").to_string();
    let mut info = Vec::with_capacity(res_pfx.len() + 24);
    info.extend_from_slice(res_pfx.as_bytes());
    info.extend_from_slice(&pkt.req_nonce_bytes);
    let mut res_key = Zeroizing::new([0u8; 32]);
    hk.expand(&info, res_key.as_mut())
        .map_err(|_| obfstr!("Response HKDF fail").to_string())?;

    let cipher = XChaCha20Poly1305::new_from_slice(&*res_key)
        .map_err(|_| obfstr!("Response cipher init fail").to_string())?;
    let pt = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(&s_nonce_raw),
                Payload {
                    msg: &ct,
                    aad: res_aad.as_bytes(),
                },
            )
            .map_err(|_| obfstr!("Response AEAD authentication failed").to_string())?,
    );

    let decoded: DecryptedV3Payload = serde_json::from_slice(&pt)
        .map_err(|_| obfstr!("Malformed decrypted payload").to_string())?;

    if !decoded.req_nonce.eq_ignore_ascii_case(&outer.req_nonce)
        || !decoded.s_nonce.eq_ignore_ascii_case(&outer.s_nonce)
        || decoded.s_ts != outer.s_ts
        || decoded.code != outer.code
        || decoded.op != outer.op
    {
        return Err(obfstr!("Inner/outer payload mismatch").to_string());
    }

    Ok((decoded, raw_response.to_string()))
}
