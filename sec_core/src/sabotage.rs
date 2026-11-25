use crate::crypto::{hmac_sha256, now_unix_secs, DecryptedV3Payload};
use crate::secrets;
use crate::syscall_arm64;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use obfstr::obfstr;
use rand::rngs::OsRng;
use rand::RngCore;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

const TAMPER_CLEAN_MARKER: u64 = 0x55AA_3105_9911_0001;
const TAMPER_COMPROMISED_MARKER: u64 = 0xDEAD_BEEF_BAD0_C0DE;

static RUNTIME_INTEGRITY_WORD: AtomicU64 = AtomicU64::new(TAMPER_CLEAN_MARKER);

/// Thread-safe encrypted/masked vault holding session & V4 bundle keys only while genuinely authorized.
pub struct ProtectedVault {
    pub active: bool,
    pub ram_pad: [u8; 32],
    pub masked_ephemeral_key: [u8; 32],
    pub masked_ticket_secret: [u8; 32],
    pub masked_bundle_keys: BTreeMap<[u8; 16], [u8; 32]>,
    pub current_ticket_hex: String,
    pub saved_license_key: Zeroizing<String>,
    pub expiry_ts: i64,
    pub is_permanent: bool,
    pub tamper_latched: bool,
}

impl Default for ProtectedVault {
    fn default() -> Self {
        Self {
            active: false,
            ram_pad: [0u8; 32],
            masked_ephemeral_key: [0u8; 32],
            masked_ticket_secret: [0u8; 32],
            masked_bundle_keys: BTreeMap::new(),
            current_ticket_hex: String::new(),
            saved_license_key: Zeroizing::new(String::new()),
            expiry_ts: 0,
            is_permanent: false,
            tamper_latched: false,
        }
    }
}

impl ProtectedVault {
    pub fn wipe(&mut self) {
        self.active = false;
        self.ram_pad.zeroize();
        self.masked_ephemeral_key.zeroize();
        self.masked_ticket_secret.zeroize();
        for (_, mut v) in std::mem::take(&mut self.masked_bundle_keys) {
            v.zeroize();
        }
        self.current_ticket_hex.zeroize();
        self.saved_license_key.zeroize();
        self.expiry_ts = 0;
        self.is_permanent = false;
    }
}

static VAULT: Mutex<Option<ProtectedVault>> = Mutex::new(None);

fn with_vault<R, F: FnOnce(&mut ProtectedVault) -> R>(f: F) -> R {
    let mut guard = VAULT.lock().unwrap_or_else(|e| e.into_inner());
    let vault = guard.get_or_insert_with(ProtectedVault::default);
    f(vault)
}

#[inline(never)]
pub fn mark_tampered_and_terminate() -> ! {
    RUNTIME_INTEGRITY_WORD.store(TAMPER_COMPROMISED_MARKER, Ordering::SeqCst);
    wipe_vault(true);
    #[cfg(target_vendor = "apple")]
    {
        unsafe {
            syscall_arm64::raw_exit(1);
        }
    }
    #[cfg(not(target_vendor = "apple"))]
    std::process::exit(1);
}

#[inline(always)]
pub fn is_runtime_tamper_latched() -> bool {
    let word = RUNTIME_INTEGRITY_WORD.load(Ordering::SeqCst);
    if word != TAMPER_CLEAN_MARKER {
        return true;
    }
    with_vault(|v| v.tamper_latched)
}

/// Immediately wipes all server-issued keys, bundle keys, and license tokens from RAM.
pub fn wipe_vault(latch_tamper: bool) {
    with_vault(|v| {
        v.wipe();
        if latch_tamper {
            v.tamper_latched = true;
        }
    });
}

/// Populates RAM vault strictly from verified server response; fails closed if any field missing.
pub fn activate_vault_session(
    license_key: &str,
    payload: &DecryptedV3Payload,
) -> Result<String, String> {
    if is_runtime_tamper_latched() {
        return Err(obfstr!("Integrity compromised").to_string());
    }
    if !payload.server_open || payload.force_update || !payload.license.valid {
        wipe_vault(false);
        return Err(obfstr!("Server denied authorization").to_string());
    }
    let Some(eph_hex) = payload.ephemeral_session_key.as_ref() else {
        wipe_vault(false);
        return Err(obfstr!("Missing ephemeral session key").to_string());
    };
    let eph_raw = Zeroizing::new(
        hex::decode(eph_hex.trim()).map_err(|_| obfstr!("Bad session key").to_string())?,
    );
    if eph_raw.len() != 32 {
        wipe_vault(false);
        return Err(obfstr!("Invalid session key len").to_string());
    }

    let mut pad = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(pad.as_mut());

    let mut ticket_secret = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(ticket_secret.as_mut());

    let mut nonce_rnd = [0u8; 16];
    OsRng.fill_bytes(&mut nonce_rnd);
    let nonce_hex = hex::encode(nonce_rnd);
    let now = now_unix_secs();

    let ticket_msg = format!(
        "TKT|{}|{}|{}",
        now, payload.license.expiry_ts, nonce_hex
    );
    let mac_bytes = hmac_sha256(ticket_secret.as_ref(), &[ticket_msg.as_bytes()]);
    let mac_hex = hex::encode(mac_bytes);
    let full_ticket = format!("{ticket_msg}|{mac_hex}");

    let mut masked_bundles = BTreeMap::new();
    for (bid_hex, bkey_hex) in &payload.bundle_keys {
        if let (Ok(id_vec), Ok(k_vec)) = (hex::decode(bid_hex), hex::decode(bkey_hex)) {
            if id_vec.len() == 16 && k_vec.len() == 32 {
                let mut bid = [0u8; 16];
                bid.copy_from_slice(&id_vec);
                let mut mk = [0u8; 32];
                for ((m, &k), &p) in mk.iter_mut().zip(k_vec.iter()).zip(pad.iter()) {
                    *m = k ^ p;
                }
                masked_bundles.insert(bid, mk);
            }
        }
    }

    with_vault(|v| {
        v.wipe();
        v.ram_pad.copy_from_slice(pad.as_ref());
        for ((ek, ts), ((&e, &t), &p)) in v
            .masked_ephemeral_key
            .iter_mut()
            .zip(v.masked_ticket_secret.iter_mut())
            .zip(eph_raw.iter().zip(ticket_secret.iter()).zip(pad.iter()))
        {
            *ek = e ^ p;
            *ts = t ^ p;
        }
        v.masked_bundle_keys = masked_bundles;
        v.current_ticket_hex = full_ticket.clone();
        *v.saved_license_key = license_key.to_string();
        v.expiry_ts = payload.license.expiry_ts;
        v.is_permanent = payload.license.is_permanent;
        v.active = true;
    });

    Ok(full_ticket)
}

pub fn get_cached_license_key() -> Option<Zeroizing<String>> {
    with_vault(|v| {
        if v.saved_license_key.is_empty() {
            None
        } else {
            Some(v.saved_license_key.clone())
        }
    })
}

/// Verifies runtime session ticket in constant time and ensures license hasn't expired.
pub fn verify_ticket_valid(ticket: &str) -> bool {
    if is_runtime_tamper_latched() || ticket.is_empty() {
        return false;
    }
    let parts: Vec<&str> = ticket.split('|').collect();
    if parts.len() != 5 || parts[0] != "TKT" {
        return false;
    }
    let Ok(exp_ts) = parts[2].parse::<i64>() else {
        return false;
    };
    let msg = format!("{}|{}|{}|{}", parts[0], parts[1], parts[2], parts[3]);
    let Ok(provided_mac) = hex::decode(parts[4]) else {
        return false;
    };

    with_vault(|v| {
        if !v.active || v.tamper_latched {
            return false;
        }
        let now = now_unix_secs();
        if !v.is_permanent && (v.expiry_ts <= 0 || now >= v.expiry_ts || now >= exp_ts) {
            v.wipe();
            return false;
        }
        let mut t_secret = Zeroizing::new([0u8; 32]);
        for (dst, (&m, &p)) in t_secret
            .iter_mut()
            .zip(v.masked_ticket_secret.iter().zip(v.ram_pad.iter()))
        {
            *dst = m ^ p;
        }
        let expected = hmac_sha256(t_secret.as_ref(), &[msg.as_bytes()]);
        bool::from(provided_mac.as_slice().ct_eq(&expected[..]))
            && bool::from(ticket.as_bytes().ct_eq(v.current_ticket_hex.as_bytes()))
    })
}

/// Stream-decrypts a V4 `.3105` container directly in RAM using masked server-issued bundle_key.
pub fn decrypt_v4_asset_in_ram(asset_bytes: &[u8], ticket: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    if !verify_ticket_valid(ticket) {
        return Err(obfstr!("Unauthorized session ticket").to_string());
    }

    // Header: format_tag[4] + bundle_id[16] + chunk_count[4] + base_nonce[24] = 48 bytes minimum
    if asset_bytes.len() < 48 {
        return Err(obfstr!("Truncated V4 container").to_string());
    }
    let expected_tag = secrets::gen::V4_FORMAT_TAG;
    if !bool::from(asset_bytes[0..4].ct_eq(&expected_tag[..])) {
        return Err(obfstr!("Invalid V4 asset format tag").to_string());
    }

    let mut bundle_id = [0u8; 16];
    bundle_id.copy_from_slice(&asset_bytes[4..20]);
    let chunk_count = u32::from_le_bytes([
        asset_bytes[20],
        asset_bytes[21],
        asset_bytes[22],
        asset_bytes[23],
    ]);
    if chunk_count == 0 || chunk_count > 4096 {
        return Err(obfstr!("Invalid chunk count").to_string());
    }
    let mut base_nonce = [0u8; 24];
    base_nonce.copy_from_slice(&asset_bytes[24..48]);

    // Unmask bundle key onto stack inside Zeroizing wrapper
    let unmasked_bundle_key = with_vault(|v| -> Result<Zeroizing<[u8; 32]>, String> {
        if !v.active || v.tamper_latched {
            return Err(obfstr!("Vault inactive").to_string());
        }
        let Some(masked) = v.masked_bundle_keys.get(&bundle_id) else {
            return Err(obfstr!("Missing bundle decryption key").to_string());
        };
        let mut key = Zeroizing::new([0u8; 32]);
        for (dst, (&m, &p)) in key.iter_mut().zip(masked.iter().zip(v.ram_pad.iter())) {
            *dst = m ^ p;
        }
        Ok(key)
    })?;

    let cipher = XChaCha20Poly1305::new_from_slice(unmasked_bundle_key.as_ref())
        .map_err(|_| obfstr!("Cipher init fail").to_string())?;
    let bundle_id_hex = hex::encode(bundle_id);
    let tag_hex = hex::encode(expected_tag);

    let mut plaintext_total = Zeroizing::new(Vec::new());
    let mut cursor = 48usize;

    for idx in 0..chunk_count {
        if cursor + 4 > asset_bytes.len() {
            return Err(obfstr!("Truncated V4 chunk len").to_string());
        }
        let ct_len = u32::from_le_bytes([
            asset_bytes[cursor],
            asset_bytes[cursor + 1],
            asset_bytes[cursor + 2],
            asset_bytes[cursor + 3],
        ]) as usize;
        cursor += 4;
        if ct_len < 16 || cursor + ct_len > asset_bytes.len() {
            return Err(obfstr!("Corrupt V4 chunk size").to_string());
        }
        let ct_slice = &asset_bytes[cursor..cursor + ct_len];
        cursor += ct_len;

        let mut c_nonce = base_nonce;
        c_nonce[20] ^= (idx & 0xff) as u8;
        c_nonce[21] ^= ((idx >> 8) & 0xff) as u8;
        c_nonce[22] ^= ((idx >> 16) & 0xff) as u8;
        c_nonce[23] ^= ((idx >> 24) & 0xff) as u8;

        let aad = format!("V4C|{bundle_id_hex}|{idx}|{tag_hex}");
        let mut pt_chunk = Zeroizing::new(
            cipher
                .decrypt(
                    XNonce::from_slice(&c_nonce),
                    Payload {
                        msg: ct_slice,
                        aad: aad.as_bytes(),
                    },
                )
                .map_err(|_| obfstr!("V4 AEAD chunk verify failed").to_string())?,
        );
        plaintext_total.extend_from_slice(&pt_chunk);
        pt_chunk.zeroize();
    }

    Ok(plaintext_total)
}
