//! Zero-Trust End-to-End Cryptographic Protocol
//! 3-Layer Security: X25519 ECDH + HKDF-SHA256 + XChaCha20-Poly1305 + Ed25519 Signature

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Pre-shared pepper combined with ECDH shared secret in HKDF
pub const PROTOCOL_INFO: &[u8] = b"3105-X-PHUCVN-V2-SECURE-CHANNEL";

/// Client request packet to `api_v2.php`
#[derive(Serialize, Deserialize, ZeroizeOnDrop)]
pub struct ClientRequestPayload {
    pub license_key: String,
    pub device_fp: String,
    pub client_ts: u64,
    pub challenge: String,
    pub app_hash: String,
}

/// Signed & encrypted response packet from `api_v2.php`
#[derive(Serialize, Deserialize, Clone, ZeroizeOnDrop)]
pub struct ServerResponsePayload {
    pub status: String,
    pub exp_ts: u64,
    pub server_ts: u64,
    pub echo_challenge: String,
    pub device_fp: String,
    pub session_payload: String,
}

/// Enclosing encrypted wire format (JSON over HTTP POST)
#[derive(Serialize, Deserialize)]
pub struct EncryptedWirePacket {
    /// Client's ephemeral X25519 public key (hex)
    pub ephemeral_pub: String,
    /// 24-byte random nonce (hex)
    pub nonce: String,
    /// Ciphertext from XChaCha20-Poly1305 (hex)
    pub ciphertext: String,
}

/// Server encrypted response format (JSON over HTTP response)
#[derive(Serialize, Deserialize)]
pub struct ServerEncryptedPacket {
    /// 24-byte nonce (hex)
    pub nonce: String,
    /// Ciphertext of response (hex)
    pub ciphertext: String,
    /// 64-byte Ed25519 detached signature (hex)
    pub signature: String,
}

/// Key derivation & session context
#[derive(ZeroizeOnDrop)]
pub struct CryptoSession {
    #[zeroize(skip)]
    pub client_challenge: String,
    pub shared_key: [u8; 32],
}

impl CryptoSession {
    /// Creates an encrypted client packet and stores the derived session key
    pub fn prepare_request(
        payload: &ClientRequestPayload,
        server_x25519_pub_bytes: &[u8; 32],
        pepper: &[u8],
    ) -> Result<(EncryptedWirePacket, Self), String> {
        let mut rng = OsRng;

        // 1. Generate Ephemeral X25519 keypair
        let client_secret = X25519Secret::random_from_rng(&mut rng);
        let client_public = X25519Public::from(&client_secret);
        let server_pub = X25519Public::from(*server_x25519_pub_bytes);

        // 2. Perform ECDH
        let shared_secret = client_secret.diffie_hellman(&server_pub);

        // 3. Derive 32-byte session key via HKDF-SHA256
        let hk = Hkdf::<Sha256>::new(Some(pepper), shared_secret.as_bytes());
        let mut derived_key = [0u8; 32];
        hk.expand(PROTOCOL_INFO, &mut derived_key)
            .map_err(|_| "HKDF expansion failed".to_string())?;

        // 4. Encrypt payload with XChaCha20-Poly1305
        let cipher = XChaCha20Poly1305::new_from_slice(&derived_key)
            .map_err(|e| format!("Cipher init error: {:?}", e))?;

        let mut nonce_bytes = [0u8; 24];
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);

        let json_bytes = serde_json::to_vec(payload)
            .map_err(|e| format!("JSON encode error: {:?}", e))?;

        let ciphertext = cipher
            .encrypt(nonce, json_bytes.as_ref())
            .map_err(|e| format!("Encryption error: {:?}", e))?;

        let packet = EncryptedWirePacket {
            ephemeral_pub: hex_encode(client_public.as_bytes()),
            nonce: hex_encode(&nonce_bytes),
            ciphertext: hex_encode(&ciphertext),
        };

        let session = Self {
            client_challenge: payload.challenge.clone(),
            shared_key: derived_key,
        };

        Ok((packet, session))
    }

    /// Decrypts and verifies the server response
    pub fn verify_and_decrypt_response(
        &self,
        server_packet: &ServerEncryptedPacket,
        server_ed25519_pub_bytes: &[u8; 32],
    ) -> Result<ServerResponsePayload, String> {
        // 1. Decrypt ciphertext using derived session key
        let nonce_bytes = hex_decode(&server_packet.nonce)?;
        if nonce_bytes.len() != 24 {
            return Err("Invalid nonce length".to_string());
        }
        let nonce = XNonce::from_slice(&nonce_bytes);

        let cipher_bytes = hex_decode(&server_packet.ciphertext)?;
        let cipher = XChaCha20Poly1305::new_from_slice(&self.shared_key)
            .map_err(|e| format!("Cipher error: {:?}", e))?;

        let decrypted_bytes = cipher
            .decrypt(nonce, cipher_bytes.as_ref())
            .map_err(|_| "Decryption failed (tampered packet or invalid key)".to_string())?;

        // 2. Verify Ed25519 signature over the decrypted JSON bytes
        let sig_bytes = hex_decode(&server_packet.signature)?;
        if sig_bytes.len() != 64 {
            return Err("Invalid signature length".to_string());
        }
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let signature = Signature::from_bytes(&sig_arr);

        let verifier = VerifyingKey::from_bytes(server_ed25519_pub_bytes)
            .map_err(|e| format!("Invalid server Ed25519 key: {:?}", e))?;

        verifier
            .verify(&decrypted_bytes, &signature)
            .map_err(|_| "Invalid Ed25519 server signature (fake server detected)".to_string())?;

        // 3. Deserialize JSON
        let payload: ServerResponsePayload = serde_json::from_slice(&decrypted_bytes)
            .map_err(|e| format!("JSON parse error: {:?}", e))?;

        // 4. Validate Challenge
        if payload.echo_challenge != self.client_challenge {
            return Err("Replay attack detected: challenge mismatch".to_string());
        }

        Ok(payload)
    }
}

pub fn hex_encode(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

pub fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("Hex string odd length".to_string());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|_| "Invalid hex character".to_string())
        })
        .collect()
}
