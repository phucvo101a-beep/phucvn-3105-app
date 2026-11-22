//! 3105 x PHUCVN Security Key Generator CLI

use ed25519_dalek::SigningKey as Ed25519SigningKey;
use rand::rngs::OsRng;
use rand::RngCore;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};

fn main() {
    let mut rng = OsRng;

    println!("============================================================");
    println!("     3105 x PHUCVN - CRYPTOGRAPHIC KEY GENERATOR (V2)      ");
    println!("============================================================\n");

    // 1. Generate X25519 Keypair
    let x25519_secret = X25519Secret::random_from_rng(&mut rng);
    let x25519_public = X25519Public::from(&x25519_secret);

    // 2. Generate Ed25519 Keypair (secure random 32-byte secret)
    let mut ed_secret = [0u8; 32];
    rng.fill_bytes(&mut ed_secret);
    let ed25519_signing = Ed25519SigningKey::from_bytes(&ed_secret);
    let ed25519_verifying = ed25519_signing.verifying_key();

    // 3. Generate Pre-Shared Pepper (32 bytes)
    let mut pepper = [0u8; 32];
    rng.fill_bytes(&mut pepper);

    println!("[1] DÁN VÀO PHP (serverkey/api_v2.php):");
    println!("------------------------------------------------------------");
    println!("define('SERVER_X25519_PRIV_HEX', '{}');", hex_encode(x25519_secret.as_bytes()));
    println!("define('SERVER_ED25519_PRIV_HEX', '{}');", hex_encode(&ed25519_signing.to_keypair_bytes()));
    println!("define('PRE_SHARED_PEPPER', '{}');\n", hex_encode(&pepper));

    println!("[2] DÁN VÀO RUST (sec_core/src/lib.rs):");
    println!("------------------------------------------------------------");
    println!("pub static SERVER_X25519_PUB: [u8; 32] = {};", format_byte_array(x25519_public.as_bytes()));
    println!("pub static SERVER_ED25519_PUB: [u8; 32] = {};", format_byte_array(ed25519_verifying.as_bytes()));
    println!("pub static PRE_SHARED_PEPPER: &[u8] = b\"{}\";\n", hex_encode(&pepper));

    println!("[3] LỆNH LẤY MÃ BĂM SPKI PIN (SHA-256) CHO DOMAIN 20-10.store:");
    println!("------------------------------------------------------------");
    println!("openssl s_client -connect 20-10.store:443 -servername 20-10.store </dev/null 2>/dev/null | \\");
    println!("  openssl x509 -pubkey -noout | \\");
    println!("  openssl pkey -pubin -outform der | \\");
    println!("  openssl dgst -sha256 -binary | xxd -p -c 32\n");
    println!("============================================================");
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn format_byte_array(bytes: &[u8]) -> String {
    let mut out = String::from("[\n    ");
    for (i, b) in bytes.iter().enumerate() {
        out.push_str(&format!("0x{:02x}, ", b));
        if (i + 1) % 8 == 0 && i + 1 < bytes.len() {
            out.push_str("\n    ");
        }
    }
    out.push_str("\n]");
    out
}
