use rand::rngs::OsRng;
use rand::RngCore;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};
use ed25519_dalek::SigningKey;

fn hex_str(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn rand_32() -> [u8; 32] {
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);
    b
}

fn main() {
    let x_priv_bytes = rand_32();
    let x_secret = X25519Secret::from(x_priv_bytes);
    let x_pub = X25519Public::from(&x_secret);

    let ed_seed = rand_32();
    let ed_signing = SigningKey::from_bytes(&ed_seed);
    let ed_pub = ed_signing.verifying_key();

    let pepper = rand_32();
    let bundle_master = rand_32();
    let ci_sync = rand_32();
    let ipc_secret = rand_32();

    println!("# ================= SERVER .env (OUTSIDE WEB ROOT) =================");
    println!("SERVER_X25519_PRIV_HEX={}", hex_str(&x_priv_bytes));
    println!("SERVER_ED25519_PRIV_HEX={}", hex_str(&ed_seed));
    println!("PRE_SHARED_PEPPER={}", hex_str(&pepper));
    println!("BUNDLE_PATCH_MASTER_KEY_HEX={}", hex_str(&bundle_master));
    println!("CI_SYNC_SECRET={}", hex_str(&ci_sync));
    println!("RUST_CORE_IPC_SECRET={}", hex_str(&ipc_secret));
    println!();
    println!("# ================= GITHUB ACTIONS SECRETS =========================");
    println!("SEC_SERVER_X25519_PUB={}", hex_str(x_pub.as_bytes()));
    println!("SEC_SERVER_ED25519_PUB={}", hex_str(ed_pub.as_bytes()));
    println!("SEC_PEPPER={}", hex_str(&pepper));
    println!("SEC_BUNDLE_MASTER_KEY={}", hex_str(&bundle_master));
    println!("SEC_CI_SYNC_SECRET={}", hex_str(&ci_sync));
}
