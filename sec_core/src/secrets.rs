use zeroize::Zeroizing;

#[path = "generated_secrets.rs"]
pub mod gen;

/// Reconstructs a 32-byte secret onto stack from two XOR-split shares.
#[inline(always)]
pub fn unsplit_32(a: &[u8; 32], b: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    for i in 0..32 {
        out[i] = a[i] ^ b[i];
    }
    out
}

pub fn server_x25519_pub() -> Zeroizing<[u8; 32]> {
    unsplit_32(&gen::X25519_SHARE_A, &gen::X25519_SHARE_B)
}

pub fn server_ed25519_pub() -> Zeroizing<[u8; 32]> {
    unsplit_32(&gen::ED25519_SHARE_A, &gen::ED25519_SHARE_B)
}

pub fn pre_shared_pepper() -> Zeroizing<Vec<u8>> {
    let len = gen::PEPPER_LEN.min(64);
    let mut out = Zeroizing::new(vec![0u8; len]);
    for i in 0..len {
        out[i] = gen::PEPPER_SHARE_A[i] ^ gen::PEPPER_SHARE_B[i];
    }
    out
}

pub fn primary_spki_pin() -> [u8; 32] {
    *unsplit_32(&gen::SPKI_PRIMARY_A, &gen::SPKI_PRIMARY_B)
}

pub fn backup_spki_pin() -> [u8; 32] {
    *unsplit_32(&gen::SPKI_BACKUP_A, &gen::SPKI_BACKUP_B)
}

pub fn api_host() -> Zeroizing<String> {
    let bytes: Vec<u8> = gen::API_HOST_ENC
        .iter()
        .map(|&b| b ^ gen::API_HOST_MASK)
        .collect();
    let decoded = Zeroizing::new(bytes);
    if let Ok(s) = std::str::from_utf8(&decoded) {
        return Zeroizing::new(s.to_string());
    }
    Zeroizing::new(String::new())
}

pub fn api_path() -> Zeroizing<String> {
    let decoded = Zeroizing::new(
        gen::API_PATH_ENC
            .iter()
            .map(|&b| b ^ gen::API_PATH_MASK)
            .collect::<Vec<u8>>(),
    );
    if let Ok(s) = std::str::from_utf8(&decoded) {
        return Zeroizing::new(s.to_string());
    }
    Zeroizing::new(String::new())
}

/// Reads SEC_SELF_SEAL via volatile loads so compiler never constant-folds the sentinel.
pub fn read_self_seal() -> Zeroizing<[u8; 80]> {
    let mut out = Zeroizing::new([0u8; 80]);
    unsafe {
        let ptr = core::ptr::addr_of!(gen::SEC_SELF_SEAL) as *const u8;
        for i in 0..80 {
            out[i] = core::ptr::read_volatile(ptr.add(i));
        }
    }
    out
}
