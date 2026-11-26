// CI Build-Time Security Constants Template
// Replaced automatically by scripts/obfuscate_build.py in GitHub Actions with per-build split/XOR shares.

pub const SEAL_REQUIRED: bool = false;
pub const REQUIRE_SPKI_PIN: bool = false;
pub const OPAQUE_SEED: u64 = 0x5A17_3105_CAFE_BEEF;

pub const X25519_SHARE_A: [u8; 32] = [0u8; 32];
pub const X25519_SHARE_B: [u8; 32] = [0u8; 32];

pub const ED25519_SHARE_A: [u8; 32] = [0u8; 32];
pub const ED25519_SHARE_B: [u8; 32] = [0u8; 32];

pub const PEPPER_LEN: usize = 32;
pub const PEPPER_SHARE_A: [u8; 64] = [0u8; 64];
pub const PEPPER_SHARE_B: [u8; 64] = [0u8; 64];

pub const SPKI_PRIMARY_A: [u8; 32] = [0u8; 32];
pub const SPKI_PRIMARY_B: [u8; 32] = [0u8; 32];

pub const SPKI_BACKUP_A: [u8; 32] = [0u8; 32];
pub const SPKI_BACKUP_B: [u8; 32] = [0u8; 32];

pub const V4_FORMAT_TAG: [u8; 4] = [0x9D, 0x7A, 0x41, 0xE3];

// XOR-masked server host & path ("tobivn.chickenkiller.com" / "/api/v3") replaced by obfuscate_build.py
pub const API_HOST_MASK: u8 = 0x5C;
pub const API_HOST_ENC: &[u8] = &[0x28, 0x33, 0x3E, 0x35, 0x2A, 0x32, 0x72, 0x3F, 0x34, 0x35, 0x3F, 0x37, 0x39, 0x32, 0x37, 0x35, 0x30, 0x30, 0x39, 0x2E, 0x72, 0x3F, 0x33, 0x31];

pub const API_PATH_MASK: u8 = 0xA3;
pub const API_PATH_ENC: &[u8] = &[0x8C, 0xC2, 0xD3, 0xCA, 0x8C, 0xD5, 0x90];

// [0..16] marker (overwritten with zeros by macho_hash.py after strip),
// [16..48] random mask, [48..80] (expected_text_sha256 ^ mask)
#[used]
#[cfg_attr(target_vendor = "apple", link_section = "__DATA,__sechash")]
pub static mut SEC_SELF_SEAL: [u8; 80] = [
    0x33, 0x31, 0x30, 0x35, 0x53, 0x45, 0x41, 0x4C,
    0x54, 0x41, 0x47, 0x5F, 0x54, 0x45, 0x4D, 0x50,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];
