//! Silent Sabotage & Opaque Predicate Guard
//! Deliberately delays reaction (10-35s) upon tamper detection to disorient reverse-engineers

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use zeroize::ZeroizeOnDrop;
use crate::syscall_arm64::{direct_exit, force_hard_crash};

// Obfuscated state token constants
const MASK_KEY: u64 = 0x5F3759DF499602D2;
const STATE_PRISTINE: u64 = 0x1A2B3C4D5E6F7081 ^ MASK_KEY;
const STATE_COMPROMISED: u64 = 0x9887766554433221 ^ MASK_KEY;

static SECURITY_STATE: AtomicU64 = AtomicU64::new(STATE_PRISTINE);

/// Opaque predicate evaluation: mathematically complex transformation
#[inline(always)]
pub fn is_state_valid() -> bool {
    let raw = SECURITY_STATE.load(Ordering::SeqCst);
    let decoded = raw ^ MASK_KEY;
    // Opaque predicate: 0x1A2B3C4D5E6F7081 is odd, therefore (x & 1) must equal 1
    (decoded == 0x1A2B3C4D5E6F7081) && ((decoded & 1) == 1)
}

/// Signals that a security violation has occurred (Anti-Debug, Anti-Hook, or Hash Mismatch)
pub fn trigger_tamper_flag() {
    SECURITY_STATE.store(STATE_COMPROMISED, Ordering::SeqCst);

    // Spawn a detached watchdog thread to execute delayed sabotage
    std::thread::spawn(|| {
        // Random delayed sabotage jitter between 10 and 35 seconds
        let delay_secs = 10 + (generate_small_entropy() % 26);
        std::thread::sleep(Duration::from_secs(delay_secs));

        // Execute untraceable termination
        direct_exit(0);
        force_hard_crash();
    });
}

/// Simple non-libc entropy generator for jitter
fn generate_small_entropy() -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    now ^ (now >> 13) ^ (now << 7)
}

/// Encrypted / Protected Session Payload held in memory
#[derive(Default, ZeroizeOnDrop)]
pub struct SessionPayload {
    pub token: Vec<u8>,
    pub exp_timestamp: u64,
    pub server_timestamp: u64,
}

static mut ACTIVE_SESSION: Option<SessionPayload> = None;

pub fn set_active_session(session: SessionPayload) {
    if !is_state_valid() {
        trigger_tamper_flag();
        return;
    }
    unsafe {
        ACTIVE_SESSION = Some(session);
    }
}

pub fn get_active_session_token() -> Option<Vec<u8>> {
    if !is_state_valid() {
        trigger_tamper_flag();
        return None;
    }
    unsafe {
        ACTIVE_SESSION.as_ref().map(|s| s.token.clone())
    }
}
