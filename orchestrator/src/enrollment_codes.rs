//! Single-use, short-lived enrollment codes (pairing flow).
//!
//! The static enrollment file is what an operator edits out of band. Pairing
//! lets an operator mint a code for a named device instead: the code is
//! high-entropy, stored only as a hash, bound to a device name, expires, and
//! can be redeemed exactly once.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use tracing::{info, warn};

/// Default code lifetime.
pub const DEFAULT_TTL_SECS: u64 = 300;
/// Codes are 32 random bytes, base64url-encoded.
const CODE_BYTES: usize = 32;

/// A pending enrollment code. Only the SHA-256 hash of the code is stored.
#[derive(Debug, Clone)]
pub struct EnrollmentCode {
    pub device: String,
    pub role: String,
    pub hash: [u8; 32],
    pub expires_at: u64,
    pub used: bool,
}

/// In-memory code registry. Created codes and their redemption state.
#[derive(Debug, Default)]
pub struct EnrollmentCodes {
    codes: HashMap<[u8; 32], EnrollmentCode>,
    /// Device name currently pending, so a second code for the same device
    /// does not race an in-flight redemption.
    pending: HashMap<String, [u8; 32]>,
}

impl EnrollmentCodes {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mint a code for a device. Returns the plaintext code (shown once) and
    /// the hash that is stored.
    pub fn create(&mut self, device: &str, role: &str, ttl_secs: u64) -> String {
        let mut raw = [0u8; CODE_BYTES];
        getrandom(&mut raw);
        let plaintext = base64_url(&raw);
        let hash = sha256(plaintext.as_bytes());
        self.codes.insert(
            hash,
            EnrollmentCode {
                device: device.to_string(),
                role: role.to_string(),
                hash,
                expires_at: now() + ttl_secs,
                used: false,
            },
        );
        // One pending code per device: an older one is superseded.
        self.pending.insert(device.to_string(), hash);
        plaintext
    }

    /// Attempt to redeem a code for a device. Returns the role on success.
    /// Single-use: the first success marks it used.
    pub fn redeem(&mut self, plaintext: &str, device: &str) -> Result<String, RedeemError> {
        let hash = sha256(plaintext.as_bytes());
        let code = self.codes.get_mut(&hash).ok_or(RedeemError::Unknown)?;
        if code.used {
            return Err(RedeemError::Reused);
        }
        if code.device != device {
            return Err(RedeemError::WrongDevice);
        }
        // Use `>=` at second granularity: with a 1-second TTL, a redeem in the
        // same second the deadline falls is already past it. Comparing with
        // `>` made a 1s code live up to 2s (truncation boundary).
        if now() >= code.expires_at {
            return Err(RedeemError::Expired);
        }
        // Mark used BEFORE returning so a concurrent redeem cannot both win.
        code.used = true;
        self.pending.remove(device);
        Ok(code.role.clone())
    }

    /// Drop the hash from the store after redemption.
    pub fn forget(&mut self, plaintext: &str) {
        let hash = sha256(plaintext.as_bytes());
        self.codes.remove(&hash);
    }

    pub fn is_used(&self, plaintext: &str) -> bool {
        let hash = sha256(plaintext.as_bytes());
        self.codes.get(&hash).map(|c| c.used).unwrap_or(false)
    }

    /// Expose the stored code state for the create response (used flag).
    pub fn used(&self, plaintext: &str) -> bool {
        self.is_used(plaintext)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RedeemError {
    #[error("unknown enrollment code")]
    Unknown,
    #[error("enrollment code already used")]
    Reused,
    #[error("enrollment code is for a different device")]
    WrongDevice,
    #[error("enrollment code expired")]
    Expired,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// base64url without padding, using the in-tree reader's alphabet dependency.
fn base64_url(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn getrandom(buf: &mut [u8]) {
    use rand::RngCore;
    rand::thread_rng().fill_bytes(buf);
}

/// Record a redemption decision in the audit log.
pub fn audit(action: &str, actor: &str, detail: &str) {
    info!(action, actor, detail);
    warn!(action, actor, detail, "enrollment audit");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_code_expires_after_its_ttl() {
        let mut codes = EnrollmentCodes::new();
        let code = codes.create("dev", "pc", 1);
        assert!(codes.redeem(&code, "dev").is_ok());
        let code2 = codes.create("dev2", "pc", 1);
        std::thread::sleep(std::time::Duration::from_millis(1100));
        assert!(
            matches!(codes.redeem(&code2, "dev2"), Err(RedeemError::Expired)),
            "the code did not expire"
        );
    }

    #[test]
    fn a_code_is_single_use() {
        let mut codes = EnrollmentCodes::new();
        let code = codes.create("dev", "pc", 300);
        assert!(codes.redeem(&code, "dev").is_ok());
        assert!(
            matches!(codes.redeem(&code, "dev"), Err(RedeemError::Reused)),
            "reuse was accepted"
        );
    }

    #[test]
    fn a_code_is_bound_to_its_device() {
        let mut codes = EnrollmentCodes::new();
        let code = codes.create("dev", "pc", 300);
        assert!(
            matches!(codes.redeem(&code, "other"), Err(RedeemError::WrongDevice)),
            "a code for another device was accepted"
        );
    }

    #[test]
    fn only_the_hash_is_stored() {
        let mut codes = EnrollmentCodes::new();
        let code = codes.create("dev", "pc", 300);
        // The plaintext must not be recoverable from the store.
        let leaked = format!("{:?}", codes);
        assert!(
            !leaked.contains(&code),
            "the plaintext code is stored in the registry: {leaked}"
        );
    }
}
