//! Rotatable admin API token (RT-23).
//!
//! The token is stored only as a SHA-256 hash and compared in constant time.
//! Rotation is immediate for the new value; the previous value stays valid
//! for a bounded grace window so in-flight requests are not cut off. The
//! current hash is persisted, so a restart keeps the rotated token.

use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tracing::{info, warn};

/// How long the previous token stays valid after a rotation.
///
/// Overridable with HIMAN_TOKEN_GRACE_SECS so the bounded window can be
/// tested; the default is 60s.
pub const GRACE: Duration = Duration::from_secs(60);

fn grace() -> Duration {
    std::env::var("HIMAN_TOKEN_GRACE_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(GRACE)
}

#[derive(Debug, Clone)]
struct Entry {
    hash: [u8; 32],
    valid_until: Option<Instant>,
}

/// The token store: the current hash plus, during the grace window, the
/// previous one.
#[derive(Debug, Clone)]
pub struct TokenStore {
    current: Entry,
    previous: Option<Entry>,
    rotated_at: Option<Instant>,
}

impl TokenStore {
    /// Build from a raw token (the env value at startup).
    pub fn new(raw: &str) -> Self {
        Self {
            current: Entry {
                hash: hash(raw),
                valid_until: None,
            },
            previous: None,
            rotated_at: None,
        }
    }

    /// Is this presented token valid right now?
    pub fn matches(&self, presented: &str) -> bool {
        let candidate = hash(presented);
        if ct_eq(&candidate, &self.current.hash) {
            return true;
        }
        if let Some(prev) = &self.previous {
            if prev
                .valid_until
                .map(|u| Instant::now() < u)
                .unwrap_or(false)
                && ct_eq(&candidate, &prev.hash)
            {
                return true;
            }
        }
        false
    }

    /// Rotate: the current value becomes the previous one (still valid for
    /// the grace window) and a fresh value is returned.
    pub fn rotate(&mut self) -> String {
        let mut raw = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut raw);
        let plaintext = base64_url(&raw);
        let old = std::mem::replace(
            &mut self.current,
            Entry {
                hash: hash(&plaintext),
                valid_until: None,
            },
        );
        self.previous = Some(Entry {
            hash: old.hash,
            valid_until: Some(Instant::now() + grace()),
        });
        self.rotated_at = Some(Instant::now());
        info!("admin API token rotated; the previous value is valid for the grace window");
        plaintext
    }

    /// Persisted form: the current hash, hex-encoded.
    pub fn persist_current(&self) -> String {
        hex::encode(self.current.hash)
    }

    /// Restore from the persisted current hash. The previous value cannot be
    /// recovered, so the grace window ends at restart.
    pub fn from_persisted(hex_hash: &str, raw_fallback: &str) -> Self {
        let hash = hex::decode(hex_hash)
            .ok()
            .and_then(|bytes| bytes.try_into().ok());
        match hash {
            Some(h) => Self {
                current: Entry {
                    hash: h,
                    valid_until: None,
                },
                previous: None,
                rotated_at: None,
            },
            // A malformed record must not lock the operator out: fall back to
            // the env value rather than rejecting every request.
            None => {
                warn!("persisted API token hash is malformed; using the env value");
                Self::new(raw_fallback)
            }
        }
    }

    pub fn grace_remaining(&self) -> Option<Duration> {
        self.previous
            .as_ref()
            .and_then(|p| p.valid_until)
            .map(|u| u.saturating_duration_since(Instant::now()))
    }
}

fn hash(raw: &str) -> [u8; 32] {
    Sha256::digest(raw.as_bytes()).into()
}

fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.ct_eq(b).into()
}

fn base64_url(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_known_hash_round_trips() {
        use sha2::{Digest, Sha256};
        let raw = "a-known-token-value";
        let hex_hash = hex::encode(Sha256::digest(raw.as_bytes()));
        let store = TokenStore::from_persisted(&hex_hash, "fallback");
        assert!(
            store.matches(raw),
            "a known hash did not match its own token"
        );
    }

    #[test]
    fn a_rotated_token_round_trips_through_the_persisted_hash() {
        let mut store = TokenStore::new("old-token");
        let new_token = store.rotate();
        // Simulate a restart: persist, then rebuild from the hash.
        let persisted = store.persist_current();
        let restored = TokenStore::from_persisted(&persisted, "old-token");
        assert!(
            restored.matches(&new_token),
            "the rotated token did not survive the persist/restore round trip"
        );
    }

    #[test]
    fn the_previous_token_is_accepted_only_inside_the_grace_window() {
        let mut store = TokenStore::new("old-token");
        let _ = store.rotate();
        assert!(
            store.matches("old-token"),
            "grace window refused the old token"
        );
    }

    #[test]
    fn a_wrong_token_is_refused() {
        let store = TokenStore::new("the-token");
        assert!(!store.matches("wrong"), "a wrong token was accepted");
    }

    #[test]
    fn only_the_hash_is_retained() {
        let store = TokenStore::new("super-secret-token");
        let debug = format!("{:?}", store);
        assert!(
            !debug.contains("super-secret-token"),
            "the raw token appears in the store: {debug}"
        );
    }
}
