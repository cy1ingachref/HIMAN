//! Shared protocol types for HIMAN.
//!
//! Every message that crosses a device boundary is a [`WireMessage`]. Messages
//! are signed with Ed25519; the signature covers the canonical JSON encoding of
//! the payload plus the envelope metadata, so a tampered envelope or payload
//! fails verification.
//!
//! Design rules:
//! - Payload is a closed enum. Adding a variant is a protocol change.
//! - Canonical encoding is serde_json's compact form (no whitespace). Field
//!   order is struct declaration order, which serde preserves.
//! - Signatures are over the exact bytes transmitted, so verification never
//!   depends on the receiver re-encoding the payload.

pub mod device;
pub mod envelope;
pub mod error;
pub mod registry;
pub mod signing;
pub mod task;

pub use device::{DeviceClass, DeviceId, DeviceInfo};
pub use envelope::{Payload, WireMessage, WireMeta};
pub use error::{ProtoError, ProtoResult};
pub use registry::KeyRegistry;
pub use signing::{KeyBundle, SigningKey, VerifyingKey};
pub use task::{HandoffToken, RiskTier, TaskId, TaskState, ToolCall, ToolName};

/// Generate a fresh 16-byte nonce, base64 standard.
///
/// The nonce binds a Hello to its Welcome. It is not a secret; it only needs
/// to be unpredictable enough that a reflected or replayed handshake cannot
/// satisfy the match.
pub fn generate_nonce() -> String {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    let mut bytes = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
    B64.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonces_are_unique() {
        let a = generate_nonce();
        let b = generate_nonce();
        assert_ne!(a, b);
    }

    #[test]
    fn nonces_are_non_empty_and_base64() {
        let n = generate_nonce();
        assert!(!n.is_empty());
        assert!(n
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='));
    }
}
