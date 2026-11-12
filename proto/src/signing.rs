use crate::error::{ProtoError, ProtoResult};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{
    Signature, Signer, SigningKey as EdSigningKey, VerifyingKey as EdVerifyingKey,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

/// A signing key held by a device or the orchestrator.
#[derive(Clone)]
pub struct SigningKey(EdSigningKey);

/// The public half, safe to embed in `DeviceInfo` and hand out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyingKey(EdVerifyingKey);

impl SigningKey {
    /// Generate a fresh key using the OS RNG.
    pub fn generate() -> Self {
        Self(EdSigningKey::generate(&mut OsRng))
    }

    /// Rebuild from a base64url seed (32 bytes). Used when a device restores
    /// its identity from secure storage (Android Keystore, TPM, keyring).
    pub fn from_seed_b64(seed: &str) -> ProtoResult<Self> {
        let bytes = B64.decode(seed)?;
        let arr: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| ProtoError::BadKey("seed must be 32 bytes".into()))?;
        Ok(Self(EdSigningKey::from_bytes(&arr)))
    }

    pub fn seed_b64(&self) -> String {
        B64.encode(self.0.to_bytes())
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey(self.0.verifying_key())
    }

    /// Sign raw bytes. Callers decide what bytes mean; the envelope layer
    /// passes the canonical payload plus metadata.
    pub fn sign(&self, message: &[u8]) -> String {
        B64.encode(self.0.sign(message).to_bytes())
    }
}

impl VerifyingKey {
    pub fn from_b64(encoded: &str) -> ProtoResult<Self> {
        let bytes = B64.decode(encoded)?;
        let arr: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| ProtoError::BadKey("key must be 32 bytes".into()))?;
        let key =
            EdVerifyingKey::from_bytes(&arr).map_err(|e| ProtoError::BadKey(e.to_string()))?;
        Ok(Self(key))
    }

    pub fn to_b64(&self) -> String {
        B64.encode(self.0.to_bytes())
    }

    pub fn verify(&self, message: &[u8], signature_b64: &str) -> ProtoResult<()> {
        let sig_bytes = B64.decode(signature_b64)?;
        let arr: [u8; 64] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| ProtoError::BadSignature("signature must be 64 bytes".into()))?;
        let sig = Signature::from_bytes(&arr);
        self.0
            .verify_strict(message, &sig)
            .map_err(|e| ProtoError::BadSignature(e.to_string()))
    }
}

/// Serializable form used when persisting keys outside the secure enclave.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyBundle {
    pub seed_b64: String,
    pub verifying_b64: String,
}

impl KeyBundle {
    pub fn generate() -> Self {
        let sk = SigningKey::generate();
        Self {
            seed_b64: sk.seed_b64(),
            verifying_b64: sk.verifying_key().to_b64(),
        }
    }

    pub fn into_signing_key(self) -> ProtoResult<SigningKey> {
        SigningKey::from_seed_b64(&self.seed_b64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_roundtrip() {
        let sk = SigningKey::generate();
        let vk = sk.verifying_key();
        let msg = b"handoff token payload";
        let sig = sk.sign(msg);
        vk.verify(msg, &sig).expect("signature must verify");
    }

    #[test]
    fn tampered_payload_fails() {
        let sk = SigningKey::generate();
        let vk = sk.verifying_key();
        let sig = sk.sign(b"original");
        assert!(vk.verify(b"tampered", &sig).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let sk_a = SigningKey::generate();
        let sk_b = SigningKey::generate();
        let sig = sk_a.sign(b"payload");
        assert!(sk_b.verifying_key().verify(b"payload", &sig).is_err());
    }

    #[test]
    fn seed_roundtrip_preserves_identity() {
        let sk = SigningKey::generate();
        let restored = SigningKey::from_seed_b64(&sk.seed_b64()).expect("valid seed");
        assert_eq!(sk.verifying_key(), restored.verifying_key());
    }

    #[test]
    fn key_bundle_roundtrip() {
        let bundle = KeyBundle::generate();
        let sk = bundle.clone().into_signing_key().expect("valid bundle");
        assert_eq!(sk.verifying_key().to_b64(), bundle.verifying_b64);
    }

    #[test]
    fn rejects_malformed_b64() {
        assert!(VerifyingKey::from_b64("not base64!!").is_err());
    }
}
