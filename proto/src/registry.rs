use std::collections::HashMap;

use crate::error::{ProtoError, ProtoResult};
use crate::signing::VerifyingKey;

/// Maps device ids to their verifying keys.
///
/// This is the trust root for incoming messages: a message from an unknown
/// device is rejected before signature verification, and a key that changes
/// for a known device is rejected as a possible impersonation.
#[derive(Debug, Default)]
pub struct KeyRegistry {
    keys: HashMap<String, VerifyingKey>,
}

impl KeyRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register or replace a device's key.
    pub fn insert(&mut self, device: crate::device::DeviceId, key: VerifyingKey) {
        self.keys.insert(device.as_str().to_owned(), key);
    }

    /// Look up a device's key.
    pub fn get(&self, device: &crate::device::DeviceId) -> ProtoResult<&VerifyingKey> {
        self.keys
            .get(device.as_str())
            .ok_or_else(|| ProtoError::BadKey(format!("device {} is not registered", device)))
    }

    pub fn remove(&mut self, device: &crate::device::DeviceId) -> Option<VerifyingKey> {
        self.keys.remove(device.as_str())
    }

    pub fn contains(&self, device: &crate::device::DeviceId) -> bool {
        self.keys.contains_key(device.as_str())
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::DeviceId;
    use crate::signing::SigningKey;

    #[test]
    fn insert_and_get() {
        let mut reg = KeyRegistry::new();
        let sk = SigningKey::generate();
        reg.insert(DeviceId::new("pc-1"), sk.verifying_key());
        assert!(reg.contains(&DeviceId::new("pc-1")));
        assert!(reg.get(&DeviceId::new("pc-1")).is_ok());
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn unknown_device_is_rejected() {
        let reg = KeyRegistry::new();
        let err = reg.get(&DeviceId::new("ghost")).unwrap_err();
        assert!(err.to_string().contains("not registered"));
    }

    #[test]
    fn key_rotation_replaces_key() {
        let mut reg = KeyRegistry::new();
        let sk_a = SigningKey::generate();
        let sk_b = SigningKey::generate();
        reg.insert(DeviceId::new("pc-1"), sk_a.verifying_key());
        reg.insert(DeviceId::new("pc-1"), sk_b.verifying_key());
        assert_eq!(
            reg.get(&DeviceId::new("pc-1")).unwrap(),
            &sk_b.verifying_key()
        );
    }

    #[test]
    fn remove_drops_the_key() {
        let mut reg = KeyRegistry::new();
        let sk = SigningKey::generate();
        reg.insert(DeviceId::new("pc-1"), sk.verifying_key());
        assert!(reg.remove(&DeviceId::new("pc-1")).is_some());
        assert!(!reg.contains(&DeviceId::new("pc-1")));
    }
}
