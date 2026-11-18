//! Presence manager: tracks which device is active and issues handoff tokens.
//!
//! Phase 1: in-memory only. The token is a signed authorization; signature
//! creation lives here, verification lives in the receiving agent.

use std::collections::HashMap;

use chrono::Utc;
use himan_proto::{DeviceId, DeviceInfo, HandoffToken, ProtoError, ProtoResult, TaskId};

use crate::policy::{Decision, PolicyEngine};

/// Snapshot of the current presence state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresenceSnapshot {
    pub active_device: Option<DeviceId>,
    pub online: Vec<DeviceId>,
}

pub struct PresenceManager {
    devices: HashMap<DeviceId, DeviceInfo>,
    active_device: Option<DeviceId>,
    policy: PolicyEngine,
    /// Token lifetime in seconds.
    ttl_secs: i64,
    /// Monotonic nonce source.
    next_nonce: u64,
}

impl PresenceManager {
    pub fn new(policy: PolicyEngine) -> Self {
        Self {
            devices: HashMap::new(),
            active_device: None,
            policy,
            ttl_secs: 300,
            next_nonce: 1,
        }
    }

    pub fn with_ttl(mut self, secs: i64) -> Self {
        self.ttl_secs = secs;
        self
    }

    pub fn register(&mut self, info: DeviceInfo) {
        self.devices.insert(info.id.clone(), info);
        if self.active_device.is_none() {
            self.active_device = Some(self.devices.keys().next().cloned().unwrap());
        }
    }

    /// Test support: the policy engine, so the enrollment boundary can be
    /// asserted directly rather than through the connection check.
    pub fn policy_snapshot_for_test(&self) -> &PolicyEngine {
        &self.policy
    }

    pub fn unregister(&mut self, id: &DeviceId) {
        self.devices.remove(id);
        if self.active_device.as_ref() == Some(id) {
            self.active_device = self.devices.keys().next().cloned();
        }
    }

    pub fn get(&self, id: &DeviceId) -> Option<&DeviceInfo> {
        self.devices.get(id)
    }

    pub fn active_device(&self) -> Option<&DeviceId> {
        self.active_device.as_ref()
    }

    pub fn snapshot(&self) -> PresenceSnapshot {
        PresenceSnapshot {
            active_device: self.active_device.clone(),
            online: self.devices.keys().cloned().collect(),
        }
    }

    /// Issue a handoff token for a task. Returns `Ok(token)` if policy allows,
    /// `Err` otherwise. The caller signs the token with the orchestrator key.
    pub fn issue_handoff(
        &mut self,
        task_id: TaskId,
        from: DeviceId,
        to: DeviceId,
    ) -> ProtoResult<HandoffToken> {
        if !self.devices.contains_key(&from) {
            return Err(ProtoError::Policy(
                "source device is not registered".to_owned(),
            ));
        }
        let target = self.devices.get(&to);
        match self.policy.evaluate_handoff(&from, &to, target) {
            Decision::Allow => {
                let nonce = self.next_nonce;
                self.next_nonce += 1;
                Ok(HandoffToken {
                    task_id,
                    from_device: from,
                    to_device: to,
                    expires_at: Utc::now().timestamp() + self.ttl_secs,
                    nonce,
                })
            }
            Decision::Deny(reason) => Err(ProtoError::Policy(reason)),
            Decision::RequireApproval => Err(ProtoError::Policy(
                "handoff unexpectedly requires approval".to_owned(),
            )),
        }
    }

    /// Flip the active device after a handoff is acknowledged.
    pub fn activate(&mut self, id: &DeviceId) -> ProtoResult<()> {
        if !self.devices.contains_key(id) {
            return Err(ProtoError::Policy(
                "cannot activate an unregistered device".to_owned(),
            ));
        }
        self.active_device = Some(id.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use himan_proto::DeviceClass;

    fn info(id: &str) -> DeviceInfo {
        DeviceInfo::new(DeviceId::new(id), DeviceClass::Pc, id.to_owned(), "unused")
    }

    fn manager() -> PresenceManager {
        let mut m = PresenceManager::new(PolicyEngine::default());
        m.register(info("pc-1"));
        m.register(info("phone-1"));
        m
    }

    #[test]
    fn first_registered_becomes_active() {
        let mut m = PresenceManager::new(PolicyEngine::default());
        m.register(info("pc-1"));
        assert_eq!(m.active_device().map(|d| d.as_str()), Some("pc-1"));
    }

    #[test]
    fn registers_and_lists_online() {
        let m = manager();
        let snap = m.snapshot();
        assert_eq!(snap.online.len(), 2);
    }

    #[test]
    fn handoff_token_is_issued() {
        let mut m = manager();
        let token = m
            .issue_handoff(
                TaskId::new("t1"),
                DeviceId::new("pc-1"),
                DeviceId::new("phone-1"),
            )
            .unwrap();
        assert_eq!(token.from_device.as_str(), "pc-1");
        assert_eq!(token.to_device.as_str(), "phone-1");
        assert_eq!(token.nonce, 1);
    }

    #[test]
    fn handoff_to_unknown_device_fails() {
        let mut m = manager();
        let result = m.issue_handoff(
            TaskId::new("t1"),
            DeviceId::new("pc-1"),
            DeviceId::new("pi-1"),
        );
        assert!(result.is_err());
    }

    #[test]
    fn handoff_from_unknown_device_fails() {
        let mut m = manager();
        let result = m.issue_handoff(
            TaskId::new("t1"),
            DeviceId::new("ghost"),
            DeviceId::new("phone-1"),
        );
        assert!(result.is_err());
    }

    #[test]
    fn nonces_are_monotonic() {
        let mut m = manager();
        let a = m
            .issue_handoff(
                TaskId::new("t1"),
                DeviceId::new("pc-1"),
                DeviceId::new("phone-1"),
            )
            .unwrap();
        let b = m
            .issue_handoff(
                TaskId::new("t2"),
                DeviceId::new("pc-1"),
                DeviceId::new("phone-1"),
            )
            .unwrap();
        assert_eq!(a.nonce + 1, b.nonce);
    }

    #[test]
    fn activate_flips_active_device() {
        let mut m = manager();
        assert_eq!(m.active_device().map(|d| d.as_str()), Some("pc-1"));
        m.activate(&DeviceId::new("phone-1")).unwrap();
        assert_eq!(m.active_device().map(|d| d.as_str()), Some("phone-1"));
    }

    #[test]
    fn activate_unknown_device_fails() {
        let mut m = manager();
        assert!(m.activate(&DeviceId::new("ghost")).is_err());
    }

    #[test]
    fn unregister_moves_active_to_next() {
        let mut m = manager();
        m.unregister(&DeviceId::new("pc-1"));
        assert_eq!(m.active_device().map(|d| d.as_str()), Some("phone-1"));
    }
}
