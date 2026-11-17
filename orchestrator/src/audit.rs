//! Tamper-evident audit log.
//!
//! Phase 1: in-memory hash chain. Each entry carries the SHA-256 of the
//! previous entry, so appending a new entry after tampering with an earlier
//! one breaks the chain. This is not a replacement for writing the chain to
//! disk or to an append-only sink; that is Phase 5 work. But the data
//! structure is the same one used there.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// One audit event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub seq: u64,
    pub ts: i64,
    /// What happened, e.g. "tool_call_allowed", "handoff_issued".
    pub action: String,
    /// Device that caused the event, if any.
    pub actor: String,
    /// Free-form detail. Must not contain secrets.
    pub detail: String,
    /// SHA-256 of the previous event's canonical form. Genesis is all zeros.
    pub prev_hash: String,
    /// SHA-256 of this event's canonical form.
    pub hash: String,
}

pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Append-only hash-chained log.
#[derive(Debug, Default)]
pub struct AuditLog {
    events: Vec<AuditEvent>,
}

impl AuditLog {
    pub fn new() -> Self {
        let mut log = Self::default();
        log.append(
            "genesis".into(),
            "orchestrator".into(),
            "audit log initialized".into(),
        );
        log
    }

    /// Append an event. The hash chain is updated automatically.
    /// Append an event at an explicit timestamp.
    ///
    /// The durable store needs the timestamp it is about to write to match the
    /// one the in-memory log hashed, so the hub appends through this instead of
    /// letting the clock run twice.
    pub fn append_at(
        &mut self,
        action: String,
        actor: String,
        detail: String,
        ts: i64,
    ) -> &AuditEvent {
        let seq = self.events.len() as u64;
        let prev_hash = self
            .events
            .last()
            .map(|e| e.hash.clone())
            .unwrap_or_else(|| GENESIS_HASH.to_owned());

        let mut event = AuditEvent {
            seq,
            ts,
            action,
            actor,
            detail,
            prev_hash,
            hash: String::new(),
        };
        event.hash = hash_event(&event);
        self.events.push(event);
        self.events.last().unwrap()
    }

    pub fn append(&mut self, action: String, actor: String, detail: String) -> &AuditEvent {
        let ts = Utc::now().timestamp();
        self.append_at(action, actor, detail, ts)
    }

    pub fn events(&self) -> &[AuditEvent] {
        &self.events
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Recompute the chain and report the first break, if any.
    pub fn verify(&self) -> Result<(), usize> {
        let mut prev = GENESIS_HASH.to_owned();
        for (idx, event) in self.events.iter().enumerate() {
            if event.prev_hash != prev {
                return Err(idx);
            }
            let expected = hash_event(event);
            if expected != event.hash {
                return Err(idx);
            }
            prev = event.hash.clone();
        }
        Ok(())
    }
}

/// Canonical hash of an event. Excludes `hash` itself.
pub fn hash_event(event: &AuditEvent) -> String {
    let canonical = format!(
        "{}|{}|{}|{}|{}|{}",
        event.seq, event.ts, event.action, event.actor, event.detail, event.prev_hash
    );
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_with_genesis() {
        let log = AuditLog::new();
        assert_eq!(log.len(), 1);
        assert_eq!(log.events()[0].action, "genesis");
    }

    #[test]
    fn chain_verifies_after_appends() {
        let mut log = AuditLog::new();
        log.append(
            "tool_call_allowed".into(),
            "pc-1".into(),
            "device_status".into(),
        );
        log.append(
            "handoff_issued".into(),
            "orchestrator".into(),
            "pc-1 -> phone-1".into(),
        );
        assert_eq!(log.len(), 3);
        assert!(log.verify().is_ok());
    }

    #[test]
    fn tampering_breaks_the_chain() {
        let mut log = AuditLog::new();
        log.append("a".into(), "pc-1".into(), "detail".into());
        // Simulate an attacker rewriting history.
        log.events[1].detail = "forged".into();
        assert!(log.verify().is_err());
    }

    #[test]
    fn removing_a_middle_entry_breaks_the_chain() {
        let mut log = AuditLog::new();
        log.append("a".into(), "pc-1".into(), "one".into());
        log.append("b".into(), "pc-1".into(), "two".into());
        log.events.remove(1);
        assert!(log.verify().is_err());
    }

    #[test]
    fn removing_the_genesis_entry_breaks_the_chain() {
        let mut log = AuditLog::new();
        log.append("a".into(), "pc-1".into(), "one".into());
        log.events.remove(0);
        assert!(log.verify().is_err());
    }

    #[test]
    fn truncating_to_genesis_only_still_verifies() {
        // This is a limitation, not a feature: a log that keeps only the
        // genesis entry is internally consistent. Real tamper evidence comes
        // from exporting the chain to an append-only sink (Phase 5).
        let mut log = AuditLog::new();
        log.append("a".into(), "pc-1".into(), "one".into());
        log.events.truncate(1);
        assert!(log.verify().is_ok());
    }

    #[test]
    fn hashes_are_unique() {
        let mut log = AuditLog::new();
        log.append("a".into(), "pc-1".into(), "one".into());
        log.append("a".into(), "pc-1".into(), "two".into());
        let hashes: Vec<&str> = log.events().iter().map(|e| e.hash.as_str()).collect();
        assert_ne!(hashes[0], hashes[1]);
        assert_ne!(hashes[1], hashes[2]);
    }
}
