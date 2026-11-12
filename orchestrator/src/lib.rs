//! HIMAN orchestrator.
//!
//! Phase 1: in-memory state, no persistence yet. Components are wired
//! separately so the policy engine and presence manager can be tested in
//! isolation before the WebSocket hub lands.

pub mod audit;
pub mod policy;
pub mod presence;
pub mod state;

pub use audit::{AuditEvent, AuditLog};
pub use policy::{Decision, PolicyEngine};
pub use presence::{PresenceManager, PresenceSnapshot};
pub use state::{StateStore, TaskRecord};
