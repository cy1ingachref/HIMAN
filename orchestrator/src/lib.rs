//! HIMAN orchestrator.
//!
//! Components are wired separately so each can be tested in isolation before
//! the WebSocket hub lands.

pub mod audit;
pub mod hub;
pub mod policy;
pub mod presence;
pub mod server;
pub mod state;

pub use audit::{AuditEvent, AuditLog};
pub use hub::{DispatchResult, Hub, HubConfig};
pub use policy::{Decision, PolicyConfig, PolicyEngine};
pub use presence::{PresenceManager, PresenceSnapshot};
pub use server::{router, serve, AppState};
pub use state::{StateStore, TaskRecord};
