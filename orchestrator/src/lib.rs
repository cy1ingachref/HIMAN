//! HIMAN orchestrator.
//!
//! Components are wired separately so each can be tested in isolation before
//! the WebSocket hub lands.

pub mod audit;
pub mod enrollment;
pub mod hub;
pub mod orchkey;
pub mod policy;
pub mod presence;
pub mod server;
pub mod state;

pub use audit::{AuditEvent, AuditLog};
pub use enrollment::{check_enrollment, EnrollmentDecision, EnrollmentError, EnrollmentFile};
pub use hub::{DispatchResult, Hub, HubConfig};
pub use orchkey::{
    load_from_file as load_orchestrator_key_from_file,
    load_or_generate as load_or_generate_orchestrator_key, OrchestratorKeyError,
};
pub use policy::{Decision, PolicyConfig, PolicyEngine};
pub use presence::{PresenceManager, PresenceSnapshot};
pub use server::{router, serve, AppState};
pub use state::{StateStore, TaskRecord};

pub use himan_agent_core::init_logging;
