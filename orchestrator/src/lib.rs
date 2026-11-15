//! HIMAN orchestrator.
//!
//! Components are wired separately so each can be tested in isolation before
//! the WebSocket hub lands.

pub mod api_auth;
pub mod audit;
pub mod enrollment;
pub mod eventlog;
pub mod handoff;
pub mod handoff_driver;
pub mod hub;
pub mod orchkey;
pub mod ownership;
pub mod policy;
pub mod presence;
pub mod server;
pub mod startup;
pub mod state;

pub use startup::{enforce_startup, insecure_dev_enabled, log_posture, StartupRequirements};

pub use api_auth::{tokens_equal, ApiToken};
pub use audit::{AuditEvent, AuditLog};
pub use enrollment::{check_enrollment, EnrollmentDecision, EnrollmentError, EnrollmentFile};
pub use eventlog::{EventLog, EventPayload, TaskEvent};
pub use handoff::{
    AuditLine as HandoffAuditLine, Handoff, HandoffError, HandoffEvent, HandoffState,
    HandoffTimeouts,
};
pub use handoff_driver::{DriveOutcome, HandoffDriver, Mailbox, RetryPolicy};
pub use hub::{DispatchResult, Hub, HubConfig};
pub use orchkey::{
    load_from_file as load_orchestrator_key_from_file,
    load_or_generate as load_or_generate_orchestrator_key, OrchestratorKeyError,
};
pub use ownership::{FenceError, OwnerRegistry, Ownership};
pub use policy::{Decision, PolicyConfig, PolicyEngine};
pub use presence::{PresenceManager, PresenceSnapshot};
pub use server::{router, router_with_auth, router_with_limits, serve, AppState, WsLimits};
pub use state::{StateStore, TaskRecord};

pub use himan_agent_core::init_logging;
