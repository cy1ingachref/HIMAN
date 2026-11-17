use serde::{Deserialize, Serialize};
use std::str::FromStr;

use crate::error::{ProtoError, ProtoResult};

pub use crate::device::{DeviceClass, DeviceId, DeviceInfo};

/// How dangerous a tool call is. Drives the policy engine and the approval UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskTier {
    /// Read-only. No approval required. e.g. `device_status`, `list_files`.
    ReadOnly,
    /// Reversible side effect. Logged, but no approval. e.g. `show_notification`.
    Reversible,
    /// Destructive or hard to reverse. Requires human approval. e.g. `upload_file`,
    /// `run_diagnostic` (which may restart a service).
    Destructive,
}

impl RiskTier {
    pub fn as_str(&self) -> &'static str {
        match self {
            RiskTier::ReadOnly => "read_only",
            RiskTier::Reversible => "reversible",
            RiskTier::Destructive => "destructive",
        }
    }

    pub fn requires_approval(&self) -> bool {
        matches!(self, RiskTier::Destructive)
    }
}

impl FromStr for RiskTier {
    type Err = ProtoError;

    fn from_str(s: &str) -> ProtoResult<Self> {
        match s {
            "read_only" => Ok(RiskTier::ReadOnly),
            "reversible" => Ok(RiskTier::Reversible),
            "destructive" => Ok(RiskTier::Destructive),
            other => Err(ProtoError::UnknownKind(other.to_owned())),
        }
    }
}

/// Whether re-issuing a tool call with the same idempotency key can cause a
/// second side effect. Drives the handoff switch procedure (docs/HANDOFF.md
/// section 2): a `NonIdempotent` call must finish on the current owner before
/// the switch, while an `Idempotent` one may be re-issued on the new owner with
/// the same `call_id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
// `rename_all = "lowercase"` would render `NonIdempotent` as "nonidempotent";
// the spec and `as_str()` both use "non_idempotent", so name it explicitly.
#[serde(rename_all = "snake_case")]
pub enum Idempotency {
    /// Safe to re-issue with the same `call_id`, e.g. `device_status`.
    Idempotent,
    /// Must run at most once, e.g. deleting a file or sending a message.
    NonIdempotent,
}

impl Idempotency {
    pub fn as_str(&self) -> &'static str {
        match self {
            Idempotency::Idempotent => "idempotent",
            Idempotency::NonIdempotent => "non_idempotent",
        }
    }
}

/// A tool name, type-checked at the protocol boundary.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ToolName(pub String);

impl ToolName {
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ToolName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Stable identifier for a task. Ulid-like string form is intentional: it is
/// lexicographically sortable by creation time.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TaskId(pub String);

impl TaskId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for TaskId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Lifecycle of a task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TaskState {
    /// Created, not yet dispatched.
    Pending,
    /// Dispatched to a device agent.
    Running,
    /// Waiting on a human approval.
    AwaitingApproval,
    /// Completed successfully.
    Succeeded,
    /// Failed (tool error or policy rejection).
    Failed,
    /// Cancelled by the user.
    Cancelled,
}

impl TaskState {
    pub fn as_str(&self) -> &'static str {
        match self {
            TaskState::Pending => "pending",
            TaskState::Running => "running",
            TaskState::AwaitingApproval => "awaiting_approval",
            TaskState::Succeeded => "succeeded",
            TaskState::Failed => "failed",
            TaskState::Cancelled => "cancelled",
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            TaskState::Succeeded | TaskState::Failed | TaskState::Cancelled
        )
    }
}

/// A signed request to run a tool on a device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolCall {
    pub task_id: TaskId,
    pub tool: ToolName,
    /// JSON object of arguments. Schema is defined by the tool registry.
    pub args: serde_json::Value,
    pub risk_tier: RiskTier,
    /// Device the call is destined for.
    pub target_device: DeviceId,
    /// Monotonic counter, used to reject replayed calls.
    pub nonce: u64,
}

/// Authorization to move a task from one device to another.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandoffToken {
    pub task_id: TaskId,
    pub from_device: DeviceId,
    pub to_device: DeviceId,
    /// Unix timestamp (seconds) after which the token is void.
    pub expires_at: i64,
    pub nonce: u64,
}

impl HandoffToken {
    pub fn is_expired(&self, now_unix: i64) -> bool {
        now_unix >= self.expires_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn risk_tier_parses_lowercase() {
        assert_eq!(RiskTier::from_str("read_only").unwrap(), RiskTier::ReadOnly);
        assert_eq!(
            RiskTier::from_str("destructive").unwrap(),
            RiskTier::Destructive
        );
        assert!(RiskTier::from_str("bogus").is_err());
    }

    #[test]
    fn only_destructive_requires_approval() {
        assert!(!RiskTier::ReadOnly.requires_approval());
        assert!(!RiskTier::Reversible.requires_approval());
        assert!(RiskTier::Destructive.requires_approval());
    }

    #[test]
    fn terminal_states_are_final() {
        assert!(TaskState::Succeeded.is_terminal());
        assert!(TaskState::Failed.is_terminal());
        assert!(TaskState::Cancelled.is_terminal());
        assert!(!TaskState::Running.is_terminal());
        assert!(!TaskState::AwaitingApproval.is_terminal());
    }

    #[test]
    fn handoff_token_expiry() {
        let token = HandoffToken {
            task_id: TaskId::new("t1"),
            from_device: DeviceId::new("pc"),
            to_device: DeviceId::new("phone"),
            expires_at: 1000,
            nonce: 1,
        };
        assert!(!token.is_expired(999));
        assert!(token.is_expired(1000));
        assert!(token.is_expired(1001));
    }

    #[test]
    fn idempotency_serializes_lowercase() {
        assert_eq!(
            serde_json::to_string(&Idempotency::Idempotent).unwrap(),
            "\"idempotent\""
        );
        assert_eq!(
            serde_json::to_string(&Idempotency::NonIdempotent).unwrap(),
            "\"non_idempotent\""
        );
        assert_eq!(Idempotency::Idempotent.as_str(), "idempotent");
        assert_eq!(Idempotency::NonIdempotent.as_str(), "non_idempotent");
    }

    #[test]
    fn device_class_serializes_lowercase() {
        assert_eq!(
            serde_json::to_string(&DeviceClass::Phone).unwrap(),
            "\"phone\""
        );
    }
}
