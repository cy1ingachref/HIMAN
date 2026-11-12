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
pub mod signing;
pub mod task;

pub use device::{DeviceClass, DeviceId, DeviceInfo};
pub use envelope::{Payload, WireMessage, WireMeta};
pub use error::{ProtoError, ProtoResult};
pub use signing::{KeyBundle, SigningKey, VerifyingKey};
pub use task::{HandoffToken, RiskTier, TaskId, TaskState, ToolCall, ToolName};
