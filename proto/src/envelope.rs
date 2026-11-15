use serde::{Deserialize, Serialize};

use crate::device::{DeviceId, DeviceInfo};
use crate::error::ProtoResult;
use crate::signing::{SigningKey, VerifyingKey};
use crate::task::{HandoffToken, TaskId, TaskState, ToolCall, ToolName};

/// Envelope metadata, present on every message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireMeta {
    /// Monotonic message id, unique per sender.
    pub seq: u64,
    /// Unix timestamp in seconds.
    pub ts: i64,
    /// Sender device id.
    pub from: DeviceId,
    /// Recipient device id, or "orchestrator".
    pub to: String,
}

/// The payload. A closed enum — adding a variant is a protocol change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data")]
pub enum Payload {
    /// Agent announces itself and its tools.
    Hello(DeviceInfo),
    /// Orchestrator acknowledges registration and echoes the Hello nonce.
    /// Signed by the orchestrator key so the agent can prove it is talking to
    /// the real orchestrator and not a reflection of its own traffic.
    Welcome {
        device_id: DeviceId,
        /// Must equal the nonce from the Hello this replies to.
        nonce: String,
        /// The orchestrator's verifying key, so the agent can pin it.
        orchestrator_key: String,
    },
    /// Agent reports a status change (battery, connectivity, load).
    Status {
        state: String,
        detail: String,
    },
    /// Signed tool call from orchestrator to agent.
    ToolCall(ToolCall),
    /// Agent reports the outcome of a tool call.
    ToolResult {
        task_id: TaskId,
        state: TaskState,
        output: String,
    },
    /// Orchestrator asks the user for approval (relayed to phone).
    ApprovalRequest {
        task_id: TaskId,
        tool: ToolName,
        reason: String,
    },
    /// User's decision, signed by the phone's hardware-backed key.
    ApprovalResponse {
        task_id: TaskId,
        approved: bool,
    },
    /// Signed authorization to move a task between devices.
    Handoff(HandoffToken),
    /// Agent acknowledges a handoff token.
    HandoffAck {
        task_id: TaskId,
        accepted: bool,
    },
    /// Orchestrator approved the handoff: checkpoint taken, token issued.
    /// Sent to the target as the prepare step (spec section 4).
    HandoffPrepare {
        handoff_id: String,
        task_id: TaskId,
        from: DeviceId,
        to: DeviceId,
        epoch: u64,
        checkpoint_seq: u64,
        token: HandoffToken,
    },
    /// Target finished loading and reports its capabilities.
    HandoffReady {
        handoff_id: String,
        applied_seq: u64,
        capabilities: String,
    },
    /// Target reports shadow progress.
    HandoffProgress {
        handoff_id: String,
        applied_seq: u64,
    },
    /// Orchestrator tells the source to stop starting new steps.
    HandoffDrain {
        handoff_id: String,
        new_epoch: u64,
    },
    /// Source reached a safe point and stopped.
    HandoffDrained {
        handoff_id: String,
        last_seq: u64,
    },
    /// The commit point: epoch bumped, ownership moved to the target.
    HandoffCommit {
        handoff_id: String,
        new_epoch: u64,
        final_seq: u64,
    },
    /// Target confirmed the commit.
    HandoffSwitched {
        handoff_id: String,
        new_epoch: u64,
    },
    /// Handoff abandoned; both devices are told.
    HandoffRollback {
        handoff_id: String,
        reason: String,
    },
    /// Agent is going away (shutdown, network loss).
    Bye {
        reason: String,
    },
    /// Ping for liveness / latency measurement.
    Ping {
        nonce: u64,
    },
    Pong {
        nonce: u64,
    },
}

/// A signed message on the wire.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireMessage {
    pub meta: WireMeta,
    pub payload: Payload,
    /// Ed25519 signature over `signing_input()`.
    pub signature: String,
}

impl Payload {
    /// Stable lowercase name of the variant. Used in logs so a single line can
    /// show whether a reply was a Welcome or an echo.
    pub fn kind_name(&self) -> &'static str {
        match self {
            Payload::Hello(_) => "hello",
            Payload::Welcome { .. } => "welcome",
            Payload::Status { .. } => "status",
            Payload::ToolCall(_) => "tool_call",
            Payload::ToolResult { .. } => "tool_result",
            Payload::ApprovalRequest { .. } => "approval_request",
            Payload::ApprovalResponse { .. } => "approval_response",
            Payload::Handoff(_) => "handoff",
            Payload::HandoffAck { .. } => "handoff_ack",
            Payload::HandoffPrepare { .. } => "handoff_prepare",
            Payload::HandoffReady { .. } => "handoff_ready",
            Payload::HandoffProgress { .. } => "handoff_progress",
            Payload::HandoffDrain { .. } => "handoff_drain",
            Payload::HandoffDrained { .. } => "handoff_drained",
            Payload::HandoffCommit { .. } => "handoff_commit",
            Payload::HandoffSwitched { .. } => "handoff_switched",
            Payload::HandoffRollback { .. } => "handoff_rollback",
            Payload::Bye { .. } => "bye",
            Payload::Ping { .. } => "ping",
            Payload::Pong { .. } => "pong",
        }
    }
}

impl WireMessage {
    /// Build the canonical byte string that is signed.
    ///
    /// The envelope is included so that metadata tampering (seq, ts, from, to)
    /// invalidates the signature. Payload is serialized with serde_json's
    /// compact form; keys are in declaration order because serde preserves
    /// struct field order.
    pub fn signing_input(meta: &WireMeta, payload: &Payload) -> ProtoResult<Vec<u8>> {
        let meta_json = serde_json::to_vec(meta)?;
        let payload_json = serde_json::to_vec(payload)?;
        let mut out = Vec::with_capacity(meta_json.len() + payload_json.len() + 1);
        out.extend_from_slice(&meta_json);
        out.push(b'|');
        out.extend_from_slice(&payload_json);
        Ok(out)
    }

    /// Sign a message. The sender is taken from `meta.from`, so the caller
    /// must own that identity's key.
    pub fn sign(meta: WireMeta, payload: Payload, key: &SigningKey) -> ProtoResult<Self> {
        let input = Self::signing_input(&meta, &payload)?;
        let signature = key.sign(&input);
        Ok(Self {
            meta,
            payload,
            signature,
        })
    }

    /// Verify against a known key. This is the real entry point.
    pub fn verify_with(&self, key: &VerifyingKey) -> ProtoResult<()> {
        let input = Self::signing_input(&self.meta, &self.payload)?;
        key.verify(&input, &self.signature)
    }

    /// Reject implausible timestamps. Not a security control on its own —
    /// the signature already covers `ts` — but it drops replayed messages
    /// cheaply before they reach the policy engine.
    pub fn is_stale(&self, now_unix: i64, max_skew_secs: i64) -> bool {
        (now_unix - self.meta.ts).abs() > max_skew_secs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::DeviceClass;
    use crate::signing::SigningKey;

    fn sample_message() -> (WireMessage, SigningKey) {
        let sk = SigningKey::generate();
        let info = DeviceInfo::new(
            DeviceId::new("pc-1"),
            DeviceClass::Pc,
            "Ashe's PC",
            sk.verifying_key().to_b64(),
        );
        let meta = WireMeta {
            seq: 1,
            ts: 1_700_000_000,
            from: DeviceId::new("pc-1"),
            to: "orchestrator".into(),
        };
        let payload = Payload::Hello(info);
        let msg = WireMessage::sign(meta, payload, &sk).unwrap();
        (msg, sk)
    }

    #[test]
    fn sign_then_verify_succeeds() {
        let (msg, sk) = sample_message();
        assert!(msg.verify_with(&sk.verifying_key()).is_ok());
    }

    #[test]
    fn fails_with_wrong_key() {
        let (msg, _) = sample_message();
        let other = SigningKey::generate();
        assert!(msg.verify_with(&other.verifying_key()).is_err());
    }

    #[test]
    fn tampered_payload_fails() {
        let (mut msg, sk) = sample_message();
        msg.payload = Payload::Ping { nonce: 999 };
        assert!(msg.verify_with(&sk.verifying_key()).is_err());
    }

    #[test]
    fn tampered_meta_fails() {
        let (mut msg, sk) = sample_message();
        msg.meta.seq = 2;
        assert!(msg.verify_with(&sk.verifying_key()).is_err());
    }

    #[test]
    fn tampered_sender_fails() {
        // Spoofing `from` breaks the signature even if the payload is intact.
        let (mut msg, sk) = sample_message();
        msg.meta.from = DeviceId::new("phone-1");
        assert!(msg.verify_with(&sk.verifying_key()).is_err());
    }

    #[test]
    fn tampered_signature_fails() {
        let (mut msg, sk) = sample_message();
        msg.signature = SigningKey::generate().sign(b"other");
        assert!(msg.verify_with(&sk.verifying_key()).is_err());
    }

    #[test]
    fn serialized_roundtrip_preserves_signature() {
        let (msg, sk) = sample_message();
        let json = serde_json::to_string(&msg).unwrap();
        let back: WireMessage = serde_json::from_str(&json).unwrap();
        assert!(back.verify_with(&sk.verifying_key()).is_ok());
    }

    #[test]
    fn ping_pong_is_deterministic() {
        let a = Payload::Ping { nonce: 7 };
        let b = Payload::Ping { nonce: 7 };
        assert_eq!(
            serde_json::to_vec(&a).unwrap(),
            serde_json::to_vec(&b).unwrap()
        );
    }

    #[test]
    fn stale_detection_uses_absolute_skew() {
        let (msg, _) = sample_message();
        assert!(msg.is_stale(1_700_000_000 + 601, 600));
        assert!(msg.is_stale(1_700_000_000 - 601, 600));
        assert!(!msg.is_stale(1_700_000_000 + 599, 600));
    }

    fn handoff_payload() -> Payload {
        Payload::HandoffPrepare {
            handoff_id: "h1".into(),
            task_id: TaskId::new("t1"),
            from: DeviceId::new("pc-1"),
            to: DeviceId::new("phone-1"),
            epoch: 8,
            checkpoint_seq: 42,
            token: HandoffToken {
                task_id: TaskId::new("t1"),
                from_device: DeviceId::new("pc-1"),
                to_device: DeviceId::new("phone-1"),
                expires_at: 1_800_000_000,
                nonce: 7,
            },
        }
    }

    #[test]
    fn handoff_payloads_round_trip_through_json() {
        let payload = handoff_payload();
        let json = serde_json::to_string(&payload).unwrap();
        let back: Payload = serde_json::from_str(&json).unwrap();
        assert_eq!(back, payload);
    }

    #[test]
    fn handoff_payloads_use_the_tag_content_wire_form() {
        // The envelope is `#[serde(tag = "kind", content = "data")]`, so a
        // mismatch here would look like a server-side rejection in a red-team
        // run rather than a broken client.
        let json = serde_json::to_string(&handoff_payload()).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["kind"], "HandoffPrepare");
        assert_eq!(value["data"]["handoff_id"], "h1");
        assert_eq!(value["data"]["checkpoint_seq"], 42);
    }

    #[test]
    fn every_handoff_kind_has_a_stable_name() {
        let names = [
            Payload::Handoff(HandoffToken {
                task_id: TaskId::new("t1"),
                from_device: DeviceId::new("pc-1"),
                to_device: DeviceId::new("phone-1"),
                expires_at: 1,
                nonce: 1,
            }),
            Payload::HandoffAck {
                task_id: TaskId::new("t1"),
                accepted: true,
            },
            handoff_payload(),
            Payload::HandoffReady {
                handoff_id: "h1".into(),
                applied_seq: 3,
                capabilities: "full".into(),
            },
            Payload::HandoffProgress {
                handoff_id: "h1".into(),
                applied_seq: 4,
            },
            Payload::HandoffDrain {
                handoff_id: "h1".into(),
                new_epoch: 8,
            },
            Payload::HandoffDrained {
                handoff_id: "h1".into(),
                last_seq: 9,
            },
            Payload::HandoffCommit {
                handoff_id: "h1".into(),
                new_epoch: 8,
                final_seq: 9,
            },
            Payload::HandoffSwitched {
                handoff_id: "h1".into(),
                new_epoch: 8,
            },
            Payload::HandoffRollback {
                handoff_id: "h1".into(),
                reason: "target lost".into(),
            },
        ];
        let expected = [
            "handoff",
            "handoff_ack",
            "handoff_prepare",
            "handoff_ready",
            "handoff_progress",
            "handoff_drain",
            "handoff_drained",
            "handoff_commit",
            "handoff_switched",
            "handoff_rollback",
        ];
        let got: Vec<&str> = names.iter().map(|p| p.kind_name()).collect();
        assert_eq!(got, expected);
    }
}
