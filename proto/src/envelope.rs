use serde::{Deserialize, Serialize};

use crate::device::{DeviceId, DeviceInfo};
use crate::error::{ProtoError, ProtoResult};
use crate::signing::VerifyingKey;
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
    /// Orchestrator acknowledges registration.
    Welcome {
        device_id: DeviceId,
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

    pub fn verify(&self) -> ProtoResult<()> {
        let vk = VerifyingKey::from_b64(self.meta.from.as_str())
            .map_err(|_| ProtoError::BadKey("sender key not registered locally".into()))?;
        let _ = vk; // placeholder; real verify uses the registry in the orchestrator
                    // NOTE: this method is superseded by `verify_with` which takes a key.
        Err(ProtoError::BadSignature("use verify_with(key)".into()))
    }

    /// Verify against a known key. This is the real entry point; `verify`
    /// exists only to make the API obvious at the call site.
    pub fn verify_with(&self, key: &VerifyingKey) -> ProtoResult<()> {
        let input = Self::signing_input(&self.meta, &self.payload)?;
        key.verify(&input, &self.signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::DeviceClass;
    use crate::signing::SigningKey;

    fn sample_message() -> (WireMessage, SigningKey) {
        let sk = SigningKey::generate();
        let info = DeviceInfo {
            id: DeviceId::new("pc-1"),
            class: DeviceClass::Pc,
            label: "Ashe's PC".into(),
            verifying_key: sk.verifying_key().to_b64(),
        };
        let meta = WireMeta {
            seq: 1,
            ts: 1_700_000_000,
            from: DeviceId::new("pc-1"),
            to: "orchestrator".into(),
        };
        let payload = Payload::Hello(info);
        let input = WireMessage::signing_input(&meta, &payload).unwrap();
        let signature = sk.sign(&input);
        (
            WireMessage {
                meta,
                payload,
                signature,
            },
            sk,
        )
    }

    #[test]
    fn verifies_with_correct_key() {
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
}
