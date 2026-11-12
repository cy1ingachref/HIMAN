//! Agent client: connects to the orchestrator, registers, and runs tools.
//!
//! The receive loop is transport-agnostic so it can be tested over the
//! in-memory duplex. `WsTransport` is the production transport.

use std::sync::Arc;

use chrono::Utc;
use himan_agent_core::transport::Connection;
use himan_proto::{
    DeviceId, DeviceInfo, Payload, SigningKey, TaskState, VerifyingKey, WireMessage, WireMeta,
};
use tracing::{info, warn};

use crate::tools::registry;

/// Why a registration attempt failed.
#[derive(Debug, thiserror::Error)]
pub enum RegisterError {
    #[error("unexpected reply: got {0}, expected Welcome")]
    UnexpectedReply(&'static str),

    #[error("welcome nonce mismatch: the reply does not belong to this handshake")]
    NonceMismatch,

    #[error("welcome signature invalid: {0}")]
    BadSignature(String),

    #[error("connection closed before Welcome arrived")]
    Closed,

    #[error("transport error: {0}")]
    Transport(String),
}

/// A running agent session.
pub struct AgentClient {
    device_id: DeviceId,
    key: SigningKey,
    conn: Connection,
    seq: u64,
}

impl AgentClient {
    pub fn new(device_id: DeviceId, key: SigningKey, conn: Connection) -> Self {
        Self {
            device_id,
            key,
            conn,
            seq: 0,
        }
    }

    /// Sign and send a message.
    async fn send(&mut self, payload: Payload) -> Result<(), himan_proto::ProtoError> {
        self.seq += 1;
        let meta = WireMeta {
            seq: self.seq,
            ts: Utc::now().timestamp(),
            from: self.device_id.clone(),
            to: "orchestrator".into(),
        };
        let msg = WireMessage::sign(meta, payload, &self.key)?;
        self.conn
            .send(msg)
            .await
            .map_err(|_| himan_proto::ProtoError::Policy("connection closed".into()))
    }

    /// Send Hello and wait for a Welcome that is bound to this attempt.
    ///
    /// Four checks, in order:
    ///   1. a message arrived at all (connection not closed)
    ///   2. it is a `Welcome`, not an echo of our own Hello
    ///   3. its nonce matches the one in our Hello
    ///   4. its signature verifies against the orchestrator key it advertises
    ///
    /// Before this existed, any reply counted as success, so a transport that
    /// echoed outgoing messages back made registration look complete while the
    /// orchestrator never saw the agent.
    pub async fn register(&mut self) -> Result<DeviceInfo, RegisterError> {
        let info = DeviceInfo::new(
            self.device_id.clone(),
            himan_proto::DeviceClass::Pc,
            "PC agent",
            self.key.verifying_key().to_b64(),
        );
        let nonce = info.nonce.clone();
        self.send(Payload::Hello(info.clone()))
            .await
            .map_err(|e| RegisterError::Transport(e.to_string()))?;

        let msg = match self.conn.recv().await {
            Some(m) => m,
            None => return Err(RegisterError::Closed),
        };

        // Log what arrived, including the kind, so a single line distinguishes
        // a genuine Welcome from an echo of our own Hello.
        info!(
            kind = msg.payload.kind_name(),
            peer = %msg.meta.from,
            seq = msg.meta.seq,
            "received reply after Hello"
        );

        let (device_id, reply_nonce, orchestrator_key) = match &msg.payload {
            Payload::Welcome {
                device_id,
                nonce,
                orchestrator_key,
            } => (device_id.clone(), nonce.clone(), orchestrator_key.clone()),
            other => {
                let kind = other.kind_name();
                warn!(got = kind, "registration failed: expected Welcome");
                return Err(RegisterError::UnexpectedReply(kind));
            }
        };

        if device_id != self.device_id {
            warn!(%device_id, "welcome is for a different device");
            return Err(RegisterError::UnexpectedReply("welcome-for-other-device"));
        }

        if reply_nonce != nonce {
            warn!("welcome nonce mismatch: reply does not belong to this handshake");
            return Err(RegisterError::NonceMismatch);
        }

        // The Welcome carries the orchestrator's key, and is signed by it. An
        // attacker who reflects our own Hello cannot produce a valid signature
        // over a Welcome, so this check alone defeats the reflection attack.
        let vk = VerifyingKey::from_b64(&orchestrator_key)
            .map_err(|e| RegisterError::BadSignature(e.to_string()))?;
        msg.verify_with(&vk)
            .map_err(|e| RegisterError::BadSignature(e.to_string()))?;

        info!(
            %device_id,
            orchestrator_key = %orchestrator_key,
            "registered with orchestrator"
        );
        Ok(info)
    }

    /// Run the receive loop until the connection closes.
    ///
    /// Incoming `ToolCall`s are verified (the payload is self-describing; the
    /// signature is checked by the hub), then executed against the local tool
    /// registry. Results are sent back as signed `ToolResult`s.
    pub async fn run(&mut self) {
        let tools = registry();
        loop {
            let msg = match self.conn.recv().await {
                Some(m) => m,
                None => {
                    info!("connection closed, agent exiting");
                    break;
                }
            };

            match msg.payload {
                Payload::ToolCall(call) => {
                    info!(tool = %call.tool, task = %call.task_id, "tool call received");

                    // The whitelist is the security boundary: a call for a
                    // tool this device does not expose is refused, not run.
                    let result = match tools.resolve(&call.tool) {
                        Ok(tool) => match tool.run(&self.device_id, call.args).await {
                            Ok(output) => output,
                            Err(e) => {
                                if self
                                    .send(Payload::ToolResult {
                                        task_id: call.task_id,
                                        state: TaskState::Failed,
                                        output: e.to_string(),
                                    })
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                                continue;
                            }
                        },
                        Err(e) => {
                            let _ = self
                                .send(Payload::ToolResult {
                                    task_id: call.task_id,
                                    state: TaskState::Failed,
                                    output: e.to_string(),
                                })
                                .await;
                            continue;
                        }
                    };

                    let state = if result.ok {
                        TaskState::Succeeded
                    } else {
                        TaskState::Failed
                    };
                    if let Err(e) = self
                        .send(Payload::ToolResult {
                            task_id: call.task_id,
                            state,
                            output: result.summary,
                        })
                        .await
                    {
                        warn!(error = %e, "failed to send tool result");
                        break;
                    }
                }
                Payload::Ping { nonce } => {
                    if let Err(e) = self.send(Payload::Pong { nonce }).await {
                        warn!(error = %e, "failed to send pong");
                        break;
                    }
                }
                other => {
                    warn!(?other, "unexpected payload from orchestrator");
                }
            }
        }
    }

    /// The device's verifying key, base64.
    pub fn verifying_key_b64(&self) -> String {
        self.key.verifying_key().to_b64()
    }

    pub fn device_id(&self) -> &DeviceId {
        &self.device_id
    }
}

/// Build a client over a WebSocket URL.
pub async fn connect_ws(
    device_id: DeviceId,
    key: SigningKey,
    url: &str,
) -> Result<AgentClient, Box<dyn std::error::Error + Send + Sync>> {
    let transport = Arc::new(himan_agent_core::WsTransport::connect(url).await?);
    let conn = himan_agent_core::transport::ws::connection_from_socket(transport, 64);
    Ok(AgentClient::new(device_id, key, conn))
}

#[cfg(test)]
mod tests {
    use super::*;
    use himan_agent_core::transport::Connection;
    use himan_proto::{TaskId, ToolCall, ToolName};
    use serde_json::json;

    #[tokio::test]
    async fn register_sends_hello() {
        let (a, peer) = Connection::channel(8);
        let key = SigningKey::generate();
        let expected_key = key.verifying_key().to_b64();
        let mut client = AgentClient::new(DeviceId::new("pc-1"), key, a);

        let handle = tokio::spawn(async move { client.register().await });

        // The peer should see a signed Hello first, and its key must match
        // the key the client signs with.
        let hello = tokio::time::timeout(std::time::Duration::from_secs(2), peer.recv())
            .await
            .expect("hello should arrive")
            .expect("some message");
        match &hello.payload {
            Payload::Hello(info) => {
                assert_eq!(info.id.as_str(), "pc-1");
                assert_eq!(info.class, himan_proto::DeviceClass::Pc);
                assert_eq!(info.verifying_key, expected_key);
                let vk = himan_proto::VerifyingKey::from_b64(&expected_key).unwrap();
                assert!(
                    hello.verify_with(&vk).is_ok(),
                    "Hello must be signed by its own key"
                );
            }
            other => panic!("expected Hello, got {other:?}"),
        }

        // Reply Welcome, echoing the Hello nonce and signed by the
        // orchestrator key it advertises.
        let hello_nonce = match &hello.payload {
            Payload::Hello(info) => info.nonce.clone(),
            other => panic!("expected Hello, got {other:?}"),
        };
        let orch_key = SigningKey::generate();
        let orch_vk = orch_key.verifying_key().to_b64();
        let welcome = WireMessage::sign(
            WireMeta {
                seq: 1,
                ts: Utc::now().timestamp(),
                from: DeviceId::new("orchestrator"),
                to: "pc-1".into(),
            },
            Payload::Welcome {
                device_id: DeviceId::new("pc-1"),
                nonce: hello_nonce,
                orchestrator_key: orch_vk,
            },
            &orch_key,
        )
        .unwrap();
        peer.send(welcome).await.unwrap();

        let info = tokio::time::timeout(std::time::Duration::from_secs(2), handle)
            .await
            .expect("register should finish")
            .expect("task should not panic")
            .expect("register should succeed");
        assert_eq!(info.id.as_str(), "pc-1");
    }

    #[tokio::test]
    async fn register_fails_when_connection_closes() {
        let (a, b) = Connection::channel(8);
        let key = SigningKey::generate();
        let mut client = AgentClient::new(DeviceId::new("pc-1"), key, a);
        drop(b);
        assert!(client.register().await.is_err());
    }

    /// A transport that loops every outbound message back as inbound.
    ///
    /// This is the exact failure mode that produced the original bug: a
    /// single channel carrying both directions, so the agent read its own
    /// Hello and reported success. With strict registration this must fail
    /// loudly instead.
    #[tokio::test]
    async fn reflection_echo_is_rejected() {
        let (loop_tx, mut loop_rx) = tokio::sync::mpsc::channel::<WireMessage>(8);
        let (in_tx, in_rx) = tokio::sync::mpsc::channel::<WireMessage>(8);

        // Echo task: whatever the agent sends comes straight back to it.
        tokio::spawn(async move {
            while let Some(msg) = loop_rx.recv().await {
                if in_tx.send(msg).await.is_err() {
                    break;
                }
            }
        });

        let mut client = AgentClient::new(
            DeviceId::new("pc-1"),
            SigningKey::generate(),
            Connection::from_parts(
                loop_tx,
                in_rx,
                std::sync::Arc::new(himan_agent_core::transport::Shutdown::default()),
            ),
        );

        let result = client.register().await;
        match result {
            Err(RegisterError::UnexpectedReply(kind)) => {
                assert_eq!(
                    kind, "hello",
                    "the echo of a Hello must be reported as hello"
                );
            }
            other => panic!("expected UnexpectedReply(hello), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn welcome_with_wrong_nonce_is_rejected() {
        let (a, peer) = Connection::channel(8);
        let key = SigningKey::generate();
        let mut client = AgentClient::new(DeviceId::new("pc-1"), key, a);

        let handle = tokio::spawn(async move { client.register().await });

        // Drain the Hello so the peer knows the client started.
        let _hello = tokio::time::timeout(std::time::Duration::from_secs(2), peer.recv())
            .await
            .expect("hello should arrive")
            .expect("some message");

        // A Welcome with a nonce that does not match the Hello.
        let orch_key = SigningKey::generate();
        let welcome = WireMessage::sign(
            WireMeta {
                seq: 1,
                ts: Utc::now().timestamp(),
                from: DeviceId::new("orchestrator"),
                to: "pc-1".into(),
            },
            Payload::Welcome {
                device_id: DeviceId::new("pc-1"),
                nonce: "not-the-hello-nonce".into(),
                orchestrator_key: orch_key.verifying_key().to_b64(),
            },
            &orch_key,
        )
        .unwrap();
        peer.send(welcome).await.unwrap();

        let result = tokio::time::timeout(std::time::Duration::from_secs(2), handle)
            .await
            .expect("register should finish")
            .expect("task should not panic");
        match result {
            Err(RegisterError::NonceMismatch) => {}
            other => panic!("expected NonceMismatch, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn welcome_with_a_foreign_signature_is_rejected() {
        let (a, peer) = Connection::channel(8);
        let key = SigningKey::generate();
        let mut client = AgentClient::new(DeviceId::new("pc-1"), key, a);

        let handle = tokio::spawn(async move { client.register().await });

        let hello = tokio::time::timeout(std::time::Duration::from_secs(2), peer.recv())
            .await
            .expect("hello should arrive")
            .expect("some message");
        let hello_nonce = match &hello.payload {
            Payload::Hello(info) => info.nonce.clone(),
            other => panic!("expected Hello, got {other:?}"),
        };

        // The Welcome claims one orchestrator key but is signed by another, so
        // verification against the advertised key must fail.
        let claimed_key = SigningKey::generate();
        let signer = SigningKey::generate();
        let welcome = WireMessage::sign(
            WireMeta {
                seq: 1,
                ts: Utc::now().timestamp(),
                from: DeviceId::new("orchestrator"),
                to: "pc-1".into(),
            },
            Payload::Welcome {
                device_id: DeviceId::new("pc-1"),
                nonce: hello_nonce,
                orchestrator_key: claimed_key.verifying_key().to_b64(),
            },
            &signer,
        )
        .unwrap();
        peer.send(welcome).await.unwrap();

        let result = tokio::time::timeout(std::time::Duration::from_secs(2), handle)
            .await
            .expect("register should finish")
            .expect("task should not panic");
        match result {
            Err(RegisterError::BadSignature(_)) => {}
            other => panic!("expected BadSignature, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn run_executes_tool_call_and_replies() {
        let (a, peer) = Connection::channel(8);
        let key = SigningKey::generate();
        let mut client = AgentClient::new(DeviceId::new("pc-1"), key, a);

        let handle = tokio::spawn(async move { client.run().await });

        // Orchestrator sends a signed ToolCall for a whitelisted read-only tool.
        let call = ToolCall {
            task_id: TaskId::new("t1"),
            tool: ToolName::new("device_status"),
            args: json!({}),
            risk_tier: himan_proto::RiskTier::ReadOnly,
            target_device: DeviceId::new("pc-1"),
            nonce: 1,
        };
        let msg = WireMessage::sign(
            WireMeta {
                seq: 1,
                ts: Utc::now().timestamp(),
                from: DeviceId::new("orchestrator"),
                to: "pc-1".into(),
            },
            Payload::ToolCall(call),
            &SigningKey::generate(),
        )
        .unwrap();
        peer.send(msg).await.unwrap();

        let reply = tokio::time::timeout(std::time::Duration::from_secs(5), peer.recv())
            .await
            .expect("tool result should arrive")
            .expect("some message");
        match reply.payload {
            Payload::ToolResult {
                task_id,
                state,
                output,
            } => {
                assert_eq!(task_id.as_str(), "t1");
                assert_eq!(state, TaskState::Succeeded);
                assert!(output.contains("CPU"), "unexpected output: {output}");
            }
            other => panic!("expected ToolResult, got {other:?}"),
        }

        peer.close().await;
        handle.abort();
    }

    #[tokio::test]
    async fn run_refuses_non_whitelisted_tool() {
        let (a, peer) = Connection::channel(8);
        let key = SigningKey::generate();
        let mut client = AgentClient::new(DeviceId::new("pc-1"), key, a);

        let handle = tokio::spawn(async move { client.run().await });

        let call = ToolCall {
            task_id: TaskId::new("t2"),
            tool: ToolName::new("rm_rf"),
            args: json!({}),
            risk_tier: himan_proto::RiskTier::Destructive,
            target_device: DeviceId::new("pc-1"),
            nonce: 2,
        };
        let msg = WireMessage::sign(
            WireMeta {
                seq: 1,
                ts: Utc::now().timestamp(),
                from: DeviceId::new("orchestrator"),
                to: "pc-1".into(),
            },
            Payload::ToolCall(call),
            &SigningKey::generate(),
        )
        .unwrap();
        peer.send(msg).await.unwrap();

        let reply = tokio::time::timeout(std::time::Duration::from_secs(5), peer.recv())
            .await
            .expect("refusal should arrive")
            .expect("some message");
        match reply.payload {
            Payload::ToolResult { state, output, .. } => {
                assert_eq!(state, TaskState::Failed);
                assert!(
                    output.contains("not permitted") || output.contains("not installed"),
                    "unexpected output: {output}"
                );
            }
            other => panic!("expected ToolResult, got {other:?}"),
        }

        handle.abort();
    }
}
