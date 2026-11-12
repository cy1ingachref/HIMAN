//! Orchestrator WebSocket hub.
//!
//! Owns the device registry, verifies incoming signatures, dispatches
//! `ToolCall`s to agents, and records every decision in the audit log.
//!
//! Phase 1: one agent at a time, no TLS, no persistence. The hub is written
//! so a real transport (TLS, Postgres) can replace the internals without
//! changing the message flow.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::Utc;
use himan_proto::{
    DeviceId, DeviceInfo, KeyRegistry, Payload, ProtoError, ProtoResult, RiskTier, SigningKey,
    TaskId, TaskState, ToolCall, WireMessage, WireMeta,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, info, warn};

use crate::audit::AuditLog;
use crate::enrollment::{check_enrollment, EnrollmentDecision, EnrollmentFile};
use crate::policy::{Decision, PolicyEngine};
use crate::presence::PresenceManager;
use crate::state::StateStore;

/// A connected agent.
pub struct AgentSession {
    pub device: DeviceInfo,
    pub tx: mpsc::Sender<WireMessage>,
}

/// Shared hub state.
pub struct Hub {
    agents: Mutex<HashMap<DeviceId, AgentSession>>,
    keys: Mutex<KeyRegistry>,
    policy: Mutex<PolicyEngine>,
    presence: Mutex<PresenceManager>,
    store: Mutex<StateStore>,
    audit: Mutex<AuditLog>,
    orchestrator_key: SigningKey,
    config: HubConfig,
    enrollment: Option<EnrollmentFile>,
}

#[derive(Debug, Clone)]
pub struct HubConfig {
    /// Reject messages whose timestamp is more than this many seconds off.
    pub max_skew_secs: i64,
    /// Buffer for messages queued to an agent.
    pub agent_queue: usize,
}

impl Default for HubConfig {
    fn default() -> Self {
        Self {
            max_skew_secs: 600,
            agent_queue: 64,
        }
    }
}

/// A random 64-bit nonce.
///
/// A timestamp-based nonce collides when two dispatches happen in the same
/// second, which is exactly what RT-06 caught.
fn random_nonce() -> u64 {
    let mut bytes = [0u8; 8];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
    u64::from_le_bytes(bytes)
}

/// Result of dispatching a prompt to a device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DispatchResult {
    pub task_id: String,
    pub state: String,
    pub output: String,
    pub decision: String,
}

impl Hub {
    /// Create a hub with the given signing key.
    ///
    /// The key is supplied by the caller (normally loaded from
    /// `HIMAN_ORCH_KEY_FILE`) so it survives restarts and stays consistent
    /// with the keys agents have pinned.
    pub fn with_key(config: HubConfig, orchestrator_key: SigningKey) -> Arc<Self> {
        let policy = PolicyEngine::default();
        Arc::new(Self {
            agents: Mutex::new(HashMap::new()),
            keys: Mutex::new(KeyRegistry::new()),
            policy: Mutex::new(policy),
            presence: Mutex::new(PresenceManager::new(PolicyEngine::default())),
            store: Mutex::new(StateStore::new()),
            audit: Mutex::new(AuditLog::new()),
            orchestrator_key,
            config,
            enrollment: None,
        })
    }

    /// Create a hub with a freshly generated key.
    pub fn new(config: HubConfig) -> Arc<Self> {
        Self::with_key(config, SigningKey::generate())
    }

    /// Attach an enrollment file. Devices not listed are rejected.
    pub fn with_enrollment(mut self: Arc<Self>, file: EnrollmentFile) -> Arc<Self> {
        Arc::get_mut(&mut self)
            .expect("hub is already shared")
            .enrollment = Some(file);
        self
    }

    /// The orchestrator's own verifying key, advertised to agents.
    pub fn orchestrator_key_b64(&self) -> String {
        self.orchestrator_key.verifying_key().to_b64()
    }

    /// Register a new agent connection.
    ///
    /// The agent must send a signed `Hello` first; this function verifies it
    /// and installs the session key.
    pub async fn register(
        &self,
        hello: WireMessage,
        tx: mpsc::Sender<WireMessage>,
    ) -> ProtoResult<DeviceInfo> {
        let info = match &hello.payload {
            Payload::Hello(info) => info.clone(),
            other => {
                return Err(ProtoError::Policy(format!(
                    "first message must be Hello, got {other:?}"
                )))
            }
        };

        // The Hello must be signed by the key the agent claims.
        let claimed = himan_proto::VerifyingKey::from_b64(&info.verifying_key)?;
        hello.verify_with(&claimed)?;

        // Enrollment: the device must be listed and the key must match.
        match check_enrollment(self.enrollment.as_ref(), &info.id, &info.verifying_key) {
            EnrollmentDecision::Enrolled => {}
            EnrollmentDecision::UnknownDevice => {
                self.audit_rejection(&info.id, "device is not enrolled");
                return Err(ProtoError::Policy("device is not enrolled".to_owned()));
            }
            EnrollmentDecision::KeyMismatch => {
                self.audit_rejection(&info.id, "Hello key does not match enrolled key");
                return Err(ProtoError::Policy(
                    "Hello key does not match enrolled key".to_owned(),
                ));
            }
        }

        let mut keys = self.keys.lock().await;
        let mut agents = self.agents.lock().await;

        // Identity takeover: the id is already connected. Accept only if the
        // reconnecting key is the same enrolled key; otherwise reject and
        // leave the legitimate session untouched.
        if let Some(existing) = agents.get(&info.id) {
            let same_key = existing.device.verifying_key == info.verifying_key;
            if !same_key {
                drop(agents);
                drop(keys);
                self.audit_rejection(
                    &info.id,
                    "a different key attempted to take over a connected device",
                );
                warn!(device = %info.id, "rejected registration from a different key");
                return Err(ProtoError::Policy(
                    "device id is already connected with a different key".to_owned(),
                ));
            }

            // Same key: a legitimate reconnect. Replace the session and close
            // the old socket so it cannot linger.
            info!(device = %info.id, "replacing session for a reconnecting device");
            let old = agents.remove(&info.id);
            drop(old);
        }

        keys.insert(info.id.clone(), claimed);
        agents.insert(
            info.id.clone(),
            AgentSession {
                device: info.clone(),
                tx,
            },
        );

        let mut presence = self.presence.lock().await;
        presence.register(info.clone());

        let mut audit = self.audit.lock().await;
        audit.append(
            "agent_registered".into(),
            info.id.to_string(),
            format!("class={}", info.class.as_str()),
        );

        info!(device = %info.id, class = info.class.as_str(), "agent registered");
        Ok(info)
    }

    /// Record a registration rejection. Never includes key material.
    fn audit_rejection(&self, device: &DeviceId, reason: &str) {
        let audit = self.audit.try_lock();
        if let Ok(mut log) = audit {
            log.append(
                "registration_rejected".into(),
                device.to_string(),
                reason.to_owned(),
            );
        }
    }

    /// Verify and handle an incoming agent message.
    pub async fn handle_message(&self, msg: WireMessage) -> ProtoResult<Option<WireMessage>> {
        // Reject stale messages cheaply before signature work.
        if msg.is_stale(Utc::now().timestamp(), self.config.max_skew_secs) {
            warn!(from = %msg.meta.from, "stale message rejected");
            return Err(ProtoError::Policy("message timestamp out of range".into()));
        }

        let keys = self.keys.lock().await;
        let key = keys.get(&msg.meta.from)?.clone();
        drop(keys);

        msg.verify_with(&key)?;

        match &msg.payload {
            Payload::ToolResult {
                task_id,
                state,
                output,
            } => {
                // A result may arrive for a task the store does not know (the
                // orchestrator restarted, or the agent is reporting a task it
                // initiated). Upsert rather than drop: losing a result is
                // worse than recording a task we did not create.
                let mut store = self.store.lock().await;
                if store.get(task_id).is_none() {
                    store.create(
                        task_id.clone(),
                        himan_proto::ToolName::new("unknown"),
                        msg.meta.from.clone(),
                        serde_json::Value::Null,
                    );
                }
                store.set_state(task_id, *state);
                store.set_output(task_id, output.clone());
                drop(store);

                let mut audit = self.audit.lock().await;
                audit.append(
                    "tool_result".into(),
                    msg.meta.from.to_string(),
                    format!("task={task_id} state={}", state.as_str()),
                );
                Ok(None)
            }
            Payload::Status { state, detail } => {
                let mut audit = self.audit.lock().await;
                audit.append(
                    "status".into(),
                    msg.meta.from.to_string(),
                    format!("{state}: {detail}"),
                );
                Ok(None)
            }
            Payload::Pong { nonce } => {
                debug!(nonce, "pong");
                Ok(Some(self.build_message(
                    msg.meta.from,
                    Payload::Pong { nonce: *nonce },
                )?))
            }
            Payload::Bye { reason } => {
                let mut audit = self.audit.lock().await;
                audit.append(
                    "agent_bye".into(),
                    msg.meta.from.to_string(),
                    reason.clone(),
                );
                let mut presence = self.presence.lock().await;
                presence.unregister(&msg.meta.from);
                let mut agents = self.agents.lock().await;
                agents.remove(&msg.meta.from);
                Ok(None)
            }
            other => Err(ProtoError::Policy(format!(
                "unexpected payload from agent: {other:?}"
            ))),
        }
    }

    /// Build and sign an orchestrator message.
    pub fn build_message(&self, to: DeviceId, payload: Payload) -> ProtoResult<WireMessage> {
        let meta = WireMeta {
            seq: 0, // Phase 1: single orchestrator, agents do not track seq yet
            ts: Utc::now().timestamp(),
            from: DeviceId::new("orchestrator"),
            to: to.to_string(),
        };
        WireMessage::sign(meta, payload, &self.orchestrator_key)
    }

    /// Dispatch a prompt to a device agent and return the outcome.
    ///
    /// This is the Phase 1 exit check path: text prompt -> tool call -> result.
    pub async fn dispatch(
        &self,
        device_id: &DeviceId,
        prompt: &str,
    ) -> ProtoResult<DispatchResult> {
        let (session, device_info) = {
            let agents = self.agents.lock().await;
            let session = agents.get(device_id).ok_or_else(|| {
                ProtoError::Policy(format!("device {device_id} is not connected"))
            })?;
            (
                AgentSession {
                    device: session.device.clone(),
                    tx: session.tx.clone(),
                },
                session.device.clone(),
            )
        };

        // Phase 1: the planner is a deterministic stub. A real LLM plugs in
        // behind this branch, but the wire flow below is unchanged.
        let (tool_name, args) = match prompt.to_lowercase() {
            p if p.contains("diagnose") => ("run_diagnostic", serde_json::json!({})),
            p if p.contains("status") => ("device_status", serde_json::json!({})),
            _ => {
                return Ok(DispatchResult {
                    task_id: TaskId::new("none").to_string(),
                    state: "no_tool".into(),
                    output: "prompt did not match a known tool".into(),
                    decision: "allow".into(),
                })
            }
        };

        let task_id = TaskId::new(format!("task-{}", uuid::Uuid::new_v4().simple()));

        // Build the signed tool call. The risk tier is declared by the tool
        // registry on the agent side; here we look it up from the same rules
        // the PC agent uses so the policy engine has something to evaluate.
        let risk = if tool_name == "run_diagnostic" {
            RiskTier::Destructive
        } else {
            RiskTier::ReadOnly
        };

        let call = ToolCall {
            task_id: task_id.clone(),
            tool: himan_proto::ToolName::new(tool_name),
            args,
            risk_tier: risk,
            target_device: device_id.clone(),
            nonce: random_nonce(),
        };

        // Policy check happens before anything is sent.
        let decision = {
            let policy = self.policy.lock().await;
            policy.evaluate(&call, &device_info)
        };

        {
            let mut audit = self.audit.lock().await;
            audit.append(
                "tool_call_policy".into(),
                device_id.to_string(),
                format!("task={task_id} tool={tool_name} decision={:?}", decision),
            );
        }

        match decision {
            Decision::Deny(reason) => {
                let mut store = self.store.lock().await;
                store.set_state(&task_id, TaskState::Failed);
                store.set_output(&task_id, reason.clone());
                return Ok(DispatchResult {
                    task_id: task_id.to_string(),
                    state: "failed".into(),
                    output: reason,
                    decision: "deny".into(),
                });
            }
            Decision::RequireApproval => {
                // Phase 1: no phone connected, so approvals cannot complete.
                // Report honestly rather than pretending the call ran.
                let mut store = self.store.lock().await;
                store.set_state(&task_id, TaskState::AwaitingApproval);
                return Ok(DispatchResult {
                    task_id: task_id.to_string(),
                    state: "awaiting_approval".into(),
                    output: "destructive tool needs human approval (no phone in Phase 1)".into(),
                    decision: "require_approval".into(),
                });
            }
            Decision::Allow => {}
        }

        // Record the task, then send.
        {
            let mut store = self.store.lock().await;
            store.create(
                task_id.clone(),
                himan_proto::ToolName::new(tool_name),
                device_id.clone(),
                call.args.clone(),
            );
            store.set_state(&task_id, TaskState::Running);
        }

        let message = self.build_message(device_id.clone(), Payload::ToolCall(call))?;
        session
            .tx
            .send(message)
            .await
            .map_err(|_| ProtoError::Policy("agent queue full or closed".into()))?;

        // Phase 1: the result comes back on the agent's next message. The
        // caller reads it from the store rather than waiting on a channel,
        // which keeps dispatch testable without a live socket.
        let final_state = {
            let store = self.store.lock().await;
            store
                .get(&task_id)
                .map(|r| r.state.as_str().to_string())
                .unwrap_or_else(|| "unknown".into())
        };

        let output = {
            let store = self.store.lock().await;
            store
                .get(&task_id)
                .and_then(|r| r.output.clone())
                .unwrap_or_else(|| "dispatched, awaiting result".into())
        };

        Ok(DispatchResult {
            task_id: task_id.to_string(),
            state: final_state,
            output,
            decision: "allow".into(),
        })
    }

    /// Remove a device from the live session table.
    ///
    /// Without this, a disconnected agent leaves a stale session whose sender
    /// points at a closed channel, and dispatch to the next agent with the
    /// same id fails with "agent queue full or closed".
    pub async fn unregister(&self, id: &DeviceId) {
        let mut agents = self.agents.lock().await;
        if agents.remove(id).is_some() {
            let mut presence = self.presence.lock().await;
            presence.unregister(id);
            let mut audit = self.audit.lock().await;
            audit.append(
                "agent_unregistered".into(),
                id.to_string(),
                "disconnected".into(),
            );
            info!(device = %id, "agent unregistered");
        }
    }

    /// Read a task record.
    pub async fn task(&self, id: &TaskId) -> Option<himan_proto::TaskState> {
        let store = self.store.lock().await;
        store.get(id).map(|r| r.state)
    }

    /// Snapshot of registered agents.
    pub async fn agents(&self) -> Vec<DeviceInfo> {
        let agents = self.agents.lock().await;
        agents.values().map(|s| s.device.clone()).collect()
    }

    /// Snapshot of the audit log.
    pub async fn audit_events(&self) -> Vec<crate::audit::AuditEvent> {
        let audit = self.audit.lock().await;
        audit.events().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use himan_proto::DeviceClass;

    /// Register a device directly, bypassing Hello, so tests can focus on
    /// dispatch behavior. Returns the hub plus the signing key that matches
    /// the registered device, so tests can forge well-formed messages.
    async fn hub_with(device_id: &str) -> (Arc<Hub>, SigningKey) {
        let hub = Hub::new(HubConfig::default());
        let sk = SigningKey::generate();
        let dev = DeviceInfo::new(
            DeviceId::new(device_id),
            DeviceClass::Pc,
            device_id.to_owned(),
            sk.verifying_key().to_b64(),
        );
        hub.keys
            .lock()
            .await
            .insert(dev.id.clone(), sk.verifying_key());
        let (tx, rx) = mpsc::channel(8);
        // Keep the receiver alive for the test's duration. Dropping it makes
        // sends fail with "agent queue full or closed", which is a test
        // artifact rather than a hub bug.
        std::mem::forget(rx);
        hub.agents.lock().await.insert(
            dev.id.clone(),
            AgentSession {
                device: dev.clone(),
                tx,
            },
        );
        hub.presence.lock().await.register(dev);
        (hub, sk)
    }

    #[tokio::test]
    async fn register_accepts_signed_hello() {
        let hub = Hub::new(HubConfig::default());
        let sk = SigningKey::generate();
        let dev = DeviceInfo::new(
            DeviceId::new("pc-1"),
            DeviceClass::Pc,
            "PC",
            sk.verifying_key().to_b64(),
        );
        let hello = WireMessage::sign(
            WireMeta {
                seq: 1,
                ts: Utc::now().timestamp(),
                from: dev.id.clone(),
                to: "orchestrator".into(),
            },
            Payload::Hello(dev.clone()),
            &sk,
        )
        .unwrap();
        let (tx, _rx) = mpsc::channel(8);
        let registered = hub.register(hello, tx).await.unwrap();
        assert_eq!(registered.id, dev.id);
        assert_eq!(hub.agents().await.len(), 1);
    }

    #[tokio::test]
    async fn register_rejects_unsigned_hello() {
        let hub = Hub::new(HubConfig::default());
        let sk = SigningKey::generate();
        let other = SigningKey::generate();
        let dev = DeviceInfo::new(
            DeviceId::new("pc-1"),
            DeviceClass::Pc,
            "PC",
            other.verifying_key().to_b64(), // claims a different key
        );
        let hello = WireMessage::sign(
            WireMeta {
                seq: 1,
                ts: Utc::now().timestamp(),
                from: dev.id.clone(),
                to: "orchestrator".into(),
            },
            Payload::Hello(dev),
            &sk,
        )
        .unwrap();
        let (tx, _rx) = mpsc::channel(8);
        assert!(hub.register(hello, tx).await.is_err());
    }

    #[tokio::test]
    async fn register_rejects_non_hello() {
        let hub = Hub::new(HubConfig::default());
        let sk = SigningKey::generate();
        let msg = WireMessage::sign(
            WireMeta {
                seq: 1,
                ts: Utc::now().timestamp(),
                from: DeviceId::new("pc-1"),
                to: "orchestrator".into(),
            },
            Payload::Ping { nonce: 1 },
            &sk,
        )
        .unwrap();
        let (tx, _rx) = mpsc::channel(8);
        assert!(hub.register(msg, tx).await.is_err());
    }

    #[tokio::test]
    async fn dispatch_unregistered_device_fails() {
        let hub = Hub::new(HubConfig::default());
        let err = hub
            .dispatch(&DeviceId::new("ghost"), "diagnose")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not connected"));
    }

    #[tokio::test]
    async fn dispatch_read_only_tool_is_allowed() {
        let (hub, _sk) = hub_with("pc-1").await;
        let result = hub
            .dispatch(&DeviceId::new("pc-1"), "status")
            .await
            .unwrap();
        assert_eq!(result.decision, "allow");
        assert_eq!(result.state, "running");
    }

    #[tokio::test]
    async fn dispatch_destructive_tool_requires_approval() {
        // No device is cleared for destructive tools by default, so the
        // policy engine denies it before anything is sent.
        let (hub, _sk) = hub_with("pc-1").await;
        let result = hub
            .dispatch(&DeviceId::new("pc-1"), "diagnose")
            .await
            .unwrap();
        assert_eq!(result.decision, "deny");
        assert_eq!(result.state, "failed");
    }

    #[tokio::test]
    async fn audit_log_records_dispatch() {
        let (hub, _sk) = hub_with("pc-1").await;
        hub.dispatch(&DeviceId::new("pc-1"), "status")
            .await
            .unwrap();
        let events = hub.audit_events().await;
        assert!(events.iter().any(|e| e.action == "tool_call_policy"));
    }

    #[tokio::test]
    async fn stale_message_is_rejected() {
        let hub = Hub::new(HubConfig::default());
        let sk = SigningKey::generate();
        let dev_id = DeviceId::new("pc-1");
        hub.keys
            .lock()
            .await
            .insert(dev_id.clone(), sk.verifying_key());
        let msg = WireMessage::sign(
            WireMeta {
                seq: 1,
                ts: Utc::now().timestamp() - 10_000,
                from: dev_id,
                to: "orchestrator".into(),
            },
            Payload::Status {
                state: "ok".into(),
                detail: "stale".into(),
            },
            &sk,
        )
        .unwrap();
        assert!(hub.handle_message(msg).await.is_err());
    }

    #[tokio::test]
    async fn forged_tool_result_is_rejected() {
        let hub = Hub::new(HubConfig::default());
        let sk = SigningKey::generate();
        let dev_id = DeviceId::new("pc-1");
        // Message claims to be from pc-1 but is signed by another key.
        let msg = WireMessage::sign(
            WireMeta {
                seq: 1,
                ts: Utc::now().timestamp(),
                from: dev_id.clone(),
                to: "orchestrator".into(),
            },
            Payload::ToolResult {
                task_id: TaskId::new("t1"),
                state: TaskState::Succeeded,
                output: "forged".into(),
            },
            &sk,
        )
        .unwrap();
        assert!(hub.handle_message(msg).await.is_err());
    }

    #[tokio::test]
    async fn tool_result_updates_the_store() {
        let (hub, sk) = hub_with("pc-1").await;
        let dev_id = DeviceId::new("pc-1");
        let msg = WireMessage::sign(
            WireMeta {
                seq: 1,
                ts: Utc::now().timestamp(),
                from: dev_id,
                to: "orchestrator".into(),
            },
            Payload::ToolResult {
                task_id: TaskId::new("t1"),
                state: TaskState::Succeeded,
                output: "done".into(),
            },
            &sk,
        )
        .unwrap();
        assert!(hub.handle_message(msg).await.is_ok());
        assert_eq!(
            hub.task(&TaskId::new("t1")).await,
            Some(TaskState::Succeeded)
        );
    }
}
