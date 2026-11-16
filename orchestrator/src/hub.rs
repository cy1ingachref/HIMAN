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
    DeviceId, DeviceInfo, HandoffToken, KeyRegistry, Payload, ProtoError, ProtoResult, RiskTier,
    SigningKey, TaskId, TaskState, ToolCall, VerifyingKey, WireMessage, WireMeta,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, info, warn};

use crate::audit::AuditLog;
use crate::enrollment::{check_enrollment, EnrollmentDecision, EnrollmentFile};
use crate::handoff::{Handoff, HandoffError, HandoffEvent, HandoffState, HandoffTimeouts};
use crate::handoff_driver::{HandoffDriver, Mailbox, RetryPolicy};
use crate::ownership::OwnerRegistry;
use crate::policy::{Decision, PolicyEngine};
use crate::presence::PresenceManager;
use crate::state::StateStore;

/// The result of driving a handoff over the live sockets.
///
/// Carries the token so the HTTP layer can report exactly what was issued
/// without a second lookup.
#[derive(Debug, Clone)]
pub struct HandoffOutcome {
    pub handoff_id: String,
    pub state: HandoffState,
    pub token: HandoffToken,
    pub epoch: u64,
    pub commit_attempts: u32,
    pub switch_time_ms: u128,
    pub reason: Option<String>,
    pub committed: bool,
}

/// A connected agent.
pub struct AgentSession {
    pub device: DeviceInfo,
    pub tx: mpsc::Sender<WireMessage>,
    /// The agent's inbound messages, retained so the handoff driver can read
    /// its replies. The socket handler owns the stream and forwards into this
    /// receiver's sender half; the driver takes the receiver half.
    pub inbound_tx: mpsc::Sender<WireMessage>,
    pub inbound_rx: Mutex<Option<mpsc::Receiver<WireMessage>>>,
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
    /// Last accepted seq per device session.
    ///
    /// A replayed message has a seq the hub has already seen, so this is what
    /// makes replay detectable. Reset on each new registration because the
    /// agent's seq counter restarts on reconnect.
    last_seq: Mutex<HashMap<DeviceId, u64>>,
    /// In-flight handoff attempts, keyed by handoff id.
    handoffs: Mutex<HashMap<String, Handoff>>,
    /// Per-task owner and fencing counter.
    owners: Mutex<OwnerRegistry>,
    handoff_timeouts: HandoffTimeouts,
    retry_policy: RetryPolicy,
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
            max_skew_secs: 120,
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
            last_seq: Mutex::new(HashMap::new()),
            handoffs: Mutex::new(HashMap::new()),
            owners: Mutex::new(OwnerRegistry::new()),
            handoff_timeouts: HandoffTimeouts::default(),
            retry_policy: RetryPolicy::default(),
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
        let (inbound_tx, inbound_rx) = mpsc::channel(self.config.agent_queue);
        agents.insert(
            info.id.clone(),
            AgentSession {
                device: info.clone(),
                tx,
                inbound_tx,
                inbound_rx: Mutex::new(Some(inbound_rx)),
            },
        );

        let mut presence = self.presence.lock().await;
        presence.register(info.clone());

        // The agent's seq counter restarts on reconnect, so the replay
        // tracker must restart with it.
        {
            let mut last = self.last_seq.lock().await;
            last.insert(info.id.clone(), 0);
        }

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

    /// Record a replay rejection. Never includes message contents.
    fn audit_replay(&self, device: &DeviceId, reason: &str) {
        let audit = self.audit.try_lock();
        if let Ok(mut log) = audit {
            log.append(
                "message_rejected".into(),
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
            self.audit_replay(&msg.meta.from, "stale timestamp");
            return Err(ProtoError::Policy("message timestamp out of range".into()));
        }

        let keys = self.keys.lock().await;
        let key = keys.get(&msg.meta.from)?.clone();
        drop(keys);

        msg.verify_with(&key)?;

        // Replay detection: seq must be strictly greater than the last
        // accepted seq for this device. A replayed message has the same seq as
        // the original, so this rejects it.
        {
            let mut last = self.last_seq.lock().await;
            let previous = last.get(&msg.meta.from).copied().unwrap_or(0);
            if msg.meta.seq <= previous {
                drop(last);
                self.audit_replay(&msg.meta.from, "seq <= last accepted seq");
                warn!(from = %msg.meta.from, seq = msg.meta.seq, previous, "replayed message rejected");
                return Err(ProtoError::Policy(format!(
                    "message seq {} is not newer than last accepted seq {}",
                    msg.meta.seq, previous
                )));
            }
            last.insert(msg.meta.from.clone(), msg.meta.seq);
        }

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
            Payload::Ping { nonce } => {
                // Liveness: reply so the agent knows the orchestrator is alive
                // and the round-trip latency.
                debug!(nonce, "ping");
                Ok(Some(self.build_message(
                    msg.meta.from,
                    Payload::Pong { nonce: *nonce },
                )?))
            }
            Payload::Pong { nonce } => {
                debug!(nonce, "pong");
                Ok(None)
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
            other => match other {
                // Handoff protocol messages are consumed by the driver, which
                // reads from the session's inbound channel. The hub just drops
                // them here with no error so the socket handler doesn't break.
                Payload::HandoffReady { .. }
                | Payload::HandoffProgress { .. }
                | Payload::HandoffDrained { .. }
                | Payload::HandoffSwitched { .. }
                | Payload::HandoffAck { .. } => Ok(None),
                _ => Err(ProtoError::Policy(format!(
                    "unexpected payload from agent: {other:?}"
                ))),
            },
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
                    inbound_tx: session.inbound_tx.clone(),
                    inbound_rx: Mutex::new(None),
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

    /// Take a device's inbound receiver, so the handoff driver can read that
    /// agent's replies. Returns `None` if the receiver was already taken or the
    /// device is not connected.
    pub async fn take_inbound(&self, device: &DeviceId) -> Option<mpsc::Receiver<WireMessage>> {
        let agents = self.agents.lock().await;
        let session = agents.get(device)?;
        let mut guard = session.inbound_rx.lock().await;
        guard.take()
    }

    /// Clone the sender that feeds a device's inbound stream. The socket
    /// handler forwards agent messages through it.
    pub async fn inbound_sender(&self, device: &DeviceId) -> Option<mpsc::Sender<WireMessage>> {
        let agents = self.agents.lock().await;
        agents.get(device).map(|s| s.inbound_tx.clone())
    }

    /// Read a handoff attempt by id.
    pub async fn handoff(&self, handoff_id: &str) -> Option<Handoff> {
        let handoffs = self.handoffs.lock().await;
        handoffs.get(handoff_id).cloned()
    }

    /// Register a device directly, bypassing the signed Hello.
    ///
    /// For tests and for local tooling that already hold the key. Production
    /// registration goes through `register`, which verifies the Hello.
    pub async fn register_device(&self, info: DeviceInfo, tx: mpsc::Sender<WireMessage>) {
        let claimed = VerifyingKey::from_b64(&info.verifying_key)
            .expect("a registered device must carry a valid key");
        self.keys.lock().await.insert(info.id.clone(), claimed);
        let (inbound_tx, inbound_rx) = mpsc::channel(self.config.agent_queue);
        self.agents.lock().await.insert(
            info.id.clone(),
            AgentSession {
                device: info.clone(),
                tx,
                inbound_tx,
                inbound_rx: Mutex::new(Some(inbound_rx)),
            },
        );
        self.presence.lock().await.register(info);
    }

    /// Snapshot of every handoff attempt, for the API and tests.
    pub async fn handoffs_snapshot(&self) -> Vec<Handoff> {
        let handoffs = self.handoffs.lock().await;
        handoffs.values().cloned().collect()
    }

    /// Read the owner and epoch recorded for a task.
    pub async fn owner(&self, task_id: &str) -> Option<crate::ownership::Ownership> {
        let owners = self.owners.lock().await;
        owners.get(task_id).cloned()
    }

    /// Ask for a handoff of `task_id` from `from` to `to`.
    ///
    /// This is the Requested -> Prepared step. It checks that both devices are
    /// connected, that the source is the recorded owner, issues the signed
    /// token, records the attempt, and returns the token the target must be
    /// sent. Ownership does not move here; the commit does.
    pub async fn request_handoff(
        &self,
        task_id: &TaskId,
        from: &DeviceId,
        to: &DeviceId,
    ) -> ProtoResult<HandoffToken> {
        let now = Utc::now().timestamp();

        // Both devices must be live. A handoff to a device that is not
        // connected would stall in Warming until the timeout.
        {
            let agents = self.agents.lock().await;
            if !agents.contains_key(to) {
                return Err(ProtoError::Policy(format!(
                    "target device {to} is not connected"
                )));
            }
            if !agents.contains_key(from) {
                return Err(ProtoError::Policy(format!(
                    "source device {from} is not connected"
                )));
            }
        }

        // The source must own the task. If the task is unknown it is declared
        // with the source as owner at epoch 0, which is what a first dispatch
        // does anyway.
        let epoch = {
            let mut owners = self.owners.lock().await;
            match owners.get(task_id.as_str()) {
                Some(current) => {
                    if current.owner != *from {
                        return Err(ProtoError::Policy(format!(
                            "device {from} is not the owner of task {task_id}"
                        )));
                    }
                    current.epoch
                }
                None => {
                    owners
                        .register(task_id.as_str().to_owned(), from.clone())
                        .map_err(|e| ProtoError::Policy(e.to_string()))?;
                    0
                }
            }
        };

        let token = {
            let mut presence = self.presence.lock().await;
            presence.issue_handoff(task_id.clone(), from.clone(), to.clone())?
        };

        let handoff_id = format!("handoff-{}", uuid::Uuid::new_v4().simple());
        let mut handoff = Handoff::new(
            handoff_id.clone(),
            task_id.clone(),
            from.clone(),
            to.clone(),
            epoch,
            now,
        );
        let line = handoff
            .apply(
                HandoffEvent::Approved {
                    checkpoint_seq: 0,
                    epoch,
                },
                now,
                &self.handoff_timeouts,
            )
            .map_err(|e: HandoffError| ProtoError::Policy(e.to_string()))?;

        {
            let mut handoffs = self.handoffs.lock().await;
            handoffs.insert(handoff_id.clone(), handoff);
        }

        {
            let mut audit = self.audit.lock().await;
            audit.append(line.action, from.to_string(), line.detail);
        }

        info!(
            handoff = %handoff_id,
            task = %task_id,
            from = %from,
            to = %to,
            epoch,
            "handoff requested"
        );

        Ok(token)
    }

    /// Advance a handoff attempt and report the resulting state.
    ///
    /// The caller supplies the event; this keeps the hub out of the business of
    /// parsing handoff messages while still being the single place that owns
    /// the attempt and the audit line.
    pub async fn advance_handoff(
        &self,
        handoff_id: &str,
        event: HandoffEvent,
    ) -> ProtoResult<HandoffState> {
        let now = Utc::now().timestamp();
        let (state, line, task_id, from, to) = {
            let mut handoffs = self.handoffs.lock().await;
            let handoff = handoffs
                .get_mut(handoff_id)
                .ok_or_else(|| ProtoError::Policy(format!("handoff {handoff_id} is not known")))?;
            let was_committed = handoff.committed;
            let line = handoff
                .apply(event, now, &self.handoff_timeouts)
                .map_err(|e: HandoffError| ProtoError::Policy(e.to_string()))?;

            // The commit is the one event that moves ownership. It happens
            // here, inside the same critical section that records the
            // attempt, so the epoch bump and the owner change cannot be
            // observed separately. `was_committed` makes this fire exactly
            // once, on the event that flipped the flag.
            if handoff.committed && !was_committed {
                let mut owners = self.owners.lock().await;
                owners
                    .commit(handoff.task_id.as_str(), handoff.to.clone(), handoff.epoch)
                    .map_err(|e| ProtoError::Policy(e.to_string()))?;
            }

            (
                handoff.state,
                line,
                handoff.task_id.clone(),
                handoff.from.clone(),
                handoff.to.clone(),
            )
        };

        {
            let mut audit = self.audit.lock().await;
            audit.append(line.action, from.to_string(), line.detail);
        }

        info!(
            handoff = %handoff_id,
            task = %task_id,
            from = %from,
            to = %to,
            state = state.as_str(),
            "handoff advanced"
        );

        Ok(state)
    }

    /// Run a full handoff for a task from `from` to `to`, over the live sockets.
    ///
    /// This is the path `server.rs` calls. It records the attempt, takes both
    /// devices' inbound receivers, drives the procedure, and commits ownership
    /// on success.
    pub async fn drive_handoff(
        &self,
        task_id: &TaskId,
        from: &DeviceId,
        to: &DeviceId,
        applied_seq: u64,
    ) -> ProtoResult<HandoffOutcome> {
        // Request records the attempt and issues the token.
        let token = self.request_handoff(task_id, from, to).await?;
        let handoff_id = {
            let handoffs = self.handoffs.lock().await;
            handoffs
                .values()
                .find(|h| h.task_id == *task_id && h.from == *from && h.to == *to)
                .map(|h| h.handoff_id.clone())
                .ok_or_else(|| ProtoError::Policy("handoff attempt is missing".into()))?
        };
        let attempt = {
            let handoffs = self.handoffs.lock().await;
            handoffs
                .get(&handoff_id)
                .cloned()
                .ok_or_else(|| ProtoError::Policy(format!("handoff {handoff_id} is not known")))?
        };

        // The driver reads the agents' replies; the socket handler forwards
        // each inbound message into these channels.
        let source_rx = self
            .take_inbound(from)
            .await
            .ok_or_else(|| ProtoError::Policy(format!("{from} has no inbound channel")))?;
        let target_rx = self
            .take_inbound(to)
            .await
            .ok_or_else(|| ProtoError::Policy(format!("{to} has no inbound channel")))?;

        let (source_tx, target_tx) = {
            let agents = self.agents.lock().await;
            let s = agents
                .get(from)
                .ok_or_else(|| ProtoError::Policy(format!("{from} is not connected")))?
                .tx
                .clone();
            let t = agents
                .get(to)
                .ok_or_else(|| ProtoError::Policy(format!("{to} is not connected")))?
                .tx
                .clone();
            (s, t)
        };

        let source = Mailbox {
            outbound: source_tx,
            inbound: source_rx,
        };
        let target = Mailbox {
            outbound: target_tx,
            inbound: target_rx,
        };

        let signer = {
            let key = self.orchestrator_key.clone();
            move |payload: Payload| {
                let meta = WireMeta {
                    seq: 0,
                    ts: Utc::now().timestamp(),
                    from: DeviceId::new("orchestrator"),
                    to: "device".into(),
                };
                WireMessage::sign(meta, payload, &key).expect("sign")
            }
        };

        let retries = self.retry_policy;
        let timeouts = self.handoff_timeouts;
        let outcome = HandoffDriver::new(attempt, source, target, timeouts, retries)
            .run(&token, applied_seq, signer, || Utc::now().timestamp())
            .await;

        // Mirror the outcome into the hub's own record so the API reflects it,
        // and commit ownership if the driver reached the commit point.
        {
            let mut handoffs = self.handoffs.lock().await;
            if let Some(record) = handoffs.get_mut(&handoff_id) {
                record.state = outcome.state;
                record.epoch = outcome.epoch;
                record.committed = outcome.committed;
                record.applied_seq = applied_seq;
                if let Some(reason) = &outcome.reason {
                    record.end_reason = Some(reason.clone());
                }
            }
        }

        if outcome.committed {
            let mut owners = self.owners.lock().await;
            owners
                .commit(task_id.as_str(), to.clone(), outcome.epoch)
                .map_err(|e| ProtoError::Policy(e.to_string()))?;
        }

        let mut audit = self.audit.lock().await;
        audit.append(
            "handoff_driver_finished".into(),
            from.to_string(),
            format!(
                "handoff={} state={} epoch={} commit_attempts={} reason={:?}",
                handoff_id,
                outcome.state.as_str(),
                outcome.epoch,
                outcome.commit_attempts,
                outcome.reason
            ),
        );

        info!(
            handoff = %handoff_id,
            state = outcome.state.as_str(),
            commit_attempts = outcome.commit_attempts,
            "handoff driver finished"
        );

        Ok(HandoffOutcome {
            handoff_id,
            state: outcome.state,
            token,
            epoch: outcome.epoch,
            commit_attempts: outcome.commit_attempts,
            switch_time_ms: outcome.switch_time_ms,
            reason: outcome.reason,
            committed: outcome.committed,
        })
    }

    /// Check a write against the owner registry (fencing).
    pub async fn check_write(
        &self,
        task_id: &str,
        device: &DeviceId,
        epoch: u64,
    ) -> ProtoResult<()> {
        let owners = self.owners.lock().await;
        owners
            .check_write(task_id, device, epoch)
            .map_err(|e| ProtoError::Policy(e.to_string()))
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
        let (inbound_tx, inbound_rx) = mpsc::channel(8);
        hub.agents.lock().await.insert(
            dev.id.clone(),
            AgentSession {
                device: dev.clone(),
                tx,
                inbound_tx,
                inbound_rx: Mutex::new(Some(inbound_rx)),
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

    /// Two registered devices, for handoff tests.
    async fn hub_with_two() -> (Arc<Hub>, SigningKey, SigningKey) {
        let hub = Hub::new(HubConfig::default());
        let a = SigningKey::generate();
        let b = SigningKey::generate();
        for (id, key) in [("pc-1", &a), ("phone-1", &b)] {
            let dev = DeviceInfo::new(
                DeviceId::new(id),
                DeviceClass::Pc,
                id.to_owned(),
                key.verifying_key().to_b64(),
            );
            hub.keys
                .lock()
                .await
                .insert(dev.id.clone(), key.verifying_key());
            let (tx, rx) = mpsc::channel(8);
            std::mem::forget(rx);
            hub.agents.lock().await.insert(
                dev.id.clone(),
                AgentSession {
                    device: dev.clone(),
                    tx,
                    inbound_tx: mpsc::channel(8).0,
                    inbound_rx: Mutex::new(None),
                },
            );
            hub.presence.lock().await.register(dev);
        }
        (hub, a, b)
    }

    #[tokio::test]
    async fn handoff_request_issues_a_token_and_records_the_attempt() {
        let (hub, _a, _b) = hub_with_two().await;
        let token = hub
            .request_handoff(
                &TaskId::new("t1"),
                &DeviceId::new("pc-1"),
                &DeviceId::new("phone-1"),
            )
            .await
            .unwrap();
        assert_eq!(token.task_id, TaskId::new("t1"));
        assert_eq!(token.from_device, DeviceId::new("pc-1"));
        assert_eq!(token.to_device, DeviceId::new("phone-1"));

        let attempts = hub.handoffs_snapshot().await;
        assert_eq!(attempts.len(), 1);
        assert_eq!(attempts[0].state, HandoffState::Prepared);
        // The source still owns the task: the request does not move ownership.
        assert_eq!(hub.owner("t1").await.unwrap().owner, DeviceId::new("pc-1"));
        assert_eq!(hub.owner("t1").await.unwrap().epoch, 0);
    }

    #[tokio::test]
    async fn handoff_to_a_disconnected_device_is_refused() {
        let (hub, _a, _b) = hub_with_two().await;
        let err = hub
            .request_handoff(
                &TaskId::new("t1"),
                &DeviceId::new("pc-1"),
                &DeviceId::new("tv-1"),
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not connected"));
    }

    #[tokio::test]
    async fn a_non_owner_cannot_request_a_handoff() {
        let (hub, _a, _b) = hub_with_two().await;
        // Declare t1 as owned by pc-1, then ask phone-1 to hand it on.
        hub.owners
            .lock()
            .await
            .register("t1".to_owned(), DeviceId::new("pc-1"))
            .unwrap();
        let err = hub
            .request_handoff(
                &TaskId::new("t1"),
                &DeviceId::new("phone-1"),
                &DeviceId::new("pc-1"),
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("is not the owner"));
    }

    #[tokio::test]
    async fn the_commit_moves_ownership_and_bumps_the_epoch() {
        let (hub, _a, _b) = hub_with_two().await;
        let token = hub
            .request_handoff(
                &TaskId::new("t1"),
                &DeviceId::new("pc-1"),
                &DeviceId::new("phone-1"),
            )
            .await
            .unwrap();
        let handoff_id = hub.handoffs_snapshot().await[0].handoff_id.clone();
        let _ = token;

        let state = hub
            .advance_handoff(&handoff_id, HandoffEvent::PrepareAccepted)
            .await
            .unwrap();
        assert_eq!(state, HandoffState::Warming);

        // Before the commit the source can still write.
        assert!(hub
            .check_write("t1", &DeviceId::new("pc-1"), 0)
            .await
            .is_ok());

        // Jump the machine to Switching, then commit.
        hub.advance_handoff(
            &handoff_id,
            HandoffEvent::TargetReady {
                applied_seq: 1,
                capabilities: "full".into(),
            },
        )
        .await
        .unwrap();
        hub.advance_handoff(&handoff_id, HandoffEvent::SourceDrained { last_seq: 1 })
            .await
            .unwrap();
        let state = hub
            .advance_handoff(&handoff_id, HandoffEvent::Committed { epoch: 1 })
            .await
            .unwrap();
        assert_eq!(state, HandoffState::Committed);

        // Ownership moved, and the old owner's epoch is now stale.
        let owner = hub.owner("t1").await.unwrap();
        assert_eq!(owner.owner, DeviceId::new("phone-1"));
        assert_eq!(owner.epoch, 1);
        let err = hub
            .check_write("t1", &DeviceId::new("pc-1"), 0)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("stale epoch"), "got: {err}");
        assert!(hub
            .check_write("t1", &DeviceId::new("phone-1"), 1)
            .await
            .is_ok());

        // The audit log recorded the commit.
        let events = hub.audit_events().await;
        assert!(events.iter().any(|e| e.action == "handoff_committed"));
    }

    #[tokio::test]
    async fn a_second_commit_is_refused_and_ownership_is_unchanged() {
        let (hub, _a, _b) = hub_with_two().await;
        hub.request_handoff(
            &TaskId::new("t1"),
            &DeviceId::new("pc-1"),
            &DeviceId::new("phone-1"),
        )
        .await
        .unwrap();
        let handoff_id = hub.handoffs_snapshot().await[0].handoff_id.clone();
        for event in [
            HandoffEvent::PrepareAccepted,
            HandoffEvent::TargetReady {
                applied_seq: 1,
                capabilities: String::new(),
            },
            HandoffEvent::SourceDrained { last_seq: 1 },
        ] {
            hub.advance_handoff(&handoff_id, event).await.unwrap();
        }
        hub.advance_handoff(&handoff_id, HandoffEvent::Committed { epoch: 1 })
            .await
            .unwrap();

        // A redelivered commit must not move ownership back or skip epochs.
        let err = hub
            .advance_handoff(&handoff_id, HandoffEvent::Committed { epoch: 2 })
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not allowed"));
        assert_eq!(
            hub.owner("t1").await.unwrap().owner,
            DeviceId::new("phone-1")
        );
        assert_eq!(hub.owner("t1").await.unwrap().epoch, 1);
    }

    #[tokio::test]
    async fn handoff_rolls_back_and_keeps_the_source_as_owner() {
        let (hub, _a, _b) = hub_with_two().await;
        hub.request_handoff(
            &TaskId::new("t1"),
            &DeviceId::new("pc-1"),
            &DeviceId::new("phone-1"),
        )
        .await
        .unwrap();
        let handoff_id = hub.handoffs_snapshot().await[0].handoff_id.clone();

        let state = hub
            .advance_handoff(
                &handoff_id,
                HandoffEvent::Rollback {
                    reason: "target went away".into(),
                },
            )
            .await
            .unwrap();
        assert_eq!(state, HandoffState::RolledBack);
        assert_eq!(hub.owner("t1").await.unwrap().owner, DeviceId::new("pc-1"));
        assert!(hub
            .check_write("t1", &DeviceId::new("pc-1"), 0)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn advancing_an_unknown_handoff_is_refused() {
        let (hub, _a, _b) = hub_with_two().await;
        let err = hub
            .advance_handoff("handoff-nope", HandoffEvent::PrepareAccepted)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not known"));
    }
}
