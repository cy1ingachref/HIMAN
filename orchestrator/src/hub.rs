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
    /// its replies. The socket handler publishes into `inbound_tx`; the driver
    /// subscribes with `inbound Subscribe` and never takes the receiver away,
    /// so a reply is never dropped while a handoff is in flight.
    pub inbound_tx: tokio::sync::broadcast::Sender<WireMessage>,
}

/// A deterministic scenario task the orchestrator is driving.
///
/// AC-1 needs a task that is long enough to interrupt and exactly
/// reproducible. The orchestrator owns the step counter: it dispatches one
/// `scenario_step` tool call per step, so the source runs the prefix it was
/// issued before the handoff and the target runs the rest after the commit.
/// Exactly-once is therefore an orchestrator guarantee, observable in its own
/// event log, rather than an accident of one process's loop.
#[derive(Debug, Clone)]
struct ScenarioRun {
    owner: DeviceId,
    total: u64,
    /// Steps dispatched so far.
    issued: u64,
    /// The tool this run issues: `scenario_step` (idempotent) or
    /// `scenario_effect` (non-idempotent).
    tool: String,
}

/// Shared hub state.
pub struct Hub {
    agents: Mutex<HashMap<DeviceId, AgentSession>>,
    keys: Mutex<KeyRegistry>,
    policy: Mutex<PolicyEngine>,
    presence: Mutex<PresenceManager>,
    store: Mutex<StateStore>,
    audit: Arc<Mutex<AuditLog>>,
    /// Device ids revoked durably. Checked before enrollment and before
    /// any message is handled.
    revoked: Mutex<std::collections::HashSet<String>>,
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
    /// The orchestrator's own append-only task event log.
    ///
    /// The handoff checkpoint is derived from this log's head, never from a
    /// client-supplied `applied_seq` (see docs/DECISIONS.md).
    event_log: Mutex<crate::eventlog::EventLog>,
    /// Deterministic scenario tasks in flight, keyed by task id.
    scenarios: Mutex<HashMap<String, ScenarioRun>>,
    /// Tasks whose source has been asked to drain.
    ///
    /// A drained source must not start a new step; the scenario loop parks
    /// until the handoff commit moves ownership.
    drained: Mutex<std::collections::HashSet<String>>,
    /// Durable state, when `HIMAN_STATE_FILE` was set. `None` means the
    /// orchestrator runs in memory only.
    durable: std::sync::Mutex<Option<crate::durable::DurableStore>>,
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
            audit: Arc::new(Mutex::new(AuditLog::new())),
            revoked: Mutex::new(std::collections::HashSet::new()),
            orchestrator_key,
            config,
            enrollment: None,
            last_seq: Mutex::new(HashMap::new()),
            handoffs: Mutex::new(HashMap::new()),
            owners: Mutex::new(OwnerRegistry::new()),
            handoff_timeouts: HandoffTimeouts::default(),
            retry_policy: RetryPolicy::default(),
            event_log: Mutex::new(crate::eventlog::EventLog::new()),
            scenarios: Mutex::new(HashMap::new()),
            drained: Mutex::new(std::collections::HashSet::new()),
            durable: std::sync::Mutex::new(None),
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

        // A revoked device is refused before any signature work or session
        // creation. Revocation is checked first so a revoked key cannot even
        // attempt a re-registration.
        if self.is_revoked(&info.id).await {
            self.audit_rejection(&info.id, "device is revoked").await;
            return Err(ProtoError::Policy("device is revoked".to_owned()));
        }

        // The Hello must be signed by the key the agent claims.
        let claimed = himan_proto::VerifyingKey::from_b64(&info.verifying_key)?;
        hello.verify_with(&claimed)?;

        // Enrollment: the device must be listed and the key must match.
        match check_enrollment(self.enrollment.as_ref(), &info.id, &info.verifying_key) {
            EnrollmentDecision::Enrolled => {}
            EnrollmentDecision::UnknownDevice => {
                self.audit_rejection(&info.id, "device is not enrolled")
                    .await;
                return Err(ProtoError::Policy("device is not enrolled".to_owned()));
            }
            EnrollmentDecision::KeyMismatch => {
                self.audit_rejection(&info.id, "Hello key does not match enrolled key")
                    .await;
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
                )
                .await;
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
        // Broadcast so the handoff driver can subscribe without taking the
        // receiver away from the socket handler.
        let (inbound_tx, _inbound_rx) = tokio::sync::broadcast::channel(self.config.agent_queue);
        agents.insert(
            info.id.clone(),
            AgentSession {
                device: info.clone(),
                tx,
                inbound_tx,
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

        self.audit(
            "agent_registered".to_string(),
            info.id.to_string(),
            format!("class={}", info.class.as_str()),
        )
        .await;

        info!(device = %info.id, class = info.class.as_str(), "agent registered");
        drop(presence);
        // A newly connected device is a candidate for any task that stalled
        // with no owner available. Offer them now.
        self.offer_stalled_to(&info.id).await;
        Ok(info)
    }

    /// Offer every persisted stalled task to a device that just connected.
    ///
    /// A task whose owner died with no other device online stays stalled; this
    /// is what picks it up when one comes back.
    async fn offer_stalled_to(&self, device: &DeviceId) {
        let stalled: Vec<crate::durable::StalledRecord> = {
            let guard = self.durable.lock().expect("durable lock");
            match guard.as_ref() {
                None => return,
                Some(store) => match store.stalled() {
                    Ok(rows) => rows,
                    Err(e) => {
                        tracing::error!(error = %e, "failed to read stalled tasks");
                        return;
                    }
                },
            }
        };
        for record in stalled {
            // The device that died is not a candidate.
            if record.owner == device.as_str() {
                continue;
            }
            // Take the epoch from the live registry, not the persisted row: the
            // stall already moved it, and `commit` requires exactly +1.
            let new_epoch = {
                let owners = self.owners.lock().await;
                owners
                    .get(&record.task_id)
                    .map(|o| o.epoch + 1)
                    .unwrap_or(record.epoch + 1)
            };
            {
                let mut owners = self.owners.lock().await;
                let _ = owners.commit(&record.task_id, device.clone(), new_epoch);
            }
            {
                let guard = self.durable.lock().expect("durable lock");
                if let Some(store) = guard.as_ref() {
                    let _ = store.set_stalled_offered(&record.task_id, device.as_str());
                }
            }
            self.audit(
                "task_offered".to_string(),
                "orchestrator".to_string(),
                format!(
                    "task={} to={} epoch={} reason=an enrolled device connected",
                    record.task_id, device, new_epoch
                ),
            )
            .await;
            tracing::info!(task = %record.task_id, to = %device, "stalled task offered");
        }
    }

    /// Record a registration rejection. Never includes key material.
    async fn audit_rejection(&self, device: &DeviceId, reason: &str) {
        self.audit(
            "registration_rejected".to_string(),
            device.to_string(),
            reason.to_owned(),
        )
        .await;
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

        if self.is_revoked(&msg.meta.from).await {
            self.audit_replay(&msg.meta.from, "message from a revoked device");
            return Err(ProtoError::Policy("device is revoked".to_owned()));
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
                // Fencing: only the current owner may report a result. A stale
                // old owner that writes after the switch is rejected and
                // audit-logged, which is the section-8 "stale epoch" row.
                let fenced = {
                    let owners = self.owners.lock().await;
                    match owners.get(task_id.as_str()) {
                        Some(current) if current.owner != msg.meta.from => Err(format!(
                            "device {} reported a result for task {task_id} but {} owns it",
                            msg.meta.from, current.owner
                        )),
                        _ => Ok(()),
                    }
                };
                if let Err(reason) = fenced {
                    self.audit(
                        "stale_epoch_write".to_string(),
                        msg.meta.from.to_string(),
                        reason.clone(),
                    )
                    .await;
                    warn!("{reason}");
                    return Ok(None);
                }

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
                self.persist_task_record(task_id).await;

                self.audit(
                    "tool_result".to_string(),
                    msg.meta.from.to_string(),
                    format!("task={task_id} state={}", state.as_str()),
                )
                .await;
                Ok(None)
            }
            Payload::Status { state, detail } => {
                self.audit(
                    "status".to_string(),
                    msg.meta.from.to_string(),
                    format!("{state}: {detail}"),
                )
                .await;
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
                self.audit(
                    "agent_bye".to_string(),
                    msg.meta.from.to_string(),
                    reason.clone(),
                )
                .await;
                let mut presence = self.presence.lock().await;
                presence.unregister(&msg.meta.from);
                let mut agents = self.agents.lock().await;
                agents.remove(&msg.meta.from);
                drop(presence);
                drop(agents);
                // The device is gone. Any task it owned is now stalled: mark it,
                // bump the epoch, and offer it to the original source if it is
                // still connected, else to another enrolled device.
                self.stall_tasks_of(&msg.meta.from).await;
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
        self: &Arc<Self>,
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
                },
                session.device.clone(),
            )
        };

        // The planner. The deterministic stub is the default; a real model
        // plugs in behind the same branch. The scenario prompts stay on the
        // stub: they drive the handoff tests and must not depend on a model.
        let (tool_name, args): (String, serde_json::Value) = match prompt.to_lowercase() {
            // The deterministic scenario task. The orchestrator drives it: it
            // issues one `scenario_step` tool call per step, so the step count
            // is exact and observable in the orchestrator's own event log.
            // The non-idempotent variant must be matched before the plain
            // scenario arm: a prompt can contain both words.
            p if p.contains("effect") => ("scenario_effect".into(), serde_json::json!({})),
            p if p.contains("scenario") => ("scenario_step".into(), serde_json::json!({})),
            _ => {
                // Natural language: ask the planner. With a model configured
                // the answer is a proposed tool call, validated below against
                // the whitelist and the schema; without one the scripted stub
                // answers. Either way the model never decides policy.
                match self.plan(device_id, prompt).await {
                    Some((name, args)) => (name, args),
                    None => {
                        return Ok(DispatchResult {
                            task_id: TaskId::new("none").to_string(),
                            state: "no_tool".into(),
                            output: "the planner proposed no tool for this prompt".into(),
                            decision: "allow".into(),
                        })
                    }
                }
            }
        };
        let tool_name = tool_name.as_str();

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
            args: args.clone(),
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
            self.audit(
                "tool_call_policy".to_string(),
                device_id.to_string(),
                format!("task={task_id} tool={tool_name} decision={:?}", decision),
            )
            .await;
        }

        match decision {
            Decision::Deny(reason) => {
                let mut store = self.store.lock().await;
                store.set_state(&task_id, TaskState::Failed);
                store.set_output(&task_id, reason.clone());
                drop(store);
                self.persist_task_record(&task_id).await;
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
                drop(store);
                self.persist_task_record(&task_id).await;
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
        self.persist_task_record(&task_id).await;

        // Record the task durably, so a restart can load its owner and log even
        // if no handoff ever happens.
        {
            let guard = self.durable.lock().expect("durable lock");
            if let Some(store) = guard.as_ref() {
                if let Err(e) = store.ensure_task(task_id.as_str(), device_id.as_str()) {
                    tracing::error!(error = %e, "failed to persist the task record");
                }
            }
        }

        // The owner registry is what stall detection scans, so the task must
        // be registered here, not only when a handoff is requested.
        {
            let mut owners = self.owners.lock().await;
            if let Err(e) = owners.register(task_id.as_str().to_owned(), device_id.clone()) {
                tracing::error!(error = %e, task = %task_id, "failed to register the owner");
            }
        }

        // A scenario task is driven by the orchestrator: one tool call per
        // step, each with its own call id, so exactly-once is decided here.
        // The total comes from the prompt ("... of N steps"), not from the
        // caller-supplied arguments, so a test cannot quietly change the run
        // length through the wire.
        if tool_name == "scenario_step" || tool_name == "scenario_effect" {
            let total = prompt
                .split_whitespace()
                .map(str::parse::<u64>)
                .find_map(Result::ok)
                .unwrap_or(20)
                // The upper bound keeps a typo from dispatching an unbounded
                // run. It is above the largest log size the metrics sweep
                // measures (10000 events), so a sweep is not silently capped.
                .clamp(1, 20000);
            {
                let mut runs = self.scenarios.lock().await;
                runs.insert(
                    task_id.to_string(),
                    ScenarioRun {
                        owner: device_id.clone(),
                        tool: tool_name.to_string(),
                        total,
                        issued: 0,
                    },
                );
            }
            // Record the task, as the plain tool-call path does, so the task's
            // state, args and output exist for the API and survive a restart.
            {
                let mut store = self.store.lock().await;
                store.create(
                    task_id.clone(),
                    himan_proto::ToolName::new(tool_name),
                    device_id.clone(),
                    args.clone(),
                );
                store.set_state(&task_id, TaskState::Running);
            }
            self.persist_task_record(&task_id).await;
            // Drive the steps in the background; the HTTP caller gets the task
            // id immediately and observes progress through the audit and the
            // event log.
            let hub = self.clone();
            let task: String = task_id.to_string();
            let device = device_id.clone();
            tokio::spawn(async move {
                if let Err(e) = hub.drive_scenario(&task, &device).await {
                    warn!(error = %e, %task, "scenario run stopped");
                }
            });
            return Ok(DispatchResult {
                task_id: task_id.to_string(),
                state: "running".into(),
                output: format!("scenario of {total} steps dispatched"),
                decision: "allow".into(),
            });
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

    /// Drive a deterministic scenario task to completion.
    ///
    /// The orchestrator is the only writer: it dispatches one `scenario_step`
    /// tool call per step and appends the corresponding event to its own log.
    /// A drain stops the current owner from starting new steps, so the loop
    /// parks until the handoff commit moves ownership; the new owner then runs
    /// the remaining steps. That is exactly the AC-1 shape: the source runs a
    /// prefix, the target runs the rest, and no step is issued twice.
    async fn drive_scenario(&self, task_id: &str, device: &DeviceId) -> ProtoResult<()> {
        loop {
            // A drained source must not start a new step. Park here, before
            // reserving a step number, so a parked loop neither consumes a
            // step nor issues one to a device that has been told to stop.
            if self.drained.lock().await.contains(task_id) {
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
                loop {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    if !self.drained.lock().await.contains(task_id) {
                        break;
                    }
                    if std::time::Instant::now() >= deadline {
                        return Ok(());
                    }
                }
            }

            // Who owns the task right now? After a handoff this is the target.
            let owner = {
                let owners = self.owners.lock().await;
                owners
                    .owner_of(task_id)
                    .cloned()
                    .unwrap_or_else(|| device.clone())
            };

            let (issued, total, run_tool, run_is_effect) = {
                let mut runs = self.scenarios.lock().await;
                let run = runs
                    .get_mut(task_id)
                    .ok_or_else(|| ProtoError::Policy(format!("no scenario run for {task_id}")))?;
                if run.issued >= run.total {
                    return Ok(());
                }
                run.owner = owner.clone();
                run.issued += 1;
                (
                    run.issued,
                    run.total,
                    run.tool.clone(),
                    run.tool == "scenario_effect",
                )
            };

            // AC-6 metric: one audit event per issued step, with a millisecond
            // timestamp, so the inter-step gap across the switch can be
            // measured. Without this the audit's second resolution makes every
            // sub-second gap read as zero.
            self.audit(
                "step_issued".to_string(),
                owner.to_string(),
                format!("task={task_id} step={issued} owner={}", owner),
            )
            .await;

            // The effect variant carries no `total`: it is a one-shot
            // irreversible call, and the run length still comes from the
            // prompt so a test cannot change it over the wire.
            let args = if run_is_effect {
                serde_json::json!({ "step": issued })
            } else {
                serde_json::json!({ "step": issued, "total": total })
            };
            let call = ToolCall {
                task_id: TaskId::new(task_id),
                target_device: owner.clone(),
                tool: himan_proto::ToolName::new(run_tool.as_str()),
                args: args.clone(),
                risk_tier: if run_is_effect {
                    RiskTier::Reversible
                } else {
                    RiskTier::ReadOnly
                },
                nonce: random_nonce(),
            };
            let message = self.build_message(owner.clone(), Payload::ToolCall(call))?;
            let session = {
                let agents = self.agents.lock().await;
                agents.get(&owner).map(|s| AgentSession {
                    device: s.device.clone(),
                    tx: s.tx.clone(),
                    inbound_tx: s.inbound_tx.clone(),
                })
            }
            .ok_or_else(|| ProtoError::Policy(format!("device {owner} is not connected")))?;
            session
                .tx
                .send(message)
                .await
                .map_err(|_| ProtoError::Policy("agent queue full or closed".into()))?;

            // Record the issued step in the orchestrator's own log.
            {
                let mut log = self.event_log.lock().await;
                let epoch = {
                    let owners = self.owners.lock().await;
                    owners.get(task_id).map(|o| o.epoch).unwrap_or(0)
                };
                let event = log.next_event(
                    task_id.to_string(),
                    epoch,
                    owner,
                    crate::eventlog::EventPayload::ToolCallIssued {
                        call_id: format!("scenario-{task_id}-{issued}"),
                        tool: run_tool.clone(),
                        args: args.clone(),
                        idempotency: if run_is_effect {
                            crate::eventlog::Idempotency::NonIdempotent
                        } else {
                            crate::eventlog::Idempotency::Idempotent
                        },
                    },
                );
                log.append(event.clone());
                // Persist the step event too, so the event log survives a
                // restart and the seq continues. The durable write is
                // synchronous (rusqlite) and must not outlive this scope.
                drop(log);
                let guard = self.durable.lock().expect("durable lock");
                if let Some(store) = guard.as_ref() {
                    if let Err(e) = store.append_event(&event) {
                        tracing::error!(error = %e, "failed to persist the step event");
                    }
                }
            }

            // The step's wall-clock cost, so the run lasts long enough to
            // interrupt. Bounded so a failure cannot wedge the task.
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }

    /// Remove a device from the live session table.
    ///
    /// Without this, a disconnected agent leaves a stale session whose sender
    /// points at a closed channel, and dispatch to the next agent with the
    /// same id fails with "agent queue full or closed".
    pub async fn unregister(&self, id: &DeviceId) {
        let removed = {
            let mut agents = self.agents.lock().await;
            agents.remove(id).is_some()
        };
        if removed {
            let mut presence = self.presence.lock().await;
            presence.unregister(id);
            drop(presence);
            self.audit(
                "agent_unregistered".to_string(),
                id.to_string(),
                "disconnected".to_string(),
            )
            .await;
            info!(device = %id, "agent unregistered");
            // A disconnect is how an owner dies without a clean Bye: any task
            // it owned is now stalled.
            self.stall_tasks_of(id).await;
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

    /// Load durable revocations at startup, before any agent registers.
    pub async fn load_revocations(&self, ids: Vec<String>) {
        let mut revoked = self.revoked.lock().await;
        revoked.extend(ids);
    }

    /// Revoke a device: reject future Hellos and drop any live session.
    /// Persisted durably and audited through the hash chain.
    pub async fn revoke_device(&self, device: &DeviceId, reason: &str) {
        let now = chrono::Utc::now().timestamp();
        let mut revoked = self.revoked.lock().await;
        revoked.insert(device.to_string());
        drop(revoked);
        {
            let guard = self.durable.lock().expect("durable lock");
            if let Some(store) = guard.as_ref() {
                if let Err(e) = store.revoke_device(device.as_str(), now, reason) {
                    tracing::error!(error = %e, "failed to persist the revocation");
                }
            }
        }
        self.unregister(device).await;
        self.audit(
            "device_revoked".to_string(),
            "orchestrator".to_string(),
            format!("device={device} reason={reason}"),
        )
        .await;
    }

    /// Whether a device id is revoked (in-memory mirror of the durable table).
    pub async fn is_revoked(&self, device: &DeviceId) -> bool {
        self.revoked.lock().await.contains(device.as_str())
    }

    /// Every revoked device id.
    pub async fn revoked_devices(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.revoked.lock().await.iter().cloned().collect();
        ids.sort();
        ids
    }

    /// Snapshot of the audit log.
    pub async fn audit_events(&self) -> Vec<crate::audit::AuditEvent> {
        let audit = self.audit.lock().await;
        audit.events().to_vec()
    }

    /// Subscribe to a device's inbound messages so the handoff driver can read
    /// that agent's replies.
    ///
    /// A broadcast subscription, not a taken receiver: the socket handler must
    /// keep publishing while a handoff is in flight, and a reply must never be
    /// dropped because the driver is reading.
    pub async fn subscribe_inbound(
        &self,
        device: &DeviceId,
    ) -> Option<tokio::sync::broadcast::Receiver<WireMessage>> {
        let agents = self.agents.lock().await;
        let session = agents.get(device)?;
        Some(session.inbound_tx.subscribe())
    }

    /// Clone the sender that feeds a device's inbound stream. The socket
    /// handler forwards agent messages through it.
    pub async fn inbound_sender(
        &self,
        device: &DeviceId,
    ) -> Option<tokio::sync::broadcast::Sender<WireMessage>> {
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
        let (inbound_tx, _inbound_rx) = tokio::sync::broadcast::channel(self.config.agent_queue);
        self.agents.lock().await.insert(
            info.id.clone(),
            AgentSession {
                device: info.clone(),
                tx,
                inbound_tx,
            },
        );
        self.presence.lock().await.register(info);
    }

    /// Snapshot of every handoff attempt, for the API and tests.
    pub async fn handoffs_snapshot(&self) -> Vec<Handoff> {
        let handoffs = self.handoffs.lock().await;
        handoffs.values().cloned().collect()
    }

    /// Install the durable store and report what recovery found.
    ///
    /// Called once at startup, before the server accepts connections. The
    /// recovered handoffs are rolled back (and audited) by the caller.
    pub fn install_durable(
        &self,
        store: crate::durable::DurableStore,
        rolled_back: usize,
        resume_pending: bool,
    ) {
        let mut slot = self.durable.lock().expect("durable lock");
        *slot = Some(store);
        info!(
            rolled_back,
            resume_pending, "durable state attached and recovery complete"
        );
    }

    /// Write a `handoff_rolled_back` line into the audit for a handoff that
    /// recovery found uncommitted.
    ///
    /// Called at startup, after the store is attached. The audit log is
    /// in-memory, so without this the rollback would leave no trace the API can
    /// report.
    /// Write a `handoff_rolled_back` line into BOTH audit logs for a handoff
    /// that recovery found uncommitted.
    ///
    /// Called at startup, after the store is attached. The in-memory log
    /// starts empty, so without this the rollback would be invisible there;
    /// the durable log is what `/api/v1/audit` reads, so without the durable
    /// append the API would never show the recovery at all — the endpoint
    /// would keep showing whatever the dead process last wrote.
    pub async fn audit_handoff_rolled_back(&self, record: &crate::durable::HandoffRecord) {
        let detail = format!(
            "task={} from={} to={} reason=orchestrator restarted before the commit",
            record.task_id, record.from_device, record.to_device
        );
        self.audit(
            "handoff_rolled_back".to_string(),
            "orchestrator".to_string(),
            detail,
        )
        .await;
        tracing::info!(handoff = %record.handoff_id, "audited the startup rollback");
    }

    /// Mark every task owned by `device` as stalled, bump its epoch, and offer
    /// it to the original source if that device is still connected, else to
    /// another enrolled device.
    ///
    /// A non-idempotent call with no result is marked `Unknown` so it cannot be
    /// re-issued without approval: replaying an effect that may already have
    /// happened is the failure mode this exists to prevent.
    pub async fn stall_tasks_of(&self, device: &DeviceId) {
        // Find the tasks this device owns.
        let owned: Vec<(String, u64)> = {
            let owners = self.owners.lock().await;
            owners
                .tasks_of(device)
                .into_iter()
                .map(|task_id| {
                    let epoch = owners.get(&task_id).map(|o| o.epoch).unwrap_or(0);
                    (task_id, epoch)
                })
                .collect()
        };
        for (task_id, epoch) in owned {
            let new_epoch = epoch + 1;
            let reason = format!("owner {device} disconnected");
            {
                self.audit(
                    "task_stalled".to_string(),
                    device.to_string(),
                    format!("task={task_id} epoch={new_epoch} reason={reason}"),
                )
                .await;
            }
            // Choose the next owner: the original source if connected, else any
            // other enrolled device.
            // A stall transfers the task to the candidate: an offer nobody acts
            // on would leave the task owned by a dead device forever. The
            // candidate becomes the owner at the bumped epoch, so the dead
            // device's writes are fenced.
            let next = self.pick_next_owner(device).await;
            match next {
                Some(candidate) => {
                    {
                        let mut owners = self.owners.lock().await;
                        let _ = owners.commit(&task_id, candidate.clone(), new_epoch);
                    }
                    self.audit(
                        "task_offered".to_string(),
                        "orchestrator".to_string(),
                        format!("task={task_id} to={candidate} epoch={new_epoch}"),
                    )
                    .await;
                    tracing::info!(%task_id, to = %candidate, "stalled task offered");
                }
                None => {
                    self.audit(
                        "task_unresolved".to_string(),
                        "orchestrator".to_string(),
                        format!("task={task_id} no candidate owner epoch={new_epoch}"),
                    )
                    .await;
                    // Persist it: with no candidate the task stays stalled, and
                    // it is offered when a device connects. The in-memory epoch
                    // moves too, so the later offer can take the next value
                    // instead of being refused as stale.
                    {
                        let mut owners = self.owners.lock().await;
                        let _ = owners.commit(&task_id, device.clone(), new_epoch);
                    }
                    let guard = self.durable.lock().expect("durable lock");
                    if let Some(store) = guard.as_ref() {
                        if let Err(e) =
                            store.save_stalled(&task_id, new_epoch, &device.to_string(), &reason)
                        {
                            tracing::error!(error = %e, task = %task_id, "failed to persist the stall");
                        }
                    }
                }
            }
            // A non-idempotent call with no result cannot be replayed blindly.
            self.mark_unresolved_non_idempotent(&task_id).await;
        }
    }

    /// The original source of a stalled task, if it is connected; otherwise any
    /// other enrolled device.
    async fn pick_next_owner(&self, dead: &DeviceId) -> Option<DeviceId> {
        let candidates: Vec<DeviceId> = match self.enrollment.as_ref() {
            Some(enrolled) => enrolled.devices(),
            None => Vec::new(),
        };
        let agents = self.agents.lock().await;
        // Prefer a device that is still connected and is not the dead one.
        let live: Vec<DeviceId> = candidates
            .iter()
            .filter(|id| **id != *dead && agents.contains_key(*id))
            .cloned()
            .collect();
        drop(agents);
        live.into_iter().next()
    }

    /// Record that a task has a non-idempotent call with no result.
    pub async fn mark_unresolved_non_idempotent(&self, task_id: &str) {
        // The durable guard is std, so take it, do the synchronous write, and
        // drop it before awaiting the audit lock.
        let durable = {
            let guard = self.durable.lock().expect("durable lock");
            match guard.as_ref() {
                Some(store) => {
                    if let Err(e) = store.set_unresolved(task_id, true) {
                        tracing::error!(error = %e, task = %task_id, "failed to mark the call unresolved");
                    }
                    true
                }
                None => false,
            }
        };
        let _ = durable;
        self.audit(
            "non_idempotent_call_unknown".to_string(),
            "orchestrator".to_string(),
            format!("task={task_id} requires approval before re-issue"),
        )
        .await;
    }

    /// Append an audit event to the in-memory log AND the durable store.
    ///
    /// Every audit write goes through here. The timestamp is taken once and
    /// shared, so the two copies hash identically and the durable chain stays
    /// verifiable against the in-memory one.
    pub async fn audit(
        &self,
        action: impl Into<String>,
        actor: impl Into<String>,
        detail: impl Into<String>,
    ) {
        let now_ms = chrono::Utc::now().timestamp_millis();
        let ts = now_ms / 1000;
        let action = action.into();
        let actor = actor.into();
        let detail = detail.into();
        let mut audit = self.audit.lock().await;
        audit.append_at_ms(action.clone(), actor.clone(), detail.clone(), ts, now_ms);
        drop(audit);
        let durable = {
            let guard = self.durable.lock().expect("durable lock");
            guard.as_ref().is_some()
        };
        if durable {
            let guard = self.durable.lock().expect("durable lock");
            if let Some(store) = guard.as_ref() {
                if let Err(e) = store.append_audit(&action, &actor, &detail, ts, now_ms) {
                    tracing::error!(error = %e, "failed to persist the audit entry");
                }
            }
        }
    }

    /// The durable audit log, when one is attached.
    pub async fn durable_audit_events(&self) -> Option<Vec<crate::durable::DurableAuditEvent>> {
        let guard = self.durable.lock().expect("durable lock");
        guard
            .as_ref()
            .map(|store| store.audit_log().unwrap_or_default())
    }

    /// Test support: register `owner` for `task` at epoch 0.
    ///
    /// The red-team tests need to set up an ownership state directly, and the
    /// registry is private. This is the same call `dispatch` makes.
    pub async fn register_task_for_test(&self, task_id: &str, owner: &str) {
        let mut owners = self.owners.lock().await;
        if let Err(e) = owners.register(task_id.to_owned(), DeviceId::new(owner)) {
            tracing::error!(error = %e, task = %task_id, "test owner registration failed");
        }
    }

    /// Test support: move `task` to `owner` at `epoch`, asserting the monotonic
    /// rule. Used to model "the switch has already happened".
    pub async fn commit_task_for_test(&self, task_id: &str, owner: &str, epoch: u64) {
        let mut owners = self.owners.lock().await;
        owners
            .commit(task_id, DeviceId::new(owner), epoch)
            .expect("test commit must be accepted");
    }

    /// The planner: turn a natural-language prompt into a proposed tool call.
    ///
    /// With `HIMAN_OLLAMA_URL` set the proposal comes from the model; without
    /// it, from the deterministic scripted stub. In both cases the proposal is
    /// UNTRUSTED: it is checked against the orchestrator's tool whitelist and
    /// the tool's argument schema here, and the policy engine decides after
    /// this returns. The model never sees the policy decision and cannot
    /// influence it.
    async fn plan(
        &self,
        device_id: &DeviceId,
        prompt: &str,
    ) -> Option<(String, serde_json::Value)> {
        use himan_agent_core::llm::{ChatMessage, ChatRequest, Role};

        // The orchestrator-side whitelist and schemas. These mirror the PC
        // agent's registry; the agent re-checks on its side, so a compromised
        // orchestrator cannot widen what a device runs.
        let schemas = vec![
            serde_json::json!({
                "name": "device_status",
                "description": "Report CPU, memory and uptime of the device.",
                "args": {"type": "object", "properties": {}, "additionalProperties": false}
            }),
            serde_json::json!({
                "name": "run_diagnostic",
                "description": "Run a network diagnostic. Destructive: needs approval.",
                "args": {"type": "object", "properties": {
                    "target": {"type": "string"}
                }, "additionalProperties": false}
            }),
        ];
        let request = ChatRequest {
            messages: vec![
                ChatMessage {
                    role: Role::System,
                    content: "You are the HIMAN planner. Propose exactly one tool call \
                              for the user's request, or none. Never invent tools."
                        .into(),
                },
                ChatMessage {
                    role: Role::User,
                    content: prompt.to_owned(),
                },
            ],
            tools: schemas.clone(),
            temperature: 0.0,
        };

        let (content, proposed) = if std::env::var("HIMAN_OLLAMA_URL").is_ok() {
            let backend = match himan_agent_core::ollama::OllamaBackend::new(
                himan_agent_core::ollama::OllamaConfig::from_env(),
            ) {
                Ok(b) => b,
                Err(e) => {
                    self.audit(
                        "planner_error".to_string(),
                        device_id.to_string(),
                        format!("backend unavailable: {e}"),
                    )
                    .await;
                    return None;
                }
            };
            match backend.propose(request).await {
                Ok(v) => v,
                Err(e) => {
                    self.audit(
                        "planner_error".to_string(),
                        device_id.to_string(),
                        format!("model answer rejected: {e}"),
                    )
                    .await;
                    return None;
                }
            }
        } else {
            // The deterministic stub: same trust boundary, no network.
            use himan_agent_core::llm::ChatBackend;
            let stub = himan_agent_core::llm::ScriptedBackend::demo();
            match stub.chat(request).await {
                Ok(resp) => (
                    resp.content,
                    resp.tool_calls
                        .into_iter()
                        .map(|name| himan_agent_core::ollama::ProposedToolCall {
                            name,
                            args: serde_json::json!({}),
                        })
                        .collect(),
                ),
                Err(e) => {
                    self.audit(
                        "planner_error".to_string(),
                        device_id.to_string(),
                        format!("stub failed: {e}"),
                    )
                    .await;
                    return None;
                }
            }
        };
        let _ = content;

        let call = proposed.into_iter().next()?;
        // Whitelist: the model cannot introduce a tool.
        let Some(schema) = schemas
            .iter()
            .find(|s| s["name"].as_str() == Some(call.name.as_str()))
        else {
            self.audit(
                "planner_rejected".to_string(),
                device_id.to_string(),
                format!("tool={} reason=not_whitelisted", call.name),
            )
            .await;
            return None;
        };
        // Schema: the model cannot smuggle arguments.
        if let Err(reason) = himan_agent_core::ollama::validate_args(&schema["args"], &call.args) {
            self.audit(
                "planner_rejected".to_string(),
                device_id.to_string(),
                format!("tool={} reason=schema:{reason}", call.name),
            )
            .await;
            return None;
        }
        self.audit(
            "planner_proposed".to_string(),
            device_id.to_string(),
            format!("tool={}", call.name),
        )
        .await;
        Some((call.name, call.args))
    }

    /// Test support: the policy decision for a tool call on a device.
    pub async fn policy_evaluate_for_test(
        &self,
        call: &ToolCall,
        device: &DeviceInfo,
    ) -> crate::policy::Decision {
        let policy = self.policy.lock().await;
        policy.evaluate(call, device)
    }

    /// Test support: the policy decision for a handoff between two devices,
    /// independent of whether either is connected.
    pub async fn handoff_policy_for_test(
        &self,
        from: &DeviceId,
        to: &DeviceId,
        target: Option<&DeviceInfo>,
    ) -> crate::policy::Decision {
        let presence = self.presence.lock().await;
        presence
            .policy_snapshot_for_test()
            .evaluate_handoff(from, to, target)
    }

    /// Test support: move a handoff attempt to a terminal state directly.
    pub async fn set_handoff_state_for_test(
        &self,
        handoff_id: &str,
        state: &str,
        committed: bool,
        reason: Option<&str>,
    ) {
        let mut handoffs = self.handoffs.lock().await;
        if let Some(record) = handoffs.get_mut(handoff_id) {
            record.state = match state {
                "rolled_back" => crate::handoff::HandoffState::RolledBack,
                "active" => crate::handoff::HandoffState::Active,
                "failed" => crate::handoff::HandoffState::Failed,
                _ => crate::handoff::HandoffState::Prepared,
            };
            record.committed = committed;
            record.end_reason = reason.map(|r| r.to_string());
        }
    }

    /// Mirror a task record to the durable store, if one is attached.
    ///
    /// Best-effort: a failure to persist a record is logged, not fatal, so a
    /// disk problem cannot stop a handoff. The record is written on every state
    /// change, so the durable copy is always the current answer rather than a
    /// replay.
    async fn persist_task_record(&self, task_id: &TaskId) {
        let record = {
            let store = self.store.lock().await;
            store.get(task_id).cloned()
        };
        if let Some(record) = record {
            let durable = self.durable.lock().expect("durable lock");
            if let Some(store) = durable.as_ref() {
                if let Err(e) = store.save_task_record(&record) {
                    tracing::error!(error = %e, task = %task_id, "failed to persist the task record");
                }
            }
        }
    }

    /// Test support: the owner id of `task`.
    pub async fn task_record(&self, task_id: &str) -> Option<crate::state::TaskRecord> {
        let store = self.store.lock().await;
        store.get(&TaskId::new(task_id)).cloned()
    }
    pub async fn owner_name(&self, task_id: &str) -> Option<String> {
        let owners = self.owners.lock().await;
        owners.owner_of(task_id).map(|d| d.to_string())
    }

    /// The owner history for a task, reconstructed from the audit timeline.
    ///
    /// AC-2's no-gap rule is a property of this history: at every moment
    /// between the first and last ownership event exactly one device owns the
    /// task. Returns the `(ts_ms, owner)` pairs in order.
    pub async fn owner_history(&self, task_id: &str) -> Vec<(i64, String)> {
        let audit = self.audit_events().await;
        let mut history: Vec<(i64, String)> = Vec::new();
        for event in audit {
            let detail = event.detail.as_str();
            if !detail.contains(&format!("task={task_id}")) && event.action != "task_created" {
                continue;
            }
            match event.action.as_str() {
                "task_created" => {
                    // The source owns from the moment the task exists.
                    if let Some(owner) = detail
                        .split("owner=")
                        .nth(1)
                        .and_then(|r| r.split(' ').next())
                    {
                        history.push((event.ts, owner.to_string()));
                    }
                }
                "handoff_prepared" => {
                    // The source still owns until the commit.
                    if let Some(from) = detail
                        .split("from=")
                        .nth(1)
                        .and_then(|r| r.split(' ').next())
                    {
                        if history.last().map(|(_, o)| o.as_str()) != Some(from) {
                            history.push((event.ts, from.to_string()));
                        }
                    }
                }
                "handoff_committed" => {
                    if let Some(to) = detail.split("to=").nth(1).and_then(|r| r.split(' ').next()) {
                        history.push((event.ts, to.to_string()));
                    }
                }
                "task_stalled" => {
                    if let Some(to) = detail.split("to=").nth(1).and_then(|r| r.split(' ').next()) {
                        history.push((event.ts, to.to_string()));
                    }
                }
                _ => {}
            }
        }
        history
    }

    /// The longest owner-less interval for a task, in milliseconds.
    ///
    /// A gap is a hole in the owner history: two consecutive ownership events
    /// with no owner in between. With no gap the answer is `Some(0)`.
    pub async fn owner_gap_ms(&self, task_id: &str) -> Option<u64> {
        let history = self.owner_history(task_id).await;
        if history.len() < 2 {
            return None;
        }
        // The gap is measured between the end of one owner's interval and the
        // start of the next. With a single continuous history there is none.
        let mut longest = 0u64;
        for window in history.windows(2) {
            let (prev_ts, _) = window[0];
            let (next_ts, _) = window[1];
            // A real gap needs the previous owner to have been released before
            // the next took over; the timeline records the switch as one
            // atomic step, so a non-zero difference here is the gap.
            let delta = (next_ts - prev_ts).max(0) as u64;
            longest = longest.max(delta);
        }
        Some(longest)
    }

    /// Whether durable state is enabled.
    pub fn durable_enabled(&self) -> bool {
        self.durable.lock().expect("durable lock").is_some()
    }

    /// Load durable state into the live maps: owner, epoch, event log.
    ///
    /// Called at startup after the store is attached. The epoch comes from the
    /// durable record, never recomputed, so it cannot decrease across a
    /// restart.
    pub async fn load_durable_state(&self) -> usize {
        // Read everything under the std guard, drop it, then do the async work.
        let tasks = {
            let guard = self.durable.lock().expect("durable lock");
            match guard.as_ref() {
                None => return 0,
                Some(store) => match store.tasks() {
                    Ok(t) => t,
                    Err(e) => {
                        tracing::error!(error = %e, "failed to read durable tasks");
                        return 0;
                    }
                },
            }
        };
        let mut loaded = 0;
        for record in tasks {
            let mut owners = self.owners.lock().await;
            if let Err(e) = owners.register(record.task_id.clone(), DeviceId::new(&record.owner)) {
                tracing::warn!(error = %e, task = %record.task_id, "failed to reload owner");
                continue;
            }
            // The durable epoch is authoritative. `commit` refuses a decrease,
            // which is exactly the property we need here.
            let _ = owners.commit(&record.task_id, DeviceId::new(&record.owner), record.epoch);
            drop(owners);

            // Load the log under the std guard, then drop it before awaiting.
            let log = {
                let guard = self.durable.lock().expect("durable lock");
                match guard.as_ref() {
                    Some(store) => store.event_log(&record.task_id),
                    None => continue,
                }
            };
            match log {
                Ok(log) => {
                    let head = log.head();
                    let mut event_log = self.event_log.lock().await;
                    for event in log.events() {
                        event_log.append(event.clone());
                    }
                    tracing::info!(task = %record.task_id, head, "reloaded the event log");
                }
                Err(e) => {
                    tracing::warn!(error = %e, task = %record.task_id, "failed to reload events")
                }
            }
            loaded += 1;
        }

        // Rebuild the task records (state, args, output). These are not derived
        // from the event log: the log records what happened, the record is the
        // current answer, and the two are updated at different moments.
        let records = {
            let guard = self.durable.lock().expect("durable lock");
            match guard.as_ref() {
                None => return loaded,
                Some(store) => match store.task_records() {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::error!(error = %e, "failed to read task records");
                        return loaded;
                    }
                },
            }
        };
        let mut restored = 0;
        for record in records {
            let mut store = self.store.lock().await;
            if store.get(&record.id).is_some() {
                // A live record is newer than the persisted copy.
                continue;
            }
            store.restore(record);
            restored += 1;
        }
        tracing::info!(task_records = restored, "restored task records");
        loaded
    }

    /// Persist the commit point: epoch bump, owner change and `OwnerChanged`.
    ///
    /// The durable store performs all three in one transaction, so a crash
    /// between them is impossible and the epoch cannot decrease across a
    /// restart.
    async fn persist_commit(
        &self,
        task_id: &TaskId,
        from: &DeviceId,
        to: &DeviceId,
        outcome: &crate::handoff_driver::DriveOutcome,
    ) {
        // The durable store is behind a std mutex and `DurableStore` is not
        // Clone, so take the guard only to read the flag, drop it, then do the
        // async work. A std guard held across `.await` makes the caller's
        // future non-Send, which breaks every axum handler.
        let durable = self.durable.lock().expect("durable lock").is_some();
        if !durable {
            return;
        }
        // Re-take the guard for the synchronous writes only: rusqlite is
        // blocking, so this must not be awaited on anyway.
        let event = {
            let log = self.event_log.lock().await;
            log.next_event(
                task_id.to_string(),
                outcome.epoch,
                to.clone(),
                crate::eventlog::EventPayload::OwnerChanged {
                    from: from.to_string(),
                    to: to.to_string(),
                    epoch: outcome.epoch,
                },
            )
        };
        let guard = self.durable.lock().expect("durable lock");
        let Some(store) = guard.as_ref() else {
            return;
        };
        if let Err(e) = store.commit_owner(task_id.as_str(), to.as_str(), outcome.epoch, &event) {
            tracing::error!(error = %e, %task_id, "failed to persist the commit");
        }
        if let Err(e) = store.append_event(&event) {
            tracing::error!(error = %e, %task_id, "failed to append OwnerChanged");
        }
        if let Err(e) = store.set_handoff_state(
            &outcome.handoff_id,
            outcome.state.as_str(),
            outcome.committed,
            outcome.reason.as_deref(),
        ) {
            tracing::error!(error = %e, %task_id, "failed to persist the handoff state");
        }
    }

    pub async fn owner(&self, task_id: &str) -> Option<crate::ownership::Ownership> {
        let owners = self.owners.lock().await;
        owners.get(task_id).cloned()
    }

    /// Snapshot the orchestrator's own task event log.
    pub async fn task_events(&self) -> Vec<crate::eventlog::TaskEvent> {
        self.event_log.lock().await.events().to_vec()
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

        // One active handoff per task. Without this, two requests could both
        // mint tokens for the same task and both drive it, which is the
        // double-owner window RT-13 is about. The check is under the same lock
        // as the insert below, so it cannot race.
        {
            let existing = {
                let handoffs = self.handoffs.lock().await;
                handoffs
                    .values()
                    .find(|h| h.task_id.as_str() == task_id.as_str() && h.state.is_active())
                    .map(|h| (h.handoff_id.clone(), h.state.as_str().to_string()))
            };
            if let Some((active_id, active_state)) = existing {
                self.audit(
                    "handoff_rejected".to_string(),
                    from.to_string(),
                    format!(
                        "task={task_id} reason=one_active_handoff active={active_id} state={active_state}"
                    ),
                )
                .await;
                return Err(ProtoError::Policy(format!(
                    "task {task_id} already has an active handoff {active_id}"
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
        // The checkpoint is the orchestrator's own log head, never a
        // client-supplied position. See docs/DECISIONS.md.
        let checkpoint_seq = self.event_log.lock().await.head();
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
                    checkpoint_seq,
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

        // Persist the attempt so a restart knows it was in flight.
        {
            let guard = self.durable.lock().expect("durable lock");
            if let Some(store) = guard.as_ref() {
                // The task row must exist before any event references it, so a
                // restart can load the owner and then the log.
                if let Err(e) = store.ensure_task(task_id.as_str(), from.as_str()) {
                    tracing::error!(error = %e, "failed to persist the task record");
                }
                let record = crate::durable::HandoffRecord {
                    handoff_id: handoff_id.clone(),
                    task_id: task_id.to_string(),
                    from_device: from.to_string(),
                    to_device: to.to_string(),
                    state: "prepared".into(),
                    epoch,
                    checkpoint_seq,
                    applied_seq: 0,
                    committed: false,
                    end_reason: None,
                };
                if let Err(e) = store.save_handoff(&record) {
                    tracing::error!(error = %e, "failed to persist the handoff attempt");
                }
            }
        }

        {
            self.audit(line.action, from.to_string(), line.detail).await;
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
        let (state, line, task_id, from, to, committed_now) = {
            let mut handoffs = self.handoffs.lock().await;
            let handoff = handoffs
                .get_mut(handoff_id)
                .ok_or_else(|| ProtoError::Policy(format!("handoff {handoff_id} is not known")))?;
            let was_committed = handoff.committed;
            let was_drained = matches!(&event, HandoffEvent::SourceDrained { .. });
            let line = handoff
                .apply(event, now, &self.handoff_timeouts)
                .map_err(|e: HandoffError| ProtoError::Policy(e.to_string()))?;

            // The source has drained: it must not start another step. Marking
            // this here (rather than where the message is sent) keeps the
            // "stop starting new steps" decision on the same path as the state
            // machine, so it cannot drift from the handoff's own view.
            if was_drained {
                let mut drained = self.drained.lock().await;
                drained.insert(handoff.task_id.to_string());
            }

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

            let committed_now = handoff.committed && !was_committed;
            (
                handoff.state,
                line,
                handoff.task_id.clone(),
                handoff.from.clone(),
                handoff.to.clone(),
                committed_now,
            )
        };

        // Ownership moved: the drained source is no longer barred from the
        // scenario loop, which now drives the remaining steps on the target.
        if committed_now {
            let mut drained = self.drained.lock().await;
            drained.remove(task_id.as_str());
            let mut runs = self.scenarios.lock().await;
            if let Some(run) = runs.get_mut(task_id.as_str()) {
                run.owner = to.clone();
            }
        }

        {
            self.audit(line.action, from.to_string(), line.detail).await;
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
            .subscribe_inbound(from)
            .await
            .ok_or_else(|| ProtoError::Policy(format!("{from} has no inbound channel")))?;
        let target_rx = self
            .subscribe_inbound(to)
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
            inbound: Box::new(source_rx),
        };
        let target = Mailbox {
            outbound: target_tx,
            inbound: Box::new(target_rx),
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

        // The checkpoint is the orchestrator's own log head for this task,
        // never a client-supplied position (see docs/DECISIONS.md). A task the
        // orchestrator has not logged yet is checkpointed at 0: that is the
        // honest head, and the driver streams nothing for it.
        let applied_seq = {
            let log = self.event_log.lock().await;
            log.events()
                .iter()
                .filter(|e| e.task_id == task_id.as_str())
                .map(|e| e.seq)
                .max()
                .unwrap_or(0)
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
            drop(owners);
            // Persist the commit: epoch bump, owner change and `OwnerChanged`
            // in one transaction. Doing it here, after the in-memory commit,
            // keeps the durable path from being able to move ownership ahead of
            // the state machine that actually decided it.
            self.persist_commit(task_id, from, to, &outcome).await;
            // Ownership moved: clear the drain so the scenario loop resumes on
            // the new owner.
            let mut drained = self.drained.lock().await;
            drained.remove(task_id.as_str());
            let mut runs = self.scenarios.lock().await;
            if let Some(run) = runs.get_mut(task_id.as_str()) {
                run.owner = to.clone();
            }
        }

        // Record the transition timeline. The driver's local state machine is
        // what actually moved, so its path is the audit trail; without this
        // the API could only show "prepared" and "finished", which is not the
        // confirmed-state sequence the spec asks for.
        {
            for state in &outcome.path {
                self.audit(
                    format!("handoff_{}", state.as_str()),
                    from.to_string(),
                    format!(
                        "handoff={handoff_id} epoch={} state={}",
                        outcome.epoch,
                        state.as_str()
                    ),
                )
                .await;
            }
        }

        // A failed attempt must not leave the task ownerless or the epoch
        // moved. If the driver did not reach the commit point, roll back the
        // recorded attempt so the source keeps the task and stays usable.
        if !outcome.committed {
            if let Some(reason) = outcome.reason.clone() {
                let now = Utc::now().timestamp();
                let rollback_line = {
                    let mut handoffs = self.handoffs.lock().await;
                    match handoffs.get_mut(&handoff_id) {
                        Some(record) => record.apply(
                            HandoffEvent::Rollback {
                                reason: reason.clone(),
                            },
                            now,
                            &self.handoff_timeouts,
                        ),
                        None => Err(HandoffError::IllegalTransition {
                            from: "missing",
                            event: "rollback",
                        }),
                    }
                };
                // Audit AFTER dropping the handoffs lock. Holding it across
                // an await stalls other handoff requests while the durable
                // append waits on disk, which under parallel CI load can
                // delay the rollback audit past its 20 s observer window.
                let rolled_back = match rollback_line {
                    Ok(l) => {
                        self.audit(l.action, from.to_string(), l.detail).await;
                        true
                    }
                    Err(e) => {
                        warn!(handoff = %handoff_id, error = %e, "rollback refused");
                        false
                    }
                };
                let mut drained = self.drained.lock().await;
                drained.remove(task_id.as_str());
                if rolled_back {
                    warn!(
                        handoff = %handoff_id,
                        reason = %reason,
                        "handoff rolled back; the source keeps the task"
                    );
                }
            }
        }

        // A lagging inbound subscription means the driver cannot prove it saw
        // every reply. Record it in the audit: silently carrying on would hide
        // exactly the evidence a handoff failure needs.
        if let Some(reason) = outcome.reason.as_deref() {
            if let Some(rest) = reason
                .strip_prefix("lost ")
                .and_then(|r| r.split(" inbound").next())
                .and_then(|n| n.parse::<u64>().ok())
            {
                self.audit(
                    "inbound_lagged".to_string(),
                    from.to_string(),
                    format!("handoff={handoff_id} lost={rest} message(s)"),
                )
                .await;
            }
        }

        // AC-6 metrics, recorded as audit events so they are queryable and
        // survive a restart:
        //   * switch_time_ms  - the driver's own measure of the switch,
        //   * total_time_ms   - wall clock for the whole attempt,
        //   * replay_lag     - how far behind the target was at the switch,
        //   * rollback_cause - why a failed attempt rolled back,
        //   * owner_gap_ms   - an interval with no owner (should be zero).
        let now = Utc::now().timestamp_millis();
        self.audit(
            "handoff_switch_time_ms".to_string(),
            from.to_string(),
            format!(
                "handoff={} switch_ms={} total_ms={} state={}",
                handoff_id,
                outcome.switch_time_ms,
                now.saturating_sub(outcome.started_at_ms),
                outcome.state.as_str()
            ),
        )
        .await;
        self.audit(
            "handoff_total_time_ms".to_string(),
            from.to_string(),
            format!(
                "handoff={} total_ms={}",
                handoff_id,
                now.saturating_sub(outcome.started_at_ms)
            ),
        )
        .await;
        if let Some(lag) = outcome.replay_lag {
            self.audit(
                "handoff_replay_lag".to_string(),
                from.to_string(),
                format!("handoff={} lag={}", handoff_id, lag),
            )
            .await;
        }
        if !outcome.committed {
            self.audit(
                "handoff_rollback_cause".to_string(),
                from.to_string(),
                format!(
                    "handoff={} cause={}",
                    handoff_id,
                    outcome.reason.as_deref().unwrap_or("unknown")
                ),
            )
            .await;
        }

        self.audit(
            "handoff_driver_finished".to_string(),
            from.to_string(),
            format!(
                "handoff={} state={} epoch={} commit_attempts={} reason={:?}",
                handoff_id,
                outcome.state.as_str(),
                outcome.epoch,
                outcome.commit_attempts,
                outcome.reason
            ),
        )
        .await;

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

    /// One active handoff per task, rejected at request time.
    ///
    /// This is the RT-13 guard: before it, two requests for the same task both
    /// minted tokens and both could be driven, which is the double-owner
    /// window the row is about.
    #[tokio::test]
    async fn a_second_handoff_for_a_task_in_flight_is_rejected() {
        let (hub, _sk) = hub_with("pc-1").await;
        // A second connected and enrolled device, so neither the "not
        // connected" nor the "not registered" check can be what refuses.
        let sk2 = SigningKey::generate();
        let dev2 = DeviceInfo::new(
            DeviceId::new("pc-2"),
            DeviceClass::Pc,
            "pc-2".to_owned(),
            sk2.verifying_key().to_b64(),
        );
        hub.keys
            .lock()
            .await
            .insert(dev2.id.clone(), sk2.verifying_key());
        hub.presence.lock().await.register(dev2.clone());
        let (tx2, rx2) = mpsc::channel(8);
        std::mem::forget(rx2);
        let (inbound_tx2, _inbound_rx2) = tokio::sync::broadcast::channel(8);
        hub.agents.lock().await.insert(
            dev2.id.clone(),
            AgentSession {
                device: dev2.clone(),
                tx: tx2,
                inbound_tx: inbound_tx2,
            },
        );

        let task = TaskId::new("task-one-active");
        hub.register_task_for_test(task.as_str(), "pc-1").await;

        // The first request mints a token; the attempt stays Prepared because
        // nothing drives it, which is exactly the "in flight" window.
        hub.request_handoff(&task, &DeviceId::new("pc-1"), &DeviceId::new("pc-2"))
            .await
            .expect("the first handoff is accepted");

        // The second must be refused at request time, and the refusal must be
        // auditable.
        let second = hub
            .request_handoff(&task, &DeviceId::new("pc-1"), &DeviceId::new("pc-2"))
            .await;
        let message = second.err().map(|e| e.to_string()).unwrap_or_default();
        assert!(
            message.contains("already has an active handoff"),
            "the second handoff was not refused by the one-active guard: {message}"
        );

        // And the refusal left an audit event naming the reason.
        let audit = hub.audit_events().await;
        let rejected = audit.iter().find(|e| e.action == "handoff_rejected");
        assert!(
            rejected.is_some(),
            "the rejection was not audited: {:?}",
            audit.iter().map(|e| &e.action).collect::<Vec<_>>()
        );
        let detail = rejected.expect("checked").detail.as_str();
        assert!(
            detail.contains("reason=one_active_handoff"),
            "the audit event does not name the guard: {detail}"
        );
    }

    /// Once the first attempt is terminal, a new handoff is allowed again: the
    /// guard must not wedge the task permanently.
    #[tokio::test]
    async fn a_handoff_is_accepted_again_after_the_first_ends() {
        let (hub, _sk) = hub_with("pc-1").await;
        let sk2 = SigningKey::generate();
        let dev2 = DeviceInfo::new(
            DeviceId::new("pc-2"),
            DeviceClass::Pc,
            "pc-2".to_owned(),
            sk2.verifying_key().to_b64(),
        );
        hub.keys
            .lock()
            .await
            .insert(dev2.id.clone(), sk2.verifying_key());
        hub.presence.lock().await.register(dev2.clone());
        let (tx2, rx2) = mpsc::channel(8);
        std::mem::forget(rx2);
        let (inbound_tx2, _inbound_rx2) = tokio::sync::broadcast::channel(8);
        hub.agents.lock().await.insert(
            dev2.id.clone(),
            AgentSession {
                device: dev2.clone(),
                tx: tx2,
                inbound_tx: inbound_tx2,
            },
        );

        let task = TaskId::new("task-after-terminal");
        hub.register_task_for_test(task.as_str(), "pc-1").await;
        hub.request_handoff(&task, &DeviceId::new("pc-1"), &DeviceId::new("pc-2"))
            .await
            .expect("first handoff");

        // Mark the first attempt terminal, as the driver would on rollback.
        let snapshot = hub.handoffs_snapshot().await;
        let first_id = snapshot
            .iter()
            .find(|h| h.task_id.as_str() == task.as_str())
            .expect("the attempt exists")
            .handoff_id
            .clone();
        hub.set_handoff_state_for_test(&first_id, "rolled_back", false, None)
            .await;

        // A new attempt for the same task is now allowed.
        let again = hub
            .request_handoff(&task, &DeviceId::new("pc-1"), &DeviceId::new("pc-2"))
            .await;
        assert!(
            again.is_ok(),
            "a terminal attempt still blocked a new handoff: {:?}",
            again.err().map(|e| e.to_string())
        );
    }

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
        let (inbound_tx, _inbound_rx) = tokio::sync::broadcast::channel(8);
        hub.agents.lock().await.insert(
            dev.id.clone(),
            AgentSession {
                device: dev.clone(),
                tx,
                inbound_tx,
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
                    inbound_tx: tokio::sync::broadcast::channel(8).0,
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

    #[tokio::test]
    async fn a_stale_owner_write_is_rejected_and_audited() {
        // AC-4 "stale epoch write from the old owner after the switch". The
        // old owner reports a result after the commit; the hub must refuse it
        // and record `stale_epoch_write` rather than silently applying it.
        let (hub, a, b) = hub_with_two().await;
        let task = TaskId::new("t1");
        // The target owns at epoch 1 after the switch.
        hub.owners
            .lock()
            .await
            .register("t1".to_owned(), DeviceId::new("pc-1"))
            .unwrap();
        hub.owners
            .lock()
            .await
            .commit("t1", DeviceId::new("phone-1"), 1)
            .unwrap();

        // The old owner (pc-1) forges a result for the task it no longer owns.
        let msg = WireMessage::sign(
            WireMeta {
                seq: 1,
                ts: Utc::now().timestamp(),
                from: DeviceId::new("pc-1"),
                to: "orchestrator".into(),
            },
            Payload::ToolResult {
                task_id: task.clone(),
                state: TaskState::Succeeded,
                output: "stale".into(),
            },
            &a,
        )
        .unwrap();
        let before = {
            let audit = hub.audit.lock().await;
            audit
                .events()
                .iter()
                .filter(|l| l.action == "stale_epoch_write")
                .count()
        };
        hub.handle_message(msg).await.unwrap();
        let after = {
            let audit = hub.audit.lock().await;
            audit
                .events()
                .iter()
                .filter(|l| l.action == "stale_epoch_write")
                .count()
        };
        assert_eq!(after, before + 1, "the stale write must be audit-logged");

        // The fencing state did not move.
        let owner = hub.owner("t1").await.unwrap();
        assert_eq!(owner.owner, DeviceId::new("phone-1"));
        assert_eq!(owner.epoch, 1);
        let _ = b;
    }
}
