//! Agent client: connects to the orchestrator, registers, and runs tools.
//!
//! The receive loop is transport-agnostic so it can be tested over the
//! in-memory duplex. `WsTransport` is the production transport.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use chrono::Utc;
use himan_agent_core::transport::Connection;
use himan_proto::{
    DeviceId, DeviceInfo, Payload, SigningKey, TaskId, TaskState, VerifyingKey, WireMessage,
    WireMeta,
};
use tracing::{info, trace, warn};

use crate::scenario_tool::scenario_registry;
#[cfg(feature = "fault-injection")]
use crate::scenario_tool::scenario_registry_with_effect;

/// A boxed, `'static` future — the shape a drain hook returns.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Why a registration attempt failed.
#[derive(Debug, thiserror::Error)]
pub enum RegisterError {
    #[error("unexpected reply: got {0}, expected Welcome")]
    UnexpectedReply(&'static str),

    #[error("welcome nonce mismatch: the reply does not belong to this handshake")]
    NonceMismatch,

    #[error("welcome is signed by a different key than the pinned orchestrator key")]
    NotPinnedKey,

    #[error("welcome signature invalid: {0}")]
    BadSignature(String),

    #[error("connection closed before Welcome arrived")]
    Closed,

    #[error("transport error: {0}")]
    Transport(String),
}

/// A bounded cache of recently seen tool-call nonces.
///
/// The agent must not execute the same tool call twice. A `HashSet` alone grows
/// without bound, so entries are dropped once the cache exceeds `capacity`.
#[derive(Debug, Default)]
pub struct NonceCache {
    seen: std::collections::HashSet<u64>,
    capacity: usize,
}

impl NonceCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            seen: std::collections::HashSet::new(),
            capacity: capacity.max(1),
        }
    }

    /// Record a nonce. Returns `false` if it was already present.
    pub fn insert(&mut self, nonce: u64) -> bool {
        if self.seen.contains(&nonce) {
            return false;
        }
        if self.seen.len() >= self.capacity {
            // Bounded eviction: clear rather than track insertion order. This
            // is a replay guard, not a cache; a cleared entry can only allow a
            // replay after many intervening calls, which the orchestrator's
            // seq tracker also blocks.
            self.seen.clear();
        }
        self.seen.insert(nonce);
        true
    }
}

/// A running agent session.
pub struct AgentClient {
    device_id: DeviceId,
    key: SigningKey,
    conn: Connection,
    seq: u64,
    /// The orchestrator's public key, pinned out of band.
    ///
    /// A Welcome is accepted only if its embedded key equals this AND the
    /// signature verifies with it. Without pinning, any server can sign its
    /// own Welcome and impersonate the orchestrator.
    pinned_orchestrator_key: Option<VerifyingKey>,
    /// The orchestrator key the Welcome signature verified against. Used to
    /// verify every later message when no out-of-band pin is configured.
    session_orchestrator_key: Option<VerifyingKey>,
    /// Tool calls already executed, so a replayed call is not run twice.
    seen_nonces: std::sync::Mutex<NonceCache>,
    /// Keepalive interval; defaults to 60s when unset or invalid.
    keepalive_interval: std::time::Duration,
    /// Number of keepalive pings sent in this session.
    keepalive_pings: u64,
    /// Number of Pongs received. A stall means the orchestrator is gone and the
    /// agent should reconnect.
    pongs_received: u64,
    /// Send handle for the keepalive task.
    keepalive_sender: Option<himan_agent_core::KeepaliveSender>,
    /// Highest log seq this device has produced, reported during a handoff.
    last_seq: u64,
    /// Set when the orchestrator asks this device to drain. A scenario run
    /// stops starting new steps; a plain agent is already idle.
    stopping: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Tool calls currently running. A drain waits for these so a
    /// non-idempotent effect is not left half-applied across a switch.
    in_flight: std::sync::Arc<std::sync::atomic::AtomicU64>,
    /// Optional drain hook: a scenario run registers its stop handle here.
    stop_hook: Option<Arc<dyn Fn() -> BoxFuture<'static, ()> + Send + Sync>>,
}

/// The token's own claims: the target must be the presenter, the task must
/// match, and the token must not be expired.
///
/// The *signature* is verified by the orchestrator's signed envelope; this
/// rule is what stops a token minted for one target being replayed at another.
/// It is a free function so the red-team test exercises exactly the code the
/// agent runs, not a copy of it.
pub fn token_matches(token: &himan_proto::HandoffToken, to: &DeviceId, task_id: &TaskId) -> bool {
    if token.to_device != *to {
        return false;
    }
    if token.task_id != *task_id {
        return false;
    }
    if token.is_expired(chrono::Utc::now().timestamp()) {
        return false;
    }
    true
}

impl AgentClient {
    pub fn new(device_id: DeviceId, key: SigningKey, conn: Connection) -> Self {
        let (keepalive_interval, configured) = crate::keepalive::configured_interval();
        if !configured {
            tracing::warn!(
                "HIMAN_KEEPALIVE_SECS is unset or invalid; using {}s",
                keepalive_interval.as_secs()
            );
        }
        let keepalive_sender = conn.keepalive_sender();
        Self {
            device_id,
            key,
            conn,
            seq: 0,
            pinned_orchestrator_key: None,
            session_orchestrator_key: None,
            seen_nonces: std::sync::Mutex::new(NonceCache::new(1024)),
            keepalive_interval,
            keepalive_pings: 0,
            pongs_received: 0,
            keepalive_sender,
            last_seq: 0,
            stopping: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            in_flight: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            stop_hook: None,
        }
    }

    /// Override the keepalive interval (used by tests).
    pub fn with_keepalive_interval(mut self, interval: std::time::Duration) -> Self {
        self.keepalive_interval = interval;
        self
    }

    /// Pin the orchestrator's public key (base64).
    ///
    /// Once set, a Welcome from any other key is rejected.
    pub fn with_pinned_orchestrator_key(
        mut self,
        key_b64: &str,
    ) -> Result<Self, himan_proto::ProtoError> {
        self.pinned_orchestrator_key = Some(VerifyingKey::from_b64(key_b64)?);
        Ok(self)
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

        // Three checks, each with its own error so the failure is diagnosable:
        //   1. the embedded key must equal the pinned key
        //   2. the signature must verify with that key
        //   3. the nonce must match this handshake
        if let Some(pinned) = &self.pinned_orchestrator_key {
            if orchestrator_key != pinned.to_b64() {
                warn!(
                    expected = %pinned.to_b64(),
                    "welcome advertises a key that is not the pinned orchestrator key"
                );
                return Err(RegisterError::NotPinnedKey);
            }
        }

        // The Welcome is signed by the key it advertises. Verify against the
        // pinned key when one is set, otherwise against the advertised key.
        let vk = VerifyingKey::from_b64(&orchestrator_key)
            .map_err(|e| RegisterError::BadSignature(e.to_string()))?;
        msg.verify_with(&vk)
            .map_err(|e| RegisterError::BadSignature(e.to_string()))?;
        // Remember the key the Welcome proved, so every later message is
        // verified against it even without an out-of-band pin.
        self.session_orchestrator_key = Some(vk);

        info!(
            %device_id,
            orchestrator_key = %orchestrator_key,
            "registered with orchestrator"
        );
        Ok(info)
    }

    /// Ask this device to stop starting new work.
    ///
    /// A drain is a request to reach a safe point, not a kill: the agent
    /// finishes the step it is in and then reports `HandoffDrained` with the
    /// last seq it produced. `stop` is the hook a running scenario uses to
    /// break between steps.
    pub async fn request_stop(&self) {
        self.stopping
            .store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(stop) = &self.stop_hook {
            stop().await;
        }
    }

    /// Install the drain hook (a scenario run's stop handle).
    pub fn with_stop_hook<F>(mut self, stop: F) -> Self
    where
        F: Fn() -> BoxFuture<'static, ()> + Send + Sync + 'static,
    {
        self.stop_hook = Some(Arc::new(stop));
        self
    }

    /// Whether a drain has been requested.
    pub fn stopping(&self) -> bool {
        self.stopping.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Run the receive loop until the connection closes.
    ///
    /// Incoming `ToolCall`s are checked before anything runs:
    ///   1. the call targets this device
    ///   2. the nonce has not been seen before (replay guard)
    ///   3. the envelope timestamp is recent
    ///
    /// Then the tool whitelist is applied. Results are sent back as signed
    /// `ToolResult`s.
    /// Run the receive loop until the connection closes.
    ///
    /// Incoming `ToolCall`s are checked before anything runs:
    ///   1. the call targets this device
    ///   2. the nonce has not been seen before (replay guard)
    ///   3. the envelope timestamp is recent
    ///
    /// Then the tool whitelist is applied. Results are sent back as signed
    /// `ToolResult`s.
    pub async fn run(&mut self) {
        info!(
            interval_secs = self.keepalive_interval.as_secs(),
            "keepalive enabled"
        );

        let mut ping_ticker = tokio::time::interval(self.keepalive_interval);
        ping_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // The first tick fires immediately; consume it so registration settles.
        ping_ticker.tick().await;

        // Pongs received at the last ping, used to detect a silent peer.
        let mut pongs_at_last_ping = self.pongs_received;

        loop {
            let incoming = tokio::select! {
                biased;
                incoming = self.conn.recv() => {
                    match incoming {
                        Some(m) => m,
                        None => {
                            info!("connection closed, agent exiting");
                            break;
                        }
                    }
                }
                _ = ping_ticker.tick() => {
                    // A missing Pong means the orchestrator is gone or wedged:
                    // reconnect rather than wait for the idle timeout.
                    if self.keepalive_pings > 0 && pongs_at_last_ping == self.pongs_received {
                        warn!(
                            interval_secs = self.keepalive_interval.as_secs(),
                            "no Pong since the previous keepalive; reconnect needed"
                        );
                        break;
                    }
                    pongs_at_last_ping = self.pongs_received;
                    self.send_keepalive_ping();
                    continue;
                }
            };
            if !self.handle_once(Some(incoming)).await {
                break;
            }
        }
    }

    /// Wait for the next envelope from the orchestrator.
    ///
    /// `None` means the connection closed. Shared with the scenario runner,
    /// which must keep answering handoff messages while its task advances.
    pub async fn recv_message(&mut self) -> Option<himan_proto::WireMessage> {
        self.conn.recv().await
    }

    /// Handle one incoming envelope. Returns `false` when the loop should stop.
    ///
    /// Shared by [`AgentClient::run`] and the scenario runner, which must keep
    /// answering handoff messages while its own task advances.
    pub async fn handle_once(&mut self, incoming: Option<himan_proto::WireMessage>) -> bool {
        let msg = match incoming {
            Some(m) => m,
            None => {
                info!("connection closed, agent exiting");
                return false;
            }
        };

        // Every post-handshake message must be signed by the orchestrator key
        // verified at registration. The Welcome check alone is not enough:
        // without this, anything that can write to the socket after the
        // handshake (a MITM on plain ws://, a hostile proxy) can inject tool
        // calls, drains and commits that the agent would act on. The key is
        // the one the Welcome proved — pinned out of band when configured,
        // otherwise the advertised key the Welcome signature verified
        // against. It is never taken from the incoming message itself.
        let orch_key = self
            .pinned_orchestrator_key
            .as_ref()
            .or(self.session_orchestrator_key.as_ref());
        match orch_key {
            Some(key) => {
                if let Err(e) = msg.verify_with(key) {
                    warn!(error = %e, from = %msg.meta.from, "message signature does not verify against the orchestrator key; dropping");
                    return true;
                }
            }
            None => {
                warn!("no orchestrator key available; dropping message");
                return true;
            }
        }

        // A test can ask for the non-idempotent effect tool, which is how a
        // non-idempotent call in flight at the switch is exercised.
        #[cfg(feature = "fault-injection")]
        let tools = if std::env::var("HIMAN_TEST_EFFECT_TOOL").as_deref() == Ok("1") {
            scenario_registry_with_effect(std::time::Duration::from_millis(100))
        } else {
            scenario_registry(std::time::Duration::from_millis(100))
        };
        #[cfg(not(feature = "fault-injection"))]
        let tools = scenario_registry(std::time::Duration::from_millis(100));
        let call = match &msg.payload {
            Payload::ToolCall(call) => call.clone(),
            Payload::Ping { nonce } => {
                if let Err(e) = self.send(Payload::Pong { nonce: *nonce }).await {
                    warn!(error = %e, "failed to send pong");
                    return false;
                }
                return true;
            }
            Payload::Pong { .. } => {
                // Keepalive reply. Count it so the caller can detect a
                // silent orchestrator and reconnect.
                self.pongs_received += 1;
                trace!("keepalive pong received");
                return true;
            }
            // Handoff prepare: the target accepts or refuses. The token
            // is verified against the pinned orchestrator key and the
            // `to` field must be this device, so a token minted for
            // another target is not accepted here.
            Payload::HandoffPrepare {
                handoff_id,
                task_id,
                from,
                to,
                epoch,
                checkpoint_seq,
                token,
            } => {
                let accepted = self.verify_handoff_token(token, to, task_id);
                info!(
                    handoff = %handoff_id,
                    task = %task_id,
                    from = %from,
                    epoch,
                    checkpoint_seq,
                    accepted,
                    "handoff prepare received"
                );
                // AC-3 needs a target that never sends Ready, so the
                // orchestrator's warming timeout fires and the handoff rolls
                // back. Compiled only under the `fault-injection` feature: a
                // production device must never refuse to answer a handoff.
                #[cfg(feature = "fault-injection")]
                if std::env::var("HIMAN_TEST_NEVER_READY").as_deref() == Ok("1") {
                    warn!(
                        handoff = %handoff_id,
                        "HIMAN_TEST_NEVER_READY=1: not sending HandoffReady"
                    );
                    return true;
                }
                // Durability test: stay in Warming long enough for the
                // orchestrator to be restarted mid-handoff.
                #[cfg(feature = "fault-injection")]
                if let Ok(ms) = std::env::var("HIMAN_TEST_SLOW_READY_MS") {
                    if let Ok(ms) = ms.parse::<u64>() {
                        tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
                    }
                }
                if let Err(e) = self
                    .send(Payload::HandoffReady {
                        handoff_id: handoff_id.clone(),
                        applied_seq: self.last_seq,
                        capabilities: "full".into(),
                    })
                    .await
                {
                    warn!(error = %e, "failed to acknowledge handoff");
                    return false;
                }
                return true;
            }
            // The target warmed: it reports the log position it has
            // applied, so the orchestrator can stream from the checkpoint.
            Payload::HandoffReady {
                handoff_id,
                applied_seq,
                capabilities,
            } => {
                info!(
                    handoff = %handoff_id,
                    applied_seq,
                    %capabilities,
                    "reporting shadow readiness"
                );
                if let Err(e) = self
                    .send(Payload::HandoffProgress {
                        handoff_id: handoff_id.clone(),
                        applied_seq: *applied_seq,
                    })
                    .await
                {
                    warn!(error = %e, "failed to send shadow progress");
                    return false;
                }
                return true;
            }
            // The orchestrator asks this device (as the source) to stop
            // starting new steps and report the last seq it produced. A
            // scenario run stops between steps; a plain agent is already
            // idle, so it drains immediately.
            Payload::HandoffDrain {
                handoff_id,
                new_epoch,
            } => {
                info!(handoff = %handoff_id, new_epoch, "drain requested");
                // AC-4 "kill the source in Shadowing": the source stops
                // answering at the drain, so the switch times out and rolls
                // back. Feature-gated.
                #[cfg(feature = "fault-injection")]
                if std::env::var("HIMAN_TEST_DRAIN_SILENT").as_deref() == Ok("1") {
                    warn!(
                        handoff = %handoff_id,
                        "HIMAN_TEST_DRAIN_SILENT=1: not sending HandoffDrained"
                    );
                    return true;
                }
                self.request_stop().await;
                // Wait for any in-flight call to finish before reporting the
                // drain. A non-idempotent effect must not be left running while
                // the target takes over and possibly replays the step.
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
                while self.in_flight.load(Ordering::SeqCst) > 0 {
                    if std::time::Instant::now() >= deadline {
                        warn!(handoff = %handoff_id, "timed out waiting for an in-flight call");
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
                if let Err(e) = self
                    .send(Payload::HandoffDrained {
                        handoff_id: handoff_id.clone(),
                        last_seq: self.last_seq,
                    })
                    .await
                {
                    warn!(error = %e, "failed to send drain acknowledgement");
                    return false;
                }
                return true;
            }
            Payload::HandoffRollback { handoff_id, reason } => {
                info!(handoff = %handoff_id, %reason, "handoff rolled back");
                return true;
            }
            Payload::HandoffCommit {
                handoff_id,
                new_epoch,
                final_seq,
            } => {
                info!(
                    handoff = %handoff_id,
                    new_epoch,
                    final_seq,
                    "handoff commit received; this device is now the owner"
                );
                // AC-4 "duplicate SwitchCommit": acknowledge twice so the
                // driver sees the same commit acknowledged two times. The
                // handoff must still be idempotent. Feature-gated.
                #[cfg(feature = "fault-injection")]
                let duplicate = std::env::var("HIMAN_TEST_DUPLICATE_COMMIT").as_deref() == Ok("1");
                #[cfg(not(feature = "fault-injection"))]
                let duplicate = false;
                if duplicate {
                    let _ = self
                        .send(Payload::HandoffSwitched {
                            handoff_id: handoff_id.clone(),
                            new_epoch: *new_epoch,
                        })
                        .await;
                }
                if let Err(e) = self
                    .send(Payload::HandoffSwitched {
                        handoff_id: handoff_id.clone(),
                        new_epoch: *new_epoch,
                    })
                    .await
                {
                    warn!(error = %e, "failed to acknowledge the commit");
                    return false;
                }
                return true;
            }
            other => {
                warn!(?other, "unexpected payload from orchestrator");
                return true;
            }
        };

        info!(tool = %call.tool, task = %call.task_id, "tool call received");

        // This device produced an event, so the log head advances. The
        // handoff drain reports it as the safe point.
        self.last_seq += 1;

        // 1. Target device check.
        if call.target_device != self.device_id {
            warn!(
                expected = %self.device_id,
                got = %call.target_device,
                "tool call targets a different device"
            );
            let _ = self
                .send(Payload::ToolResult {
                    task_id: call.task_id,
                    state: TaskState::Failed,
                    output: "tool call targets a different device".into(),
                })
                .await;
            return true;
        }

        // 2. Replay guard: the nonce must not have been seen before.
        let fresh = self
            .seen_nonces
            .lock()
            .map(|mut cache| cache.insert(call.nonce))
            .unwrap_or(false);
        if !fresh {
            warn!(nonce = call.nonce, "replayed tool call rejected");
            let _ = self
                .send(Payload::ToolResult {
                    task_id: call.task_id,
                    state: TaskState::Failed,
                    output: "tool call nonce already seen".into(),
                })
                .await;
            return true;
        }

        // 3. Freshness: reject stale envelopes.
        if msg.is_stale(chrono::Utc::now().timestamp(), 120) {
            warn!(task = %call.task_id, "tool call timestamp is stale");
            let _ = self
                .send(Payload::ToolResult {
                    task_id: call.task_id,
                    state: TaskState::Failed,
                    output: "tool call is stale".into(),
                })
                .await;
            return true;
        }

        // The whitelist is the security boundary: a call for a tool this
        // device does not expose is refused, not run.
        let result = match tools.resolve(&call.tool) {
            Ok(tool) => {
                // Track the call so a drain can wait for it: a non-idempotent
                // effect must finish before the switch, otherwise the target
                // could replay it.
                self.in_flight.fetch_add(1, Ordering::SeqCst);
                let idempotency = tool.idempotency();
                let outcome = tool.run(&self.device_id, call.args).await;
                self.in_flight.fetch_sub(1, Ordering::SeqCst);
                tracing::debug!(tool = %call.tool, ?idempotency, "tool call finished");
                match outcome {
                    Ok(output) => output,
                    Err(e) => {
                        if self
                            .send(Payload::ToolResult {
                                task_id: call.task_id.clone(),
                                state: TaskState::Failed,
                                output: e.to_string(),
                            })
                            .await
                            .is_err()
                        {
                            return false;
                        }
                        return true;
                    }
                }
            }
            Err(e) => {
                let _ = self
                    .send(Payload::ToolResult {
                        task_id: call.task_id,
                        state: TaskState::Failed,
                        output: e.to_string(),
                    })
                    .await;
                return true;
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
            return false;
        }
        true
    }

    /// Decide whether this device accepts a handoff token.
    ///
    /// Three checks, mirroring the Welcome checks: the token must not be
    /// expired, `to` must be this device, and `task_id` must match the prepare.
    /// The token's *signature* is verified by the orchestrator sending it in a
    /// signed envelope; this method enforces the token's own claims, which is
    /// what stops a token minted for another target from being replayed here.
    fn verify_handoff_token(
        &self,
        token: &himan_proto::HandoffToken,
        to: &DeviceId,
        task_id: &TaskId,
    ) -> bool {
        if !token_matches(token, to, task_id) {
            warn!(
                expected = %self.device_id,
                got = %to,
                "handoff token is for a different target or task, or expired"
            );
            return false;
        }
        true
    }

    /// Send one signed keepalive Ping.
    ///
    /// The orchestrator answers with a Pong. A failure means the write half is
    /// gone, so the caller should reconnect.
    fn send_keepalive_ping(&mut self) {
        self.keepalive_pings += 1;
        let nonce = self.keepalive_pings;
        let meta = WireMeta {
            seq: self.seq,
            ts: chrono::Utc::now().timestamp(),
            from: self.device_id.clone(),
            to: "orchestrator".into(),
        };
        self.seq += 1;

        match WireMessage::sign(meta, Payload::Ping { nonce }, &self.key) {
            Ok(ping) => {
                // The send handle is independent of the receiver, so this runs
                // without blocking the main recv loop.
                if let Some(sender) = self.keepalive_sender.clone() {
                    tokio::spawn(async move {
                        if let Err(e) =
                            himan_agent_core::transport::Connection::send_via(&sender, ping).await
                        {
                            tracing::warn!(error = %e, "keepalive ping failed");
                        }
                    });
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to sign keepalive ping");
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
    // TLS is mandatory for agent<->orchestrator traffic: signatures prove
    // device data. Plain ws:// is refused unless this is a debug build
    // explicitly compiled with the insecure-ws-dev feature for loopback use.
    if url.starts_with("ws://") && !crate::INSECURE_WS_ALLOWED {
        return Err("refusing insecure ws:// URL: TLS (wss://) is required; \
                    a debug build with the insecure-ws-dev feature may use \
                    plain ws:// for loopback development"
            .into());
    }
    if !url.starts_with("ws://") && !url.starts_with("wss://") {
        return Err(format!("unsupported WebSocket URL scheme: {url:?}").into());
    }
    let transport = Arc::new(himan_agent_core::WsTransport::connect(url).await?);
    let conn = himan_agent_core::transport::ws::connection_from_socket(transport, 64);
    Ok(AgentClient::new(device_id, key, conn))
}

#[cfg(test)]
mod tests {
    use super::*;
    use himan_agent_core::transport::Connection;
    use himan_proto::{HandoffToken, TaskId, ToolCall, ToolName};
    use serde_json::json;

    fn token_for(to: &str, task: &str, expires_at: i64) -> HandoffToken {
        HandoffToken {
            task_id: TaskId::new(task),
            from_device: DeviceId::new("pc-1"),
            to_device: DeviceId::new(to),
            expires_at,
            nonce: 1,
        }
    }

    #[test]
    fn a_token_for_this_device_and_task_is_accepted() {
        let (_a, _b) = Connection::channel(8);
        let key = SigningKey::generate();
        let client = AgentClient::new(DeviceId::new("phone-1"), key, _a);
        let token = token_for("phone-1", "t1", chrono::Utc::now().timestamp() + 300);
        assert!(client.verify_handoff_token(&token, &DeviceId::new("phone-1"), &TaskId::new("t1")));
    }

    #[test]
    fn a_token_minted_for_another_target_is_refused() {
        let (_a, _b) = Connection::channel(8);
        let key = SigningKey::generate();
        let client = AgentClient::new(DeviceId::new("phone-1"), key, _a);
        // A token for pc-2 must not be accepted by phone-1 even though the
        // prepare claims `to` is phone-1.
        let token = token_for("pc-2", "t1", chrono::Utc::now().timestamp() + 300);
        assert!(!client.verify_handoff_token(
            &token,
            &DeviceId::new("phone-1"),
            &TaskId::new("t1")
        ));
    }

    #[test]
    fn a_token_for_another_task_is_refused() {
        let (_a, _b) = Connection::channel(8);
        let key = SigningKey::generate();
        let client = AgentClient::new(DeviceId::new("phone-1"), key, _a);
        let token = token_for("phone-1", "t2", chrono::Utc::now().timestamp() + 300);
        assert!(!client.verify_handoff_token(
            &token,
            &DeviceId::new("phone-1"),
            &TaskId::new("t1")
        ));
    }

    #[test]
    fn an_expired_token_is_refused() {
        let (_a, _b) = Connection::channel(8);
        let key = SigningKey::generate();
        let client = AgentClient::new(DeviceId::new("phone-1"), key, _a);
        let token = token_for("phone-1", "t1", chrono::Utc::now().timestamp() - 1);
        assert!(!client.verify_handoff_token(
            &token,
            &DeviceId::new("phone-1"),
            &TaskId::new("t1")
        ));
    }

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
        let orch_key = SigningKey::generate();
        let mut client = AgentClient::new(DeviceId::new("pc-1"), key, a)
            .with_pinned_orchestrator_key(&orch_key.verifying_key().to_b64())
            .expect("pin");

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
            &orch_key,
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
        let orch_key = SigningKey::generate();
        let mut client = AgentClient::new(DeviceId::new("pc-1"), key, a)
            .with_pinned_orchestrator_key(&orch_key.verifying_key().to_b64())
            .expect("pin");

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
            &orch_key,
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

    /// A post-handshake message signed by a DIFFERENT key must be dropped:
    /// no tool runs, no reply is sent. This is the MITM-on-plain-ws case —
    /// the Welcome was genuine, but a later frame is injected by something
    /// that can write to the socket.
    #[tokio::test]
    async fn a_message_signed_by_another_key_is_dropped() {
        let (a, peer) = Connection::channel(8);
        let key = SigningKey::generate();
        let orch_key = SigningKey::generate();
        let mut client = AgentClient::new(DeviceId::new("pc-1"), key, a)
            .with_pinned_orchestrator_key(&orch_key.verifying_key().to_b64())
            .expect("pin");

        let handle = tokio::spawn(async move { client.run().await });

        let call = ToolCall {
            task_id: TaskId::new("t-injected"),
            tool: ToolName::new("device_status"),
            args: json!({}),
            risk_tier: himan_proto::RiskTier::ReadOnly,
            target_device: DeviceId::new("pc-1"),
            nonce: 7,
        };
        // Signed by the ATTACKER's key, not the pinned orchestrator key.
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

        // Nothing may come back: the frame is dropped before any handler.
        let silent = tokio::time::timeout(std::time::Duration::from_millis(500), peer.recv()).await;
        assert!(
            silent.is_err(),
            "an injected message produced a reply: {:?}",
            silent.ok()
        );

        // The session is still alive: a correctly signed call works after it.
        let good = WireMessage::sign(
            WireMeta {
                seq: 2,
                ts: Utc::now().timestamp(),
                from: DeviceId::new("orchestrator"),
                to: "pc-1".into(),
            },
            Payload::ToolCall(ToolCall {
                task_id: TaskId::new("t-good"),
                tool: ToolName::new("device_status"),
                args: json!({}),
                risk_tier: himan_proto::RiskTier::ReadOnly,
                target_device: DeviceId::new("pc-1"),
                nonce: 8,
            }),
            &orch_key,
        )
        .unwrap();
        peer.send(good).await.unwrap();
        let reply = tokio::time::timeout(std::time::Duration::from_secs(5), peer.recv())
            .await
            .expect("the legitimate call should still be answered")
            .expect("some message");
        match reply.payload {
            Payload::ToolResult { task_id, state, .. } => {
                assert_eq!(task_id.as_str(), "t-good");
                assert_eq!(state, TaskState::Succeeded);
            }
            other => panic!("expected ToolResult, got {other:?}"),
        }

        peer.close().await;
        handle.abort();
    }

    /// An unsigned-tampered commit is dropped too: the attacker must not be
    /// able to make the device believe a handoff committed.
    #[tokio::test]
    async fn an_injected_handoff_commit_is_dropped() {
        let (a, peer) = Connection::channel(8);
        let key = SigningKey::generate();
        let orch_key = SigningKey::generate();
        let mut client = AgentClient::new(DeviceId::new("pc-1"), key, a)
            .with_pinned_orchestrator_key(&orch_key.verifying_key().to_b64())
            .expect("pin");

        let handle = tokio::spawn(async move { client.run().await });

        let msg = WireMessage::sign(
            WireMeta {
                seq: 1,
                ts: Utc::now().timestamp(),
                from: DeviceId::new("orchestrator"),
                to: "pc-1".into(),
            },
            Payload::HandoffCommit {
                handoff_id: "h-forged".into(),
                new_epoch: 99,
                final_seq: 0,
            },
            &SigningKey::generate(),
        )
        .unwrap();
        peer.send(msg).await.unwrap();

        // A real commit is acknowledged with HandoffSwitched; a forged one
        // must produce nothing.
        let silent = tokio::time::timeout(std::time::Duration::from_millis(500), peer.recv()).await;
        assert!(
            silent.is_err(),
            "a forged commit was acknowledged: {:?}",
            silent.ok()
        );

        peer.close().await;
        handle.abort();
    }
}
