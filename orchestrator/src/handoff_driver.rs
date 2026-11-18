//! Handoff driver: walks one handoff from Prepared to Active.
//!
//! [`crate::handoff::Handoff`] decides *when* ownership may move; this module
//! actually moves it. It sends `HandoffPrepare` to the target, waits for
//! `HandoffReady`, reports shadow lag, asks the source to drain, waits for
//! `HandoffDrained`, performs the commit, sends `HandoffCommit`, and retries
//! the commit a bounded number of times before declaring the target failed.
//!
//! Transport-agnostic in the same way the agent loop is: the caller supplies
//! two [`Mailbox`] handles and a signer. Nothing here opens a socket, so the
//! procedure is testable with in-memory mailboxes while the live wiring
//! supplies real ones.

use std::time::Duration;

use himan_proto::{DeviceId, HandoffToken, Payload, WireMessage};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::handoff::{Handoff, HandoffEvent, HandoffState, HandoffTimeouts};

/// A bounded number of commit retries before the target is declared failed
/// (spec section 8: retry `HandoffCommit`, then mark the target failed and
/// offer the task to another device).
#[derive(Debug, Clone, Copy)]
pub struct RetryPolicy {
    pub commit_attempts: u32,
    pub delay: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            commit_attempts: 3,
            delay: Duration::from_millis(200),
        }
    }
}

/// One device's two message paths.
///
/// `outbound` is where the orchestrator queues messages for the agent;
/// `inbound` is where that agent's replies arrive. Splitting them is what lets
/// the driver send and receive without borrowing a session twice.
pub struct Mailbox {
    pub outbound: mpsc::Sender<WireMessage>,
    /// Receives that agent's replies. A trait object so the production path can
    /// hand the driver a broadcast subscription (which cannot be "taken away"
    /// from the socket handler) while the unit tests use a plain channel pair.
    pub inbound: Box<dyn Inbound + Send + Sync>,
}

/// The result of waiting for the next inbound message.
#[derive(Debug)]
pub enum InboundEvent {
    /// A message arrived. Boxed so a small variant (Lagged) does not inflate
    /// the enum to the size of a whole wire message.
    Message(Box<WireMessage>),
    /// The stream ended: the peer is gone.
    Closed,
    /// This subscriber fell behind and lost messages.
    ///
    /// A lag is not a timeout and not a closed channel. It means the driver
    /// cannot prove it saw every reply, so the caller must record it rather
    /// than silently carrying on.
    Lagged(u64),
}

/// One inbound message source: the next reply from an agent.
#[async_trait::async_trait]
pub trait Inbound: Send + Sync {
    async fn recv(&mut self) -> InboundEvent;
}

#[async_trait::async_trait]
impl Inbound for mpsc::Receiver<WireMessage> {
    async fn recv(&mut self) -> InboundEvent {
        match self.recv().await {
            Some(msg) => InboundEvent::Message(Box::new(msg)),
            None => InboundEvent::Closed,
        }
    }
}

#[async_trait::async_trait]
impl Inbound for tokio::sync::broadcast::Receiver<WireMessage> {
    async fn recv(&mut self) -> InboundEvent {
        match self.recv().await {
            Ok(msg) => InboundEvent::Message(Box::new(msg)),
            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => InboundEvent::Lagged(n),
            Err(tokio::sync::broadcast::error::RecvError::Closed) => InboundEvent::Closed,
        }
    }
}

impl Mailbox {
    /// Create two mailboxes wired to each other.
    ///
    /// Deliberately two separate channel pairs rather than one shared channel:
    /// routing both directions through one channel is exactly the bug that made
    /// the agent's registration read its own Hello back as a Welcome.
    pub fn pair(capacity: usize) -> (Self, Self) {
        let (a_tx, a_rx) = mpsc::channel(capacity);
        let (b_tx, b_rx) = mpsc::channel(capacity);
        (
            Self {
                outbound: a_tx,
                inbound: Box::new(b_rx),
            },
            Self {
                outbound: b_tx,
                inbound: Box::new(a_rx),
            },
        )
    }
}

/// What the driver did. Every field is asserted on by the acceptance tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriveOutcome {
    pub handoff_id: String,
    pub state: HandoffState,
    pub epoch: u64,
    /// Wall-clock time from the first send to the terminal state.
    pub switch_time_ms: u128,
    /// States the attempt passed through, in order, without repeats.
    pub path: Vec<HandoffState>,
    /// Why the attempt ended, if it did not reach Active.
    pub reason: Option<String>,
    /// Commit messages actually sent, including retries.
    pub commit_attempts: u32,
    /// Whether the state machine committed.
    pub committed: bool,
    /// Devices the task was offered to after a failure, if any.
    pub offered_to: Vec<DeviceId>,
    /// Wall-clock start of the attempt, for the total-time metric.
    pub started_at_ms: i64,
    /// How far behind the source the target was at the switch, in log events.
    pub replay_lag: Option<u64>,
}

/// A driver bound to one handoff attempt.
pub struct HandoffDriver {
    handoff: Handoff,
    source: Mailbox,
    target: Mailbox,
    timeouts: HandoffTimeouts,
    retries: RetryPolicy,
    path: Vec<HandoffState>,
    /// Wall-clock start, kept so the outcome can report total time.
    started_at_ms: i64,
    /// How far behind the source the target was when the switch happened.
    replay_lag: Option<u64>,
}

impl HandoffDriver {
    pub fn new(
        handoff: Handoff,
        source: Mailbox,
        target: Mailbox,
        timeouts: HandoffTimeouts,
        retries: RetryPolicy,
    ) -> Self {
        Self {
            handoff,
            source,
            target,
            timeouts,
            retries,
            path: vec![HandoffState::Prepared],
            started_at_ms: chrono::Utc::now().timestamp_millis(),
            replay_lag: None,
        }
    }

    /// Run the procedure to a terminal state.
    ///
    /// `sign` turns a payload into a signed message so the driver never holds
    /// key material; `clock` supplies the timestamp that drives timeouts.
    pub async fn run<F, C>(
        mut self,
        token: &HandoffToken,
        applied_seq: u64,
        sign: F,
        mut clock: C,
    ) -> DriveOutcome
    where
        F: Fn(Payload) -> WireMessage,
        C: FnMut() -> i64,
    {
        let start = std::time::Instant::now();
        let attempts = 0u32;

        let prepared = self.prepare(token, applied_seq, &sign, &mut clock).await;
        if let Some(reason) = prepared {
            return self.finish(start, attempts, Some(reason));
        }

        let shadowed = self.shadow(applied_seq, &sign, &mut clock).await;
        if let Some(reason) = shadowed {
            return self.finish(start, attempts, Some(reason));
        }

        self.commit_and_ack(applied_seq, &sign, &mut clock, start, attempts)
            .await
    }

    /// Prepared -> Shadowing. Returns `Some(reason)` on failure.
    async fn prepare<F, C>(
        &mut self,
        token: &HandoffToken,
        applied_seq: u64,
        sign: &F,
        clock: &mut C,
    ) -> Option<String>
    where
        F: Fn(Payload) -> WireMessage,
        C: FnMut() -> i64,
    {
        let prepare = sign(Payload::HandoffPrepare {
            handoff_id: self.handoff.handoff_id.clone(),
            task_id: self.handoff.task_id.clone(),
            from: self.handoff.from.clone(),
            to: self.handoff.to.clone(),
            epoch: self.handoff.epoch,
            checkpoint_seq: self.handoff.checkpoint_seq,
            token: token.clone(),
        });
        if let Err(e) = Self::send(&self.target, prepare).await {
            return Some(format!("prepare not delivered: {e}"));
        }

        match Self::wait_for(
            &mut self.target,
            |p| matches!(p, Payload::HandoffReady { .. }),
            self.timeouts.shadowing,
        )
        .await
        {
            Reply::Matched => {
                info!("driver: received HandoffReady from target");
                self.apply(HandoffEvent::PrepareAccepted, clock);
                self.apply(
                    HandoffEvent::TargetReady {
                        applied_seq,
                        capabilities: "full".into(),
                    },
                    clock,
                );
                None
            }
            Reply::Other(kind) => Some(format!("expected HandoffReady, got {kind}")),
            Reply::Silent => Some("target never sent HandoffReady".into()),
            Reply::Lagged(n) => Some(format!(
                "lost {n} inbound message(s) waiting for HandoffReady"
            )),
        }
    }

    /// Shadowing -> Switching. Returns `Some(reason)` on failure.
    async fn shadow<F, C>(&mut self, applied_seq: u64, sign: &F, clock: &mut C) -> Option<String>
    where
        F: Fn(Payload) -> WireMessage,
        C: FnMut() -> i64,
    {
        self.apply(HandoffEvent::ShadowProgress { applied_seq }, clock);

        let drain = sign(Payload::HandoffDrain {
            handoff_id: self.handoff.handoff_id.clone(),
            new_epoch: self.handoff.epoch + 1,
        });
        if let Err(e) = Self::send(&self.source, drain).await {
            return Some(format!("drain not delivered: {e}"));
        }

        match Self::wait_for(
            &mut self.source,
            |p| matches!(p, Payload::HandoffDrained { .. }),
            self.timeouts.shadowing,
        )
        .await
        {
            Reply::Matched => {
                info!("driver: received HandoffDrained from source");
                self.apply(
                    HandoffEvent::SourceDrained {
                        last_seq: applied_seq,
                    },
                    clock,
                );
                None
            }
            Reply::Other(kind) => Some(format!("expected HandoffDrained, got {kind}")),
            Reply::Silent => Some("source never drained".into()),
            Reply::Lagged(n) => Some(format!(
                "lost {n} inbound message(s) waiting for HandoffDrained"
            )),
        }
    }

    /// Switching -> Active, with a bounded commit retry. Returns the outcome.
    async fn commit_and_ack<F, C>(
        &mut self,
        applied_seq: u64,
        sign: &F,
        clock: &mut C,
        start: std::time::Instant,
        mut attempts: u32,
    ) -> DriveOutcome
    where
        F: Fn(Payload) -> WireMessage,
        C: FnMut() -> i64,
    {
        let new_epoch = self.handoff.epoch + 1;
        let commit = sign(Payload::HandoffCommit {
            handoff_id: self.handoff.handoff_id.clone(),
            new_epoch,
            final_seq: applied_seq,
        });

        loop {
            if let Err(e) = Self::send(&self.target, commit.clone()).await {
                return self.finish(start, attempts, Some(format!("commit not delivered: {e}")));
            }
            attempts += 1;

            match Self::wait_for(
                &mut self.target,
                |p| matches!(p, Payload::HandoffSwitched { .. }),
                self.timeouts.switching,
            )
            .await
            {
                Reply::Matched => {
                    // The commit is recorded once, on the transition out of
                    // Switching. A retry that also lands is a no-op, which is
                    // what makes the commit idempotent by (handoff_id, epoch).
                    if self.handoff.state == HandoffState::Switching {
                        self.apply(HandoffEvent::Committed { epoch: new_epoch }, clock);
                        // Replay lag: how much of the source's log the target
                        // had not applied when the switch happened. Recorded
                        // for the AC-6 metric.
                        self.replay_lag =
                            Some(self.handoff.checkpoint_seq.saturating_sub(applied_seq));
                    }
                    self.apply(HandoffEvent::SwitchAcked, clock);
                    info!(handoff = %self.handoff.handoff_id, attempts, "handoff complete");
                    return self.finish(start, attempts, None);
                }
                Reply::Other(kind) => {
                    return self.finish(
                        start,
                        attempts,
                        Some(format!("expected HandoffSwitched, got {kind}")),
                    );
                }
                Reply::Lagged(n) => {
                    return self.finish(
                        start,
                        attempts,
                        Some(format!(
                            "lost {n} inbound message(s) waiting for HandoffSwitched"
                        )),
                    );
                }
                Reply::Silent => {
                    if attempts >= self.retries.commit_attempts {
                        warn!(
                            handoff = %self.handoff.handoff_id,
                            attempts,
                            "target never acknowledged the commit; marking it failed"
                        );
                        self.apply(
                            HandoffEvent::Failed {
                                reason: "no ack after commit retries".into(),
                            },
                            clock,
                        );
                        return self.finish(
                            start,
                            attempts,
                            Some("no ack after commit retries".into()),
                        );
                    }
                    tokio::time::sleep(self.retries.delay).await;
                }
            }
        }
    }

    fn apply<C: FnMut() -> i64>(&mut self, event: HandoffEvent, clock: &mut C) {
        let now = clock();
        match self.handoff.apply(event, now, &self.timeouts) {
            Ok(_) => {
                if self.path.last() != Some(&self.handoff.state) {
                    self.path.push(self.handoff.state);
                }
            }
            Err(e) => warn!(
                handoff = %self.handoff.handoff_id,
                error = %e,
                "handoff transition refused"
            ),
        }
    }

    async fn send(mailbox: &Mailbox, msg: WireMessage) -> Result<(), String> {
        mailbox
            .outbound
            .send(msg)
            .await
            .map_err(|e| format!("agent queue full or closed: {e}"))
    }

    /// Wait up to the shadowing deadline for a matching reply.
    ///
    /// A free function rather than a method so that `&mut mailbox` and the
    /// driver's other fields are never borrowed at the same time.
    async fn wait_for<F>(mailbox: &mut Mailbox, predicate: F, limit: Duration) -> Reply
    where
        F: Fn(&Payload) -> bool,
    {
        // A device that is mid-task keeps sending `ToolResult`s while the
        // handoff is in flight, and keepalive `Pong`s arrive on their own
        // schedule. Those are not refusals to answer, so they are skipped.
        // The deadline covers the whole window, not one message. Anything
        // else is a wrong reply and is reported, not swallowed.
        let deadline = std::time::Instant::now() + limit;
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Reply::Silent;
            }
            match tokio::time::timeout(remaining, mailbox.inbound.recv()).await {
                Ok(InboundEvent::Message(msg)) => {
                    if predicate(&msg.payload) {
                        return Reply::Matched;
                    }
                    if matches!(
                        &msg.payload,
                        Payload::ToolResult { .. } | Payload::Pong { .. }
                    ) {
                        continue;
                    }
                    return Reply::Other(msg.payload.kind_name());
                }
                Ok(InboundEvent::Closed) => return Reply::Silent,
                // A lag means the driver cannot prove it saw every reply.
                // Report it so the caller records `inbound_lagged` instead of
                // silently continuing as if nothing was missed.
                Ok(InboundEvent::Lagged(n)) => return Reply::Lagged(n),
                Err(_) => return Reply::Silent,
            }
        }
    }

    fn finish(
        &self,
        start: std::time::Instant,
        attempts: u32,
        reason: Option<String>,
    ) -> DriveOutcome {
        DriveOutcome {
            handoff_id: self.handoff.handoff_id.clone(),
            state: self.handoff.state,
            epoch: self.handoff.epoch,
            switch_time_ms: start.elapsed().as_millis(),
            path: self.path.clone(),
            reason,
            commit_attempts: attempts,
            committed: self.handoff.committed,
            offered_to: Vec::new(),
            started_at_ms: self.started_at_ms,
            replay_lag: self.replay_lag,
        }
    }
}

enum Reply {
    Matched,
    Other(&'static str),
    Silent,
    /// The inbound subscription fell behind and lost `n` messages.
    Lagged(u64),
}

#[cfg(test)]
mod tests;
