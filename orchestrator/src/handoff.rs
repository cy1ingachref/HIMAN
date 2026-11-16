//! Handoff state machine.
//!
//! Implements the protocol in `docs/HANDOFF.md` sections 1-3: one owner at a
//! time, make-before-break, and a single atomic commit point.
//!
//! This module is deliberately **pure**. It owns no sockets, no clock and no
//! audit log: the caller feeds it events with a timestamp and reads back the
//! state plus the audit lines to append. That is what makes every transition,
//! every illegal transition and every timeout testable with a fake clock
//! (spec section 11.1), and it is why the failure matrix in section 8 can be
//! exercised without standing up two devices.
//!
//! The orchestrator-side wiring (sending the messages, checking enrollment,
//! fencing stale epochs) sits on top of this.

use std::time::Duration;

use himan_proto::{DeviceId, TaskId};

/// Where a handoff attempt currently stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandoffState {
    /// Asked for, not yet approved.
    Requested,
    /// Policy allowed it, checkpoint taken, token issued.
    Prepared,
    /// Target is loading state, tools and assets.
    Warming,
    /// Target applies the log live, side-effect free.
    Shadowing,
    /// Orchestrator is flipping ownership.
    Switching,
    /// Target owns the task and has acknowledged the commit.
    Active,
    /// The atomic commit (epoch bump + owner change) has been made, but the
    /// target has not acked yet. The commit point has passed, so rollback is
    /// impossible; only the ack step may still fail.
    Committed,
    /// Abandoned; the source still owns.
    RolledBack,
    /// Unrecoverable orchestrator error; the task stays with the source.
    Failed,
}

impl HandoffState {
    pub fn as_str(&self) -> &'static str {
        match self {
            HandoffState::Requested => "requested",
            HandoffState::Prepared => "prepared",
            HandoffState::Warming => "warming",
            HandoffState::Shadowing => "shadowing",
            HandoffState::Switching => "switching",
            HandoffState::Active => "active",
            HandoffState::Committed => "committed",
            HandoffState::RolledBack => "rolled_back",
            HandoffState::Failed => "failed",
        }
    }

    /// Terminal for this attempt: no further transition is legal.
    ///
    /// `Committed` is deliberately not terminal. The commit has been made and
    /// rollback is impossible, but the target's `SwitchAck` is still expected
    /// and is the only event this state accepts — the spec's failure matrix
    /// calls this "after commit, before ack".
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            HandoffState::Active | HandoffState::RolledBack | HandoffState::Failed
        )
    }

    /// The commit point has passed, so rollback is no longer possible.
    pub fn is_committed(&self) -> bool {
        matches!(
            self,
            HandoffState::Committed | HandoffState::Active | HandoffState::Failed
        )
    }
}

/// Why a transition was refused or a handoff rolled back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandoffError {
    /// The transition is not allowed from the current state.
    IllegalTransition {
        from: &'static str,
        event: &'static str,
    },
    /// The event arrived after the state's deadline.
    Timeout,
    /// A guard (target enrolled, lag below threshold, safe point) did not hold.
    Guard(&'static str),
    /// The attempt is already terminal.
    AlreadyTerminal(&'static str),
}

impl std::fmt::Display for HandoffError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HandoffError::IllegalTransition { from, event } => {
                write!(f, "{event} is not allowed in state {from}")
            }
            HandoffError::Timeout => write!(f, "handoff step timed out"),
            HandoffError::Guard(g) => write!(f, "handoff guard failed: {g}"),
            HandoffError::AlreadyTerminal(s) => write!(f, "handoff is already {s}"),
        }
    }
}

impl std::error::Error for HandoffError {}

/// One step's deadline. Defaults come from the spec's transition table.
#[derive(Debug, Clone, Copy)]
pub struct HandoffTimeouts {
    pub prepared: Duration,
    pub warming: Duration,
    pub shadowing: Duration,
    pub switching: Duration,
}

impl Default for HandoffTimeouts {
    fn default() -> Self {
        // `HIMAN_TEST_HANDOFF_TIMEOUT_SECS` exists so an acceptance test can
        // force a rollback quickly instead of waiting out the production
        // window. Unset, the spec's values apply.
        let secs = std::env::var("HIMAN_TEST_HANDOFF_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok());
        match secs {
            Some(s) if s > 0 => Self {
                prepared: Duration::from_secs(s),
                warming: Duration::from_secs(s),
                shadowing: Duration::from_secs(s),
                switching: Duration::from_secs(s),
            },
            _ => Self {
                prepared: Duration::from_secs(5),
                warming: Duration::from_secs(5),
                shadowing: Duration::from_secs(20),
                switching: Duration::from_secs(10),
            },
        }
    }
}

/// Events that drive the machine. Pure data; signatures and enrollment are
/// checked by the caller before the event is fed in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandoffEvent {
    /// Policy approved; checkpoint taken and token issued.
    Approved { checkpoint_seq: u64, epoch: u64 },
    /// Target accepted the prepare and is loading.
    PrepareAccepted,
    /// Target finished loading and is ready to shadow.
    TargetReady {
        applied_seq: u64,
        capabilities: String,
    },
    /// Target reported shadow progress.
    ShadowProgress { applied_seq: u64 },
    /// Source drained to a safe point.
    SourceDrained { last_seq: u64 },
    /// The atomic commit (epoch bump + owner change) succeeded.
    Committed { epoch: u64 },
    /// Target acknowledged the commit.
    SwitchAcked,
    /// Roll back: failure, timeout or an explicit request.
    Rollback { reason: String },
    /// Unrecoverable orchestrator error.
    Failed { reason: String },
}

/// A line the caller should append to the tamper-evident audit log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditLine {
    pub action: String,
    pub detail: String,
}

/// One handoff attempt.
#[derive(Debug, Clone)]
pub struct Handoff {
    pub handoff_id: String,
    pub task_id: TaskId,
    pub from: DeviceId,
    pub to: DeviceId,
    pub state: HandoffState,
    /// Per-task fencing counter. Starts at the task's current epoch.
    pub epoch: u64,
    /// Sequence number the checkpoint was taken at.
    pub checkpoint_seq: u64,
    /// Highest log seq the target has applied.
    pub applied_seq: u64,
    /// Log seq the source drained to.
    pub last_seq: u64,
    /// When the current state was entered, as a caller-supplied clock value.
    pub state_entered_at: i64,
    /// Whether the atomic commit has been made.
    pub committed: bool,
    /// Caller-supplied clock value at which the commit happened.
    pub committed_at: Option<i64>,
    /// Why the attempt ended, if it did.
    pub end_reason: Option<String>,
}

impl Handoff {
    pub fn new(
        handoff_id: impl Into<String>,
        task_id: TaskId,
        from: DeviceId,
        to: DeviceId,
        epoch: u64,
        now_unix: i64,
    ) -> Self {
        Self {
            handoff_id: handoff_id.into(),
            task_id,
            from,
            to,
            state: HandoffState::Requested,
            epoch,
            checkpoint_seq: 0,
            applied_seq: 0,
            last_seq: 0,
            state_entered_at: now_unix,
            committed: false,
            committed_at: None,
            end_reason: None,
        }
    }

    /// Rebuild an attempt that is already Prepared.
    ///
    /// `request_handoff` applies `Approved` and records the attempt; the driver
    /// needs that same attempt rather than a fresh one starting at `Requested`,
    /// or it would refuse its own `PrepareAccepted`.
    pub fn prepared(
        handoff_id: impl Into<String>,
        task_id: TaskId,
        from: DeviceId,
        to: DeviceId,
        epoch: u64,
        checkpoint_seq: u64,
        now_unix: i64,
    ) -> Self {
        let mut h = Self::new(handoff_id, task_id, from, to, epoch, now_unix);
        h.checkpoint_seq = checkpoint_seq;
        h.enter(HandoffState::Prepared, now_unix);
        h
    }

    fn enter(&mut self, state: HandoffState, now_unix: i64) {
        self.state = state;
        self.state_entered_at = now_unix;
    }

    /// Deadline for the current state, if it has one.
    ///
    /// `Committed` keeps the switching deadline: the commit has been made and
    /// only the ack remains, so the caller still needs a bound on how long to
    /// wait before retrying it.
    fn timeout(&self, timeouts: &HandoffTimeouts) -> Option<Duration> {
        match self.state {
            HandoffState::Requested | HandoffState::Prepared => Some(timeouts.prepared),
            HandoffState::Warming => Some(timeouts.warming),
            HandoffState::Shadowing => Some(timeouts.shadowing),
            HandoffState::Switching | HandoffState::Committed => Some(timeouts.switching),
            HandoffState::Active | HandoffState::RolledBack | HandoffState::Failed => None,
        }
    }

    /// Apply an event. Returns the audit line to append, or the reason it was
    /// refused. `now_unix` is the caller's clock so timeouts are testable.
    pub fn apply(
        &mut self,
        event: HandoffEvent,
        now_unix: i64,
        timeouts: &HandoffTimeouts,
    ) -> Result<AuditLine, HandoffError> {
        // The commit-point guard is checked before the terminal check: after a
        // commit the attempt is terminal, but a rollback must be told "too
        // late" rather than "already finished".
        if self.committed {
            match event {
                HandoffEvent::Rollback { .. } => {
                    return Err(HandoffError::Guard(
                        "cannot roll back after the commit point",
                    ));
                }
                HandoffEvent::Failed { .. } => {
                    return Err(HandoffError::Guard(
                        "cannot fail after the commit point; retry the ack instead",
                    ));
                }
                _ => {}
            }
        }

        if self.state.is_terminal() {
            // `Active` is terminal, but a redelivered `SwitchAck` is still
            // accepted: the spec makes the ack idempotent by
            // `(handoff_id, new_epoch)`, and a retry after a lost ack must not
            // look like a protocol error.
            if !(self.state == HandoffState::Active && event == HandoffEvent::SwitchAcked) {
                return Err(HandoffError::AlreadyTerminal(self.state.as_str()));
            }
        }

        // A timeout rolls back before the event is considered, so a late
        // `TargetReady` cannot resurrect a handoff that already timed out.
        if self.timed_out(now_unix, timeouts) {
            let reason = "timed out".to_owned();
            self.roll_back(now_unix, &reason);
            return Err(HandoffError::Timeout);
        }

        let action = match event {
            HandoffEvent::Approved {
                checkpoint_seq,
                epoch,
            } => {
                self.require(HandoffState::Requested, "approved")?;
                self.checkpoint_seq = checkpoint_seq;
                self.epoch = epoch;
                self.enter(HandoffState::Prepared, now_unix);
                "handoff_prepared"
            }
            HandoffEvent::PrepareAccepted => {
                self.require(HandoffState::Prepared, "prepare_accepted")?;
                self.enter(HandoffState::Warming, now_unix);
                "handoff_warming"
            }
            HandoffEvent::TargetReady {
                applied_seq,
                capabilities,
            } => {
                self.require(HandoffState::Warming, "target_ready")?;
                self.applied_seq = applied_seq;
                self.enter(HandoffState::Shadowing, now_unix);
                // Capabilities are carried for the caller's renderer, not the
                // machine. Recording the seq keeps the audit line useful.
                let _ = capabilities;
                "handoff_ready"
            }
            HandoffEvent::ShadowProgress { applied_seq } => {
                self.require(HandoffState::Shadowing, "shadow_progress")?;
                // A target may never fall behind: gaps are rejected, so a
                // backwards applied_seq is a protocol violation, not progress.
                if applied_seq < self.applied_seq {
                    return Err(HandoffError::Guard("applied_seq went backwards"));
                }
                self.applied_seq = applied_seq;
                "handoff_shadow_progress"
            }
            HandoffEvent::SourceDrained { last_seq } => {
                self.require(HandoffState::Shadowing, "source_drained")?;
                // Guard: the target must have applied everything the source
                // produced, otherwise the switch would drop events.
                if self.applied_seq < last_seq {
                    return Err(HandoffError::Guard("target has not applied last_seq"));
                }
                self.last_seq = last_seq;
                self.enter(HandoffState::Switching, now_unix);
                "handoff_switching"
            }
            HandoffEvent::Committed { epoch } => {
                self.require(HandoffState::Switching, "committed")?;
                // The commit increments the epoch by exactly one; anything else
                // means a second writer moved ownership underneath us.
                if epoch != self.epoch + 1 {
                    return Err(HandoffError::Guard("epoch did not increment by one"));
                }
                self.epoch = epoch;
                self.commit(now_unix);
                "handoff_committed"
            }
            HandoffEvent::SwitchAcked => {
                // From Committed this is the real transition. From Active it is
                // a redelivered ack, which the spec makes idempotent by
                // `(handoff_id, new_epoch)`.
                match self.state {
                    HandoffState::Committed => {
                        self.enter(HandoffState::Active, now_unix);
                        "handoff_active"
                    }
                    HandoffState::Active => "handoff_active",
                    other => {
                        return Err(HandoffError::IllegalTransition {
                            from: other.as_str(),
                            event: "switch_acked",
                        });
                    }
                }
            }
            HandoffEvent::Rollback { reason } => {
                let action = "handoff_rolled_back";
                self.roll_back(now_unix, &reason);
                return Ok(AuditLine {
                    action: action.to_owned(),
                    detail: reason,
                });
            }
            HandoffEvent::Failed { reason } => {
                self.enter(HandoffState::Failed, now_unix);
                self.end_reason = Some(reason.clone());
                return Ok(AuditLine {
                    action: "handoff_failed".to_owned(),
                    detail: reason,
                });
            }
        };

        Ok(AuditLine {
            action: action.to_owned(),
            detail: self.detail(),
        })
    }

    fn require(&self, expected: HandoffState, event: &'static str) -> Result<(), HandoffError> {
        if self.state != expected {
            return Err(HandoffError::IllegalTransition {
                from: self.state.as_str(),
                event,
            });
        }
        Ok(())
    }

    fn roll_back(&mut self, now_unix: i64, reason: &str) {
        self.enter(HandoffState::RolledBack, now_unix);
        self.end_reason = Some(reason.to_owned());
    }

    /// The atomic commit: epoch is already validated, so the owner flips and
    /// the point of no return is recorded in one step.
    ///
    /// `Active` is deliberately not set here — the target must ack first. The
    /// spec's failure matrix calls this window "after commit, before ack".
    fn commit(&mut self, now_unix: i64) {
        self.committed = true;
        self.committed_at = Some(now_unix);
        self.enter(HandoffState::Committed, now_unix);
    }

    /// Has the current state exceeded its deadline?
    pub fn timed_out(&self, now_unix: i64, timeouts: &HandoffTimeouts) -> bool {
        match self.timeout(timeouts) {
            Some(limit) => now_unix - self.state_entered_at > limit.as_secs() as i64,
            None => false,
        }
    }

    /// The owner during the current state. Before the commit the source owns;
    /// from the commit on the target owns (spec section 3).
    ///
    /// This is driven by `committed_at`, not by `state`, so the answer is
    /// unambiguous in the Committed-but-not-yet-acked window: the commit has
    /// already moved ownership even though the handoff is not Active yet.
    pub fn owner(&self) -> &DeviceId {
        if self.committed {
            &self.to
        } else {
            &self.from
        }
    }

    fn detail(&self) -> String {
        format!(
            "handoff={} task={} epoch={} checkpoint_seq={} applied_seq={} last_seq={}",
            self.handoff_id,
            self.task_id,
            self.epoch,
            self.checkpoint_seq,
            self.applied_seq,
            self.last_seq
        )
    }
}

#[cfg(test)]
mod tests;
