//! Append-only per-task event log.
//!
//! The log is the source of truth for a task (docs/HANDOFF.md section 2): it
//! is numbered `seq 1..n`, every event carries `task_id`, `seq`, `epoch` and
//! the committing device, and a handoff streams it to the target so the task
//! can move without losing context.
//!
//! This type is pure data plus append/verify, with no I/O. The orchestrator
//! owns one per task and enforces the fencing rules when appending.

use himan_proto::DeviceId;
use serde::{Deserialize, Serialize};

/// Whether re-issuing a tool call with the same `call_id` can cause a second
/// side effect. Re-exported from the protocol crate so event and tool agree.
pub use himan_proto::Idempotency;

/// The minimum event set from the spec. Each carries `task_id`, `seq`, `epoch`
/// and `device` through [`TaskEvent`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum EventPayload {
    TaskCreated {
        goal: String,
    },
    StepStarted {
        step: u64,
    },
    ToolCallIssued {
        call_id: String,
        tool: String,
        args: serde_json::Value,
        idempotency: Idempotency,
    },
    ToolResultRecorded {
        call_id: String,
        result: String,
        ok: bool,
    },
    ApprovalRecorded {
        approval_id: String,
        signer: String,
    },
    NoteAdded {
        note: String,
    },
    OwnerChanged {
        from: String,
        to: String,
        epoch: u64,
    },
}

impl EventPayload {
    pub fn kind_name(&self) -> &'static str {
        match self {
            EventPayload::TaskCreated { .. } => "task_created",
            EventPayload::StepStarted { .. } => "step_started",
            EventPayload::ToolCallIssued { .. } => "tool_call_issued",
            EventPayload::ToolResultRecorded { .. } => "tool_result_recorded",
            EventPayload::ApprovalRecorded { .. } => "approval_recorded",
            EventPayload::NoteAdded { .. } => "note_added",
            EventPayload::OwnerChanged { .. } => "owner_changed",
        }
    }
}

/// One numbered entry in a task's log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskEvent {
    pub task_id: String,
    /// 1-based, continuous. A gap means the log is incomplete.
    pub seq: u64,
    /// Fencing counter at the time of the commit.
    pub epoch: u64,
    pub device: DeviceId,
    pub payload: EventPayload,
}

/// An append-only, contiguous log.
#[derive(Debug, Default)]
pub struct EventLog {
    events: Vec<TaskEvent>,
    /// `call_id`s of non-idempotent calls that have no result yet.
    unresolved_non_idempotent: Vec<String>,
}

impl EventLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    pub fn head(&self) -> u64 {
        self.events.last().map(|e| e.seq).unwrap_or(0)
    }

    pub fn events(&self) -> &[TaskEvent] {
        &self.events
    }

    /// Append an event at the next seq. Returns the assigned seq.
    ///
    /// Callers that need atomicity with an ownership change should use
    /// [`crate::ownership::OwnerRegistry::commit`] alongside this; the log
    /// itself has no failure mode beyond a closed task.
    pub fn append(&mut self, event: TaskEvent) -> u64 {
        if let EventPayload::ToolCallIssued {
            call_id,
            idempotency,
            ..
        } = &event.payload
        {
            if *idempotency == Idempotency::NonIdempotent && !self.is_resolved(call_id) {
                self.unresolved_non_idempotent.push(call_id.clone());
            }
        }
        if let EventPayload::ToolResultRecorded { call_id, .. } = &event.payload {
            self.unresolved_non_idempotent.retain(|c| c != call_id);
        }
        let seq = event.seq;
        self.events.push(event);
        seq
    }

    fn is_resolved(&self, call_id: &str) -> bool {
        self.events.iter().any(
            |e| matches!(&e.payload, EventPayload::ToolResultRecorded { call_id: c, .. } if c == call_id),
        )
    }

    /// Build the next event for this log, assigning seq and stamping the
    /// committing device and epoch.
    pub fn next_event(
        &self,
        task_id: String,
        epoch: u64,
        device: DeviceId,
        payload: EventPayload,
    ) -> TaskEvent {
        TaskEvent {
            task_id,
            seq: self.head() + 1,
            epoch,
            device,
            payload,
        }
    }

    /// Events strictly after `checkpoint_seq`.
    pub fn since(&self, checkpoint_seq: u64) -> Vec<TaskEvent> {
        self.events
            .iter()
            .filter(|e| e.seq > checkpoint_seq)
            .cloned()
            .collect()
    }

    /// The log is usable for a handoff only if seq is continuous from 1.
    pub fn is_contiguous(&self) -> bool {
        self.events
            .iter()
            .enumerate()
            .all(|(i, e)| e.seq as usize == i + 1)
    }

    /// Apply a batch streamed from the orchestrator. Rejects a gap, a
    /// backwards seq, or a different task id — the target must never build on
    /// an inconsistent log.
    pub fn apply_stream(&mut self, incoming: &[TaskEvent]) -> Result<(), String> {
        for event in incoming {
            if event.task_id != self.task_id() {
                return Err(format!(
                    "streamed event is for task {}, expected {}",
                    event.task_id,
                    self.task_id()
                ));
            }
            if event.seq != self.head() + 1 {
                return Err(format!(
                    "streamed event seq {} does not follow head {}",
                    event.seq,
                    self.head()
                ));
            }
            self.append(event.clone());
        }
        Ok(())
    }

    fn task_id(&self) -> String {
        self.events
            .first()
            .map(|e| e.task_id.clone())
            .unwrap_or_default()
    }

    /// `call_id`s of non-idempotent calls that were issued but never resolved.
    ///
    /// The switch must not proceed while this is non-empty (spec section 2:
    /// a non-idempotent call must finish on the current owner first).
    pub fn unresolved_non_idempotent(&self) -> &[String] {
        &self.unresolved_non_idempotent
    }

    /// `call_id`s of idempotent calls that were issued but never resolved.
    ///
    /// These may be re-issued on the new owner with the same `call_id` after
    /// the commit, which is why they are safe to carry across.
    pub fn unresolved_idempotent(&self) -> Vec<String> {
        let mut out = Vec::new();
        for event in &self.events {
            if let EventPayload::ToolCallIssued {
                call_id,
                idempotency,
                ..
            } = &event.payload
            {
                if *idempotency == Idempotency::Idempotent && !self.is_resolved(call_id) {
                    out.push(call_id.clone());
                }
            }
        }
        out
    }

    /// Every `call_id` in the log, so a re-issued call can be detected as a
    /// duplicate rather than executed twice.
    pub fn call_ids(&self) -> Vec<String> {
        self.events
            .iter()
            .filter_map(|e| match &e.payload {
                EventPayload::ToolCallIssued { call_id, .. } => Some(call_id.clone()),
                _ => None,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests;
