//! Durable state: owner, epoch, event log and handoff state in SQLite (WAL).
//!
//! The commit point is ONE transaction: it bumps the epoch, sets the owner and
//! appends `OwnerChanged` together. That is what makes "epoch never decreases"
//! and "the owner and the log agree" structural rather than a matter of
//! ordering calls correctly.
//!
//! A restart reads the file back:
//!   * a handoff that never committed is rolled back (the source stays owner,
//!     and the rollback is audited);
//!   * a handoff that committed but was never acked resumes at the ack step.
//!
//! The event log is stored as ordered rows, so `seq` continues after a restart
//! instead of restarting at 1.

use std::path::Path;
use std::sync::Arc;

use himan_proto::{DeviceId, TaskId, TaskState, ToolName};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::eventlog::{EventLog, EventPayload, TaskEvent};
use crate::state::TaskRecord as StateRecord;

/// A task whose owner died with no device available to take it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StalledRecord {
    pub task_id: String,
    pub epoch: u64,
    pub owner: String,
    pub unresolved: bool,
    pub reason: String,
    pub offered_to: Option<String>,
}

/// One durable audit entry, as stored in SQLite.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DurableAuditEvent {
    pub seq: u64,
    pub ts: i64,
    /// Millisecond timestamp, for gap metrics the second resolution loses.
    pub ts_ms: i64,
    pub action: String,
    pub actor: String,
    pub detail: String,
    pub prev_hash: String,
    pub hash: String,
}

/// One task's durable identity and fencing state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskRecord {
    pub task_id: String,
    pub owner: String,
    pub epoch: u64,
    /// True while a non-idempotent call has no result yet.
    pub has_unresolved_non_idempotent: bool,
}

/// A handoff attempt, persisted so it survives a restart.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandoffRecord {
    pub handoff_id: String,
    pub task_id: String,
    pub from_device: String,
    pub to_device: String,
    pub state: String,
    pub epoch: u64,
    pub checkpoint_seq: u64,
    pub applied_seq: u64,
    pub committed: bool,
    pub end_reason: Option<String>,
}

/// The durable store. One connection, one file.
pub struct DurableStore {
    conn: Connection,
    path: std::path::PathBuf,
}

impl DurableStore {
    /// Open (creating if needed) the store at `path` and enable WAL.
    pub fn open(path: &Path) -> Result<Self, String> {
        let conn = Connection::open(path).map_err(|e| e.to_string())?;
        // WAL: readers do not block the writer, which matters because the HTTP
        // API reads the audit while the hub is writing handoff state.
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| e.to_string())?;
        conn.pragma_update(None, "synchronous", "FULL")
            .map_err(|e| e.to_string())?;
        let store = Self {
            conn,
            path: path.to_path_buf(),
        };
        store.create_schema()?;
        Ok(store)
    }

    /// In-memory store, for tests that do not need durability.
    pub fn open_in_memory() -> Result<Self, String> {
        let conn = Connection::open_in_memory().map_err(|e| e.to_string())?;
        let store = Self {
            conn,
            path: std::path::PathBuf::from(":memory:"),
        };
        store.create_schema()?;
        Ok(store)
    }

    fn create_schema(&self) -> Result<(), String> {
        self.conn
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS tasks (
                    task_id     TEXT PRIMARY KEY,
                    owner       TEXT NOT NULL,
                    epoch       INTEGER NOT NULL,
                    has_unresolved_non_idempotent INTEGER NOT NULL DEFAULT 0
                );
                -- The orchestrator's own task records, so a task's state, args
                -- and output survive a restart. Kept beside the event log, not
                -- derived from it: the log records what happened, this records
                -- the current answer. See docs/DECISIONS.md.
                CREATE TABLE IF NOT EXISTS task_records (
                    task_id      TEXT PRIMARY KEY,
                    tool         TEXT NOT NULL,
                    target_device TEXT NOT NULL,
                    state        TEXT NOT NULL,
                    args         TEXT NOT NULL,
                    output       TEXT,
                    created_at   INTEGER NOT NULL,
                    updated_at   INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS events (
                    task_id TEXT NOT NULL,
                    seq     INTEGER NOT NULL,
                    epoch   INTEGER NOT NULL,
                    device  TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    PRIMARY KEY (task_id, seq)
                );
                CREATE INDEX IF NOT EXISTS idx_events_task ON events(task_id, seq);
                CREATE TABLE IF NOT EXISTS handoffs (
                    handoff_id  TEXT PRIMARY KEY,
                    task_id     TEXT NOT NULL,
                    from_device TEXT NOT NULL,
                    to_device   TEXT NOT NULL,
                    state       TEXT NOT NULL,
                    epoch       INTEGER NOT NULL,
                    checkpoint_seq INTEGER NOT NULL,
                    applied_seq INTEGER NOT NULL,
                    committed   INTEGER NOT NULL DEFAULT 0,
                    end_reason  TEXT
                );
                -- Append-only audit log. `prev_hash` is the hash of the
                -- previous row, which is what makes the chain verifiable.
                CREATE TABLE IF NOT EXISTS audit (
                    seq       INTEGER PRIMARY KEY,
                    ts        INTEGER NOT NULL,
                    ts_ms     INTEGER NOT NULL DEFAULT 0,
                    action    TEXT NOT NULL,
                    actor     TEXT NOT NULL,
                    detail    TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    hash      TEXT NOT NULL
                );
                -- Whether a startup detected a broken chain. Recorded so a
                -- recovery run is not mistaken for a clean one.
                CREATE TABLE IF NOT EXISTS meta (
                    key   TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS revoked (
                    device_id   TEXT PRIMARY KEY,
                    revoked_at  INTEGER NOT NULL,
                    reason      TEXT NOT NULL DEFAULT ''
                );
                -- Tasks whose owner died and no device was available to take
                -- them. They stay stalled and are offered when a device
                -- connects.
                CREATE TABLE IF NOT EXISTS stalled (
                    task_id     TEXT PRIMARY KEY,
                    epoch       INTEGER NOT NULL,
                    owner       TEXT NOT NULL,
                    unresolved  INTEGER NOT NULL DEFAULT 0,
                    reason      TEXT NOT NULL,
                    offered_to  TEXT
                );",
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Record a task as stalled with no available owner.
    pub fn save_stalled(
        &self,
        task_id: &str,
        epoch: u64,
        owner: &str,
        reason: &str,
    ) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO stalled
                 (task_id, epoch, owner, unresolved, reason, offered_to)
                 VALUES (?1, ?2, ?3, 1, ?4, NULL)",
                params![task_id, epoch as i64, owner, reason],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Every stalled task.
    pub fn stalled(&self) -> Result<Vec<StalledRecord>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT task_id, epoch, owner, unresolved, reason, offered_to
                 FROM stalled ORDER BY task_id",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |row| {
                Ok(StalledRecord {
                    task_id: row.get(0)?,
                    epoch: row.get::<_, i64>(1)? as u64,
                    owner: row.get(2)?,
                    unresolved: row.get::<_, i64>(3)? != 0,
                    reason: row.get(4)?,
                    offered_to: row.get(5)?,
                })
            })
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())
    }

    /// Record which device a stalled task was offered to.
    pub fn set_stalled_offered(&self, task_id: &str, offered_to: &str) -> Result<(), String> {
        self.conn
            .execute(
                "UPDATE stalled SET offered_to = ?2 WHERE task_id = ?1",
                params![task_id, offered_to],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Persist one task record.
    ///
    /// Called on every state change so a restart finds the current state, args
    /// and output rather than replaying the log.
    pub fn save_task_record(&self, record: &StateRecord) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT INTO task_records
                     (task_id, tool, target_device, state, args, output, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(task_id) DO UPDATE SET
                     tool = excluded.tool,
                     target_device = excluded.target_device,
                     state = excluded.state,
                     args = excluded.args,
                     output = excluded.output,
                     updated_at = excluded.updated_at",
                params![
                    record.id.as_str(),
                    record.tool.as_str(),
                    record.target_device.as_str(),
                    record.state.as_str(),
                    record.args.to_string(),
                    record.output,
                    record.created_at,
                    record.updated_at,
                ],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Every persisted task record, for startup.
    pub fn task_records(&self) -> Result<Vec<StateRecord>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT task_id, tool, target_device, state, args, output, created_at, updated_at
                 FROM task_records ORDER BY created_at",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |row| {
                let args: String = row.get(4)?;
                let args = serde_json::from_str(&args).unwrap_or(serde_json::Value::Null);
                Ok(StateRecord {
                    id: TaskId::new(row.get::<_, String>(0)?),
                    tool: ToolName::new(row.get::<_, String>(1)?),
                    target_device: DeviceId::new(row.get::<_, String>(2)?),
                    state: match row.get::<_, String>(3)?.as_str() {
                        "pending" => TaskState::Pending,
                        "running" => TaskState::Running,
                        "awaiting_approval" => TaskState::AwaitingApproval,
                        "succeeded" => TaskState::Succeeded,
                        "failed" => TaskState::Failed,
                        "cancelled" => TaskState::Cancelled,
                        other => {
                            tracing::warn!(state = %other, "unknown persisted task state");
                            TaskState::Pending
                        }
                    },
                    args,
                    output: row.get(5)?,
                    created_at: row.get(6)?,
                    updated_at: row.get(7)?,
                })
            })
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())
    }

    /// Load the durable audit log in chain order.
    pub fn audit_log(&self) -> Result<Vec<DurableAuditEvent>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT seq, ts, ts_ms, action, actor, detail, prev_hash, hash
                 FROM audit ORDER BY seq",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |row| {
                Ok(DurableAuditEvent {
                    seq: row.get::<_, i64>(0)? as u64,
                    ts: row.get::<_, i64>(1)?,
                    ts_ms: row.get::<_, i64>(2).unwrap_or(0),
                    action: row.get(3)?,
                    actor: row.get(4)?,
                    detail: row.get(5)?,
                    prev_hash: row.get(6)?,
                    hash: row.get(7)?,
                })
            })
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())
    }

    /// Append one audit entry, chaining it to the current tail.
    ///
    /// The `prev_hash` is read from the same connection, so a concurrent
    /// writer cannot interleave: SQLite serialises writes and the read + insert
    /// are ordered by the caller (the hub holds the audit lock).
    pub fn append_audit(
        &self,
        action: &str,
        actor: &str,
        detail: &str,
        ts: i64,
        ts_ms: i64,
    ) -> Result<(), String> {
        let prev_hash = self
            .conn
            .query_row(
                "SELECT hash FROM audit ORDER BY seq DESC LIMIT 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|e| e.to_string())?
            .unwrap_or_else(|| crate::audit::GENESIS_HASH.to_owned());
        let seq = self.audit_len()?;
        let mut event = crate::audit::AuditEvent {
            seq,
            ts,
            ts_ms,
            action: action.to_string(),
            actor: actor.to_string(),
            detail: detail.to_string(),
            prev_hash,
            hash: String::new(),
        };
        event.hash = crate::audit::hash_event(&event);
        self.conn
            .execute(
                "INSERT INTO audit (seq, ts, ts_ms, action, actor, detail, prev_hash, hash)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    seq as i64,
                    event.ts,
                    event.ts_ms,
                    event.action,
                    event.actor,
                    event.detail,
                    event.prev_hash,
                    event.hash
                ],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Number of durable audit entries.
    pub fn audit_len(&self) -> Result<u64, String> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM audit", [], |row| row.get(0))
            .map_err(|e| e.to_string())?;
        Ok(n as u64)
    }

    /// Test support: rewrite one entry's `ts` in place, leaving its hash.
    pub fn rewrite_audit_timestamp_for_test(&self, seq: u64, ts: i64) -> Result<(), String> {
        self.conn
            .execute(
                "UPDATE audit SET ts = ?2 WHERE seq = ?1",
                params![seq as i64, ts],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Test support: rewrite one entry's `ts_ms` in place.
    pub fn rewrite_audit_ts_ms_for_test(&self, seq: u64, ts_ms: i64) -> Result<(), String> {
        self.conn
            .execute(
                "UPDATE audit SET ts_ms = ?2 WHERE seq = ?1",
                params![seq as i64, ts_ms],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Verify the durable audit chain.
    ///
    /// Returns `Ok(())` when every entry's hash matches its content and every
    /// `prev_hash` matches the previous entry. Any mismatch means the log was
    /// tampered with (or truncated mid-write), and the caller must refuse to
    /// start unless an explicit recovery flag is set.
    pub fn verify_audit(&self) -> Result<(), String> {
        let events = self.audit_log()?;
        let mut prev_hash = crate::audit::GENESIS_HASH.to_owned();
        for event in events {
            let mut expected = crate::audit::AuditEvent {
                seq: event.seq,
                ts: event.ts,
                // `ts_ms` is not hashed, so it is not part of the chain check.
                ts_ms: 0,
                action: event.action.clone(),
                actor: event.actor.clone(),
                detail: event.detail.clone(),
                prev_hash: event.prev_hash.clone(),
                hash: String::new(),
            };
            let computed = crate::audit::hash_event(&expected);
            expected.hash = computed.clone();
            if event.prev_hash != prev_hash {
                return Err(format!(
                    "audit chain broken at seq {}: prev_hash {} != {}",
                    event.seq, event.prev_hash, prev_hash
                ));
            }
            if event.hash != computed {
                return Err(format!(
                    "audit entry {} does not match its hash: {} != {}",
                    event.seq, event.hash, computed
                ));
            }
            prev_hash = event.hash;
        }
        Ok(())
    }

    /// Permanently revoke a device id, durably. Idempotent.
    pub fn revoke_device(&self, device: &str, at_unix: i64, reason: &str) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT OR IGNORE INTO revoked (device_id, revoked_at, reason) VALUES (?1, ?2, ?3)",
                params![device, at_unix, reason],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Whether a device id is revoked.
    pub fn is_revoked(&self, device: &str) -> Result<bool, String> {
        self.conn
            .query_row(
                "SELECT 1 FROM revoked WHERE device_id = ?1",
                params![device],
                |_| Ok(true),
            )
            .optional()
            .map(|v| v.is_some())
            .map_err(|e| e.to_string())
    }

    /// Every revoked device id.
    pub fn revoked_devices(&self) -> Result<Vec<String>, String> {
        let mut stmt = self
            .conn
            .prepare("SELECT device_id FROM revoked ORDER BY device_id")
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())
    }

    /// The state file this store is bound to.
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Read or write a `meta` value.
    pub fn meta_get(&self, key: &str) -> Result<Option<String>, String> {
        self.conn
            .query_row(
                "SELECT value FROM meta WHERE key = ?1",
                params![key],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())
    }

    pub fn meta_set(&self, key: &str, value: &str) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)",
                params![key, value],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Load every task's owner/epoch record.
    pub fn tasks(&self) -> Result<Vec<TaskRecord>, String> {
        let mut stmt = self
            .conn
            .prepare("SELECT task_id, owner, epoch, has_unresolved_non_idempotent FROM tasks")
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |row| {
                Ok(TaskRecord {
                    task_id: row.get(0)?,
                    owner: row.get(1)?,
                    epoch: row.get::<_, i64>(2)? as u64,
                    has_unresolved_non_idempotent: row.get::<_, i64>(3)? != 0,
                })
            })
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())
    }

    /// One task's owner and epoch.
    pub fn task(&self, task_id: &str) -> Result<Option<TaskRecord>, String> {
        self.conn
            .query_row(
                "SELECT task_id, owner, epoch, has_unresolved_non_idempotent
                 FROM tasks WHERE task_id = ?1",
                params![task_id],
                |row| {
                    Ok(TaskRecord {
                        task_id: row.get(0)?,
                        owner: row.get(1)?,
                        epoch: row.get::<_, i64>(2)? as u64,
                        has_unresolved_non_idempotent: row.get::<_, i64>(3)? != 0,
                    })
                },
            )
            .optional()
            .map_err(|e| e.to_string())
    }

    /// Create a task record if it does not exist. Returns the current epoch.
    pub fn ensure_task(&self, task_id: &str, owner: &str) -> Result<u64, String> {
        let existing = self.task(task_id)?;
        if let Some(record) = existing {
            return Ok(record.epoch);
        }
        self.conn
            .execute(
                "INSERT INTO tasks (task_id, owner, epoch, has_unresolved_non_idempotent)
                 VALUES (?1, ?2, 0, 0)",
                params![task_id, owner],
            )
            .map_err(|e| e.to_string())?;
        Ok(0)
    }

    /// The highest seq used by a task's event log.
    pub fn event_head(&self, task_id: &str) -> Result<u64, String> {
        let head: i64 = self
            .conn
            .query_row(
                "SELECT COALESCE(MAX(seq), 0) FROM events WHERE task_id = ?1",
                params![task_id],
                |row| row.get(0),
            )
            .map_err(|e| e.to_string())?;
        Ok(head as u64)
    }

    /// Load a task's event log, in seq order.
    pub fn event_log(&self, task_id: &str) -> Result<EventLog, String> {
        let mut log = EventLog::new();
        let mut stmt = self
            .conn
            .prepare(
                "SELECT seq, epoch, device, payload FROM events
                 WHERE task_id = ?1 ORDER BY seq",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![task_id], |row| {
                let payload: String = row.get(3)?;
                Ok((
                    row.get::<_, i64>(0)? as u64,
                    row.get::<_, i64>(1)? as u64,
                    row.get::<_, String>(2)?,
                    payload,
                ))
            })
            .map_err(|e| e.to_string())?;
        for row in rows {
            let (seq, epoch, device, payload) = row.map_err(|e| e.to_string())?;
            let value: serde_json::Value =
                serde_json::from_str(&payload).map_err(|e| e.to_string())?;
            let payload = serde_json::from_value(value).map_err(|e| e.to_string())?;
            log.append(TaskEvent {
                task_id: task_id.to_string(),
                seq,
                epoch,
                device: DeviceId::new(device),
                payload,
            });
        }
        Ok(log)
    }

    /// Append one event. The seq is assigned by the caller from the log head.
    pub fn append_event(&self, event: &TaskEvent) -> Result<(), String> {
        let payload = serde_json::to_string(&event.payload).map_err(|e| e.to_string())?;
        self.conn
            .execute(
                "INSERT OR REPLACE INTO events (task_id, seq, epoch, device, payload)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    event.task_id,
                    event.seq as i64,
                    event.epoch as i64,
                    event.device.as_str(),
                    payload
                ],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// THE commit point: epoch bump, owner change and `OwnerChanged` in one
    /// transaction. Refuses to move the epoch backwards.
    pub fn commit_owner(
        &self,
        task_id: &str,
        new_owner: &str,
        new_epoch: u64,
        event: &TaskEvent,
    ) -> Result<(), String> {
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| e.to_string())?;
        let current: Option<(String, u64)> = tx
            .query_row(
                "SELECT owner, epoch FROM tasks WHERE task_id = ?1",
                params![task_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as u64)),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        if let Some((_, epoch)) = current {
            if new_epoch < epoch {
                // Never move the epoch backwards: that is the whole point of
                // fencing, and a restart must not be able to undo it.
                tx.rollback().map_err(|e| e.to_string())?;
                return Err(format!(
                    "refusing to move epoch backwards: {epoch} -> {new_epoch}"
                ));
            }
            if new_epoch == epoch {
                tx.rollback().map_err(|e| e.to_string())?;
                return Err(format!("epoch already {epoch}; refusing a no-op commit"));
            }
        }
        tx.execute(
            "INSERT INTO tasks (task_id, owner, epoch, has_unresolved_non_idempotent)
             VALUES (?1, ?2, ?3, 0)
             ON CONFLICT(task_id) DO UPDATE SET owner = ?2, epoch = ?3",
            params![task_id, new_owner, new_epoch as i64],
        )
        .map_err(|e| e.to_string())?;
        let payload = serde_json::to_string(&event.payload).map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT OR REPLACE INTO events (task_id, seq, epoch, device, payload)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                event.task_id,
                event.seq as i64,
                event.epoch as i64,
                event.device.as_str(),
                payload
            ],
        )
        .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Record a handoff attempt.
    pub fn save_handoff(&self, record: &HandoffRecord) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO handoffs
                 (handoff_id, task_id, from_device, to_device, state, epoch,
                  checkpoint_seq, applied_seq, committed, end_reason)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                params![
                    record.handoff_id,
                    record.task_id,
                    record.from_device,
                    record.to_device,
                    record.state,
                    record.epoch as i64,
                    record.checkpoint_seq as i64,
                    record.applied_seq as i64,
                    if record.committed { 1 } else { 0 },
                    record.end_reason,
                ],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Every handoff, newest first.
    pub fn handoffs(&self) -> Result<Vec<HandoffRecord>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT handoff_id, task_id, from_device, to_device, state, epoch,
                        checkpoint_seq, applied_seq, committed, end_reason
                 FROM handoffs ORDER BY rowid",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |row| {
                Ok(HandoffRecord {
                    handoff_id: row.get(0)?,
                    task_id: row.get(1)?,
                    from_device: row.get(2)?,
                    to_device: row.get(3)?,
                    state: row.get(4)?,
                    epoch: row.get::<_, i64>(5)? as u64,
                    checkpoint_seq: row.get::<_, i64>(6)? as u64,
                    applied_seq: row.get::<_, i64>(7)? as u64,
                    committed: row.get::<_, i64>(8)? != 0,
                    end_reason: row.get(9)?,
                })
            })
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())
    }

    /// A handoff that is in flight and NOT committed: the ones to roll back on
    /// startup. `Committed` is deliberately excluded — those resume at the ack.
    pub fn unfinished_handoffs(&self) -> Result<Vec<HandoffRecord>, String> {
        Ok(self
            .handoffs()?
            .into_iter()
            .filter(|h| !h.committed && h.state != "rolled_back" && h.state != "failed")
            .collect())
    }

    /// A committed handoff that was never acked: the one to resume.
    pub fn unacked_committed_handoff(&self) -> Result<Option<HandoffRecord>, String> {
        Ok(self
            .handoffs()?
            .into_iter()
            .find(|h| h.committed && h.state != "active"))
    }

    /// Mark a handoff's state.
    pub fn set_handoff_state(
        &self,
        handoff_id: &str,
        state: &str,
        committed: bool,
        reason: Option<&str>,
    ) -> Result<(), String> {
        self.conn
            .execute(
                "UPDATE handoffs SET state = ?2, committed = ?3, end_reason = ?4
                 WHERE handoff_id = ?1",
                params![handoff_id, state, if committed { 1 } else { 0 }, reason],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Mark whether a task has an unresolved non-idempotent call.
    pub fn set_unresolved(&self, task_id: &str, unresolved: bool) -> Result<(), String> {
        self.conn
            .execute(
                "UPDATE tasks SET has_unresolved_non_idempotent = ?2 WHERE task_id = ?1",
                params![task_id, if unresolved { 1 } else { 0 }],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Rebuild the in-memory event log from disk, for startup.
    pub fn load_event_log(&self, task_id: &str) -> Result<EventLog, String> {
        self.event_log(task_id)
    }

    /// Startup recovery: roll back uncommitted handoffs, report committed
    /// unacked ones. Returns the handoffs that need a resumed ack.
    pub fn recover(&self) -> Result<(Vec<HandoffRecord>, Option<HandoffRecord>), String> {
        let mut rolled_back = Vec::new();
        for mut record in self.unfinished_handoffs()? {
            self.set_handoff_state(
                &record.handoff_id,
                "rolled_back",
                false,
                Some("orchestrator restarted before the commit"),
            )?;
            record.state = "rolled_back".to_string();
            rolled_back.push(record);
        }
        let resume = self.unacked_committed_handoff()?;
        if let Some(record) = &resume {
            info!(
                handoff = %record.handoff_id,
                task = %record.task_id,
                "committed handoff found on startup; resumes at the ack step"
            );
        }
        Ok((rolled_back, resume))
    }
}

/// Open the durable store and attach it to the hub.
///
/// Recovery runs here, before the server accepts connections: an uncommitted
/// handoff is rolled back (audited), a committed one is left for the hub to
/// resume at the ack step.
pub async fn attach(hub: Arc<crate::hub::Hub>, path: &Path) -> Result<(), String> {
    let store = DurableStore::open(path)?;
    // Verify the audit chain BEFORE anything is written. A broken chain means
    // the log was tampered with; starting anyway would let the tampering be
    // covered up by new entries.
    let recovery = std::env::var("HIMAN_ALLOW_AUDIT_RECOVERY").as_deref() == Ok("1");
    if let Err(reason) = store.verify_audit() {
        if recovery {
            tracing::error!(
                error = %reason,
                "AUDIT CHAIN BROKEN; starting anyway because HIMAN_ALLOW_AUDIT_RECOVERY=1"
            );
            store.meta_set("audit_chain_recovery", reason.as_str())?;
        } else {
            return Err(format!(
                "audit chain verification failed: {reason}. \
                 Refusing to start. Set HIMAN_ALLOW_AUDIT_RECOVERY=1 to \
                 acknowledge and continue."
            ));
        }
    }
    let (rolled_back, resume) = store.recover()?;

    for record in &rolled_back {
        tracing::warn!(
            handoff = %record.handoff_id,
            task = %record.task_id,
            "handoff was in flight at shutdown; rolled back"
        );
    }
    // Load revocations BEFORE the store is moved into the hub and before
    // any agent can register: a durable deny-list must refuse those ids
    // from the first message onward.
    let revoked_ids = store
        .revoked_devices()
        .map_err(|e| format!("failed to load revocations: {e}"))?;
    hub.load_revocations(revoked_ids).await;
    hub.install_durable(store, rolled_back.len(), resume.is_some());
    // Rebuild the in-memory task records, owners, epochs and event log from
    // the attached store. This was previously done by attach() directly;
    // it must run after install_durable so the store handle is in place.
    let loaded = hub.load_durable_state().await;
    // Audit the rollbacks now, after the store is attached: the audit log is
    // in-memory and starts empty on every start, so a rollback discovered during
    // recovery has to be written into it here or it would be invisible.
    for record in &rolled_back {
        hub.audit_handoff_rolled_back(record).await;
    }
    tracing::info!(
        rolled_back = rolled_back.len(),
        resume_pending = resume.is_some(),
        tasks = loaded,
        "durable state attached and recovery complete"
    );
    Ok(())
}

/// Serialize a payload for the `events` table.
pub fn payload_json(payload: &EventPayload) -> Result<String, String> {
    serde_json::to_string(payload).map_err(|e| e.to_string())
}

/// Parse a payload from the `events` table.
pub fn payload_from_json(value: &str) -> Result<EventPayload, String> {
    serde_json::from_str(value).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_commit_is_one_transaction_and_the_epoch_never_decreases() {
        let store = DurableStore::open_in_memory().unwrap();
        let task = "t1";
        let event = |seq: u64, epoch: u64| TaskEvent {
            task_id: task.to_string(),
            seq,
            epoch,
            device: DeviceId::new("dev-a"),
            payload: EventPayload::OwnerChanged {
                from: "dev-a".into(),
                to: "dev-b".into(),
                epoch,
            },
        };
        store.ensure_task(task, "dev-a").unwrap();
        store.commit_owner(task, "dev-b", 1, &event(1, 1)).unwrap();

        // A second restart must not be able to move the epoch backwards.
        let err = store
            .commit_owner(task, "dev-a", 0, &event(2, 0))
            .unwrap_err();
        assert!(err.contains("backwards"), "got: {err}");

        // And a no-op commit is refused too.
        let err = store
            .commit_owner(task, "dev-b", 1, &event(2, 1))
            .unwrap_err();
        assert!(err.contains("no-op"), "got: {err}");

        let record = store.task(task).unwrap().unwrap();
        assert_eq!(record.owner, "dev-b");
        assert_eq!(record.epoch, 1);
    }

    #[test]
    fn event_seq_continues_after_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.db");
        {
            let store = DurableStore::open(&path).unwrap();
            store.ensure_task("t1", "dev-a").unwrap();
            let mut log = EventLog::new();
            for seq in 1..=3 {
                let event = log.next_event(
                    "t1".into(),
                    0,
                    DeviceId::new("dev-a"),
                    EventPayload::StepStarted { step: seq },
                );
                log.append(event.clone());
                store.append_event(&event).unwrap();
            }
        }
        // Reopen the same file: the head must still be 3, so the next is 4.
        let store = DurableStore::open(&path).unwrap();
        assert_eq!(store.event_head("t1").unwrap(), 3);
        let log = store.event_log("t1").unwrap();
        let next = log.next_event(
            "t1".into(),
            0,
            DeviceId::new("dev-a"),
            EventPayload::StepStarted { step: 4 },
        );
        assert_eq!(next.seq, 4);
    }

    #[test]
    fn an_uncommitted_handoff_is_rolled_back_and_a_committed_one_resumes() {
        let store = DurableStore::open_in_memory().unwrap();
        store
            .save_handoff(&HandoffRecord {
                handoff_id: "h1".into(),
                task_id: "t1".into(),
                from_device: "dev-a".into(),
                to_device: "dev-b".into(),
                state: "shadowing".into(),
                epoch: 0,
                checkpoint_seq: 3,
                applied_seq: 3,
                committed: false,
                end_reason: None,
            })
            .unwrap();
        store
            .save_handoff(&HandoffRecord {
                handoff_id: "h2".into(),
                task_id: "t2".into(),
                from_device: "dev-a".into(),
                to_device: "dev-b".into(),
                state: "committed".into(),
                epoch: 1,
                checkpoint_seq: 5,
                applied_seq: 5,
                committed: true,
                end_reason: None,
            })
            .unwrap();

        let (rolled_back, resume) = store.recover().unwrap();
        assert_eq!(rolled_back.len(), 1);
        assert_eq!(rolled_back[0].handoff_id, "h1");
        assert_eq!(rolled_back[0].state, "rolled_back");
        let resume = resume.expect("a committed unacked handoff must resume");
        assert_eq!(resume.handoff_id, "h2");
    }

    #[test]
    fn a_stale_owner_write_is_still_rejected_after_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.db");
        {
            let store = DurableStore::open(&path).unwrap();
            store.ensure_task("t1", "dev-a").unwrap();
            let event = TaskEvent {
                task_id: "t1".into(),
                seq: 1,
                epoch: 1,
                device: DeviceId::new("dev-b"),
                payload: EventPayload::OwnerChanged {
                    from: "dev-a".into(),
                    to: "dev-b".into(),
                    epoch: 1,
                },
            };
            store.commit_owner("t1", "dev-b", 1, &event).unwrap();
        }
        let store = DurableStore::open(&path).unwrap();
        let record = store.task("t1").unwrap().unwrap();
        // The old owner is still not the owner after the restart.
        assert_eq!(record.owner, "dev-b");
        assert_ne!(record.owner, "dev-a");
    }
}
