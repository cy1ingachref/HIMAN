//! In-memory task store. Phase 1: no persistence, no SQLite. The interface is
//! shaped so a SQLite-backed store can be dropped in without changing callers.

use std::collections::HashMap;

use chrono::Utc;
use himan_proto::{DeviceId, TaskId, TaskState, ToolName};
use serde::{Deserialize, Serialize};

/// A stored task.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskRecord {
    pub id: TaskId,
    pub tool: ToolName,
    pub target_device: DeviceId,
    pub state: TaskState,
    /// JSON args, stored verbatim.
    pub args: serde_json::Value,
    pub output: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl TaskRecord {
    fn new(id: TaskId, tool: ToolName, target_device: DeviceId, args: serde_json::Value) -> Self {
        let now = Utc::now().timestamp();
        Self {
            id,
            tool,
            target_device,
            state: TaskState::Pending,
            args,
            output: None,
            created_at: now,
            updated_at: now,
        }
    }
}

/// Thread-safe in-memory store. Swap for a SQLite store in Phase 2.
#[derive(Debug, Default)]
pub struct StateStore {
    tasks: HashMap<TaskId, TaskRecord>,
    /// Ordered task ids, newest last.
    order: Vec<TaskId>,
}

impl StateStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn create(
        &mut self,
        id: TaskId,
        tool: ToolName,
        target_device: DeviceId,
        args: serde_json::Value,
    ) -> &TaskRecord {
        let record = TaskRecord::new(id.clone(), tool, target_device, args);
        self.tasks.insert(id.clone(), record);
        self.order.push(id);
        self.tasks
            .get(&self.order.last().cloned().unwrap())
            .unwrap()
    }

    pub fn get(&self, id: &TaskId) -> Option<&TaskRecord> {
        self.tasks.get(id)
    }

    pub fn set_state(&mut self, id: &TaskId, state: TaskState) -> Option<TaskState> {
        let record = self.tasks.get_mut(id)?;
        let previous = record.state;
        record.state = state;
        record.updated_at = Utc::now().timestamp();
        Some(previous)
    }

    /// Insert a record restored from durable storage, keeping its recorded
    /// timestamps rather than stamping "now".
    pub fn restore(&mut self, record: TaskRecord) -> &TaskRecord {
        if !self.tasks.contains_key(&record.id) {
            self.order.push(record.id.clone());
        }
        self.tasks.insert(record.id.clone(), record);
        self.tasks
            .get(&self.order.last().cloned().unwrap())
            .unwrap()
    }

    pub fn set_output(&mut self, id: &TaskId, output: String) {
        if let Some(record) = self.tasks.get_mut(id) {
            record.output = Some(output);
            record.updated_at = Utc::now().timestamp();
        }
    }

    pub fn list(&self) -> Vec<&TaskRecord> {
        self.order
            .iter()
            .filter_map(|id| self.tasks.get(id))
            .collect()
    }

    pub fn len(&self) -> usize {
        self.tasks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn task(id: &str) -> TaskId {
        TaskId::new(id)
    }

    #[test]
    fn create_and_get() {
        let mut store = StateStore::new();
        store.create(
            task("t1"),
            ToolName::new("device_status"),
            DeviceId::new("pc-1"),
            json!({}),
        );
        let record = store.get(&task("t1")).unwrap();
        assert_eq!(record.state, TaskState::Pending);
        assert_eq!(record.tool.as_str(), "device_status");
    }

    #[test]
    fn set_state_returns_previous() {
        let mut store = StateStore::new();
        store.create(
            task("t1"),
            ToolName::new("device_status"),
            DeviceId::new("pc-1"),
            json!({}),
        );
        let prev = store.set_state(&task("t1"), TaskState::Running);
        assert_eq!(prev, Some(TaskState::Pending));
        assert_eq!(store.get(&task("t1")).unwrap().state, TaskState::Running);
    }

    #[test]
    fn set_state_on_missing_task_returns_none() {
        let mut store = StateStore::new();
        assert_eq!(store.set_state(&task("ghost"), TaskState::Running), None);
    }

    #[test]
    fn list_is_in_insertion_order() {
        let mut store = StateStore::new();
        for i in 0..3 {
            store.create(
                task(&format!("t{i}")),
                ToolName::new("device_status"),
                DeviceId::new("pc-1"),
                json!({}),
            );
        }
        let ids: Vec<&str> = store.list().iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, vec!["t0", "t1", "t2"]);
    }

    #[test]
    fn output_is_stored() {
        let mut store = StateStore::new();
        store.create(
            task("t1"),
            ToolName::new("device_status"),
            DeviceId::new("pc-1"),
            json!({}),
        );
        store.set_output(&task("t1"), "all good".into());
        assert_eq!(
            store.get(&task("t1")).unwrap().output.as_deref(),
            Some("all good")
        );
    }

    #[test]
    fn empty_store_is_empty() {
        let store = StateStore::new();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
    }
}
