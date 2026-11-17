//! Ownership and epoch fencing (docs/HANDOFF.md section 5).
//!
//! The state machine decides *when* ownership moves; this module is what makes
//! the move **stick**. It is the answer to "can this device still write for
//! this task?" and it is deliberately independent of the handoff state machine
//! so it can be enforced at the message boundary in `hub.rs`.
//!
//! The rule is the spec's invariant 5: every ownership change increments a
//! per-task epoch, and a write carrying an older epoch, or coming from a
//! device that is not the owner, is rejected. That is what stops a slow or
//! partitioned old owner from writing after the switch.

use std::collections::HashMap;

use himan_proto::DeviceId;

/// Current owner and fencing counter for one task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ownership {
    pub owner: DeviceId,
    pub epoch: u64,
}

/// Why a write was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FenceError {
    /// The device is registered but is not the current owner.
    NotOwner {
        task_id: String,
        device: String,
        owner: String,
    },
    /// The device is the owner but its epoch is behind the current one.
    StaleEpoch {
        task_id: String,
        device: String,
        epoch: u64,
        current_epoch: u64,
    },
}

impl std::fmt::Display for FenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FenceError::NotOwner {
                task_id,
                device,
                owner,
            } => write!(
                f,
                "device {device} is not the owner of task {task_id} (owner is {owner})"
            ),
            FenceError::StaleEpoch {
                task_id,
                device,
                epoch,
                current_epoch,
            } => write!(
                f,
                "device {device} wrote task {task_id} with stale epoch {epoch} (current {current_epoch})"
            ),
        }
    }
}

impl std::error::Error for FenceError {}

/// Per-task ownership with fencing.
#[derive(Debug, Default)]
pub struct OwnerRegistry {
    tasks: HashMap<String, Ownership>,
}

impl OwnerRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Declare a task owned by `owner` at epoch 0. Idempotent for an unchanged
    /// record; a different owner at the same epoch is refused.
    pub fn register(&mut self, task_id: String, owner: DeviceId) -> Result<(), FenceError> {
        match self.tasks.get(&task_id) {
            Some(existing) if existing.owner == owner && existing.epoch == 0 => Ok(()),
            Some(existing) => Err(FenceError::NotOwner {
                task_id,
                device: owner.to_string(),
                owner: existing.owner.to_string(),
            }),
            None => {
                self.tasks.insert(task_id, Ownership { owner, epoch: 0 });
                Ok(())
            }
        }
    }

    pub fn get(&self, task_id: &str) -> Option<&Ownership> {
        self.tasks.get(task_id)
    }

    pub fn owner_of(&self, task_id: &str) -> Option<&DeviceId> {
        self.tasks.get(task_id).map(|o| &o.owner)
    }

    /// Every task this registry knows, as `(task_id, owner, epoch)`.
    ///
    /// Used by stall detection, which has to find all tasks a dead device
    /// owned; the registry is small, so a linear scan is fine.
    pub fn all(&self) -> Vec<(String, DeviceId, u64)> {
        self.tasks
            .iter()
            .map(|(task_id, o)| (task_id.clone(), o.owner.clone(), o.epoch))
            .collect()
    }

    /// The ids of every task owned by `owner`.
    pub fn tasks_of(&self, owner: &DeviceId) -> Vec<String> {
        self.tasks
            .iter()
            .filter(|(_, o)| o.owner == *owner)
            .map(|(task_id, _)| task_id.clone())
            .collect()
    }

    pub fn len(&self) -> usize {
        self.tasks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    /// Check a write. `epoch` is checked **before** ownership, deliberately:
    /// the stale-epoch case the spec's failure matrix names is an old owner
    /// writing after the switch, and reporting that as "not the owner" would
    /// lose the one detail that makes it diagnosable. A device that is behind
    /// on the epoch is stale regardless of whether it also lost ownership.
    ///
    /// A higher epoch is also refused: only the orchestrator advances the
    /// counter, through `commit`.
    pub fn check_write(
        &self,
        task_id: &str,
        device: &DeviceId,
        epoch: u64,
    ) -> Result<(), FenceError> {
        let current = self
            .tasks
            .get(task_id)
            .ok_or_else(|| FenceError::NotOwner {
                task_id: task_id.to_owned(),
                device: device.to_string(),
                owner: "none".to_owned(),
            })?;

        if epoch != current.epoch {
            return Err(FenceError::StaleEpoch {
                task_id: task_id.to_owned(),
                device: device.to_string(),
                epoch,
                current_epoch: current.epoch,
            });
        }

        if current.owner != *device {
            return Err(FenceError::NotOwner {
                task_id: task_id.to_owned(),
                device: device.to_string(),
                owner: current.owner.to_string(),
            });
        }

        Ok(())
    }

    /// The atomic commit: bump the epoch by one and move ownership. Refuses a
    /// jump of more than one, so a forged or replayed ownership change cannot
    /// skip epochs.
    pub fn commit(
        &mut self,
        task_id: &str,
        new_owner: DeviceId,
        new_epoch: u64,
    ) -> Result<Ownership, FenceError> {
        let current = self
            .tasks
            .get(task_id)
            .ok_or_else(|| FenceError::NotOwner {
                task_id: task_id.to_owned(),
                device: new_owner.to_string(),
                owner: "none".to_owned(),
            })?;

        if new_epoch != current.epoch + 1 {
            return Err(FenceError::StaleEpoch {
                task_id: task_id.to_owned(),
                device: new_owner.to_string(),
                epoch: new_epoch,
                current_epoch: current.epoch,
            });
        }

        let updated = Ownership {
            owner: new_owner,
            epoch: new_epoch,
        };
        self.tasks.insert(task_id.to_owned(), updated.clone());
        Ok(updated)
    }
}

#[cfg(test)]
mod tests;
