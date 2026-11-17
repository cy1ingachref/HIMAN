# HIMAN handoff protocol (v0.1 draft)

Goal: move an active task from one device to another with no lost context, no stalled work, and no repeated actions. The user should never see a gap.

Suggested location in the repo: `docs/HANDOFF.md`.

## 1. Invariants

These must hold in every state and under every failure in section 8.

1. **One owner.** At any instant a task has exactly one owning device. Only the owner may execute tools or commit events for that task.
2. **No gap.** The old owner keeps working until the new owner is confirmed in sync (make before break).
3. **No lost events.** Every committed event is in the orchestrator's append-only log before it is acted on elsewhere.
4. **No repeated side effects.** A tool call with a given idempotency key executes at most once across all devices.
5. **Fenced ownership.** Every ownership change increments a per-task `epoch`. Commits carrying an older epoch are rejected.
6. **Rollback is always possible** until the switch commit, and the source remains the owner until then.
7. **Visuals follow truth.** The character animation starts only after the orchestrator confirms the matching state change.

## 2. Concepts

| Term | Meaning |
|---|---|
| Task | Unit of work with an id, goal, status and owner |
| Event log | Per-task, append-only, numbered `seq` 1..n. The source of truth |
| Checkpoint | Snapshot of the task's materialized state at a given `seq` |
| Epoch | Per-task counter, incremented on every ownership change (fencing token) |
| Handoff | One attempt to move ownership, identified by `handoff_id` |
| Shadow replay | The target applies log events to its local state without executing tools |
| Safe point | A moment with no in-flight non-idempotent tool call |

### Event types (minimum)

`TaskCreated`, `StepStarted`, `ToolCallIssued { call_id, tool, args, idempotency }`, `ToolResultRecorded { call_id, result }`, `ApprovalRecorded { approval_id, signer }`, `NoteAdded`, `OwnerChanged { from, to, epoch }`.

Each event carries `task_id`, `seq`, `epoch`, `device`, a timestamp, and a signature from the committing device.

### Tool classification

Every tool declares `idempotency: Idempotent | NonIdempotent` in its schema.

- Idempotent (for example `device_status`): can be re-issued on the new owner with the same `call_id`.
- NonIdempotent (for example delete a file, send a message): must finish on the current owner before the switch. It is never replayed.

## 3. State machine

```
Requested -> Prepared -> Warming -> Shadowing -> Switching -> Active
     \           \          \           \            \
      +-----------+----------+-----------+------------+--> RolledBack
```

`Active` and `RolledBack` are terminal for a handoff. `Failed` is a terminal state reserved for unrecoverable orchestrator errors (the task stays with the source).

| State | Meaning | Owner during state |
|---|---|---|
| Requested | A handoff was asked for by the user or planner | source |
| Prepared | Policy allowed it, checkpoint taken, token issued | source |
| Warming | Target is loading state, tools and assets | source |
| Shadowing | Target applies the log live, side-effect free | source |
| Switching | Orchestrator is flipping ownership | source until commit, then target |
| Active | Target owns the task, source drained | target |
| RolledBack | Handoff abandoned, source still owns | source |

### Transitions

| From | To | Trigger | Guard | Timeout default | On timeout |
|---|---|---|---|---|---|
| Requested | Prepared | Policy approves | target enrolled and connected, source owns task | 5 s | RolledBack |
| Prepared | Warming | Target accepts `HandoffPrepare` | token verifies | 5 s | RolledBack |
| Warming | Shadowing | Target sends `HandoffReady` | checkpoint loaded, capabilities reported | 20 s | RolledBack |
| Shadowing | Switching | Orchestrator sees lag at or below threshold | `target.applied_seq >= log.head - lag_max` and a safe point is reached | 30 s | RolledBack |
| Switching | Active | Source drained and target acks `SwitchCommit` | epoch incremented atomically | 10 s | RolledBack if commit not yet made, otherwise retry the ack |
| any before commit | RolledBack | Rollback requested, failure, or timeout | none | n/a | n/a |

The commit point is the single atomic write that increments `epoch` and appends `OwnerChanged`. Before it, rollback is free. After it, the target is the owner and only the ack step may retry.

## 4. Messages

All messages travel in the existing signed envelope (seq, nonce, freshness window, sender signature). Names are Rust-style; the wire form is JSON.

```rust
struct HandoffRequest   { task_id, to: DeviceId, reason }            // user/planner -> orchestrator (HTTP body: `HandoffRequest` in server.rs)
struct HandoffPrepare   { handoff_id, task_id, from, to, epoch,
                          checkpoint_seq, token }    // orchestrator -> target
struct HandoffReady     { handoff_id, applied_seq, capabilities }    // target -> orchestrator
struct HandoffProgress  { handoff_id, applied_seq }                  // target -> orchestrator (periodic)
struct HandoffDrain     { handoff_id, new_epoch }                    // orchestrator -> source: stop starting new steps
struct HandoffDrained   { handoff_id, last_seq }                     // source -> orchestrator
struct HandoffCommit    { handoff_id, new_epoch, final_seq }         // orchestrator -> target
struct HandoffSwitched  { handoff_id, new_epoch }                    // target -> orchestrator
struct HandoffRollback  { handoff_id, reason }                       // orchestrator -> both
```

These are the `Payload` variants in `proto/src/envelope.rs` (prefixed
`Handoff` to keep the enum readable). An earlier draft of this document used
the shorter names `ShadowProgress`, `SwitchPrepare`, `DrainDone`,
`SwitchCommit`, `SwitchAck`; the code and this document now agree.

### Handoff token

Signed by the orchestrator. Binds `{ handoff_id, task_id, from, to, epoch, expires_at }`. The target verifies the signature against the pinned orchestrator key and checks that `to` is itself and `expires_at` has not passed. One use only.

### Event stream to the target

During Warming and Shadowing the orchestrator streams log events with `seq > checkpoint_seq`. The target applies them in order, rejects gaps, and reports `applied_seq`.

## 5. Ownership and fencing

- The orchestrator stores `{ owner, epoch }` per task.
- Every `ToolCallIssued`, `ToolResultRecorded` and commit carries the sender's `epoch`.
- The orchestrator rejects any event whose `epoch` is lower than the current one, or whose sender is not the owner. This blocks a slow or partitioned old owner from writing after the switch.
- Tool execution on a device requires a valid, unexpired execution lease for `(task_id, epoch)` issued with each dispatch.

## 6. Switch procedure (the part that must be exact)

1. Orchestrator sends `SwitchPrepare` to the source. The source stops starting new steps and finishes any in-flight non-idempotent call.
2. The source reports `DrainDone { last_seq }` once at a safe point. Idempotent calls still in flight are cancelled and their `call_id`s stay in the log as issued but unresolved.
3. Orchestrator waits until `target.applied_seq == last_seq`.
4. In one atomic transaction the orchestrator increments `epoch`, sets `owner = target`, and appends `OwnerChanged`. This is the commit point.
5. Orchestrator sends `SwitchCommit` to the target. The target starts executing, re-issuing any unresolved idempotent calls with the same `call_id` and idempotency key.
6. Target sends `SwitchAck`. The handoff becomes `Active`.
7. The source goes idle and releases its resources.

If step 1 or 2 times out, roll back: send `Rollback` to both and tell the source to resume.

## 7. Character events

The orchestrator emits presentation events from confirmed state changes only.

| Confirmed state | Source renderer | Target renderer |
|---|---|---|
| Warming | normal | hidden, loading |
| Shadowing | normal | faint ghost of the character |
| Commit made | leave animation starts | arrival animation starts |
| Active | character gone, idle badge | character fully active |
| RolledBack | normal | ghost fades out |

The target adapts quality to its reported capabilities (shape detail, effects). The task logic does not change.

## 8. Failure matrix

| Failure | State | Expected behavior |
|---|---|---|
| Source crashes | Warming or Shadowing | Roll back. Task is recoverable from log and checkpoint, so the orchestrator may offer the task to the target as a fresh recovery handoff |
| Source crashes | Switching, before commit | Treat the log head as final. If no non-idempotent call is unresolved, commit to target. Otherwise mark that call `Unknown` and require approval before re-issuing |
| Target crashes | Warming, Shadowing, Switching before commit | Roll back, source continues |
| Target crashes | after commit | Task is stalled by a dead owner. Orchestrator offers it to another device or back to the source with a new epoch |
| Orchestrator restarts | any | Handoff state is persisted. On restart, any handoff not yet committed is rolled back. A committed one continues at the ack step |
| Network partition | any before commit | Timeouts roll back |
| Duplicate `SwitchCommit` | any | Idempotent by `(handoff_id, new_epoch)` |
| Stale `epoch` event | any | Rejected and audit-logged |
| Replayed handoff message | any | Rejected by nonce and seq checks |
| Handoff token used twice | any | Second use rejected |
| Target not enrolled | Requested | Rejected by policy |

## 9. Policy and security

- Handoff requires the target to be enrolled and currently connected with the pinned key.
- The orchestrator signs tokens; devices never sign ownership changes.
- Pending approvals stay valid across a handoff, because the approver's signature is bound to `(task_id, action)` and not to the device running the task. Open question: should approvals also bind to `epoch`?
- A task in the destructive risk tier cannot be handed off while it has an unresolved non-idempotent call.
- Every state transition is written to the tamper-evident audit log: `handoff_requested`, `handoff_prepared`, `handoff_ready`, `switch_committed`, `handoff_active`, `handoff_rolled_back`, each with `handoff_id`, devices, epoch and durations. No key material is logged.

## 10. Metrics for the evaluation chapter

| Metric | Target |
|---|---|
| Handoff gap (time with no owner) | 0 ms by construction |
| Switch time (SwitchPrepare to SwitchAck) | measured, p50 and p95 |
| Total handoff time (Requested to Active) | measured |
| Lost events | 0 |
| Duplicate side effects | 0 |
| Rollback rate | measured, with cause |
| Replay lag at switch | measured |

## 11. Test plan

1. **Pure state machine tests**: every transition, every illegal transition, timeouts, using a fake clock. Property test: after any sequence of events and failures the invariants in section 1 hold.
2. **Integration tests** with two agents (two instances of the PC agent with different device ids stand in for PC and phone):
   - happy path: task runs across the handoff with continuous log seq and one owner
   - kill source in Shadowing, in Switching before commit
   - kill target in Warming and after commit
   - drop `SwitchCommit`, duplicate `SwitchCommit`, delay `SwitchAck`
   - old owner writes with a stale epoch after the switch
   - non-idempotent call in flight at the switch
   - orchestrator restart mid-handoff
3. **Red-team additions**: forged `SwitchCommit`, replayed handoff token, handoff to an unenrolled device, handoff token bound to a different target, two simultaneous handoffs for the same task.
4. **End-to-end test** in CI with real binaries.

## 12. Open questions

- Checkpoint frequency and size limits (every N events or every T seconds).
- Where large artifacts (files, datasets) live so a handoff does not copy them.
- How the phone agent keeps the connection alive in the background for Warming and Shadowing.
- Whether approvals bind to epoch.
- Whether the user can pin a task to a device and block handoffs for it.
