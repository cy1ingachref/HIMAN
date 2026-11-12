# HIMAN — Red-team test log

Each attack has a test in `orchestrator/tests/redteam.rs`. This table records
the expected defense, the test, the status before the fix (with the actual
failure output), the status after the fix, and the commit that fixed it.

A test for a defense that does not exist yet is marked
`#[ignore = "RT-XX pending"]` so CI stays green. The ignore is removed in the
task that implements the defense.

No keys, seeds or tokens appear in this document or in test output. Public
keys are fine.

## Summary

| ID | Attack | Expected defense | Test | Before fix | After fix | Commit |
|---|---|---|---|---|---|---|
| RT-01 | Handshake reflection | Agent rejects an echoed Hello | `rt01_agent_rejects_reflected_hello` | PASS | PASS | already defended |
| RT-02 | Wrong nonce in Welcome | Agent rejects a nonce mismatch | `rt02_wrong_nonce_is_rejected` | PASS | PASS | already defended |
| RT-03 | Identity takeover | Reject a new key for a connected id | `rt03_identity_takeover_is_rejected` | IGNORED (pending) | TBD | TBD |
| RT-04 | Fake orchestrator | Agent rejects an unpinned key | `rt04_fake_orchestrator_is_rejected` | IGNORED (pending) | TBD | TBD |
| RT-05 | ToolResult replay | Hub rejects seq <= last | `rt05_tool_result_replay_is_rejected` | IGNORED (pending) | TBD | TBD |
| RT-06 | Task-id collision | Random 128-bit task ids | `rt06_task_ids_are_unique_within_a_second` | **FAIL** | TBD | TBD |
| RT-07 | Unauthenticated API call | 401 without a valid bearer token | `rt07_unauthenticated_api_call_is_rejected` | IGNORED (pending) | TBD | TBD |
| RT-08 | Silent / oversized WebSocket | Socket closed within the timeout | `rt08_silent_connection_is_closed` | IGNORED (pending) | TBD | TBD |

## Before-state evidence

Captured by running `cargo test -p himan-orchestrator --test redteam` at
commit `b50677f` (the commit before the fixes).

### RT-06 fails (the one real defect found before fixes)

```
thread 'rt06_task_ids_are_unique_within_a_second' (8656) panicked at orchestrator\tests\redteam.rs:446:5:
assertion `left != right` failed: RT-06 FAILED: two dispatches in the same second got the same task id: task-1794519005
  left: "task-1794519005"
 right: "task-1794519005"
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
test rt06_task_ids_are_unique_within_a_second ... FAILED

test result: FAILED. 0 passed; 1 failed; 0 ignored; 7 filtered out
```

Cause: the task id is derived from `Utc::now().timestamp()`, so two dispatches
in the same second collide. The tool-call nonce has the same defect.

### RT-01 and RT-02 pass already

```
test rt01_agent_rejects_reflected_hello ... ok
test rt02_wrong_nonce_is_rejected ... ok
```

These were defended when the handshake was hardened: `register()` requires a
`Welcome`, checks the nonce, and verifies the signature.

### RT-03, RT-04, RT-05, RT-07, RT-08 pending

```
test rt03_identity_takeover_is_rejected ... ignored, RT-03 pending: enrollment not implemented
test rt04_fake_orchestrator_is_rejected ... ignored, RT-04 pending: orchestrator key pinning not implemented
test rt05_tool_result_replay_is_rejected ... ignored, RT-05 pending: sequence tracking not implemented
test rt07_unauthenticated_api_call_is_rejected ... ignored, RT-07 pending: API authentication not implemented
test rt08_silent_connection_is_closed ... ignored, RT-08 pending: WebSocket hardening not implemented
```

These defenses are not implemented yet. Each is written as a test against the
expected behavior so the gap is explicit and the fix is verifiable.

## After-state

To be filled in as each task lands, with the commit hash and the passing test
output.

## Attack notes for the thesis

- **RT-01 (reflection)** is the motivating case for the socket-echo bug: an
  agent that accepts any reply as registration success can be tricked into
  believing it is enrolled when the orchestrator never saw it. The defense is
  to require a specific reply shape.
- **RT-03 (identity takeover)** and **RT-04 (fake orchestrator)** are the two
  halves of enrollment and key pinning. Neither is useful without the other:
  enrollment without pinning lets a fake orchestrator issue WELCOMEs, and
  pinning without enrollment lets any key claim a device id.
- **RT-05 (replay)** is defeated by sequence tracking, which is also what
  makes the audit log trustworthy about ordering.
- **RT-08 (silent socket)** is a resource-exhaustion attack, not a
  confidentiality one. The defense is a deadline plus a size cap.
