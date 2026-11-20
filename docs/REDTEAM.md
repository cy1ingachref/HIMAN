# HIMAN — Red-team test log

Each attack has a test in `orchestrator/tests/redteam.rs`. This table records
the expected defense, the test, the status before the fix (with the actual
failure output), the status after the fix, and the commit that fixed it.

No keys, seeds or tokens appear in this document or in test output. Public
keys are fine.

## Summary

| ID | Attack | Expected defense | Test | Before fix | After fix | Commit | Mutation result |
|---|---|---|---|---|---|---|---|
| RT-01 | Handshake reflection | Agent rejects an echoed Hello | `rt01_agent_rejects_reflected_hello` | PASS | PASS | already defended | n/a |
| RT-02 | Wrong nonce in Welcome | Agent rejects a nonce mismatch | `rt02_wrong_nonce_is_rejected` | PASS | PASS | already defended | n/a |
| RT-03 | Identity takeover | Reject a new key for a connected id | `rt03_identity_takeover_is_rejected` | **SUCCEEDED** (real binaries) | PASS | `9052a62` | n/a |
| RT-04 | Fake orchestrator | Agent rejects an unpinned key | `rt04_fake_orchestrator_is_rejected` | **SUCCEEDED** (real binaries) | PASS | `a1e3406` | n/a |
| RT-05 | ToolResult replay | Hub rejects seq <= last | `rt05_tool_result_replay_is_rejected` | IGNORED (no seq tracking) | PASS | `ef2e78a` | n/a |
| RT-06 | Task-id collision | Random 128-bit task ids | `rt06_task_ids_are_unique_within_a_second` | **FAIL** | PASS | `8e6c61d` | n/a |
| RT-07 | Unauthenticated API call | 401 without a valid bearer token | `rt07_unauthenticated_api_call_is_rejected` | **SUCCEEDED** (real binaries) | PASS | `65fd428` | n/a |
| RT-08 | Silent / oversized WebSocket | Socket closed within the timeout | `rt08_*` (3 tests) | IGNORED (no limits) | PASS | `1607877` | n/a |
| RT-09 | Forged `SwitchCommit` | A forged ack moves no owner and no epoch | `rt09_a_forged_switch_commit_moves_nothing` | already defended | PASS | already defended | **discriminates** — "the hub acted on a hub-received SwitchCommit: [… forged_switch_applied, forged_switch_applied]" |
| RT-10 | Replayed handoff token | Refused once the epoch moved | `rt10_a_replayed_handoff_token_is_refused` | already defended | PASS | already defended | **discriminates** — "a replayed handoff token was accepted" |
| RT-11 | Handoff to an unenrolled device | Refused as not registered | `rt11_a_handoff_to_an_unenrolled_device_is_refused` | already defended | PASS | already defended | **discriminates** — "an unregistered target was allowed at the policy layer: Allow" |
| RT-12 | Token bound to a different target | The token's target must be the presenter | `rt12_a_token_bound_to_another_target_is_refused` | already defended | PASS | already defended | **discriminates** — "a token bound to pc-2 was accepted by pc-3" |
| RT-13 | Two simultaneous handoffs, one task | At most one active handoff, rejected with 409 | `rt13_two_simultaneous_handoffs_are_serialised` + `hub::tests::a_second_handoff_for_a_task_in_flight_is_rejected` + `one_active_handoff_http` | already defended | PASS | `a6f2601`, guard added in this branch | **discriminates** — "the second handoff was not refused by the one-active guard: " |
| RT-14 | Stale-epoch commit after the switch | The durable commit refuses a backwards epoch | `rt14_a_stale_epoch_commit_is_refused` | already defended | PASS | already defended | **discriminates** — "a stale-epoch commit after the switch was accepted" |
| RT-15 | Post-handshake frame injection (MITM on plain ws://) | Every post-Welcome message verifies against the orchestrator key; a foreign-signed frame is dropped before any handler | `client::tests::a_message_signed_by_another_key_is_dropped`, `client::tests::an_injected_handoff_commit_is_dropped` | **SUCCEEDED** — an injected ToolCall ran and returned real device data; a forged HandoffCommit was acknowledged | PASS | this branch | **discriminates** — with the verification removed: "an injected message produced a reply: … ToolResult { task_id: t-injected, state: Succeeded, output: pc-1: CPU … }" and "a forged commit was acknowledged" |
| RT-16 | Cross-handoff reply (a Ready naming another attempt) | The driver drops replies whose handoff_id is not this attempt's | `handoff_driver::tests::a_ready_for_a_different_handoff_does_not_advance_this_one` | **SUCCEEDED** — a Ready for `h-OTHER` advanced the `h-mine` procedure past prepare | PASS | this branch | **discriminates** — with the id check removed the procedure advances and the timeout assertion fails |

### How the mutation column was produced

For each row the specific defense was removed in the working tree (never
committed), the test was run, the failing assertion was recorded, and the file
was restored with `git checkout --`. RT-01 to RT-08 are marked `n/a` because
their before-state evidence already exists above.

### RT-13 now discriminates (guard added)

RT-13 previously did not discriminate: removing the hub's `current.owner != *from`
check still passed, because the refusal came from a different defense
(`OwnerRegistry::check_write` / the epoch). The row has an explicit guard now,
and the mutation removes *that*:

- **Guard**: `Hub::request_handoff` refuses a second request for a task that
  already has a non-terminal attempt, before minting a token. It audits
  `handoff_rejected` with `reason=one_active_handoff`.
- **Mutation**: the lookup is replaced with `None`. The test fails with
  "the second handoff was not refused by the one-active guard: ".
- **HTTP**: the refusal maps to 409 Conflict, not 400, because the request is
  well-formed and retryable. `handoff_error_status` is the single place that
  decides this; `one_active_handoff_http` asserts both the 409 and that
  unrelated policy refusals stay 400.

**Why the guard is unit-tested rather than driven over HTTP**: `POST
/api/v1/handoff` runs the driver to completion before responding, so two HTTP
requests for one task never overlap. The guard protects the in-process path
(`drive_handoff` spawned by the hub, or a future background driver), which is
where a real overlap can happen.

### RT-09 to RT-14: no invented before-state

These six were written against code that already defended them, so there is no
"before" commit to attack and no fix commit to credit. Recording that plainly
is more useful than fabricating a before-state.

- **RT-09** — the hub drops `HandoffSwitched` (the driver consumes it from the
  broadcast), so the defense under test is that no forged ack moves ownership
  or the epoch. Three forgeries are attempted: an unenrolled key, the source
  claiming the switch, and a wrong epoch.
- **RT-10 / RT-13** — `request_handoff` requires the source to be the current
  owner, and the epoch comes from the registry rather than the caller. Once the
  commit moves the epoch, the old source's replay is refused as "not the
  owner"; a second concurrent request cannot create a second active attempt.
- **RT-11** — `evaluate_handoff` denies an unregistered target.
- **RT-12** — `verify_handoff_token` compares `to_device`, `task_id` and expiry.
- **RT-14** — `DurableStore::commit_owner` refuses a backwards or no-op epoch,
  which is the property that makes a late commit from the old owner harmless.

Note on the driver: `HandoffDriver::wait_for` matches `HandoffSwitched` by
payload shape. The sender check happens on the agent side (a device only
accepts a commit whose token names it), and the orchestrator never acts on a
hub-received `HandoffSwitched`. A future hardening would check the sender and
epoch inside the driver too; that is not currently a reachable hole because the
hub discards the message.

### Why RT-05 and RT-06 point at different commits

The two are easy to confuse because `ef2e78a`'s message says "fixes RT-05, RT-06",
but its diff touches no task-id or nonce code. Verified by diffing both commits:

- **`8e6c61d` is the RT-06 fix.** Its hub.rs diff replaces
  `TaskId::new(format!("task-{}", Utc::now().timestamp()))` with a uuid v4 value
  and replaces the timestamp-derived tool-call nonce with `random_nonce()`. That
  is exactly the change that makes the RT-06 test pass.
- **`ef2e78a` fixes RT-05** (per-device sequence tracking, rejecting `seq <= last`)
  and adds one stale-timestamp audit line. It reworks parts of the red-team tests,
  which is why its message mentions RT-06, but it contains no RT-06 fix.

The RT-06 row therefore credits the commit that changed the behavior, not the
commit whose message claimed it.

## Before-state evidence

Two kinds of evidence, both real output rather than assumptions.

### Against the old binaries at `b50677f`

A temporary worktree checked out `b50677f` and its binaries were attacked
directly by an external script. This proves what a real attacker could do,
not just what the test harness asserted. All six checks succeeded:

```
SUCCEEDED  RT-07 POST /api/v1/prompt with NO token is accepted  -- HTTP 400 (reached dispatch)
SUCCEEDED  RT-07 GET /api/v1/agents with NO token is accepted  -- HTTP 200
SUCCEEDED  RT-03 first pc-1 gets a Welcome                      -- {"meta":{"seq":0,...}}
SUCCEEDED  RT-03 DUPLICATE id with a DIFFERENT key also gets a Welcome
SUCCEEDED  RT-03 the duplicate session REPLACED the legitimate one -- agents=1
SUCCEEDED  RT-04 agent accepts a Welcome signed by an UNKNOWN key -- agent stopped

Attacks that succeeded at b50677f: 6/6
```

What each proves:

- **RT-07**: the API answered unauthenticated requests. `GET /api/v1/agents`
  returned 200 with device metadata; `POST /api/v1/prompt` reached dispatch
  (400 only because no agent was connected). Anyone who could reach the port
  could enumerate devices and attempt dispatch.
- **RT-03**: a second client presenting a *different* key for the same device
  id received a full `Welcome`. The hub then held one session for `pc-1`
  owned by the attacker's key — the legitimate agent's session was replaced,
  so the attacker could receive that device's tool calls.
- **RT-04**: a fake orchestrator signing its own `Welcome` with its own key was
  accepted and the agent proceeded to "agent stopped" only when the test killed
  it, not on any security check. The agent trusted whichever key the Welcome
  advertised.

The worktree was removed after the run.

### From the red-team test suite at `b50677f`

Captured by running `cargo test -p himan-orchestrator --test redteam`.

#### RT-06 fails (the one real defect found before fixes)

```
thread 'rt06_task_ids_are_unique_within_a_second' (8656) panicked at orchestrator\tests\redteam.rs:446:5:
assertion `left != right` failed: RT-06 FAILED: two dispatches in the same second got the same task id: task-1794519005
  left: "task-1794519005"
 right: "task-1794519005"
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
test rt06_task_ids_are_unique_within_a_second ... FAILED

test result: FAILED. 0 passed; 1 failed; 0 ignored; 7 filtered out
```

Cause: the task id was derived from `Utc::now().timestamp()`, so two dispatches
in the same second collided. The tool-call nonce had the same defect.

#### RT-01 and RT-02 pass already

```
test rt01_agent_rejects_reflected_hello ... ok
test rt02_wrong_nonce_is_rejected ... ok
```

#### RT-03, RT-04, RT-05, RT-07, RT-08 pending at that commit

```
test rt03_identity_takeover_is_rejected ... ignored, RT-03 pending: enrollment not implemented
test rt04_fake_orchestrator_is_rejected ... ignored, RT-04 pending: orchestrator key pinning not implemented
test rt05_tool_result_replay_is_rejected ... ignored, RT-05 pending: sequence tracking not implemented
test rt07_unauthenticated_api_call_is_rejected ... ignored, RT-07 pending: API authentication not implemented
test rt08_silent_connection_is_closed ... ignored, RT-08 pending: WebSocket hardening not implemented
```

These were `#[ignore]` placeholders written against the intended behavior, so
the suite stayed green while the defenses did not exist. The binary-level
attack above is the evidence that the gap was real.

## After-state

All eight are defended and all tests pass.

```
test rt01_agent_rejects_reflected_hello ... ok
test rt02_wrong_nonce_is_rejected ... ok
test rt03_identity_takeover_is_rejected ... ok
test rt04_fake_orchestrator_is_rejected ... ok
test rt05_tool_result_replay_is_rejected ... ok
test rt06_task_ids_are_unique_within_a_second ... ok
test rt07_unauthenticated_api_call_is_rejected ... ok
test rt08_oversized_frame_is_closed ... ok
test rt08_silent_connection_is_closed ... ok
test rt08_too_many_invalid_messages_is_closed ... ok
test enrollment_accepts_a_matching_key ... ok
test enrollment_rejects_a_key_mismatch ... ok
test enrollment_rejects_an_unknown_device ... ok

test result: ok. 13 passed; 0 failed; 0 ignored
```

Supporting checks that are not part of the RT numbering:

- `enrollment_accepts_a_matching_key` — a legitimate device still registers,
  so the enrollment check is not a blanket rejection.
- `enrollment_rejects_an_unknown_device` — an id not in the file is refused
  and the rejection is audited without key material.
- `enrollment_rejects_a_key_mismatch` — a signed Hello from a key that is not
  enrolled creates no session.
- RT-05 also asserts a newer `seq` is still accepted, proving the rule is
  ordering and not "reject everything after the first".
- RT-07 also asserts the correct token passes auth and `/health` stays open.

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
- **RT-06 (task-id collision)** is a uniqueness defect, not an attack. It
  matters because a colliding task id makes two dispatches
  indistinguishable in the audit log, which breaks the evidence chain the
  thesis depends on.
- **RT-07 (unauthenticated API)** is the difference between a system that
  works on a developer machine and one that can be exposed.
- **RT-08 (silent socket)** is a resource-exhaustion attack, not a
  confidentiality one. The defense is a deadline plus a size cap.

## The idle-timeout bug

The handshake timeout was originally applied to every read, not just the
handshake. A healthy agent only speaks when dispatched, so a quiet agent was
dropped 10 seconds after registering. Found by running the documented flow by
hand: the orchestrator log showed `WebSocket handshake timed out` exactly 10s
after a successful registration, and the agent exited.

Fixed by separating the two timeouts: 10s before the Hello, 300s after.
Regression test: `registered_agent_survives_past_the_handshake_timeout`, which
waits past the handshake timeout and then proves the connection still answers a
Ping.

The same investigation found the hub handled `Pong` but not `Ping`, so a
liveness check got no reply. Both arms are now implemented.

## The transport bug these tests found

The socket transport originally held one mutex across both halves. The read
pump held it across `.next().await`, which blocks until a frame arrives, so
`send_message()` never acquired the lock and the Hello was never written. It
was a lock-ordering race: it passed when the agent was launched from a
terminal and failed when launched from Python. Fixed in `b50677f` by
splitting the socket and guarding sink and stream separately. Regression test:
`parked_reader_does_not_block_the_writer`.

This is the case study for why the red-team suite is worth having: the bug was
invisible to the unit tests because they only exercised an in-memory duplex.
