# HIMAN — Roadmap

Status of each phase. Mark a phase done only when its exit check passes.

## Phase 0: Planning — DONE 2026-11-12

- [x] Device set frozen (PC + Android, optional Pi/router)
- [x] LLM approach chosen (pluggable backend + stub)
- [x] Repository created: `cy1ingachref/HIMAN`
- [x] Workspace skeleton, 4 crates
- [ ] Supervisor, deadline, exact PFE duration — still TBD (user side)

## Phase 1: Foundation — DONE 2026-11-13

- [x] `proto` crate: message types, signing, envelope
- [x] `agent-core`: Tool trait + registry with whitelist
- [x] `agent-core`: `ChatBackend` trait + `ScriptedBackend` stub
- [x] `orchestrator`: policy engine
- [x] `orchestrator`: presence manager + handoff tokens
- [x] `orchestrator`: state store
- [x] `orchestrator`: hash-chained audit log
- [x] `agent-pc`: real `device_status` + `run_diagnostic` tools
- [x] WebSocket hub: orchestrator accepts agent connections
- [x] Exit check: a signed tool call works end-to-end over the wire
      (`orchestrator/tests/integration.rs` + `e2e.rs`)
- [x] Red-team suite RT-01..RT-08, all passing (`docs/REDTEAM.md`)
- [x] Logging visible by default (`orchestrator/tests/logging.rs`)
- [x] CI: fmt, clippy, test, e2e, audit, secret scan

## Phase 2: Agent loop

- [ ] Tool schemas + registry exposed over the wire
- [ ] Real LLM backend behind `ChatBackend`
- [ ] Task state machine persisted (SQLite)
- [ ] Exit check: text prompt becomes a tool call and a result, with persistence

## Phase 3: Phone and handoff

- [ ] Android app shell: foreground service, Keystore, push wake-up
- [ ] Phone tools: `device_status`, `request_approval`, `list_files`,
      `upload_file`, `show_notification`
- [x] Handoff state machine (`orchestrator/src/handoff.rs`), pure and
      fake-clock testable — spec `docs/HANDOFF.md` sections 1-3
- [x] Epoch fencing and one-owner enforcement
      (`orchestrator/src/ownership.rs`) — spec section 5
- [x] Handoff wire messages (`HandoffPrepare`, `HandoffReady`,
      `HandoffProgress`, `HandoffDrain`, `HandoffDrained`, `HandoffCommit`,
      `HandoffSwitched`, `HandoffRollback`) — spec section 4
- [x] Hub flow + HTTP surface (`POST /api/v1/handoff`,
      `GET /api/v1/tasks/{id}/owner`)
- [x] Agent answers `HandoffPrepare` / `HandoffCommit` and enforces the
      token's own claims (target, task, expiry)
- [x] Handoff driver that owns both sockets and walks
      Requested -> Prepared -> Warming -> Shadowing -> Switching -> Committed
      -> Active (`orchestrator/src/handoff_driver.rs`)
- [x] AC-1/AC-2/AC-3 on the real binaries
      (`orchestrator/tests/{ac1_happy_path,ac2_ac3}.rs`)
- [x] AC-4 failure matrix: stale-epoch write, duplicate and dropped
      `SwitchCommit`, source dies in Shadowing, target dies before commit,
      non-idempotent effect in flight (`orchestrator/tests/ac4_matrix.rs`,
      `orchestrator/tests/non_idempotent.rs`)
- [ ] Agent-side target: warm state, shadow the log, report `applied_seq`
- [ ] Exit check: task started on PC finishes on phone
- [ ] Secure mesh (Tailscale/WireGuard/Headscale)

### TODO — the switch procedure is not driven end to end yet

The state machine, the fencing, the wire types and the agent's token check
exist and are tested, but nothing on the orchestrator *sends* `HandoffPrepare`
to the target or feeds the target's `HandoffReady` back into
`advance_handoff`. Today `advance_handoff` is reached only from tests.

Concretely missing: a handoff driver that owns the two sockets and walks
Requested -> Prepared -> Warming -> Shadowing -> Switching -> Committed ->
Active, plus the agent loop's shadow mode (apply log events side-effect free
and report `applied_seq`). Until that lands, the e2e exit check
"task started on PC finishes on phone" is not claimable.

### Phase 3 durability (`feat/phase3-durability`)

- [x] SQLite durable state (WAL): per-task owner/epoch, the event log, the
      handoff state and the audit log
      (`orchestrator/src/durable.rs`)
- [x] The commit point is one transaction: epoch bump, owner change and
      `OwnerChanged` together; it refuses a backwards or no-op epoch
- [x] Startup recovery: an uncommitted handoff rolls back (and is audited), a
      committed unacked one resumes at the ack step
- [x] The audit log is a hash chain (`prev_hash`); a broken chain refuses to
      start unless `HIMAN_ALLOW_AUDIT_RECOVERY=1`, which is recorded
- [x] A dead owner's tasks are stalled, epoch-bumped, offered to a live
      enrolled device, and marked unresolved when a non-idempotent call has no
      result (`orchestrator/tests/stalled_owner.rs`)
- [x] A stall with no device online is persisted and offered when one
      connects (`orchestrator/tests/stalled_pending.rs`)
- [x] Restart tests on the real binaries
      (`orchestrator/tests/durability.rs`, `durable_audit.rs`)
- [x] Fault-injection hooks are behind the `fault-injection` feature and a CI
      guard fails the job if any reaches the release binary
- [x] AC-5 handoff red team, RT-09 to RT-14
      (`orchestrator/tests/redteam.rs`, `docs/REDTEAM.md`)
- [x] AC-6 metrics as audit events, CSV + p50/p95, nightly job
      (`orchestrator/examples/handoff_metrics.rs`)
- [ ] Handoff state itself survives a restart *uncommitted* (rolls back, by
      design) and committed-unacked resumes — covered, but a target-side
      re-offer after the new owner dies is not implemented

### Phase 3 exit check

| AC | Meaning | Status |
|---|---|---|
| AC-1 | mid-run handoff, one owner, every step once | PASS |
| AC-2 | no owner-less interval in the audit timeline | PASS |
| AC-3 | a target that never readies rolls back at the timeout | PASS |
| AC-4 | the failure matrix | **5 of 8 rows** — see below |
| AC-5 | handoff red team RT-09..RT-14 | PASS |
| AC-6 | metrics recorded and reported | PASS |

AC-1, AC-2, AC-3, AC-5 and AC-6 pass. The exit check "task started on PC finishes
on phone" is claimable **for the PC-to-PC stand-in** used by the tests; the
phone shell itself is still Phase 3's unfinished Android work.

**AC-4 is not complete: 5 of 8 rows.** Covered: stale-epoch write from the old
owner (hub unit test), duplicate `SwitchCommit`, drop `SwitchCommit`, source
dies in Shadowing, target dies before commit, plus the non-idempotent effect in
flight (`non_idempotent.rs`). Not covered:

- kill the target **after** commit — there is no re-offer path for a task
  whose new owner dies;
- orchestrator restart mid-handoff — the durable store rolls an uncommitted
  handoff back and resumes a committed-unacked one, but a *target-side* ack
  lost across the restart has no recovery path.



## Phase 4: Character

- [ ] Three.js character with 5–6 states
- [ ] Transfer animation driven by orchestrator events
- [ ] Tauri 2 packaging for PC, then Android shell

## Phase 5: Security layer

- [x] Risk tiers enforced end-to-end
- [x] Signed tool calls verified by the receiving agent
- [x] Enrollment, key pinning, replay detection, API auth, WS hardening
- [ ] Keystore-backed approval flow on the phone
- [ ] Audit log exported to an append-only sink
- [ ] Mutual TLS for the agent↔orchestrator channel

### TODO — bind address is not configurable yet, but dev mode must stay local

`HIMAN_PORT` selects only the port; the orchestrator always binds `127.0.0.1`
(see `orchestrator/src/server.rs`). When a configurable bind address is added,
`HIMAN_INSECURE_DEV=1` MUST refuse any non-loopback address (anything other
than `127.0.0.1`, `::1`, or `localhost`) and exit with a clear error.

Reason: dev mode disables both the API token check and the enrollment
allowlist. If an operator can point that at a routable interface, an
unauthenticated tool-dispatch endpoint becomes reachable on the LAN. Fail
closed, exactly as the startup check does for a missing token.

Note that today's default already binds loopback-only, so this TODO is about
preserving that property when configurability arrives, not fixing a live hole.

## Phase 6: Red team and evaluation

- [x] Attack suite: reflection, nonce, takeover, fake orchestrator, replay,
      id collision, unauthenticated API, silent/oversized WebSocket
- [x] Measure attack success before and after defenses (`docs/REDTEAM.md`)
- [ ] Prompt injection, token theft, fake character
- [ ] Run demo scenarios repeatedly, record results
- [ ] Small user study

## Phase 7: Writing and defense

- [ ] Thesis draft, chapter by chapter
- [ ] Demo video
- [ ] Slides and rehearsal
