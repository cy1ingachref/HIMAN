# HIMAN — Security review (Phase 2 finalization)

Scope: the planner/Ollama path, API authentication and device enrollment,
the handoff/recovery protocol, and production networking posture. Every
finding below was checked against the actual code at the review commit;
reproductions are named tests, not descriptions.

Severity scale: Critical (remote code/ownership takeover with no
preconditions), High (same with a realistic precondition), Medium (limited
impact or narrow window), Low (hardening), Informational (posture note).

## Findings

### F-1 — HIGH (fixed): post-handshake messages were not signature-verified

- File/function: `agent-pc/src/client.rs`, `AgentClient::handle_once`.
- Scenario: the Welcome handshake verified the orchestrator's signature,
  but every later frame was dispatched without verification. Anything that
  can write to the socket after registration — a MITM on plain `ws://`, a
  hostile proxy, a compromised intermediate — could inject a `ToolCall`
  (the agent ran it and returned real device data), a `HandoffDrain`
  (stops the device's work), or a `HandoffCommit` (the device acknowledges
  ownership it was never granted).
- Evidence: with the fix reverted, `a_message_signed_by_another_key_is_dropped`
  fails with `ToolResult { task_id: t-injected, state: Succeeded, output:
  "pc-1: CPU …" }` — the injected call executed. The forged-commit test
  shows the acknowledgment.
- Fix: every post-Welcome message is verified against the orchestrator key
  — the out-of-band pin when configured, otherwise the key the Welcome
  signature proved (`session_orchestrator_key`). A frame that fails is
  dropped before any handler; the session stays alive.
- Tests: `client::tests::a_message_signed_by_another_key_is_dropped`,
  `client::tests::an_injected_handoff_commit_is_dropped` (RT-15).
  Mutation-checked: removing the verification makes both fail.
- Residual: without an out-of-band pin, the first Welcome is still
  trust-on-first-use (see F-6). The fix closes post-handshake injection,
  not initial impersonation.

### F-2 — MEDIUM (fixed): the driver accepted replies for another handoff

- File/function: `orchestrator/src/handoff_driver.rs`, `wait_for`.
- Scenario: the wait loop matched on payload kind only. A `HandoffReady`
  naming a different (older, aborted, or forged) handoff advanced the
  current procedure past prepare; a `HandoffSwitched` for another attempt
  could acknowledge a commit the target never made. The hub verifies
  signatures and seq before the driver sees a message, so the attacker
  must be a registered device — but a legitimate device replaying its own
  old replies (or a buggy one) hits this without any malice.
- Fix: `wait_for` drops any handoff reply whose `handoff_id` is not the
  current attempt's, then keeps waiting.
- Test: `handoff_driver::tests::a_ready_for_a_different_handoff_does_not_advance_this_one`
  (RT-16). Mutation-checked: removing the id check advances the procedure
  and the test fails.

### F-3 — MEDIUM (fixed): no device revocation

- File/function: `orchestrator/src/enrollment.rs`, `check_enrollment`.
- Scenario: enrollment is a static file read at startup. Removing a device
  from the file does not disconnect an already-registered session, and
  there is no revocation list; a compromised device key stays valid until
  the orchestrator restarts with a new file.
- Impact: a stolen device key cannot be cut off without a restart.
- Recommended fix (separate task): a revocation check on every message
  (or a watched enrollment file + session teardown), with an audit event.
  Not implemented here: it changes the enrollment lifecycle and needs its
  own design and tests.

### F-4 — MEDIUM (fixed): no API rate limiting or lockout

- File/function: `orchestrator/src/api_auth.rs`, `require_token`.
- Scenario: the token comparison is constant-time, but nothing limits
  failed attempts per source. An attacker who can reach the port can
  brute-force the token online. The WebSocket side has connection and
  invalid-message caps (`WsLimits`), the HTTP side has none.
- Impact: depends on token entropy and network exposure; the loopback
  bind (F-7) limits it today.
- Recommended fix (separate task): per-source failure counters with
  backoff/lockout, audited. Larger than a low-risk patch.

### F-5 — LOW (open): handoff replies are not bound to the epoch in the driver

- File/function: `orchestrator/src/handoff_driver.rs`, `commit_and_ack`.
- Scenario: after F-2, a reply must name this handoff, but the driver does
  not check `new_epoch` on `HandoffSwitched` against the epoch it committed.
  The hub's durable commit refuses a backwards epoch (RT-14), and the
  agent only answers a commit it received, so the window is narrow: a
  registered device sending a correctly-named but wrong-epoch ack.
- Recommended fix: compare `new_epoch` to `self.handoff.epoch + 1` in the
  ack predicate. Small, but it changes the driver's matching semantics;
  proposed as a follow-up with its own mutation check rather than bundled
  into this review's fixes.

### F-6 — LOW (posture): trust-on-first-use without a pin

- File/function: `agent-pc/src/main.rs`, `run_ws_with_reconnect`;
  `agent-pc/src/client.rs`, `register`.
- Scenario: without `HIMAN_ORCH_KEY`/`--orchestrator-key`, the agent
  accepts the key the first Welcome advertises (it logs a warning). A
  MITM present at first contact impersonates the orchestrator for the
  whole session. With a pin, RT-04 shows impersonation is refused.
- Status: documented and warned; the deployment requirement is "always
  pin". Not a code bug — the pin path exists and is tested.

### F-7 — INFORMATIONAL: loopback bind is the exposure boundary

- File/function: `orchestrator/src/server.rs`, `serve` — binds
  `127.0.0.1:{port}` only. There is no TLS/WSS listener. The service is
  not reachable off-host as shipped; exposing it requires a deliberate
  change (reverse proxy or a new bind), which is exactly the gate the
  project's "public exposure is a security gate" rule intends.
- Startup refuses to run without an API token and enrollment unless
  `HIMAN_INSECURE_DEV=1` is set explicitly (`startup.rs`, tested).

### F-8 — INFORMATIONAL: planner/Ollama trust boundary holds

Checked, no finding:
- Whitelist: `Hub::plan` refuses a non-whitelisted tool before the policy
  engine; mutation-checked (the exit test dispatches the unknown tool when
  the guard is removed).
- Schema: `validate_args` rejects wrong types, missing required, unknown
  args, non-objects, and unsupported schema keywords (rejected, not
  guessed). Tests cover each.
- Bounds: request/connect timeouts and a hard response byte cap enforced
  on the actual stream; oversized and slow responses are errors, tested.
- Malformed JSON is `Rejected`, never a panic; tested.
- Audit: `planner_proposed`, `planner_rejected`, `planner_error` are all
  written; the exit test asserts the order proposal → policy → result.
- Policy independence: `PolicyEngine::evaluate` takes only the `ToolCall`
  and `DeviceInfo`; prompt/result text is not an input. The injection test
  drives the real engine and the decision is unchanged.
- Credentials: the Ollama path carries no auth material; the API token is
  never logged (`require_token` logs the path only); the orchestrator
  prints only its PUBLIC key. `cargo audit` and the gitleaks scan are green.

### F-9 — INFORMATIONAL: handoff/recovery consistency holds under test

Checked, no finding beyond F-2/F-5:
- One owner: epoch fencing + the one-active-handoff guard (RT-13, 409).
- Replay: hub seq tracking (RT-05), agent nonce cache, stale-timestamp
  refusal on both sides.
- Crash consistency: durable audit hash chain verified at startup;
  uncommitted handoffs rolled back by recovery and audited durably
  (the restart_mid_shadowing fix); task records restored. 360-run sweep:
  0 rollbacks, 0 owner gap, 0 replay lag.
- The checkpoint is the orchestrator's own log head, never client-supplied
  (`hub.rs`, DECISIONS).

## What this review does NOT claim

A green suite is not proof of complete security. Not covered: formal
protocol verification, fuzzing of the wire parser, side channels beyond
the constant-time token compare, supply-chain audit of dependencies beyond
`cargo audit`, and any test under real packet loss or concurrent load.
TLS, revocation, rate limiting and token rotation are MISSING features,
not existing protections — see docs/PRODUCTION.md.


## Fixes applied after the review (RT-17/18/19)

- F-3 (device revocation) FIXED: POST /api/v1/devices/:id/revoke writes a
  durable `revoked` table row plus a hash-chained `device_revoked` audit
  event, drops the live session, and refuses future Hellos and messages.
  Revocations load at startup before any agent registers. Evidence:
  `revocation.rs` (2) + `revocation_e2e.rs` (1, real binaries), mutation-checked.
- F-4 (HTTP rate limiting) FIXED: `RateLimiter` throttles failures per source
  IP and per presented token (SHA-256 keyed), 10 failures lock for 60 s,
  each map capped at 4096 with oldest-first eviction. Evidence:
  `rate_limit.rs` (4), mutation-checked.
- TLS/WSS (PRODUCTION.md item 1) PARTIALLY CLOSED: the agent now refuses
  plain ws:// unless compiled with `insecure-ws-dev` in a debug build; a CI
  guard greps the release binary for the escape hatch. The orchestrator
  validates HIMAN_TLS_CERT/KEY PEM material and refuses to serve plain HTTP
  without HIMAN_INSECURE_DEV. TERMINATION is still delegated to a TLS
  reverse proxy — native rustls listeners on the orchestrator are NOT
  implemented. Evidence: `tls_guard.rs` (2) + CI release-binary grep,
  mutation-checked.
