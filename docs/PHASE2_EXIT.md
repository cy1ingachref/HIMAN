# HIMAN — Phase 2 exit checklist

Each item lists the evidence (test, run, or file) that supports it. An
item is checked only when the evidence exists and was actually run.

| # | Criterion | Status | Evidence |
|---|---|---|---|
| 1 | Tool schemas + registry exposed over the wire | [x] | `ToolRegistry::schemas` sent as function tools in `Hub::plan`; `ollama_backend` tests |
| 2 | Real LLM backend behind `ChatBackend` | [x] | `agent-core/src/ollama.rs`; 7 fake-Ollama HTTP tests (valid, malformed, unknown tool, schema, oversized, slow, injection) |
| 3 | Model output is untrusted: whitelist + schema before policy | [x] | `Hub::plan`; `planner_exit::a_malicious_model_answer_is_refused_before_execution`; mutation-checked (guard removed -> unknown tool dispatched) |
| 4 | Prompt -> tool call -> result with audit trail | [x] | `planner_exit::a_natural_language_prompt_becomes_a_tool_call_and_a_result` (real binaries + fake Ollama); audit order planner_proposed -> tool_call_policy -> tool_result asserted |
| 5 | Task state machine persisted (SQLite) | [x] | `task_records` table; `durability::task_state_args_and_output_survive_a_restart`; mutation-checked |
| 6 | Startup recovery rolls back + audits durably | [x] | `durability::restart_mid_shadowing...` requires the recovery reason; 12.3-13.4 s; mutation-checked |
| 7 | Production router: every route exists + requires auth | [x] | `production_router` (3 tests); mutation-checked both ways (drop /record, remove auth layer) |
| 8 | One active handoff per task (409) | [x] | RT-13 + `one_active_handoff_http`; guard mutation-checked |
| 9 | Post-handshake message authentication | [x] | RT-15 (2 tests); mutation-checked — injected ToolCall ran before the fix |
| 10 | Handoff replies bound to the attempt | [x] | RT-16; mutation-checked |
| 11 | Metrics sweep reproducible + recorded | [x] | run 44587040931, 360 runs, `docs/data/handoff-metrics-44587040931.csv`, `docs/METRICS.md` comparison vs baseline |
| 12 | Security review with ranked findings | [x] | `docs/SECURITY_REVIEW.md` (F-1..F-9); 2 fixed + mutation-checked, rest documented |
| 13 | Production networking posture explicit | [x] | `docs/PRODUCTION.md` — existing vs missing, TLS/revocation/rate-limit named as NOT implemented |
| 14 | Multi-step planner: design before code | [x] | `docs/PLANNER_MULTISTEP_PROPOSAL.md` — gates + test plan, NOT implemented |
| 15 | Full workspace suite green | [x] | 313 passed, 0 failed, 0 ignored; fmt + clippy -D warnings clean |
| 16 | Hard blockers closed (rate limit, revocation, TLS default) | [x] | RT-17/18/19 each red-first, mutation-checked; CI run 44843418351 all six jobs green |
| 17 | Restart flake root-caused and proven | [x] | SO_REUSEADDR + fail-fast health wait; dedicated x20 job green 20/20 in CI run 44843418351 |

## Honest limits (not exit blockers, but stated)

- The suite is not proof of complete security: no fuzzing, no formal
  protocol verification, no loss/concurrency measurement (see
  SECURITY_REVIEW "does NOT claim").
- TLS, revocation, rate limiting, token rotation are MISSING — Phase 2
  exits with them documented as the next phase's blockers, not done.
- The planner executes one call; multi-step is a proposal only.
- The durable_audit CI flake was NOT runner slowness: the restarted child's
  stderr showed `Address already in use (os error 98)` — a plain bind failed
  over lingering TIME_WAIT sockets and the health wait polled a dead process
  for 60 s. Fixed with SO_REUSEADDR + fail-fast health wait; a dedicated
  job now runs the test 20 consecutive times in CI (20/20 green in run
  44843418351).
- Native TLS termination (RT-21) and the port-hijack guard (RT-20) closed
  the remaining blockers; see the RT-20/RT-21 rows in REDTEAM.md.
- Pairing codes (RT-22) close the out-of-band enrollment gap; the static
  file remains a fallback.
- Token rotation is implemented (RT-23); per-client tokens remain out of
  scope.
- Still not production-ready: no audit-log access scoping.
