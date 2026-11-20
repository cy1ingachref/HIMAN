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
| 15 | Full workspace suite green | [x] | 304 passed, 0 failed, 0 ignored; fmt + clippy -D warnings clean |

## Honest limits (not exit blockers, but stated)

- The suite is not proof of complete security: no fuzzing, no formal
  protocol verification, no loss/concurrency measurement (see
  SECURITY_REVIEW "does NOT claim").
- TLS, revocation, rate limiting, token rotation are MISSING — Phase 2
  exits with them documented as the next phase's blockers, not done.
- The planner executes one call; multi-step is a proposal only.
- One CI flake observed: `durable_audit::audit_entries_survive_a_restart`
  timed out on a 60 s health wait in run 44587040931's per-commit job
  (the metrics job in the same run was green). It passes locally and in
  run 44573834587. Treated as runner slowness, not a code regression;
  flagged for a retry rather than hidden.
