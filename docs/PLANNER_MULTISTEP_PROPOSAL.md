# Proposal: bounded multi-step planner execution (NOT implemented)

Status: design proposal + test plan. The planner today executes only the
FIRST proposed tool call (`Hub::plan` -> one dispatch). This document
specifies what a multi-step executor must have before any of it is built.
Per the task rules, no autonomous multi-step execution is implemented
here.

## Is single-call sufficient for the next phase?

For Phase 3 (phone + handoff) yes: the acceptance criteria are about
moving ONE task between devices, and every handoff test drives a single
deterministic task. Multi-step autonomy is a Phase 4 concern. Building it
now would add an unbounded execution surface before the networking gate
(TLS, revocation, rate limiting) is closed. Recommendation: keep
single-call through Phase 3; design multi-step now, build it after the
networking blockers.

## Required properties (each is a gate, not a nice-to-have)

1. **Explicit execution limits.** A plan carries `max_steps` (hard cap,
   default small, e.g. 5) and `max_wall_ms`. The executor refuses a plan
   that exceeds either; the cap is enforced per step, not just at parse.
2. **Per-step policy checks.** Every step is a fresh `ToolCall` through
   `PolicyEngine::evaluate`. A plan is never approved as a whole; an
   Allow on step 1 says nothing about step 2. The model cannot carry an
   approval forward.
3. **Approval for risky tools.** A Destructive step pauses the plan at
   `AwaitingApproval` and resumes only on an explicit human decision
   (the phone approval path). No auto-approval, no timeout-approval.
4. **Cancellation and timeout.** A plan can be cancelled by the user or
   the orchestrator; cancellation stops before the next step and is
   audited. Each step has its own timeout; a hung tool fails the step,
   not the whole executor.
5. **Durable progress tracking.** Each step's proposal, decision, result
   and the plan's cursor are persisted (the existing `task_records` /
   event log machinery) BEFORE the next step starts, so a crash resumes
   at a known position rather than re-running or skipping.
6. **Recovery after partial execution.** On restart, a plan with a
   persisted cursor resumes at the next unexecuted step; a step whose
   result is Unknown (non-idempotent, in flight at crash) is NOT retried
   automatically — it surfaces for a decision, exactly like the AC-4
   non-idempotent rule.
7. **Audit for every step.** `plan_step_proposed`, `plan_step_policy`,
   `plan_step_result`, `plan_cancelled`, `plan_completed`, each naming
   the plan id and step index. The trail must distinguish proposed from
   executed.

## Trust boundary (unchanged from single-call)

The model proposes; it never decides. Every proposed step goes through
the same whitelist + schema validation (`Hub::plan`'s checks) and the
same policy engine. A plan is a list of UNTRUSTED proposals, not an
authorization. Prompt injection in a tool result cannot alter a later
step's policy decision, because the decision's inputs are the ToolCall
and DeviceInfo only.

## Test plan (write these BEFORE the executor)

- `plan_over_max_steps_is_refused` — a 6-step plan against a cap of 5
  never dispatches step 6; mutation: remove the cap -> fails.
- `each_step_is_policy_checked` — step 2 is Destructive on an uncleared
  device; step 1 Allow does not let step 2 run; mutation: check once ->
  fails.
- `destructive_step_pauses_for_approval` — no phone approval, the plan
  parks at AwaitingApproval and does not advance.
- `cancel_stops_before_the_next_step` — cancel mid-plan; the in-flight
  step finishes, the next never starts; audited.
- `step_timeout_fails_the_step_not_the_executor` — a hung tool times
  out; the plan records the failure and stops cleanly.
- `restart_resumes_at_the_cursor` — kill the orchestrator after step 2's
  result is persisted; restart resumes at step 3, steps 1-2 not re-run.
- `unknown_non_idempotent_step_is_not_retried` — crash with a
  non-idempotent step in flight; restart surfaces Unknown, no auto-retry.
- `injection_in_a_result_does_not_change_a_later_decision` — a tool
  result carrying injection text; step N+1's policy decision is
  identical to the clean run.
- `every_step_is_audited_in_order` — the audit trail has proposal ->
  policy -> result per step, with plan id and index.

## Open design questions (decide before building)

- Plan representation: a single task with a step cursor, or a parent
  task with child tasks? The handoff machinery moves ONE task; a plan
  that handoffs mid-execution must move the cursor with it.
- Where the executor lives: orchestrator-side (policy is there) vs
  agent-side (tools are there). Recommendation: orchestrator drives,
  agent executes one step at a time — same shape as the scenario loop,
  so handoff/recovery reuse the existing path.
- Approval UX on the phone (Phase 3 dependency).
