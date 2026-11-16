# HIMAN — Decisions log

One row per decision. Newest at the bottom. Keep it short; the reasoning
matters more than the prose.

| Date | Decision | Reason | Alternatives considered |
|---|---|---|---|
| 2026-11-12 | Device set frozen: PC (Windows) + Android phone, optional Pi/router | Two devices prove handoff; a third is scope creep | iOS, "all devices", Flutter |
| 2026-11-12 | No Flutter. Phone shell is native Kotlin + Rust core | Flutter adds a full framework for a thin shell; Kotlin gives direct Keystore/foreground-service access | Flutter (user rejected), Tauri mobile (immature) |
| 2026-11-12 | No Ollama. Pluggable `ChatBackend` trait + deterministic stub | De-risks the pipeline without a model download; real backend swaps in later | Ollama local model (user rejected) |
| 2026-11-12 | Rust workspace: `proto`, `agent-core`, `orchestrator`, `agent-pc` | Shared protocol crate keeps wire types in one place | Python, single crate |
| 2026-11-12 | Ed25519 signatures over canonical JSON (meta + payload) | Simple, no PKI, verifies tampered envelope and payload | RSA (heavier), HMAC (shared secret, no device identity) |
| 2026-11-12 | Policy engine is a plain struct, not a trait | Phase 1 needs one policy; trait indirection adds nothing yet | Trait-based engine |
| 2026-11-12 | In-memory state store, interface shaped for SQLite | Phase 1 has no persistence requirement; swapping later is cheap | sqlx from day one |
| 2026-11-12 | Hash-chained in-memory audit log | Tamper evidence is a core claim; the chain is testable now | Plain append-only Vec |
| 2026-11-12 | `run_diagnostic` marked Destructive even though Phase 1 is read-only | Exercises the approval path honestly instead of pretending it is not needed | Marking it Reversible |
| 2026-11-12 | Rust toolchain: MSVC host, VS Build Tools 2022 present | Verified `cargo build` links; no MinGW needed | GNU target (no gcc on PATH) |
| 2026-11-12 | Socket transport splits sink and stream, each with its own lock | One shared mutex let the read pump block `send()` forever; a parked reader must never block a writer | A single mutex, a pump channel |
| 2026-11-12 | Handshake requires a `Welcome`, nonce-bound and signed | Any reply counting as success made a transport echo look like registration | Accepting the first reply |
| 2026-11-12 | Nonce-bound Welcome + pinned orchestrator key | A fake orchestrator could otherwise sign its own Welcome | Trusting the key the Welcome advertises |
| 2026-11-12 | Enrollment file maps device id → public key | Stops identity takeover: without it any key can claim any id | Trust-on-first-use, which is defeated by a race |
| 2026-11-12 | Agent and orchestrator keys persist to files | A fresh key per run breaks enrollment and pinning | Regenerating per run |
| 2026-11-12 | Task ids are uuid v4, tool-call nonces are random 64-bit | A timestamp-derived id collides within the same second, breaking the audit trail | Timestamp ids |
| 2026-11-12 | Per-device `seq` tracker rejects replays | A captured signed `ToolResult` could be replayed | Nonce-only replay protection |
| 2026-11-12 | HTTP API requires a constant-time bearer token | The API dispatched tool calls to every enrolled device with no auth | No auth, or a timing-vulnerable comparison |
| 2026-11-12 | WebSocket limits: handshake timeout, frame cap, connection semaphore, invalid-message budget | A silent or oversized connection holds a task and a socket indefinitely | No limits |
| 2026-11-12 | CI actions pinned by SHA; audit + gitleaks + dependabot | A moved tag would run arbitrary code in CI | Floating tags |
| 2026-11-16 | Handoff checkpoint is the orchestrator's own event-log head; a client-supplied `applied_seq` is accepted on the wire but ignored | A handoff is a request to move a task, not a request to pick the log prefix the target applies. A caller that could set the position could commit below the real head (dropping steps) or above it (stalling the switch). Only the orchestrator's append-only log is authoritative | Trust the caller's `applied_seq`; reject the request outright (breaks existing clients) |
| 2026-11-16 | A drained source is barred from starting new steps; the scenario loop parks until the commit clears the drain, then resumes on the new owner | AC-1 requires the source to be drained *and* the target to run the remaining steps. Without the bar, the source keeps issuing steps after the switch; without the park-then-resume, the target never runs anything | Let both devices race; stop the source only after the commit |
| 2026-11-16 | The handoff driver's `wait_for` skips `ToolResult` and `Pong`, but reports any other unexpected reply | A mid-task device keeps sending tool results during the handoff, so treating one as a refusal broke AC-1. Swallowing *everything* would hide a genuinely wrong reply | Treat every interleaved message as fatal; skip all messages |
| 2026-11-16 | A device's inbound messages are a `broadcast` channel the handoff driver subscribes to; the receiver is never taken away from the socket handler | `take_inbound` removed the receiver, so every agent reply during a handoff was dropped — the driver could never see `HandoffReady` or `HandoffDrained`, and a real handoff could not complete | Keep a single `mpsc` receiver and hand it to the driver (broken: replies lost); poll a shared `Vec` (adds locking, still one consumer) |
| 2026-11-16 | A failed handoff rolls the recorded attempt back and clears the drain, so the source keeps the task at its old epoch and stays usable | Without it a timed-out target left the source drained and the task without a usable owner, which is a worse state than no handoff at all | Leave the attempt `Failed` and hope the caller retries; only roll back on an explicit request |
| 2026-11-16 | A lagging inbound subscription is reported (`Reply::Lagged(n)`, audit `inbound_lagged`), not skipped | A lag means the driver cannot prove it saw every reply. Skipping it silently hides the exact evidence a handoff failure needs | Skip and continue (the old behaviour); treat it as a timeout |
| 2026-11-16 | Fault injection (`HIMAN_TEST_NEVER_READY`) is compiled only under agent-pc's `fault-injection` feature, off by default; the feature build uses its own `CARGO_TARGET_DIR` | A production binary must not contain a switch that makes a device refuse to answer a handoff. Cargo features are additive and share one artifact path, so a separate target dir is what makes the two builds genuinely distinct | Leave the hook in the default build behind an env var (rejected: reachable in production); ship a second binary name (rejected: two code paths to keep in sync) |

## Conventions

- Crate names use the `himan-` prefix; binary is `himan-agent-pc`.
- All user-visible commits use `cy1ingachref` as author.
- Unit tests are co-located in `#[cfg(test)]` modules. Integration, red-team
  and end-to-end tests live in `orchestrator/tests/`, because they exercise
  public API and real binaries rather than private helpers.
- Every commit must leave the workspace in a state where
  `cargo test --workspace` and `cargo clippy --workspace --all-targets -- -D warnings`
  both pass.
- A defense for a red-team finding is not done until the named RT test passes
  and the before/after output is recorded in `docs/REDTEAM.md`.
