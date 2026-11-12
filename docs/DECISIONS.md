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

## Conventions

- Crate names use the `himan-` prefix; binary is `himan-agent-pc`.
- All user-visible commits use `cy1ingachref` as author.
- Tests are co-located in `#[cfg(test)]` modules, not `tests/` directories,
  because the types under test are small and private helpers matter.
- Every commit must leave the workspace in a state where
  `cargo test --workspace` and `cargo clippy --workspace --all-targets -- -D warnings`
  both pass.
