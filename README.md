# HIMAN

Secure Multi-Device AI Agent Orchestration — a zero-trust architecture for
autonomous cross-device task execution, with an embodied 3D character.

Repository: https://github.com/cy1ingachref/HIMAN
Phase: 1 — Foundation (complete, 144 tests)

## What this is

An AI agent that follows the user across devices they own. The agent has no
device-bound identity: memory, tasks and permissions live on a central
orchestrator, and each device runs a small agent that exposes what that device
can do. A 3D shape character moves visibly between devices so the handoff is
understandable. The research contribution is making that safe.

## Device set (frozen, Phase 0)

| Device | Role | Shell |
|---|---|---|
| Windows PC | orchestrator host + agent + 3D view | Rust (`agent-pc`) + Tauri 2 + Three.js |
| Android phone | agent + approvals + 3D view | Native Kotlin + Rust core (JNI) |
| Raspberry Pi / router | optional third device | Rust (`agent-pi`) |

No iOS. No Flutter.

## Layout

    proto/          shared message types, signing primitives
    orchestrator/   planner, policy engine, presence manager, state store
    agent-core/     tool trait, transport, LLM backend trait + stub
    agent-pc/       Windows PC agent
    app/desktop/    Tauri 2 shell + Three.js character
    app/android/    Native Kotlin app + Rust core
    docs/           architecture, protocol spec, red-team log, decisions

## Build & test

    cargo build --workspace
    cargo test --workspace
    cargo clippy --workspace --all-targets -- -D warnings

Test layers:

| Layer | Location | What it proves |
|---|---|---|
| Unit | `#[cfg(test)]` modules | types and helpers |
| Integration | `orchestrator/tests/integration.rs` | in-process round trip |
| Red team | `orchestrator/tests/redteam.rs` | each named attack is refused |
| End to end | `orchestrator/tests/e2e.rs` | the real binaries work together |
| Logging | `orchestrator/tests/logging.rs` | logs appear without `RUST_LOG` |

## Running it

    # terminal 1: orchestrator
    HIMAN_PORT=8787 HIMAN_ORCH_KEY_FILE=./orchestrator.key \
    HIMAN_ENROLLED_FILE=./enrolled.json cargo run -p himan-orchestrator

    # terminal 2: agent
    cargo run -p himan-agent-pc -- --ws ws://127.0.0.1:8787/ws \
        --orchestrator-key <public key printed by the orchestrator>

`enrolled.json` maps device id to the agent's public key. Generate it with
`himan-agent-pc keygen --out ./agent.key` and copy the printed public key.
See `docs/PROTOCOL.md` for every configuration variable.

## Security model

Every message is Ed25519-signed over meta and payload. Devices are enrolled by
public key, the orchestrator key is pinned by the agent, and every defense is a
named test in `docs/REDTEAM.md`:

| Attack | Defense |
|---|---|
| Handshake reflection | registration requires a `Welcome` |
| Wrong nonce | nonce-bound handshake |
| Identity takeover | enrollment + session key check |
| Fake orchestrator | pinned orchestrator key |
| Tool result replay | per-device `seq` tracker |
| Task id collision | uuid v4 ids |
| Unauthenticated API | constant-time bearer token |
| Silent / oversized socket | timeout, size cap, connection limit |

Key material is never committed, logged or printed. Only public keys are.

## LLM backend

`agent-core::llm::ChatBackend` is a trait. The shipped implementation is a
deterministic scripted stub — no Ollama, no network, no API key required. Swap
in a real backend later by implementing the same trait.

## CI

fmt, clippy, unit + integration tests, end-to-end with the real binaries,
`cargo audit`, and a gitleaks secret scan. Third-party actions are pinned by
commit SHA; Dependabot updates the pins.
