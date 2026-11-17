# HIMAN

Secure Multi-Device AI Agent Orchestration — a zero-trust architecture for
autonomous cross-device task execution, with an embodied 3D character.

Repository: https://github.com/cy1ingachref/HIMAN
Phase: 3 — Phone and handoff (in progress, 275 tests)

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
    orchestrator/   planner, policy engine, presence manager, state store,
                    durable SQLite state, handoff driver
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
| End to end | `orchestrator/tests/*.rs` | the real binaries work together |
| Handoff acceptance | `orchestrator/tests/{ac1_happy_path,ac2_ac3,ac4_matrix}.rs` | AC-1/AC-2/AC-3, the failure matrix |
| Durability | `orchestrator/tests/{durability,durable_audit,stalled_owner,stalled_pending,non_idempotent}.rs` | restarts, the audit chain, dead owners |
| Logging | `orchestrator/tests/logging.rs` | logs appear without `RUST_LOG` |

Fault-injection hooks are compiled only under agent-pc's `fault-injection`
feature (off by default) and CI fails if any hook name appears in the release
binary.

## Durability

Set `HIMAN_STATE_FILE=/path/to/state.db` to persist owner, epoch, event log,
handoff state and the audit log in SQLite (WAL). Unset means in-memory only.
On startup the audit chain is verified; a broken chain refuses to start unless
`HIMAN_ALLOW_AUDIT_RECOVERY=1` is set, which is recorded. See
`docs/HANDOFF.md` sections 13 and 14.

## Running it

The orchestrator fails closed: it will not start without both an API token and
an enrollment file. For local development only, `HIMAN_INSECURE_DEV=1` overrides
that check and logs a loud warning for each missing protection.

    # terminal 1: orchestrator
    HIMAN_PORT=8787 \
    HIMAN_ORCH_KEY_FILE=./orchestrator.key \
    HIMAN_ENROLLED_FILE=./enrolled.json \
    HIMAN_API_TOKEN=$(openssl rand -hex 32) \
        cargo run -p himan-orchestrator

    # terminal 2: agent
    cargo run -p himan-agent-pc -- --ws ws://127.0.0.1:8787/ws \
        --orchestrator-key <public key printed by the orchestrator>

`enrolled.json` maps device id to the agent's public key. Generate it with
`himan-agent-pc keygen --out ./agent.key` and copy the printed public key.
See `docs/PROTOCOL.md` for every configuration variable.

The agent sends a signed keepalive `Ping` every `HIMAN_KEEPALIVE_SECS`
(default 60, well below the orchestrator's 300s idle timeout) and reconnects if
the orchestrator stops answering.

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
