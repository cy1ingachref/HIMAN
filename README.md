# HIMAN

Secure Multi-Device AI Agent Orchestration — a zero-trust architecture for
autonomous cross-device task execution, with an embodied 3D character.

Student: Achref Ferjani (Ashe) — Network Systems Engineering, 3ISI-IRS, ISSATM
Repository: https://github.com/cy1ingachref/HIMAN
Phase: 1 — Foundation

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
| Android phone (Redmi Note 13) | agent + approvals + 3D view | Native Kotlin + Rust core (JNI) |
| Raspberry Pi / router | optional third device | Rust (`agent-pi`) |

No iOS. No Flutter.

## Layout

    proto/          shared message types, signing primitives
    orchestrator/   planner, policy engine, presence manager, state store
    agent-core/     tool trait, transport, LLM backend trait + stub
    agent-pc/       Windows PC agent
    app/desktop/    Tauri 2 shell + Three.js character
    app/android/    Native Kotlin app + Rust core
    docs/           architecture, protocol spec, threat model

## Build & test

    cargo build --workspace
    cargo test --workspace
    cargo clippy --workspace --all-targets -- -D warnings

## LLM backend

`agent-core::llm::ChatBackend` is a trait. The shipped implementation is a
deterministic scripted stub — no Ollama, no network, no API key required. Swap
in a real backend later by implementing the same trait.
