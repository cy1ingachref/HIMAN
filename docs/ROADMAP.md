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
- [ ] Presence manager + signed handoff tokens over the wire
- [ ] Secure mesh (Tailscale/WireGuard/Headscale)
- [ ] Exit check: task started on PC finishes on phone

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
