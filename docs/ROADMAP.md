# HIMAN — Roadmap

Status of each phase. Mark a phase done only when its exit check passes.

## Phase 0: Planning — DONE 2026-11-12

- [x] Device set frozen (PC + Android, optional Pi/router)
- [x] LLM approach chosen (pluggable backend + stub)
- [x] Repository created: `cy1ingachref/HIMAN`
- [x] Workspace skeleton, 4 crates
- [ ] Supervisor, deadline, exact PFE duration — still TBD (user side)

## Phase 1: Foundation — IN PROGRESS

- [x] `proto` crate: message types, signing, envelope — 17 tests
- [x] `agent-core`: Tool trait + registry with whitelist — 7 tests
- [x] `agent-core`: `ChatBackend` trait + `ScriptedBackend` stub — 9 tests
- [x] `orchestrator`: policy engine — 10 tests
- [x] `orchestrator`: presence manager + handoff tokens — 9 tests
- [x] `orchestrator`: state store — 6 tests
- [x] `orchestrator`: hash-chained audit log — 7 tests
- [x] `agent-pc`: real `device_status` + `run_diagnostic` tools — 9 tests
- [x] `agent-pc`: demo loop prompt → tool call → result (verified by running)
- [ ] WebSocket hub: orchestrator accepts agent connections
- [ ] Exit check: a script triggers a tool call end-to-end over the wire

## Phase 2: Agent loop

- [ ] Tool schemas + registry exposed over the wire
- [ ] Real LLM backend (Ollama or cloud) behind `ChatBackend`
- [ ] Task state machine persisted (SQLite)
- [ ] Exit check: text prompt becomes a tool call and a result, with persistence

## Phase 3: Phone and handoff

- [ ] Android app shell: foreground service, Keystore, push wake-up
- [ ] Phone tools: `device_status`, `request_approval`, `list_files`,
      `upload_file`, `show_notification`
- [ ] Presence manager + signed handoff tokens over the wire
- [ ] Exit check: task started on PC finishes on phone

## Phase 4: Character

- [ ] Three.js character with 5–6 states
- [ ] Transfer animation driven by orchestrator events
- [ ] Tauri 2 packaging for PC, then Android shell

## Phase 5: Security layer

- [ ] Risk tiers enforced end-to-end (not just in the engine)
- [ ] Signed tool calls verified by the receiving agent
- [ ] Keystore-backed approval flow on the phone
- [ ] Audit log exported to an append-only sink

## Phase 6: Red team and evaluation

- [ ] Attack suite: prompt injection, token theft, device impersonation,
      fake character
- [ ] Measure attack success before and after defenses
- [ ] Run demo scenarios repeatedly, record results
- [ ] Small user study

## Phase 7: Writing and defense

- [ ] Thesis draft, chapter by chapter
- [ ] Demo video
- [ ] Slides and rehearsal
