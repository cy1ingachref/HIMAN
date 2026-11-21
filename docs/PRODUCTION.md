# HIMAN — Production networking readiness

What exists today, what is missing, and what must happen before HIMAN
crosses an untrusted network. Nothing here claims a protection that is
not implemented and tested.

## Existing protections (implemented + tested)

| Protection | Where | Evidence |
|---|---|---|
| Loopback-only bind | `server.rs::serve` binds `127.0.0.1` | no off-host listener exists |
| Fail-closed startup | `startup.rs::enforce_startup` | refuses without API token + enrollment unless `HIMAN_INSECURE_DEV=1`; unit tests |
| Bearer-token API auth | `api_auth.rs` | constant-time compare (SHA-256 + subtle); `production_router` test: every route 401 without/with-wrong token |
| Device enrollment | `enrollment.rs` | unknown device + key mismatch refused; RT-03/RT-11 |
| Signed envelopes | `proto/envelope.rs` | every hub message verified; agent verifies every post-Welcome message (RT-15) |
| Plain ws:// refused by default | `agent-pc::connect_ws` | RT-19; release-binary CI guard |
| Device revocation | `durable.rs::revoked`, Hub::revoke_device | RT-18 (real binaries, restart) |
| HTTP rate limiting | `api_auth::RateLimiter` | RT-17 (4 tests, bounded memory) |
| Orchestrator key pinning | `agent-pc` `HIMAN_ORCH_KEY` | RT-04 fake orchestrator refused |
| Replay protection | hub seq tracking, agent nonce cache, stale-ts | RT-05; agent tests |
| Handoff token binding | target + task + expiry | RT-10/RT-12 |
| One owner / epoch fencing | `ownership.rs`, durable commit | RT-13/RT-14; 360-run sweep 0 owner gap |
| WS abuse caps | `WsLimits` | handshake/idle timeouts, frame size, connection cap, invalid-message cap; RT-08 |
| Audit hash chain | `durable.rs` | tamper refused at startup; durable_audit tests |
| Secret hygiene | gitleaks CI + `cargo audit` | green; token never logged |

## Missing features (NOT implemented — do not claim these)

1. **TLS / WSS.** The transport is plain `ws://` and HTTP. There is no
   TLS listener, no certificate handling, no `wss://` support. On an
   untrusted network the signatures prove authenticity but NOT
   confidentiality: tool args, results, device status and audit content
   are readable by any observer. Required: a TLS terminator (reverse
   proxy with a real certificate) or native rustls listeners on both
   ends, plus `wss://` in the agent URL. Until then, HIMAN is
   loopback-only by design.
2. **Token rotation.** `HIMAN_API_TOKEN` is a static pre-shared secret.
   No rotation endpoint, no overlap window, no per-client tokens. A
   leaked token is valid until the operator changes the env and restarts.
3. ~~**Device revocation.**~~ CLOSED (RT-18): durable revocation, live
   session drop, restart-persistent deny-list.
4. ~~**Rate limiting / lockout on the HTTP API.**~~ CLOSED (RT-17): per-IP
   and per-token bounded lockout implemented.
5. **Enrollment transport security.** The enrollment file is provisioned
   out of band; there is no authenticated enrollment protocol, so the
   initial key exchange relies on the operator copying keys safely.
6. **Audit-data exposure control.** `/api/v1/audit` returns the full log
   to any valid token holder. Fine for a single operator; needs
   scoping/redaction before multi-tenant or shared-token use.

## Deployment gate (current, enforced by convention + bind)

HIMAN today is safe to run ONLY on loopback or a trusted private network
segment. Before any untrusted-network use, in order:

1. TLS/WSS termination with a verified certificate (blocker).
2. Always pin the orchestrator key on every agent (`HIMAN_ORCH_KEY`).
3. High-entropy API token, provisioned out of band, never committed.
4. Enrollment file provisioned out of band; revocation is implemented
   (RT-18) and must be exercised operationally.
5. ~~Rate limiting + lockout on the API.~~ CLOSED (RT-17).
6. Decide audit-log access scope.

Remaining hard blocker: item 1. The agent now refuses plain ws:// by
default and a CI guard keeps the release binary free of the dev escape
hatch, but actual termination still sits with a reverse proxy. The rest
is operational practice. This list is the input to the next phase's
networking work, not a claim that any of it is done.
