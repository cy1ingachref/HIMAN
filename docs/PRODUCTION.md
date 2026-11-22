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
| Pairing / enrollment codes | `enrollment_codes.rs`, `/api/v1/enroll/redeem` | RT-22 (single-use, hash-only, audited) |
| API token rotation | `token_store.rs`, `/api/v1/admin/token` | RT-23 (grace window, durable, audited) |
| HTTP rate limiting | `api_auth::RateLimiter` | RT-17 (4 tests, bounded memory) |
| Orchestrator key pinning | `agent-pc` `HIMAN_ORCH_KEY` | RT-04 fake orchestrator refused |
| Replay protection | hub seq tracking, agent nonce cache, stale-ts | RT-05; agent tests |
| Handoff token binding | target + task + expiry | RT-10/RT-12 |
| One owner / epoch fencing | `ownership.rs`, durable commit | RT-13/RT-14; 360-run sweep 0 owner gap |
| WS abuse caps | `WsLimits` | handshake/idle timeouts, frame size, connection cap, invalid-message cap; RT-08 |
| Audit hash chain | `durable.rs` | tamper refused at startup; durable_audit tests |
| Secret hygiene | gitleaks CI + `cargo audit` | green; token never logged |

## Missing features (NOT implemented — do not claim these)

1. ~~**TLS / WSS.**~~ CLOSED (RT-21): the orchestrator terminates TLS
   natively (HIMAN_TLS_CERT / HIMAN_TLS_KEY) and the agent connects over
   `wss://`, verifying the server certificate against HIMAN_TLS_CA_PEM.
   Plain HTTP/WS is refused unless HIMAN_INSECURE_DEV=1. A reverse proxy is
   now an optional deployment choice, not a requirement.
2. ~~**Token rotation.**~~ CLOSED (RT-23): POST /api/v1/admin/token rotates
   without a restart, with a bounded grace window, audit, and durable
   persistence. Per-client tokens remain out of scope.
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
4. ~~Enrollment file provisioned out of band.~~ Pairing codes are implemented
   (RT-22); the static file remains a fallback path, so keep it out of band
   and exercise revocation (RT-18) operationally.
5. ~~Rate limiting + lockout on the API.~~ CLOSED (RT-17).
6. Decide audit-log access scope.

No hard blockers remain: TLS termination, device revocation and API rate
limiting are all closed and mutation-checked. What is still not
production-ready: static API token with no rotation, no audit-log access
scoping decision, and enrollment is still an out-of-band file. This list is
operational practice, not a claim that the networking phase is done.
