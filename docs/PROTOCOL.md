# HIMAN — Protocol specification

This is the contract between the orchestrator and device agents. Everything
here is implemented and tested; `docs/REDTEAM.md` records the attacks each
defense defeats.

## Envelope

Every message is a `WireMessage`:

```rust
pub struct WireMessage {
    pub meta: WireMeta,
    pub payload: Payload,
    pub signature: String,
}

pub struct WireMeta {
    pub seq: u64,          // monotonic per sender, replay-checked
    pub ts: i64,           // unix seconds, staleness-checked
    pub from: DeviceId,
    pub to: String,        // "orchestrator" or a DeviceId
}
```

## Signing

Signature is Ed25519 over:

```
canonical_json(meta) || b"|" || canonical_json(payload)
```

`canonical_json` is `serde_json::to_vec` (compact, no whitespace, struct field
order preserved). The separator `|` prevents ambiguity between meta and
payload boundaries.

The `meta` is signed because `seq`, `ts`, `from` and `to` are all
security-relevant. An attacker who can rewrite `from` can impersonate another
device; one who can rewrite `seq` can reorder or replay messages.

## Registration

```
agent                                    orchestrator
  │  Hello { DeviceInfo, nonce }           │
  │ ─────────────────────────────────────► │
  │                                        │  enroll: id known? key matches?
  │                                        │  takeover: id already connected?
  │                                        │  signature verifies?
  │  Welcome { device_id, nonce,           │
  │            orchestrator_key }          │
  │ ◄───────────────────────────────────── │
  │  pinned_key == orchestrator_key?       │
  │  signature verifies with pinned_key?   │
  │  nonce matches this attempt?           │
```

Every step is enforced, and each failure has its own error:

| Failure | Error | Test |
|---|---|---|
| Server echoes our Hello | `UnexpectedReply` | RT-01 |
| Welcome nonce differs | `NonceMismatch` | RT-02 |
| Device not in enrollment file | `Policy` | RT-03 |
| Hello key ≠ enrolled key | `Policy` | RT-03 |
| Different key on a connected id | `Policy` | RT-03 |
| Welcome key ≠ pinned key | `NotPinnedKey` | RT-04 |
| Signature invalid | `BadSignature` | — |

A reconnect with the same enrolled key replaces the session and closes the old
socket. A reconnect with a different key is rejected and the legitimate
session is left untouched.

## Replay and ordering

The orchestrator keeps the last accepted `seq` per device. A message whose
`seq` is not strictly greater is rejected as a replay and audited as
`message_rejected`. The tracker is reset on registration because the agent's
counter restarts on reconnect.

Messages whose timestamp is more than `max_skew_secs` (default 120s) from the
server clock are rejected as stale.

On the agent side, a bounded nonce cache (1024 entries) rejects a tool call
whose nonce has already been seen, so a replayed call is not executed twice.

## Payload kinds

| Kind | Direction | Purpose |
|---|---|---|
| `Hello` | agent → orchestrator | Register, send `DeviceInfo` + verifying key |
| `Welcome` | orchestrator → agent | Acknowledge registration, pin the key |
| `Status` | agent → orchestrator | Battery, connectivity, load |
| `ToolCall` | orchestrator → agent | Signed request to run a tool |
| `ToolResult` | agent → orchestrator | Outcome of a tool call |
| `ApprovalRequest` | orchestrator → phone | Ask the user to approve |
| `ApprovalResponse` | phone → orchestrator | User decision, signed |
| `Handoff` | orchestrator → agent | Signed handoff token |
| `HandoffAck` | agent → orchestrator | Accept/reject a handoff |
| `Bye` | agent → orchestrator | Shutdown or network loss |
| `Ping` / `Pong` | both | Liveness and latency |

Adding a variant is a protocol change and requires updating `Payload`.

## Agent-side tool call checks

Before anything runs, the agent checks in order:

1. `target_device` matches this device
2. the nonce has not been seen before
3. the envelope timestamp is recent

Then the tool whitelist is applied: a call for a tool this device does not
expose is refused, not run.

## Risk tiers

| Tier | Meaning | Approval |
|---|---|---|
| `read_only` | No side effects | Not required |
| `reversible` | Side effects, undoable | Not required, logged |
| `destructive` | Hard to reverse | Required |

The policy engine may raise a tier, never lower it.

## HTTP API

| Route | Auth | Purpose |
|---|---|---|
| `GET /health` | none | Liveness probe |
| `GET /api/v1/agents` | bearer | List registered devices |
| `GET /api/v1/audit` | bearer | Hash-chained audit log |
| `POST /api/v1/prompt` | bearer | Dispatch a prompt to a device |
| `GET /ws` | signature | Agent WebSocket |

`/api/v1/*` requires `Authorization: Bearer $HIMAN_API_TOKEN`. Comparison is
constant-time. `/health` and `/ws` are exempt: the former for load balancers,
the latter because agents authenticate by signature.

## Configuration

| Variable | Used by | Purpose |
|---|---|---|
| `HIMAN_PORT` | orchestrator | Listen port (default 8787) |
| `HIMAN_ORCH_KEY_FILE` | orchestrator | Persisted signing key seed |
| `HIMAN_ENROLLED_FILE` | orchestrator | Device id → public key map (**required**) |
| `HIMAN_API_TOKEN` | orchestrator | HTTP bearer token (**required**) |
| `HIMAN_INSECURE_DEV` | orchestrator | Set to `1` to start without a token or enrollment file |
| `HIMAN_AGENT_KEY_FILE` | agent | Persisted signing key seed |
| `HIMAN_ORCH_KEY` | agent | Pinned orchestrator public key |
| `HIMAN_KEEPALIVE_SECS` | agent | Signed Ping interval, default 60 |

## Fail-closed startup

The orchestrator refuses to start unless **both** `HIMAN_API_TOKEN` and
`HIMAN_ENROLLED_FILE` are set. The failure names the missing variable and exits
with status 1; it is not a warning.

Setting `HIMAN_INSECURE_DEV=1` allows startup with either protection missing,
but logs a loud `INSECURE DEV MODE` warning for each one. Only the exact value
`1` enables it — `true`, `yes` and `0` do not, so a near-miss cannot silently
disable a control.

    $ himan-orchestrator
    ERROR refusing to start: HIMAN_API_TOKEN is not set, so the HTTP API would
    be open. Set it, or set HIMAN_INSECURE_DEV=1 to acknowledge the risk.

Tests: `orchestrator/tests/startup.rs` covers all four cases (no token, no
enrollment file, insecure mode, both protections present).

Key files contain a base64 Ed25519 seed. They are secrets: never committed,
never logged, never printed. Only derived public keys are printed.

## WebSocket limits

| Limit | Default | Purpose |
|---|---|---|
| Handshake timeout | 10s | Close a connection that never sends its Hello |
| Idle timeout | 300s | Close a registered connection that goes silent |
| Max frame | 64 KiB | Reject an oversized frame |
| Max connections | 256 | Cap concurrent sockets |
| Max invalid messages | 8 | Close a garbage stream |

The handshake timeout applies only until the Hello arrives. Applying it to
every read would disconnect a healthy agent that simply had nothing to say,
which is why the idle timeout is separate and much longer.

## Not implemented

- Mutual TLS / WireGuard mesh — Phase 3
- Persistence — Phase 2
- Real LLM backend — Phase 2
- Handoff to a phone — Phase 3
