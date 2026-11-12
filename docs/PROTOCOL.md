# HIMAN — Protocol specification

Phase 1 version. This is the contract between the orchestrator and device
agents. Everything here is implemented in `proto/` and tested.

## Envelope

Every message is a `WireMessage`:

```rust
pub struct WireMessage {
    pub meta: WireMeta,
    pub payload: Payload,
    pub signature: String,
}

pub struct WireMeta {
    pub seq: u64,          // monotonic per sender
    pub ts: i64,           // unix seconds
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

Verification uses the sender's `verifying_key` from the device registry. A
message from an unregistered device is rejected before signature verification.

### Why the meta is signed

`seq`, `ts`, `from` and `to` are all security-relevant. An attacker who can
rewrite `from` can impersonate another device; one who can rewrite `seq` can
reorder or replay messages. Signing only the payload would leave those open.

## Payload kinds

| Kind | Direction | Purpose |
|---|---|---|
| `Hello` | agent → orchestrator | Register, send `DeviceInfo` + verifying key |
| `Welcome` | orchestrator → agent | Acknowledge registration |
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

## Handoff protocol

```
1. Planner or user decides the task should move to another device.
2. Policy engine evaluates the handoff (target must be registered).
3. PresenceManager issues a HandoffToken (task, from, to, expiry, nonce).
4. Orchestrator signs the token and sends it to the target as Payload::Handoff.
5. Target verifies the signature and checks expiry + nonce, replies HandoffAck.
6. Orchestrator flips active_device.
7. Both renderers play the transfer animation, after the ack.
```

Step 7 is deliberately last: the animation must not imply a handoff that has
not actually been acknowledged.

## Risk tiers

| Tier | Meaning | Approval |
|---|---|---|
| `read_only` | No side effects | Not required |
| `reversible` | Side effects, undoable | Not required, logged |
| `destructive` | Hard to reverse | Required |

The policy engine may raise a tier, never lower it. A tool's default tier is
declared by the tool itself; the engine can override via `always_approve`.

## Tool call flow

```
ToolCall { task_id, tool, args, risk_tier, target_device, nonce }
    │
    ├─ policy.evaluate(call, device)
    │     Allow             → execute
    │     RequireApproval   → ApprovalRequest to phone, wait for ApprovalResponse
    │     Deny(reason)      → ToolResult { state: Failed, output: reason }
    │
    └─ agent executes tool, replies ToolResult
```

Replay protection: `nonce` is monotonic per sender and must be greater than
the last accepted nonce for that sender. A replayed call is dropped.

## Not in Phase 1

- Transport (WebSocket hub) — Phase 1.5
- Mutual TLS / WireGuard mesh — Phase 3
- Persistence — Phase 2
- Real LLM — Phase 2
