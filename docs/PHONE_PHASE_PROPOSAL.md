# Proposal: phone phase (NOT implemented)

Status: design proposal + test plan. This document specifies what a phone
client needs before it is built. No phone code, no changes to ROADMAP.md or
DECISIONS.md, and no new decisions are made here. The properties below are
gates, not nice-to-haves.

## Why a proposal rather than code now

The networking and enrollment gates are closed (RT-19..RT-23): the
orchestrator terminates TLS natively, the agent verifies the server
certificate, devices pair with single-use codes, and the admin token can be
rotated. What is missing is the phone-specific runtime: secure key storage,
background execution limits, and handoff over a flaky mobile network. Those
are platform contracts, not protocol bugs, and they deserve a written test
plan before any implementation.

## 1. Secure key storage

1. **Android Keystore / iOS Secure Enclave only.** The device signing key is
   generated inside the hardware-backed store and is never exportable. A
   software keystore, a file in app data, or a key in a backup is a failed
   gate.
2. **Attestation where available.** Android Key Attestation / iOS App Attest
   bind the public key to the app instance so a cloned app cannot present a
   copied identity. If a platform cannot attest, the enrollment code becomes
   the sole binding and is used exactly once (RT-22).
3. **Biometric/device unlock for signing.** Each Hello and ToolResult
   signature requires the key to be unlocked. An app that signs while locked
   is a failed gate.
4. **No key material in logs, dumps, or analytics.** The enrollment code and
   token are equally excluded. A test must assert the plaintext code never
   appears in a stored representation (mirroring RT-22's hash-only check).

## 2. WSS with certificate pinning

1. **Use the enrollment fingerprint.** The RT-22 pairing response already
   carries the orchestrator signing key and the TLS CA fingerprint. The phone
   pins both: the CA for the transport, the signing key for the frames.
2. **TLS does not replace frame verification.** F-1/RT-15 stays in force:
   every post-Welcome frame is signature-verified against the pinned key.
   A compromise of the TLS layer must not let an attacker inject a drain or a
   commit.
3. **Pin rotation is explicit.** A new CA requires a new pairing code; the
   app never silently accepts an untrusted certificate. Certificate
   verification is never disabled, not even in the app's debug build.
4. **Hostname and expiry are checked.** The RT-21 negative cases (wrong CA,
   mismatched hostname) apply to the phone client too.

## 3. Background execution limits

1. **Assume the app is suspended at any time.** Android Doze and iOS
   background suspension will stop the WebSocket. The protocol must treat a
   silent peer as stalled, not as a completed handoff.
2. **No background long-lived socket promises.** Push notifications
   (FCM/APNs) wake the app; the app then reconnects and re-registers. A design
   that assumes a permanently live socket in the background is a failed gate.
3. **Re-registration is safe.** A reconnect with the same key resumes the
   same device identity; the enrollment code is not consumed again. Ownership
   stays with the device (the existing reconnect guard).
4. **Keepalive is advisory.** The agent's keepalive turns a silent peer into
   a visible failure; it is not a liveness proof. The hub's stall detection is
   authoritative.

## 4. Handoff over a flaky mobile network

1. **Mid-handoff disconnection rolls back.** The AC-4 matrix already covers
   source/target death in every phase; the phone must not add a path that
   leaves the task ownerless or the epoch moved.
2. **Idempotent redelivery.** A retry of HandoffReady/Drained/Commit must not
   advance the driver twice. The driver binds each reply to its
   `expected_handoff_id` (RT-16); the phone relies on that rather than on
   transport exactly-once delivery.
3. **Bounded retries with backoff.** Reconnect uses exponential backoff with
   jitter; there is no unbounded retry loop and no hot reconnect storm.
4. **Offline work is local and reversible.** A tool call accepted while
   offline is queued locally and dispatched after reconnection through the
   same policy check. Destructive tools require approval and are never
   auto-queued.

## 5. Gates

- G1: hardware-backed key, non-exportable, attested where available.
- G2: WSS to the pinned CA, plus frame signature verification with the pinned
  signing key; wrong CA and wrong hostname are refused.
- G3: app survives suspension and re-registration without re-enrolling.
- G4: every AC-4 row passes with the phone as source or target.
- G5: rate limiter and enrollment-code failure cases (reuse, expiry, wrong
  device, revoked key) are unchanged by the phone client.
- G6: no plaintext code, token, or key material in logs or backups.

## 6. Test plan

1. **Key storage:** on-device test asserts the signing key is
   non-exportable; a backup restore cannot sign as the device.
2. **Pinning:** reuse the RT-21 throwaway CA; assert the phone refuses a
   wrong-CA and a mismatched-hostname server, and that a valid CA plus valid
   signature completes a ToolCall/ToolResult round trip.
3. **Suspension:** force the app into the background mid-handoff; assert the
   hub marks the task stalled and the rollback is audited; foreground the app
   and assert clean re-registration.
4. **Flaky network:** inject packet loss and a mid-ack disconnect; assert the
   driver rolls back deterministically and the audit is hash-chained.
5. **Enrollment:** scan the RT-22 deep link; assert a single-use code cannot
   be redeemed twice and a revoked device cannot re-enroll.
6. **Regression:** run the full workspace suite and the dedicated
   durable_audit, enrollment and AC-4 CI jobs; none may be skipped.

## Still not production-ready

Audit-log access scoping is undecided: the hash chain proves integrity but
there is no per-actor read policy. Per-client API tokens are out of scope.
This document proposes gates only; it does not implement them.
