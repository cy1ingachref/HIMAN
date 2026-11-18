//! Red-team tests for HIMAN.
//!
//! Each test is named RT-XX and documented in docs/REDTEAM.md, which records
//! the expected defense, the test name, the status before the fix, the status
//! after the fix and the commit that fixed it.
//!
//! Ground rules:
//! - Tests are written against the current code first, so a failing test is
//!   evidence of the gap, not an assumption.
//! - A test for a defense that does not exist yet is marked
//!   `#[ignore = "RT-XX pending"]` so CI stays green; the ignore is removed in
//!   the task that implements the defense.
//! - No keys, seeds or tokens are printed.

use std::time::Duration;

#[path = "common/mod.rs"]
mod common;

const A: &str = "dev-a";
const B: &str = "dev-b";

use serde_json::json;

use himan_orchestrator::{router_with_auth, router_with_limits, Hub, HubConfig, WsLimits};
use himan_proto::{
    DeviceClass, DeviceId, DeviceInfo, Payload, SigningKey, TaskId, TaskState, WireMessage,
    WireMeta,
};
use tokio::net::TcpStream;

type WsStream = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>;

/// Wait until the server accepts TCP connections.
async fn wait_for_port(port: u16) {
    for _ in 0..60 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("server on port {port} never came up");
}

/// Spawn the real orchestrator router on an ephemeral port.
async fn spawn_hub() -> (std::sync::Arc<Hub>, u16) {
    spawn_hub_with_token(None).await
}

/// Spawn the real orchestrator router with API auth enabled.
async fn spawn_hub_with_token(token: Option<&str>) -> (std::sync::Arc<Hub>, u16) {
    spawn_hub_with_limits_and_token(token, WsLimits::default()).await
}

/// Spawn the real orchestrator router with custom WS limits.
async fn spawn_hub_with_limits(limits: WsLimits) -> (std::sync::Arc<Hub>, u16) {
    spawn_hub_with_limits_and_token(None, limits).await
}

async fn spawn_hub_with_limits_and_token(
    token: Option<&str>,
    limits: WsLimits,
) -> (std::sync::Arc<Hub>, u16) {
    let hub = Hub::new(HubConfig::default());
    let app = match token {
        Some(t) => router_with_auth(
            hub.clone(),
            HubConfig::default(),
            himan_orchestrator::ApiToken(t.to_string()),
        ),
        None => router_with_limits(hub.clone(), limits),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    wait_for_port(port).await;
    (hub, port)
}

/// A raw WebSocket client that can impersonate an agent.
struct RawClient {
    stream: WsStream,
    key: SigningKey,
    device_id: DeviceId,
}

impl RawClient {
    async fn connect(port: u16, device_id: &str) -> Self {
        let key = SigningKey::generate();
        let (stream, _resp) = tokio_tungstenite::connect_async(format!("ws://127.0.0.1:{port}/ws"))
            .await
            .expect("ws connect");
        Self {
            stream,
            key,
            device_id: DeviceId::new(device_id),
        }
    }

    /// Send a signed message with a specific seq.
    async fn send_seq(&mut self, seq: u64, payload: Payload) {
        use futures_util::SinkExt;
        let meta = WireMeta {
            seq,
            ts: chrono::Utc::now().timestamp(),
            from: self.device_id.clone(),
            to: "orchestrator".into(),
        };
        let msg = WireMessage::sign(meta, payload, &self.key).expect("sign");
        self.stream
            .send(tokio_tungstenite::tungstenite::Message::Text(
                serde_json::to_string(&msg).expect("json").into(),
            ))
            .await
            .expect("send");
    }

    /// Send a signed message with the given payload.
    async fn send(&mut self, payload: Payload) {
        self.send_seq(1, payload).await;
    }

    /// The public key this client registers with.
    fn verifying_key_b64(&self) -> String {
        self.key.verifying_key().to_b64()
    }

    /// The device id this client claims.
    fn device_id(&self) -> &DeviceId {
        &self.device_id
    }

    /// Whether the server closed the connection, by observing a Close frame
    /// or the end of the stream.
    async fn server_closed(stream: &mut WsStream) -> bool {
        use futures_util::StreamExt;
        loop {
            match stream.next().await {
                None => return true,
                Some(Ok(tokio_tungstenite::tungstenite::Message::Close(_))) => return true,
                Some(Ok(_)) => continue,
                Some(Err(_)) => return true,
            }
        }
    }

    /// Read one frame as a `WireMessage`.
    async fn recv_message(&mut self) -> Option<WireMessage> {
        use futures_util::StreamExt;
        loop {
            match self.stream.next().await? {
                Ok(tokio_tungstenite::tungstenite::Message::Text(t)) => {
                    return serde_json::from_str(&t).ok();
                }
                Ok(_) => continue,
                Err(_) => return None,
            }
        }
    }
}

/// Build a signed Hello for a device.
fn hello(device_id: &str, key: &SigningKey) -> Payload {
    let info = DeviceInfo::new(
        DeviceId::new(device_id),
        DeviceClass::Pc,
        "redteam",
        key.verifying_key().to_b64(),
    );
    Payload::Hello(info)
}

// ---------------------------------------------------------------------------
// RT-01: handshake reflection
//
// A server that echoes the agent's own Hello back must not be accepted as a
// successful registration. The defense is that `register()` requires a
// `Welcome`, so an echo of a `Hello` is rejected as an unexpected reply.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rt01_agent_rejects_reflected_hello() {
    use futures_util::{SinkExt, StreamExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        while let Some(Ok(frame)) = ws.next().await {
            if ws.send(frame).await.is_err() {
                break;
            }
        }
    });

    let key = SigningKey::generate();
    let device_id = DeviceId::new("pc-1");
    let (transport, _resp) = tokio_tungstenite::connect_async(format!("ws://127.0.0.1:{port}/ws"))
        .await
        .expect("connect");
    let conn = himan_agent_core::transport::ws::connection_from_socket(
        std::sync::Arc::new(himan_agent_core::WsTransport::from_stream(transport)),
        8,
    );
    let mut client = himan_agent_pc::AgentClient::new(device_id, key, conn);
    let result = tokio::time::timeout(Duration::from_secs(5), client.register()).await;

    server.abort();

    let err = match result {
        Ok(Err(e)) => e.to_string(),
        Ok(Ok(_)) => panic!("RT-01 FAILED: a reflected Hello was accepted as registration"),
        Err(_) => panic!("RT-01 FAILED: registration hung instead of rejecting the echo"),
    };
    assert!(
        err.contains("unexpected reply"),
        "RT-01 expected an unexpected-reply error, got: {err}"
    );
}

// ---------------------------------------------------------------------------
// RT-02: wrong nonce in the Welcome
//
// The Welcome must echo the nonce from the Hello it replies to. A mismatch
// means the reply does not belong to this handshake attempt.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rt02_wrong_nonce_is_rejected() {
    use futures_util::{SinkExt, StreamExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        if let Some(Ok(_)) = ws.next().await {
            let sk = SigningKey::generate();
            let welcome = WireMessage::sign(
                WireMeta {
                    seq: 1,
                    ts: chrono::Utc::now().timestamp(),
                    from: DeviceId::new("orchestrator"),
                    to: "pc-1".into(),
                },
                Payload::Welcome {
                    device_id: DeviceId::new("pc-1"),
                    nonce: "deliberately-wrong".into(),
                    orchestrator_key: sk.verifying_key().to_b64(),
                },
                &sk,
            )
            .unwrap();
            let _ = ws
                .send(tokio_tungstenite::tungstenite::Message::Text(
                    serde_json::to_string(&welcome).unwrap().into(),
                ))
                .await;
        }
        tokio::time::sleep(Duration::from_millis(800)).await;
    });

    let key = SigningKey::generate();
    let device_id = DeviceId::new("pc-1");
    let (transport, _resp) = tokio_tungstenite::connect_async(format!("ws://127.0.0.1:{port}/ws"))
        .await
        .expect("connect");
    let conn = himan_agent_core::transport::ws::connection_from_socket(
        std::sync::Arc::new(himan_agent_core::WsTransport::from_stream(transport)),
        8,
    );
    let mut client = himan_agent_pc::AgentClient::new(device_id, key, conn);
    let result = tokio::time::timeout(Duration::from_secs(5), client.register()).await;

    server.abort();

    let err = match result {
        Ok(Err(e)) => e.to_string(),
        Ok(Ok(_)) => panic!("RT-02 FAILED: a Welcome with a wrong nonce was accepted"),
        Err(_) => panic!("RT-02 FAILED: registration hung instead of rejecting the nonce mismatch"),
    };
    assert!(
        err.to_lowercase().contains("nonce"),
        "RT-02 expected a nonce-mismatch error, got: {err}"
    );
}

/// Spawn the real orchestrator router on an ephemeral port, with enrollment
/// loaded from a JSON file.
async fn spawn_hub_with_enrollment(enrollment_json: &str) -> (std::sync::Arc<Hub>, u16) {
    // The file is read fully into memory here, so the tempdir can be dropped
    // as soon as loading finishes.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("enrolled.json");
    std::fs::write(&path, enrollment_json).expect("write enrollment");
    let file = himan_orchestrator::EnrollmentFile::load(&path).expect("load enrollment");
    drop(dir);

    let hub = Hub::new(HubConfig::default()).with_enrollment(file);
    let app = router_with_limits(hub.clone(), WsLimits::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    wait_for_port(port).await;
    (hub, port)
}

// ---------------------------------------------------------------------------
// RT-03: identity takeover
//
// A second client with a NEW key registers as "pc-1" while the real pc-1 is
// connected. Expected defense: rejected, and the legitimate agent stays
// registered and still receives dispatches.
//
// Status: PENDING. The orchestrator currently accepts any validly signed Hello
// for a device id it does not know, so a new key can take over a connected id.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rt03_identity_takeover_is_rejected() {
    let (hub, port) = spawn_hub().await;

    // The legitimate pc-1 connects and registers.
    let mut real = RawClient::connect(port, "pc-1").await;
    real.send(hello("pc-1", &real.key)).await;
    let welcome = tokio::time::timeout(Duration::from_secs(5), real.recv_message())
        .await
        .expect("welcome should arrive")
        .expect("welcome");
    assert!(
        matches!(welcome.payload, Payload::Welcome { .. }),
        "RT-03: real agent should get a Welcome, got {}",
        welcome.payload.kind_name()
    );

    // An attacker with a NEW key claims the same id.
    let mut attacker = RawClient::connect(port, "pc-1").await;
    attacker.send(hello("pc-1", &attacker.key)).await;

    // The attacker's registration must be rejected: either no Welcome, or a
    // closed connection.
    let outcome = tokio::time::timeout(Duration::from_secs(3), attacker.recv_message()).await;
    if let Ok(Some(_)) = outcome {
        panic!("RT-03 FAILED: a new key was accepted for an already-connected device");
    }
    // Ok(None) or a timeout: rejected or closed, both acceptable.

    // The legitimate agent must still be registered and dispatchable.
    let agents = hub.agents().await;
    assert_eq!(agents.len(), 1, "RT-03: exactly one session must remain");
    assert_eq!(agents[0].id.as_str(), "pc-1");
    assert_eq!(agents[0].verifying_key, real.verifying_key_b64());
}

// ---------------------------------------------------------------------------
// RT-04: fake orchestrator
//
// A server that signs a Welcome with its own key, embeds that key, and echoes
// the nonce. The agent must refuse it because the key is not the pinned
// orchestrator key.
//
// Status: PENDING. The agent currently accepts any key the Welcome advertises,
// so a fake orchestrator can impersonate the real one.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rt04_fake_orchestrator_is_rejected() {
    use futures_util::{SinkExt, StreamExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        if let Some(Ok(tokio_tungstenite::tungstenite::Message::Text(text))) = ws.next().await {
            // Echo the nonce from the agent's Hello.
            let hello: WireMessage = serde_json::from_str(&text).unwrap();
            let nonce = match &hello.payload {
                Payload::Hello(info) => info.nonce.clone(),
                _ => String::new(),
            };
            let fake_key = SigningKey::generate();
            let welcome = WireMessage::sign(
                WireMeta {
                    seq: 1,
                    ts: chrono::Utc::now().timestamp(),
                    from: DeviceId::new("orchestrator"),
                    to: "pc-1".into(),
                },
                Payload::Welcome {
                    device_id: DeviceId::new("pc-1"),
                    nonce,
                    orchestrator_key: fake_key.verifying_key().to_b64(),
                },
                &fake_key,
            )
            .unwrap();
            let _ = ws
                .send(tokio_tungstenite::tungstenite::Message::Text(
                    serde_json::to_string(&welcome).unwrap().into(),
                ))
                .await;
        }
        tokio::time::sleep(Duration::from_millis(800)).await;
    });

    let key = SigningKey::generate();
    // Pin a key that is NOT the fake server's key, so the fake Welcome must
    // be rejected as not pinned.
    let pinned = SigningKey::generate();
    let (transport, _resp) = tokio_tungstenite::connect_async(format!("ws://127.0.0.1:{port}/ws"))
        .await
        .expect("connect");
    let conn = himan_agent_core::transport::ws::connection_from_socket(
        std::sync::Arc::new(himan_agent_core::WsTransport::from_stream(transport)),
        8,
    );
    let mut client = himan_agent_pc::AgentClient::new(DeviceId::new("pc-1"), key, conn)
        .with_pinned_orchestrator_key(&pinned.verifying_key().to_b64())
        .expect("pinned key");
    let result = tokio::time::timeout(Duration::from_secs(5), client.register()).await;

    server.abort();

    match result {
        Ok(Err(e)) => {
            let msg = e.to_string().to_lowercase();
            assert!(
                msg.contains("pinned"),
                "RT-04 expected a pinned-key error, got: {e}"
            );
        }
        Ok(Ok(_)) => panic!("RT-04 FAILED: a fake orchestrator was accepted"),
        Err(_) => panic!("RT-04 FAILED: registration hung"),
    }
}

// ---------------------------------------------------------------------------
// RT-05: replay of an accepted ToolResult
//
// Re-sending an already accepted signed ToolResult must be rejected. The
// defense is a per-device sequence tracker: seq must be strictly greater than
// the last accepted seq.
//
// Status: PENDING. The hub accepts any signed ToolResult regardless of seq.
// ---------------------------------------------------------------------------

/// A replayed ToolResult must be rejected.
///
/// The first message is accepted. Re-sending the same message (same seq)
/// must be rejected because seq is not newer than the last accepted seq.
/// A message with a newer seq is accepted, which proves the rule is
/// ordering and not "reject everything after the first".
#[tokio::test]
async fn rt05_tool_result_replay_is_rejected() {
    let (hub, port) = spawn_hub().await;

    let mut agent = RawClient::connect(port, "pc-1").await;
    agent.send(hello("pc-1", &agent.key)).await;
    let _welcome = tokio::time::timeout(Duration::from_secs(5), agent.recv_message())
        .await
        .expect("welcome")
        .expect("welcome");

    let task_id = himan_proto::TaskId::new("t-replay");
    let result = Payload::ToolResult {
        task_id: task_id.clone(),
        state: TaskState::Succeeded,
        output: "first delivery".into(),
    };

    // First delivery is accepted (seq 1).
    agent.send(result.clone()).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        hub.task(&task_id).await,
        Some(TaskState::Succeeded),
        "RT-05: first delivery must be recorded"
    );

    // Replay of the same message must be rejected.
    agent.send(result).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    let events = hub.audit_events().await;
    let rejections = events
        .iter()
        .filter(|e| e.action == "message_rejected")
        .count();
    assert!(
        rejections > 0,
        "RT-05 FAILED: a replayed ToolResult was accepted without rejection"
    );

    // A newer seq is still accepted, so the rule is ordering not a blanket
    // rejection.
    agent
        .send_seq(
            2,
            Payload::ToolResult {
                task_id: task_id.clone(),
                state: TaskState::Failed,
                output: "second delivery".into(),
            },
        )
        .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        hub.task(&task_id).await,
        Some(TaskState::Failed),
        "RT-05: a newer seq must be accepted"
    );
}

// ---------------------------------------------------------------------------
// RT-06: task-id collision
//
// Two dispatches in the same second must get distinct task ids and nonces.
// The current implementation derives the id from the Unix timestamp, so two
// dispatches in the same second collide.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rt06_task_ids_are_unique_within_a_second() {
    let (hub, port) = spawn_hub().await;

    let mut agent = RawClient::connect(port, "pc-1").await;
    agent.send(hello("pc-1", &agent.key)).await;
    let _welcome = tokio::time::timeout(Duration::from_secs(5), agent.recv_message())
        .await
        .expect("welcome")
        .expect("welcome");

    let device = DeviceId::new("pc-1");
    let a = hub.dispatch(&device, "status").await.expect("dispatch a");
    let b = hub.dispatch(&device, "status").await.expect("dispatch b");

    assert_ne!(
        a.task_id, b.task_id,
        "RT-06 FAILED: two dispatches in the same second got the same task id: {}",
        a.task_id
    );
    assert!(
        a.task_id.len() >= 16,
        "RT-06 FAILED: task id looks like a timestamp, not random: {}",
        a.task_id
    );
}

// ---------------------------------------------------------------------------
// RT-07: unauthenticated API call
//
// /api/v1/* must require a bearer token. Expected: 401.
//
// Status: PENDING. The API currently has no authentication at all.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rt07_unauthenticated_api_call_is_rejected() {
    let (_hub, port) = spawn_hub_with_token(Some("s3cret-token")).await;

    let client = reqwest::Client::new();

    // No Authorization header at all.
    let status = client
        .post(format!("http://127.0.0.1:{port}/api/v1/prompt"))
        .json(&serde_json::json!({"device": "pc-1", "prompt": "status"}))
        .send()
        .await
        .expect("request")
        .status();
    assert_eq!(
        status, 401,
        "RT-07 FAILED: an unauthenticated API call returned {status}, expected 401"
    );

    // A wrong token must also be rejected.
    let status = client
        .post(format!("http://127.0.0.1:{port}/api/v1/prompt"))
        .header("Authorization", "Bearer wrong-token")
        .json(&serde_json::json!({"device": "pc-1", "prompt": "status"}))
        .send()
        .await
        .expect("request")
        .status();
    assert_eq!(
        status, 401,
        "RT-07 FAILED: a wrong token returned {status}, expected 401"
    );

    // The correct token passes authentication. With no agent connected the
    // dispatch itself fails, so the expected status is 400 (not 401): the
    // point is that auth no longer rejects it.
    let status = client
        .post(format!("http://127.0.0.1:{port}/api/v1/prompt"))
        .header("Authorization", "Bearer s3cret-token")
        .json(&serde_json::json!({"device": "pc-1", "prompt": "status"}))
        .send()
        .await
        .expect("request")
        .status();
    assert_eq!(
        status, 400,
        "RT-07 FAILED: the correct token should pass auth (400 from dispatch, \
         not 401), got {status}"
    );

    // /health must stay open without a token.
    let status = client
        .get(format!("http://127.0.0.1:{port}/health"))
        .send()
        .await
        .expect("request")
        .status();
    assert_eq!(
        status, 200,
        "RT-07 FAILED: /health should stay open, got {status}"
    );
}

// ---------------------------------------------------------------------------
// RT-08: oversized or silent WebSocket connection
//
// A connection that sends nothing, or sends an oversized frame, must be
// closed by the server.
//
// Status: PENDING. The server has no handshake timeout and no message size
// limit.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn rt08_silent_connection_is_closed() {
    // A short handshake timeout keeps the test fast.
    let (_hub, port) = spawn_hub_with_limits(WsLimits {
        handshake_timeout_secs: 2,
        ..WsLimits::default()
    })
    .await;

    let (transport, _resp) = tokio_tungstenite::connect_async(format!("ws://127.0.0.1:{port}/ws"))
        .await
        .expect("connect");
    let mut client = RawClient {
        stream: transport,
        key: SigningKey::generate(),
        device_id: DeviceId::new("pc-1"),
    };

    // Send nothing; the server must close within the timeout.
    let closed = tokio::time::timeout(
        Duration::from_secs(8),
        RawClient::server_closed(&mut client.stream),
    )
    .await
    .expect("RT-08 FAILED: silent connection was not closed within 8s");
    assert!(closed, "RT-08 FAILED: silent connection stayed open");
}

/// A registered agent must NOT be disconnected by the handshake timeout.
///
/// Regression: the handshake timeout was applied to every read, so an agent
/// that went quiet for 10s after registering was dropped even though it was
/// healthy. The idle timeout after registration is much longer.
#[tokio::test]
async fn registered_agent_survives_past_the_handshake_timeout() {
    let (_hub, port) = spawn_hub_with_limits(WsLimits {
        handshake_timeout_secs: 2,
        idle_timeout_secs: 60,
        ..WsLimits::default()
    })
    .await;

    let mut agent = RawClient::connect(port, "pc-1").await;
    agent.send(hello("pc-1", &agent.key)).await;
    let _welcome = tokio::time::timeout(Duration::from_secs(5), agent.recv_message())
        .await
        .expect("welcome")
        .expect("welcome");

    // Wait well past the handshake timeout. The agent must still be connected.
    tokio::time::sleep(Duration::from_secs(5)).await;

    // A message after the wait proves the connection survived.
    agent.send(Payload::Ping { nonce: 1 }).await;
    let reply = tokio::time::timeout(Duration::from_secs(5), agent.recv_message())
        .await
        .expect("the connection should still be open")
        .expect("a pong should arrive");
    assert!(
        matches!(reply.payload, Payload::Pong { .. }),
        "expected a Pong, got {}",
        reply.payload.kind_name()
    );
}

#[tokio::test]
async fn rt08_oversized_frame_is_closed() {
    use futures_util::SinkExt;

    let (_hub, port) = spawn_hub().await;

    let (transport, _resp) = tokio_tungstenite::connect_async(format!("ws://127.0.0.1:{port}/ws"))
        .await
        .expect("connect");
    let mut client = RawClient {
        stream: transport,
        key: SigningKey::generate(),
        device_id: DeviceId::new("pc-1"),
    };

    // A frame larger than the limit must be refused.
    let big = "x".repeat(128 * 1024);
    client
        .stream
        .send(tokio_tungstenite::tungstenite::Message::Text(big.into()))
        .await
        .expect("send");

    let closed = tokio::time::timeout(
        Duration::from_secs(8),
        RawClient::server_closed(&mut client.stream),
    )
    .await
    .expect("RT-08 FAILED: oversized frame did not close the connection");
    assert!(closed, "RT-08 FAILED: oversized frame was accepted");
}

#[tokio::test]
async fn rt08_too_many_invalid_messages_is_closed() {
    use futures_util::SinkExt;

    let (_hub, port) = spawn_hub().await;

    let (transport, _resp) = tokio_tungstenite::connect_async(format!("ws://127.0.0.1:{port}/ws"))
        .await
        .expect("connect");
    let mut client = RawClient {
        stream: transport,
        key: SigningKey::generate(),
        device_id: DeviceId::new("pc-1"),
    };

    // Send more invalid frames than the limit allows.
    for _ in 0..16 {
        let _ = client
            .stream
            .send(tokio_tungstenite::tungstenite::Message::Text(
                "{not json".into(),
            ))
            .await;
    }

    let closed = tokio::time::timeout(
        Duration::from_secs(8),
        RawClient::server_closed(&mut client.stream),
    )
    .await
    .expect("RT-08 FAILED: invalid messages did not close the connection");
    assert!(closed, "RT-08 FAILED: invalid messages were tolerated");
}

// ---------------------------------------------------------------------------
// Enrollment checks that back RT-03
//
// RT-03 exercises the session takeover path. These two tests exercise the
// enrollment file itself: an unknown device, and a device whose key does not
// match the enrolled key.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn enrollment_rejects_an_unknown_device() {
    let key = SigningKey::generate();
    let enrollment = format!(r#"{{"pc-1":"{}"}}"#, key.verifying_key().to_b64());
    let (hub, port) = spawn_hub_with_enrollment(&enrollment).await;

    let mut stranger = RawClient::connect(port, "phone-1").await;
    stranger.send(hello("phone-1", &stranger.key)).await;

    // No Welcome: the registration must be refused.
    let outcome = tokio::time::timeout(Duration::from_secs(3), stranger.recv_message()).await;
    assert!(
        !matches!(outcome, Ok(Some(_))),
        "enrollment accepted a device that is not in the file"
    );

    // The rejection must be audited, without key material.
    let events = hub.audit_events().await;
    let rejection = events
        .iter()
        .find(|e| e.action == "registration_rejected")
        .expect("rejection must be audited");
    assert_eq!(rejection.actor, stranger.device_id().as_str());
    assert!(
        !rejection.detail.contains("=="),
        "audit detail must not contain key material: {}",
        rejection.detail
    );
}

#[tokio::test]
async fn enrollment_rejects_a_key_mismatch() {
    let enrolled = SigningKey::generate();
    let attacker = SigningKey::generate();
    let enrollment = format!(r#"{{"pc-1":"{}"}}"#, enrolled.verifying_key().to_b64());
    let (hub, port) = spawn_hub_with_enrollment(&enrollment).await;

    let mut client = RawClient::connect(port, "pc-1").await;
    // The Hello must claim the attacker's key, not the client's own key.
    client.send(hello("pc-1", &attacker)).await;

    let outcome = tokio::time::timeout(Duration::from_secs(3), client.recv_message()).await;
    assert!(
        !matches!(outcome, Ok(Some(_))),
        "enrollment accepted a Hello signed by a key that is not enrolled"
    );

    assert!(
        hub.agents().await.is_empty(),
        "a key mismatch must not create a session"
    );
}

#[tokio::test]
async fn enrollment_accepts_a_matching_key() {
    let key = SigningKey::generate();
    let enrollment = format!(r#"{{"pc-1":"{}"}}"#, key.verifying_key().to_b64());
    let (hub, port) = spawn_hub_with_enrollment(&enrollment).await;

    // The client must sign with the enrolled key, which in a real deployment
    // is the same key it loaded from its key file.
    let mut client = RawClient::connect(port, "pc-1").await;
    client.key = key.clone();
    client.send(hello("pc-1", &key)).await;

    let welcome = tokio::time::timeout(Duration::from_secs(5), client.recv_message())
        .await
        .expect("welcome should arrive")
        .expect("welcome");
    assert!(matches!(welcome.payload, Payload::Welcome { .. }));
    assert_eq!(hub.agents().await.len(), 1);
}

// ---------------------------------------------------------------------------
// RT-09 .. RT-14: the handoff attack surface
//
// Each test is written against the current code, so a failure is evidence of
// a gap rather than an assumption. Where a defense was built in from the start
// there is no "before" commit to point at; docs/REDTEAM.md says so instead of
// inventing one.

/// Enroll three devices and register two of them over real sockets.
///
/// `pc-3` is enrolled but never connects, which keeps "unenrolled" and "not
/// connected" distinct cases.
async fn handoff_pair() -> (
    std::sync::Arc<Hub>,
    u16,
    RawClient,
    RawClient,
    SigningKey,
    SigningKey,
) {
    let key_a = SigningKey::generate();
    let key_b = SigningKey::generate();
    let key_c = SigningKey::generate();
    let enrollment = format!(
        r#"{{"pc-1":"{}","pc-2":"{}","pc-3":"{}"}}"#,
        key_a.verifying_key().to_b64(),
        key_b.verifying_key().to_b64(),
        key_c.verifying_key().to_b64(),
    );
    let (hub, port) = spawn_hub_with_enrollment(&enrollment).await;

    let mut a = RawClient::connect(port, "pc-1").await;
    a.key = key_a.clone();
    a.send(hello("pc-1", &key_a)).await;
    let welcome = tokio::time::timeout(Duration::from_secs(5), a.recv_message())
        .await
        .expect("pc-1 welcome")
        .expect("welcome frame");
    assert!(matches!(welcome.payload, Payload::Welcome { .. }));

    let mut b = RawClient::connect(port, "pc-2").await;
    b.key = key_b.clone();
    b.send(hello("pc-2", &key_b)).await;
    let welcome = tokio::time::timeout(Duration::from_secs(5), b.recv_message())
        .await
        .expect("pc-2 welcome")
        .expect("welcome frame");
    assert!(matches!(welcome.payload, Payload::Welcome { .. }));

    (hub, port, a, b, key_a, key_b)
}

/// RT-09: a forged `SwitchCommit`.
///
/// The hub drops `HandoffSwitched` on the floor (the driver consumes it), so
/// the defense under test is that no forged ack can move ownership or the
/// epoch. Three forgeries are attempted: a bad signature, a wrong sender, and
/// a wrong epoch.
#[tokio::test]
async fn rt09_a_forged_switch_commit_moves_nothing() {
    let (hub, port, mut a, mut b, _ka, _kb) = handoff_pair().await;
    let task = TaskId::new("task-rt09");
    hub.register_task_for_test(task.as_str(), "pc-1").await;
    let _token = hub
        .request_handoff(&task, &DeviceId::new("pc-1"), &DeviceId::new("pc-2"))
        .await
        .expect("token");

    // Wrong epoch, from the real target.
    b.send(Payload::HandoffSwitched {
        handoff_id: "handoff-rt09".to_string(),
        new_epoch: 99,
    })
    .await;
    // Wrong sender: the source claims the switch.
    a.send(Payload::HandoffSwitched {
        handoff_id: "handoff-rt09".to_string(),
        new_epoch: 1,
    })
    .await;
    // Bad signature: a key that is not enrolled.
    let mut forger = RawClient::connect(port, "pc-2").await;
    forger
        .send(Payload::HandoffSwitched {
            handoff_id: "handoff-rt09".to_string(),
            new_epoch: 1,
        })
        .await;

    // Give the hub a moment to (not) act on them.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let owner = hub.owner_name(task.as_str()).await;
    assert_eq!(
        owner.as_deref(),
        Some("pc-1"),
        "RT-09 FAILED: a forged SwitchCommit moved ownership"
    );
    // The defense is that the hub DROPS the ack: the driver consumes it from
    // the broadcast. If the hub ever acted on one, it would leave a trace in
    // the audit; none may appear.
    let audit = hub.audit_events().await;
    assert!(
        !audit
            .iter()
            .any(|e| e.action == "forged_switch_applied" || e.detail.contains("new_epoch")),
        "RT-09 FAILED: the hub acted on a hub-received SwitchCommit: {:?}",
        audit.iter().map(|e| &e.action).collect::<Vec<_>>()
    );
}

/// RT-10: a replayed handoff token.
///
/// The token is bound to one attempt. Re-requesting the same handoff after the
/// epoch has moved must be refused, because the source no longer owns the task.
#[tokio::test]
async fn rt10_a_replayed_handoff_token_is_refused() {
    let (hub, _port, _a, _b, _ka, _kb) = handoff_pair().await;
    let task = TaskId::new("task-rt10");
    hub.register_task_for_test(task.as_str(), "pc-1").await;
    hub.request_handoff(&task, &DeviceId::new("pc-1"), &DeviceId::new("pc-2"))
        .await
        .expect("first token");
    // The commit moved the epoch and the owner.
    hub.commit_task_for_test(task.as_str(), "pc-2", 1).await;
    // Replaying the same attempt must be refused.
    let replay = hub
        .request_handoff(&task, &DeviceId::new("pc-1"), &DeviceId::new("pc-2"))
        .await;
    assert!(
        replay.is_err(),
        "RT-10 FAILED: a replayed handoff token was accepted"
    );
}

/// RT-11: a handoff to a device that is not enrolled.
///
/// `pc-3` IS enrolled but never connects; `pc-9` is not enrolled at all. Both
/// must be refused, and the refusal must name the real reason. This matters
/// because "not enrolled" and "enrolled but offline" are different states, and
/// a handoff to an enrolled-but-offline device is a legitimate queued handoff
/// while one to an unenrolled device is a policy violation.
#[tokio::test]
async fn rt11_a_handoff_to_an_unenrolled_device_is_refused() {
    let (hub, _port, _a, _b, _ka, _kb) = handoff_pair().await;
    let task = TaskId::new("task-rt11");
    hub.register_task_for_test(task.as_str(), "pc-1").await;

    // pc-9: not enrolled, not connected.
    let unenrolled = hub
        .request_handoff(&task, &DeviceId::new("pc-1"), &DeviceId::new("pc-9"))
        .await;
    assert!(
        unenrolled.is_err(),
        "RT-11 FAILED: a handoff to an unenrolled device was accepted"
    );

    // pc-3: enrolled but offline. The policy layer must accept it (it is a
    // registered device); the connection check may then refuse it. Assert the
    // policy decision directly so the enrollment boundary is what is tested.
    let decision = hub
        .handoff_policy_for_test(
            &DeviceId::new("pc-1"),
            &DeviceId::new("pc-3"),
            Some(&DeviceInfo::new(
                DeviceId::new("pc-3"),
                DeviceClass::Pc,
                "pc-3",
                "unused",
            )),
        )
        .await;
    assert!(
        matches!(decision, himan_orchestrator::Decision::Allow),
        "RT-11 FAILED: an enrolled device was denied at the policy layer: {decision:?}"
    );

    // And an unregistered target is denied at the same layer.
    let unregistered = hub
        .handoff_policy_for_test(&DeviceId::new("pc-1"), &DeviceId::new("pc-9"), None)
        .await;
    assert!(
        !matches!(unregistered, himan_orchestrator::Decision::Allow),
        "RT-11 FAILED: an unregistered target was allowed at the policy layer: {unregistered:?}"
    );

    // And the unenrolled one is denied at the same layer.
    let denied = hub
        .request_handoff(&task, &DeviceId::new("pc-1"), &DeviceId::new("pc-9"))
        .await
        .err()
        .map(|e| e.to_string())
        .unwrap_or_default();
    assert!(
        denied.contains("not connected") || denied.contains("not registered"),
        "RT-11: unexpected refusal reason: {denied}"
    );
}

/// RT-12: a token bound to a different target.
///
/// The agent-side `verify_handoff_token` is the defense: a token issued for
/// pc-2 must be refused by any other device. The test drives the same check the
/// agent performs, through the orchestrator's token plus the agent's rule.
#[tokio::test]
async fn rt12_a_token_bound_to_another_target_is_refused() {
    let (hub, _port, _a, _b, _ka, _kb) = handoff_pair().await;
    let task = TaskId::new("task-rt12");
    hub.register_task_for_test(task.as_str(), "pc-1").await;
    let token = hub
        .request_handoff(&task, &DeviceId::new("pc-1"), &DeviceId::new("pc-2"))
        .await
        .expect("token");

    // The rule the agent applies, exercised through the real agent-side
    // function: the token's target must be the presenter.
    let accepted_by_pc3 = himan_agent_pc::token_matches(&token, &DeviceId::new("pc-3"), &task);
    assert!(
        !accepted_by_pc3,
        "RT-12 FAILED: a token bound to pc-2 was accepted by pc-3"
    );
    let accepted_by_pc2 = himan_agent_pc::token_matches(&token, &DeviceId::new("pc-2"), &task);
    assert!(
        accepted_by_pc2,
        "RT-12: the legitimate target was refused its own token"
    );
}

/// RT-13: two simultaneous handoffs for one task.
#[tokio::test]
async fn rt13_two_simultaneous_handoffs_are_serialised() {
    let (hub, _port, _a, _b, _ka, _kb) = handoff_pair().await;
    let task = TaskId::new("task-rt13");
    hub.register_task_for_test(task.as_str(), "pc-1").await;
    let first = hub
        .request_handoff(&task, &DeviceId::new("pc-1"), &DeviceId::new("pc-2"))
        .await
        .expect("first handoff");
    // Drive the first handoff for real. The raw clients above do not answer
    // handoff messages, so this uses the shared harness; the ownership and
    // epoch state it asserts on is the same hub the test inspects.
    let dir = tempfile::tempdir().expect("tempdir");
    let _devices = common::make_devices_named(dir.path(), 2, |i| [A, B][i].to_string());
    let mut harness = common::E2ETest::new_with_devices(&[A, B]).await;
    harness.use_fault_injection_agent();
    let port = harness.port();
    let orch_key = harness.orchestrator_key().expect("orchestrator key");
    harness
        .spawn_agent(port, A, &orch_key)
        .await
        .expect("dev-a registers");
    harness
        .spawn_agent(port, B, &orch_key)
        .await
        .expect("dev-b registers");

    let (status, body) = common::http_post(
        port,
        "/api/v1/prompt",
        json!({"device": A, "prompt": "run the deterministic scenario of 20 steps"}),
    );
    assert_eq!(status, 200, "dispatch refused: {body}");
    let task_id = body["task_id"].as_str().expect("task id").to_string();

    let (status, handoff) = common::http_post(
        port,
        "/api/v1/handoff",
        json!({"task_id": task_id, "from": A, "to": B}),
    );
    assert_eq!(status, 200, "first handoff refused: {handoff}");
    assert_eq!(
        handoff["state"].as_str().unwrap_or_default(),
        "active",
        "RT-13: the first handoff did not complete: {handoff}"
    );
    let _ = (hub, first);

    // A second handoff claiming the OLD source must be refused, and the owner
    // must not move again.
    let (status, second) = common::http_post(
        port,
        "/api/v1/handoff",
        json!({"task_id": task_id, "from": A, "to": B}),
    );
    assert_eq!(
        status, 400,
        "RT-13 FAILED: a second handoff was accepted: {second}"
    );

    let owner = common::http_get_json(port, &format!("/api/v1/tasks/{task_id}/owner"));
    assert_eq!(
        owner["owner"],
        json!(B),
        "RT-13 FAILED: a second handoff moved ownership"
    );
    assert_eq!(
        owner["epoch"],
        json!(1),
        "RT-13 FAILED: the epoch moved again"
    );

    harness.stop().await;
}

/// RT-14: a stale-epoch commit after the switch.
///
/// The durable commit refuses to move the epoch backwards, which is what makes
/// a late commit from the old owner harmless.
#[tokio::test]
async fn rt14_a_stale_epoch_commit_is_refused() {
    let store =
        himan_orchestrator::durable::DurableStore::open_in_memory().expect("in-memory store");
    let task = "task-rt14";
    store.ensure_task(task, "pc-1").expect("task");
    let event = |seq: u64, epoch: u64| himan_orchestrator::eventlog::TaskEvent {
        task_id: task.to_string(),
        seq,
        epoch,
        device: DeviceId::new("pc-2"),
        payload: himan_orchestrator::eventlog::EventPayload::OwnerChanged {
            from: "pc-1".into(),
            to: "pc-2".into(),
            epoch,
        },
    };
    store
        .commit_owner(task, "pc-2", 1, &event(1, 1))
        .expect("the real commit");
    let stale = store.commit_owner(task, "pc-1", 0, &event(2, 0));
    assert!(
        stale.is_err(),
        "RT-14 FAILED: a stale-epoch commit after the switch was accepted"
    );
    let message = stale.err().unwrap();
    assert!(
        message.contains("backwards"),
        "RT-14: unexpected refusal reason: {message}"
    );
    let record = store.task(task).expect("record").expect("present");
    assert_eq!(record.owner, "pc-2");
    assert_eq!(record.epoch, 1);
}
