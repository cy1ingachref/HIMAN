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

use himan_orchestrator::{router, Hub, HubConfig};
use himan_proto::{
    DeviceClass, DeviceId, DeviceInfo, Payload, SigningKey, TaskState, WireMessage, WireMeta,
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
    let hub = Hub::new(HubConfig::default());
    let app = router(hub.clone(), HubConfig::default());
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

    /// Send a signed message with the given payload.
    async fn send(&mut self, payload: Payload) {
        use futures_util::SinkExt;
        let meta = WireMeta {
            seq: 1,
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

    /// Whether the server closed the connection.
    async fn is_closed(&mut self) -> bool {
        use futures_util::StreamExt;
        self.stream.next().await.is_none()
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
#[ignore = "RT-03 pending: enrollment not implemented"]
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
    assert_eq!(agents[0].verifying_key, real.key.verifying_key().to_b64());
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
#[ignore = "RT-04 pending: orchestrator key pinning not implemented"]
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
    let (transport, _resp) = tokio_tungstenite::connect_async(format!("ws://127.0.0.1:{port}/ws"))
        .await
        .expect("connect");
    let conn = himan_agent_core::transport::ws::connection_from_socket(
        std::sync::Arc::new(himan_agent_core::WsTransport::from_stream(transport)),
        8,
    );
    let mut client = himan_agent_pc::AgentClient::new(DeviceId::new("pc-1"), key, conn);
    let result = tokio::time::timeout(Duration::from_secs(5), client.register()).await;

    server.abort();

    match result {
        Ok(Err(e)) => {
            let msg = e.to_string().to_lowercase();
            assert!(
                msg.contains("pinned") || msg.contains("orchestrator key"),
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

#[tokio::test]
#[ignore = "RT-05 pending: sequence tracking not implemented"]
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

    // First delivery is accepted.
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
        .filter(|e| e.action == "message_rejected" || e.detail.contains("replay"))
        .count();
    assert!(
        rejections > 0,
        "RT-05 FAILED: a replayed ToolResult was accepted without rejection"
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
#[ignore = "RT-07 pending: API authentication not implemented"]
async fn rt07_unauthenticated_api_call_is_rejected() {
    let (_hub, port) = spawn_hub().await;

    // No Authorization header at all.
    let client = reqwest::Client::new();
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
#[ignore = "RT-08 pending: WebSocket hardening not implemented"]
async fn rt08_silent_connection_is_closed() {
    let (_hub, port) = spawn_hub().await;

    // Connect and send nothing. The server must close within the timeout.
    let (transport, _resp) = tokio_tungstenite::connect_async(format!("ws://127.0.0.1:{port}/ws"))
        .await
        .expect("connect");
    let mut client = RawClient {
        stream: transport,
        key: SigningKey::generate(),
        device_id: DeviceId::new("pc-1"),
    };

    let closed = tokio::time::timeout(Duration::from_secs(8), client.is_closed())
        .await
        .expect("RT-08 FAILED: silent connection was not closed within 8s");
    assert!(closed, "RT-08 FAILED: silent connection stayed open");
}
