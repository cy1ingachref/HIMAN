//! Phase 1 exit check: a real orchestrator and a real agent over a real
//! WebSocket, end to end.
//!
//! This is the test that would have caught the socket-echo bug. It does not
//! touch any running server: it binds an ephemeral port, spawns the server,
//! connects a real agent over WebSocket, and asserts the whole path.
//!
//! Run with `cargo test -p himan-orchestrator --test integration -- --nocapture`.

use std::sync::Arc;
use std::time::Duration;

use himan_orchestrator::{Hub, HubConfig};
use himan_proto::{DeviceId, DeviceInfo, Payload, SigningKey, TaskState, WireMessage, WireMeta};
use serde_json::json;

/// Wait for the server to accept connections.
async fn wait_for_server(port: u16) {
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("server on port {port} never came up");
}

/// A minimal WebSocket agent, speaking the real handshake.
struct TestAgent {
    key: SigningKey,
    device_id: DeviceId,
}

impl TestAgent {
    fn new(id: &str) -> Self {
        Self {
            key: SigningKey::generate(),
            device_id: DeviceId::new(id),
        }
    }

    /// Connect and register. Fails if the Welcome is not a genuine, signed,
    /// nonce-matching reply.
    async fn connect(self, url: &str) -> Result<RegisteredAgent, String> {
        let (transport, _resp) = tokio_tungstenite::connect_async(url)
            .await
            .map_err(|e| format!("connect failed: {e}"))?;
        let mut stream = transport;

        // Build and send a signed Hello with a fresh nonce.
        let info = DeviceInfo::new(
            self.device_id.clone(),
            himan_proto::DeviceClass::Pc,
            "integration agent",
            self.key.verifying_key().to_b64(),
        );
        let nonce = info.nonce.clone();
        let meta = WireMeta {
            seq: 1,
            ts: chrono::Utc::now().timestamp(),
            from: self.device_id.clone(),
            to: "orchestrator".into(),
        };
        let hello = WireMessage::sign(meta, Payload::Hello(info), &self.key)
            .map_err(|e| format!("sign hello: {e}"))?;
        let json = serde_json::to_string(&hello).map_err(|e| e.to_string())?;
        use futures_util::SinkExt;
        stream
            .send(tokio_tungstenite::tungstenite::Message::Text(json.into()))
            .await
            .map_err(|e| format!("send hello: {e}"))?;

        // Read the Welcome and enforce the same rules register() enforces.
        use futures_util::StreamExt;
        let reply = match tokio::time::timeout(Duration::from_secs(5), stream.next()).await {
            Ok(Some(Ok(tokio_tungstenite::tungstenite::Message::Text(t)))) => t.to_string(),
            Ok(Some(Ok(other))) => return Err(format!("unexpected frame: {other:?}")),
            Ok(Some(Err(e))) => return Err(format!("stream error: {e}")),
            Ok(None) => return Err("server closed before Welcome".into()),
            Err(_) => return Err("timeout waiting for Welcome".into()),
        };

        let welcome: WireMessage =
            serde_json::from_str(&reply).map_err(|e| format!("bad Welcome json: {e}"))?;

        let Payload::Welcome {
            device_id,
            nonce: reply_nonce,
            orchestrator_key,
        } = &welcome.payload
        else {
            return Err(format!(
                "expected Welcome, got {}",
                welcome.payload.kind_name()
            ));
        };

        if device_id != &self.device_id {
            return Err(format!("welcome for wrong device: {device_id}"));
        }
        if reply_nonce != &nonce {
            return Err("welcome nonce mismatch".into());
        }

        let vk = himan_proto::VerifyingKey::from_b64(orchestrator_key)
            .map_err(|e| format!("bad orchestrator key: {e}"))?;
        welcome
            .verify_with(&vk)
            .map_err(|e| format!("welcome signature invalid: {e}"))?;

        Ok(RegisteredAgent {
            stream,
            key: self.key,
            device_id: self.device_id,
        })
    }
}

/// A registered agent, ready to receive tool calls.
struct RegisteredAgent {
    stream: tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    key: SigningKey,
    device_id: DeviceId,
}

impl RegisteredAgent {
    /// Send a signed ToolResult back to the orchestrator.
    async fn send_result(
        &mut self,
        task_id: &str,
        state: TaskState,
        output: &str,
    ) -> Result<(), String> {
        use futures_util::SinkExt;
        let meta = WireMeta {
            seq: 2,
            ts: chrono::Utc::now().timestamp(),
            from: self.device_id.clone(),
            to: "orchestrator".into(),
        };
        let msg = WireMessage::sign(
            meta,
            Payload::ToolResult {
                task_id: himan_proto::TaskId::new(task_id),
                state,
                output: output.to_owned(),
            },
            &self.key,
        )
        .map_err(|e| e.to_string())?;
        let json = serde_json::to_string(&msg).map_err(|e| e.to_string())?;
        self.stream
            .send(tokio_tungstenite::tungstenite::Message::Text(json.into()))
            .await
            .map_err(|e| e.to_string())
    }

    fn verifying_key(&self) -> String {
        self.key.verifying_key().to_b64()
    }
}

/// Spawn the orchestrator on an ephemeral port and return its URL plus a
/// handle to inspect the hub.
async fn spawn_orchestrator() -> (String, Arc<Hub>, u16) {
    let hub = Hub::new(HubConfig::default());
    let app = himan_orchestrator::router(hub.clone(), HubConfig::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let port = listener.local_addr().expect("local addr").port();

    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    wait_for_server(port).await;
    (format!("ws://127.0.0.1:{port}/ws"), hub, port)
}

/// The Phase 1 exit check, as an automated test.
#[tokio::test]
async fn orchestrator_agent_round_trip() {
    let (url, hub, _port) = spawn_orchestrator().await;

    // 1. A real agent connects over a real WebSocket and registers.
    let agent = TestAgent::new("pc-1")
        .connect(&url)
        .await
        .expect("agent should register");
    assert_eq!(agent.device_id.as_str(), "pc-1");

    // 2. The orchestrator actually knows about it. This is the assertion the
    //    manual curl was for, and the one the echo bug defeated.
    let agents = hub.agents().await;
    assert_eq!(agents.len(), 1, "registered agent must appear in the hub");
    assert_eq!(agents[0].id.as_str(), "pc-1");
    assert_eq!(agents[0].verifying_key, agent.verifying_key());

    // 3. A prompt dispatches a tool call to that agent.
    let device_id = DeviceId::new("pc-1");
    let result = hub
        .dispatch(&device_id, "status")
        .await
        .expect("dispatch should succeed");
    assert_eq!(result.decision, "allow", "read-only tool must be allowed");
    assert_eq!(result.state, "running");
    let task_id = result.task_id;

    // 4. The agent answers with a signed ToolResult carrying real host data.
    //    The test agent simulates the PC agent's device_status tool.
    let mut agent = agent;
    agent
        .send_result(
            &task_id,
            TaskState::Succeeded,
            "pc-1: CPU 21.6%, memory 10211/16016 MB",
        )
        .await
        .expect("send tool result");

    // 5. Give the server a moment to process the result.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // 6. The hub recorded the outcome.
    let state = hub.task(&himan_proto::TaskId::new(&task_id)).await;
    assert_eq!(
        state,
        Some(TaskState::Succeeded),
        "hub must record the result"
    );

    // 7. The audit log shows the registration and the dispatch.
    let audit = hub.audit_events().await;
    let actions: Vec<&str> = audit.iter().map(|e| e.action.as_str()).collect();
    assert!(
        actions.contains(&"agent_registered"),
        "audit must record registration, got {actions:?}"
    );
    assert!(
        actions.contains(&"tool_call_policy"),
        "audit must record the dispatch, got {actions:?}"
    );
    assert!(
        actions.contains(&"tool_result"),
        "audit must record the result, got {actions:?}"
    );
}

/// A destructive tool is refused before it reaches the agent.
#[tokio::test]
async fn destructive_tool_is_denied_over_the_wire() {
    let (url, hub, _port) = spawn_orchestrator().await;

    let _agent = TestAgent::new("pc-1")
        .connect(&url)
        .await
        .expect("agent should register");

    let result = hub
        .dispatch(&DeviceId::new("pc-1"), "diagnose")
        .await
        .expect("dispatch should return a decision");
    assert_eq!(result.decision, "deny");
    assert_eq!(result.state, "failed");
}

/// An agent that connects but never sends a valid Hello is not registered.
#[tokio::test]
async fn unregistered_agent_cannot_receive_work() {
    let (url, hub, _port) = spawn_orchestrator().await;

    // Connect at the WebSocket level but send garbage.
    let (transport, _resp) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("ws connect");
    let mut stream = transport;
    use futures_util::SinkExt;
    stream
        .send(tokio_tungstenite::tungstenite::Message::Text(
            json!({"junk": true}).to_string().into(),
        ))
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(200)).await;

    assert!(
        hub.agents().await.is_empty(),
        "an agent that never sent a valid Hello must not be registered"
    );
}

/// The orchestrator rejects a dispatch to an unknown device.
#[tokio::test]
async fn dispatch_to_unknown_device_fails() {
    let (_url, hub, _port) = spawn_orchestrator().await;
    let err = hub
        .dispatch(&DeviceId::new("ghost"), "status")
        .await
        .expect_err("unknown device must fail");
    assert!(err.to_string().contains("not connected"));
}
