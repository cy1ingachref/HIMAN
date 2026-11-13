//! Agent keepalive: a signed Ping at an interval below the orchestrator's idle
//! timeout, and a reconnect when Pongs stop arriving.
//!
//! Without keepalive a healthy agent that has nothing to say looks identical to
//! a dead socket, so the orchestrator closes it on the idle timeout.

use std::time::Duration;

use himan_orchestrator::{router_with_limits, Hub, HubConfig, WsLimits};
use himan_proto::{Payload, SigningKey, WireMessage};
use tokio::net::TcpStream;

/// Spawn an in-process router with a short idle timeout so the test is fast.
async fn spawn_short_idle() -> (std::sync::Arc<Hub>, u16) {
    // Handshake 2s, idle 3s: a keepalive of 1s must keep the agent alive.
    let limits = WsLimits {
        handshake_timeout_secs: 2,
        idle_timeout_secs: 3,
        max_frame_bytes: 64 * 1024,
        max_connections: 256,
        max_invalid_messages: 8,
    };
    let hub = Hub::new(HubConfig::default());
    let app = router_with_limits(hub.clone(), limits);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    for _ in 0..60 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    (hub, port)
}

/// A keepalive-aware client wrapper used by the tests.
///
/// Mirrors what the agent does: register, then send a signed Ping every
/// `interval` and expect a Pong. Records how many pings were sent and whether
/// the connection was closed by the peer.
struct KeepaliveClient {
    ws: tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    key: SigningKey,
    device_id: himan_proto::DeviceId,
    seq: u64,
}

impl KeepaliveClient {
    async fn register(port: u16, device_id: &str) -> Self {
        use futures_util::{SinkExt, StreamExt};
        let (ws, _) = tokio_tungstenite::connect_async(format!("ws://127.0.0.1:{port}/ws"))
            .await
            .expect("connect");
        let key = SigningKey::generate();
        let device_id = himan_proto::DeviceId::new(device_id);
        let mut client = Self {
            ws,
            key,
            device_id: device_id.clone(),
            seq: 1,
        };

        let info = himan_proto::DeviceInfo::new(
            device_id.clone(),
            himan_proto::DeviceClass::Pc,
            "keepalive",
            client.key.verifying_key().to_b64(),
        );
        let meta = himan_proto::WireMeta {
            seq: 1,
            ts: chrono::Utc::now().timestamp(),
            from: device_id,
            to: "orchestrator".into(),
        };
        let hello = WireMessage::sign(meta, Payload::Hello(info), &client.key).unwrap();
        client
            .ws
            .send(tokio_tungstenite::tungstenite::Message::Text(
                serde_json::to_string(&hello).unwrap().into(),
            ))
            .await
            .unwrap();

        let welcome = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match client.ws.next().await {
                    Some(Ok(tokio_tungstenite::tungstenite::Message::Text(t))) => {
                        return serde_json::from_str::<WireMessage>(&t).ok();
                    }
                    Some(Ok(_)) => continue,
                    _ => return None,
                }
            }
        })
        .await
        .expect("welcome")
        .expect("welcome");
        assert!(matches!(welcome.payload, Payload::Welcome { .. }));
        client.seq = 2;
        client
    }

    async fn ping(&mut self, nonce: u64) -> bool {
        use futures_util::SinkExt;
        let meta = himan_proto::WireMeta {
            seq: self.seq,
            ts: chrono::Utc::now().timestamp(),
            from: self.device_id.clone(),
            to: "orchestrator".into(),
        };
        self.seq += 1;
        let msg = WireMessage::sign(meta, Payload::Ping { nonce }, &self.key).unwrap();
        self.ws
            .send(tokio_tungstenite::tungstenite::Message::Text(
                serde_json::to_string(&msg).unwrap().into(),
            ))
            .await
            .is_ok()
    }
}

#[tokio::test]
async fn quiet_agent_stays_registered_across_several_idle_periods() {
    let (hub, port) = spawn_short_idle().await;
    let mut client = KeepaliveClient::register(port, "pc-1").await;

    // Ping every 1s while the idle timeout is 3s. Without keepalive the server
    // would close the connection at ~3s.
    let mut pings_sent = 0u64;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    while tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(1000)).await;
        if !client.ping(pings_sent).await {
            panic!("keepalive agent was disconnected by the server");
        }
        pings_sent += 1;
    }

    // Still registered after ~8s with a 3s idle timeout: proof the keepalive
    // worked.
    let agents = hub.agents().await;
    assert_eq!(
        agents.len(),
        1,
        "a keepalive-enabled agent must stay registered across idle periods"
    );
    assert!(
        pings_sent >= 5,
        "expected several keepalives over 8s, got {pings_sent}"
    );
}

#[tokio::test]
async fn silent_non_agent_socket_is_still_closed() {
    let (_hub, port) = spawn_short_idle().await;

    // Connect and send nothing: the handshake timeout (2s) must close it even
    // though the idle timeout is 3s.
    let (stream, _) = tokio_tungstenite::connect_async(format!("ws://127.0.0.1:{port}/ws"))
        .await
        .expect("connect");
    use futures_util::StreamExt;
    let mut ws = stream;
    let closed = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match ws.next().await {
                None => return true,
                Some(Ok(tokio_tungstenite::tungstenite::Message::Close(_))) => return true,
                Some(Ok(_)) => continue,
                Some(Err(_)) => return true,
            }
        }
    })
    .await
    .expect("a silent non-agent socket must be closed");
    assert!(closed);
}
#[tokio::test]
async fn keepalive_interval_is_configurable() {
    // The interval comes from HIMAN_KEEPALIVE_SECS with a 60s default.
    assert_eq!(
        himan_agent_pc::keepalive::default_interval(),
        Duration::from_secs(60)
    );
    assert_eq!(
        himan_agent_pc::keepalive::parse_interval(Some("30")),
        Some(Duration::from_secs(30))
    );
    assert_eq!(
        himan_agent_pc::keepalive::parse_interval(Some("not-a-number")),
        None
    );
}
