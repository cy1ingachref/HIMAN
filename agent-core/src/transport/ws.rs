//! WebSocket client transport.
//!
//! Thin wrapper over `tokio-tungstenite` with `rustls`. Messages cross as
//! JSON text frames, one `WireMessage` per frame.

use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message as WsMessage;

use crate::transport::{Connection, Shutdown, TransportError};
use himan_proto::WireMessage;

/// A WebSocket connection to an orchestrator.
#[derive(Debug)]
pub struct WsTransport {
    sink: tokio::sync::Mutex<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    >,
}

impl WsTransport {
    /// Connect to `url` (e.g. `ws://127.0.0.1:8787/ws`).
    pub async fn connect(url: &str) -> Result<Self, TransportError> {
        let (stream, _response) = tokio_tungstenite::connect_async(url)
            .await
            .map_err(|e| TransportError::WebSocket(e.to_string()))?;
        Ok(Self {
            sink: tokio::sync::Mutex::new(stream),
        })
    }

    /// Wrap an already-connected stream (used by tests).
    pub fn from_stream(
        stream: tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    ) -> Self {
        Self {
            sink: tokio::sync::Mutex::new(stream),
        }
    }

    /// Read one message. Returns `None` on clean close.
    pub async fn next_message(&self) -> Option<Result<WireMessage, TransportError>> {
        let mut guard = self.sink.lock().await;
        loop {
            match guard.next().await {
                Some(Ok(WsMessage::Text(text))) => {
                    return Some(serde_json::from_str(&text).map_err(TransportError::from));
                }
                Some(Ok(WsMessage::Binary(bin))) => {
                    return Some(serde_json::from_slice(&bin).map_err(TransportError::from));
                }
                Some(Ok(WsMessage::Close(_))) | None => return None,
                Some(Ok(_)) => continue, // ping/pong/frame — handled by tungstenite
                Some(Err(e)) => return Some(Err(TransportError::WebSocket(e.to_string()))),
            }
        }
    }

    /// Send a message.
    pub async fn send_message(&self, msg: &WireMessage) -> Result<(), TransportError> {
        let json = serde_json::to_string(msg)?;
        let mut guard = self.sink.lock().await;
        guard
            .send(WsMessage::Text(json.into()))
            .await
            .map_err(|e| TransportError::WebSocket(e.to_string()))
    }

    /// Close the connection.
    pub async fn close(&self) {
        let mut guard = self.sink.lock().await;
        let _ = guard.close(None).await;
    }
}

/// Build a `Connection` around a WebSocket by pumping `next_message` into a
/// channel.
///
/// The `Sender` impl must go to the socket, not into the receive channel:
/// routing outgoing messages through the pump would make an agent read its own
/// messages back, which is exactly the bug this design avoids.
pub fn connection_from_socket(
    transport: std::sync::Arc<WsTransport>,
    capacity: usize,
) -> Connection {
    let (tx, rx) = tokio::sync::mpsc::channel::<WireMessage>(capacity);
    let shutdown = std::sync::Arc::new(Shutdown::default());

    tokio::spawn({
        let transport = transport.clone();
        let shutdown = shutdown.clone();
        let tx = tx.clone();
        async move {
            while let Some(result) = transport.next_message().await {
                match result {
                    Ok(msg) => {
                        if tx.send(msg).await.is_err() {
                            break; // receiver dropped
                        }
                    }
                    Err(_) => break, // protocol or socket error ends the pump
                }
            }
            shutdown.stop().await;
        }
    });

    Connection::from_socket(transport, rx, shutdown)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    /// The socket adapter must not feed a peer's outbound messages back into
    /// its own inbound channel. This is the direction test that the original
    /// echo bug defeated: with the bug, the agent read its own Hello.
    #[tokio::test]
    async fn socket_adapter_does_not_echo_outbound_messages() {
        // A real loopback WebSocket server: echoes nothing, just records
        // whatever it receives.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let received = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::<String>::new()));
        let received_clone = received.clone();

        let server = tokio::spawn(async move {
            use futures_util::StreamExt;
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            while let Some(Ok(msg)) = ws.next().await {
                if let tokio_tungstenite::tungstenite::Message::Text(t) = msg {
                    received_clone.lock().await.push(t.to_string());
                }
            }
        });

        // Connect through the real transport.
        let url = format!("ws://{addr}/");
        let transport =
            std::sync::Arc::new(crate::transport::WsTransport::connect(&url).await.unwrap());
        let conn = crate::transport::ws::connection_from_socket(transport, 8);

        // Send one message from the agent.
        let sk = himan_proto::SigningKey::generate();
        let msg = himan_proto::WireMessage::sign(
            himan_proto::WireMeta {
                seq: 1,
                ts: chrono::Utc::now().timestamp(),
                from: himan_proto::DeviceId::new("pc-1"),
                to: "orchestrator".into(),
            },
            himan_proto::Payload::Ping { nonce: 42 },
            &sk,
        )
        .unwrap();
        conn.send(msg).await.unwrap();

        // The server must have received it.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let got = received.lock().await;
        assert_eq!(got.len(), 1, "server must receive exactly one frame");
        assert!(
            got[0].contains("\"nonce\":42"),
            "frame must carry our nonce"
        );

        // And the agent must NOT receive its own message back: recv() would
        // hang if the echo bug were present, so the timeout proves absence.
        let echoed = tokio::time::timeout(std::time::Duration::from_millis(300), conn.recv()).await;
        assert!(
            echoed.is_err(),
            "socket adapter must not echo outbound messages back to the sender"
        );

        server.abort();
    }

    #[tokio::test]
    async fn socket_adapter_delivers_inbound_messages() {
        // Same setup, but the server sends a message and the agent must
        // receive it. Proves the inbound direction works independently.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            use futures_util::{SinkExt, StreamExt};
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            // Wait for the agent's frame, then reply with a Pong.
            let ping = tokio::time::timeout(Duration::from_secs(3), ws.next())
                .await
                .expect("server should receive the agent's frame")
                .expect("stream open")
                .expect("valid frame");
            assert!(
                ping.to_string().contains("\"nonce\":42"),
                "server got the agent's ping, got {ping}"
            );

            let sk = himan_proto::SigningKey::generate();
            let msg = himan_proto::WireMessage::sign(
                himan_proto::WireMeta {
                    seq: 1,
                    ts: chrono::Utc::now().timestamp(),
                    from: himan_proto::DeviceId::new("orchestrator"),
                    to: "pc-1".into(),
                },
                himan_proto::Payload::Pong { nonce: 7 },
                &sk,
            )
            .unwrap();
            let json = serde_json::to_string(&msg).unwrap();
            ws.send(tokio_tungstenite::tungstenite::Message::Text(json.into()))
                .await
                .unwrap();
            // Keep the socket open long enough for the client to read the reply.
            tokio::time::sleep(Duration::from_millis(500)).await;
        });

        let url = format!("ws://{addr}/");
        let transport =
            std::sync::Arc::new(crate::transport::WsTransport::connect(&url).await.unwrap());
        let conn = crate::transport::ws::connection_from_socket(transport, 8);

        let sk = himan_proto::SigningKey::generate();
        conn.send(
            himan_proto::WireMessage::sign(
                himan_proto::WireMeta {
                    seq: 1,
                    ts: chrono::Utc::now().timestamp(),
                    from: himan_proto::DeviceId::new("pc-1"),
                    to: "orchestrator".into(),
                },
                himan_proto::Payload::Ping { nonce: 42 },
                &sk,
            )
            .unwrap(),
        )
        .await
        .unwrap();

        let got = tokio::time::timeout(std::time::Duration::from_secs(3), conn.recv())
            .await
            .expect("inbound message must arrive")
            .expect("some message");
        match got.payload {
            himan_proto::Payload::Pong { nonce } => assert_eq!(nonce, 7),
            other => panic!("expected Pong, got {}", other.kind_name()),
        }

        server.abort();
    }
}
