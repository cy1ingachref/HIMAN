//! WebSocket client transport.
//!
//! Thin wrapper over `tokio-tungstenite` with `rustls`. Messages cross as
//! JSON text frames, one `WireMessage` per frame.
//!
//! The read half is NOT behind the sink mutex. A reader parked on
//! `stream.next().await` blocks until a frame arrives, so putting it under the
//! same lock as writes makes `send()` wait forever.
//!
//! That was a real bug. The first version wrapped the whole socket in one
//! `Mutex<WebSocketStream>`; the read pump held that lock across
//! `.next().await`, so `send_message()` never acquired it and the Hello was
//! never written. It presented as an intermittent hang that depended on which
//! task won the lock race — it passed when the agent was launched from a
//! terminal and failed when launched from Python.

use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message as WsMessage;

use crate::transport::{Connection, Shutdown, TransportError};
use himan_proto::WireMessage;

/// A WebSocket connection to an orchestrator.
///
/// `sink` is mutex-guarded because writes are serialized. `stream` is not
/// guarded because a pending read must not block a write.
#[derive(Debug)]
pub struct WsTransport {
    sink: tokio::sync::Mutex<SocketSink>,
    stream: tokio::sync::Mutex<SocketStream>,
}

/// The write half of a connected WebSocket.
pub type SocketSink = futures_util::stream::SplitSink<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    WsMessage,
>;

/// The read half of a connected WebSocket.
pub type SocketStream = futures_util::stream::SplitStream<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
>;

impl WsTransport {
    /// Connect to `url` (e.g. `ws://127.0.0.1:8787/ws`) and split the socket.
    pub async fn connect(url: &str) -> Result<Self, TransportError> {
        let (socket, _response) = tokio_tungstenite::connect_async(url)
            .await
            .map_err(|e| TransportError::WebSocket(e.to_string()))?;
        Ok(Self::from_socket(socket))
    }

    /// Wrap an already-connected socket by splitting it.
    pub fn from_socket(
        socket: tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    ) -> Self {
        let (sink, stream) = socket.split();
        Self {
            sink: tokio::sync::Mutex::new(sink),
            stream: tokio::sync::Mutex::new(stream),
        }
    }

    /// Send a message. Takes the sink lock only for the duration of the write.
    pub async fn send_message(&self, msg: &WireMessage) -> Result<(), TransportError> {
        let json = serde_json::to_string(msg)?;
        let mut sink = self.sink.lock().await;
        sink.send(WsMessage::Text(json.into()))
            .await
            .map_err(|e| TransportError::WebSocket(e.to_string()))
    }

    /// Read one message. Returns `None` on clean close.
    ///
    /// Callers hold the stream lock while awaiting a frame. That is safe only
    /// because the sink is a separate lock.
    pub async fn next_message(&self) -> Option<Result<WireMessage, TransportError>> {
        let mut stream = self.stream.lock().await;
        loop {
            match stream.next().await {
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

    /// Close the connection.
    pub async fn close(&self) {
        let mut sink = self.sink.lock().await;
        let _ = sink.close().await;
    }
}

/// Build a `Connection` around a WebSocket.
///
/// Outgoing messages go to the socket's sink half; incoming frames are pumped
/// into the receive channel from the stream half. The two directions use
/// separate locks, so a parked reader cannot block a writer.
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
                    Err(_) => break,
                }
            }
            shutdown.stop().await;
        }
    });

    Connection::from_socket(transport, rx, shutdown)
}

#[cfg(test)]
mod tests {
    use super::*;
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

        let url = format!("ws://{addr}/");
        let transport = std::sync::Arc::new(WsTransport::connect(&url).await.unwrap());
        let conn = crate::transport::ws::connection_from_socket(transport, 8);

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

        tokio::time::sleep(Duration::from_millis(300)).await;
        let got = received.lock().await;
        assert_eq!(got.len(), 1, "server must receive exactly one frame");
        assert!(
            got[0].contains("\"nonce\":42"),
            "frame must carry our nonce"
        );

        // And the agent must NOT receive its own message back.
        let echoed = tokio::time::timeout(Duration::from_millis(300), conn.recv()).await;
        assert!(
            echoed.is_err(),
            "socket adapter must not echo outbound messages back to the sender"
        );

        server.abort();
    }

    #[tokio::test]
    async fn socket_adapter_delivers_inbound_messages() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            use futures_util::{SinkExt, StreamExt};
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();

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
            tokio::time::sleep(Duration::from_millis(500)).await;
        });

        let url = format!("ws://{addr}/");
        let transport = std::sync::Arc::new(WsTransport::connect(&url).await.unwrap());
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

        let got = tokio::time::timeout(Duration::from_secs(3), conn.recv())
            .await
            .expect("inbound message must arrive")
            .expect("some message");
        match got.payload {
            himan_proto::Payload::Pong { nonce } => assert_eq!(nonce, 7),
            other => panic!("expected Pong, got {}", other.kind_name()),
        }

        server.abort();
    }

    /// A parked reader must not block a writer.
    ///
    /// Regression test for the deadlock where one mutex covered both halves
    /// and the read pump held it across `.next().await`, so `send()` never
    /// acquired it and the Hello was never written.
    #[tokio::test]
    async fn parked_reader_does_not_block_the_writer() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            use futures_util::{SinkExt, StreamExt};
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let _ = tokio::time::timeout(Duration::from_secs(3), ws.next()).await;
            for nonce in 1..=2 {
                let sk = himan_proto::SigningKey::generate();
                let msg = himan_proto::WireMessage::sign(
                    himan_proto::WireMeta {
                        seq: nonce,
                        ts: chrono::Utc::now().timestamp(),
                        from: himan_proto::DeviceId::new("orchestrator"),
                        to: "pc-1".into(),
                    },
                    himan_proto::Payload::Pong { nonce },
                    &sk,
                )
                .unwrap();
                ws.send(tokio_tungstenite::tungstenite::Message::Text(
                    serde_json::to_string(&msg).unwrap().into(),
                ))
                .await
                .unwrap();
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        });

        let url = format!("ws://{addr}/");
        let transport = std::sync::Arc::new(WsTransport::connect(&url).await.unwrap());
        let conn = crate::transport::ws::connection_from_socket(transport, 8);

        // Park a reader, then send. With the shared-lock bug this deadlocks.
        let reader = tokio::spawn({
            let conn = conn.clone();
            async move { conn.recv().await }
        });
        tokio::task::yield_now().await;

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
        .expect("send must not deadlock while the reader is parked");

        let got = tokio::time::timeout(Duration::from_secs(3), reader)
            .await
            .expect("reader must finish")
            .expect("task must not panic")
            .expect("inbound message must arrive");
        match got.payload {
            himan_proto::Payload::Pong { .. } => {}
            other => panic!("expected Pong, got {}", other.kind_name()),
        }

        server.abort();
    }
}
