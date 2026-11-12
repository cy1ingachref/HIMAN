//! WebSocket client transport.
//!
//! Thin wrapper over `tokio-tungstenite` with `rustls`. Messages cross as
//! JSON text frames, one `WireMessage` per frame.

use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message as WsMessage;

use crate::transport::{Connection, Sender, Shutdown, TransportError};
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

/// Adapter so `WsTransport` satisfies the `Sender` trait used by
/// `Connection`.
pub struct WsSender {
    inner: std::sync::Arc<WsTransport>,
}

impl WsSender {
    pub fn new(inner: std::sync::Arc<WsTransport>) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl Sender for WsSender {
    async fn send(&self, msg: WireMessage) -> Result<(), TransportError> {
        self.inner.send_message(&msg).await
    }
}

/// Build a `Connection` around a WebSocket by pumping `next_message` into a
/// channel. This is the bridge that lets the socket transport reuse the same
/// agent loop as the in-memory duplex.
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

    Connection::from_parts(tx, rx, shutdown)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ws_transport_is_constructible() {
        // No server needed: just proving the type is usable and errors are
        // reported rather than panicking on a refused connection.
        let result = WsTransport::connect("ws://127.0.0.1:1/nope").await;
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("websocket"), "unexpected error: {msg}");
    }
}
