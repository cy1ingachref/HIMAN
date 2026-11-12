//! Transport abstraction.
//!
//! Phase 1 goal: the agent loop must be testable without a network. So the
//! wire is a trait, and `Connection::channel` provides a paired in-memory
//! implementation with backpressure, explicit close, and a shutdown handle
//! that unblocks readers.
//!
//! `transport::ws` is the real WebSocket implementation. The orchestrator-side
//! hub lives in the orchestrator crate because it needs axum's connection
//! state.

use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::{mpsc, Mutex, Notify};

use himan_proto::WireMessage;

/// One direction of a connection.
#[async_trait]
pub trait Sender: Send + Sync {
    async fn send(&self, msg: WireMessage) -> Result<(), TransportError>;
}

/// The receiving half of a connection: a stream of incoming messages.
pub type Receiver = mpsc::Receiver<WireMessage>;

/// Signals that a connection direction is finished, so blocked readers wake.
///
/// Per direction, not per connection: A closing its send side must not stop B
/// from sending to A. `close()` on a connection marks both directions, but a
/// dropped sender only marks its own direction.
///
/// Uses an `AtomicBool` plus `Notify::enable()` rather than a mutex-guarded
/// flag: `notify_waiters()` only wakes waiters that have already registered,
/// so a flag check must not be the sole guard against the lost-wakeup race.
#[derive(Debug, Default)]
pub struct Shutdown {
    notify: Notify,
    stopped: std::sync::atomic::AtomicBool,
}

impl Shutdown {
    /// Mark finished. Idempotent.
    pub async fn stop(&self) {
        if !self.stopped.swap(true, std::sync::atomic::Ordering::SeqCst) {
            self.notify.notify_waiters();
        }
    }

    /// Resolve immediately if already stopped, otherwise wait for stop.
    async fn cancelled(&self) {
        let notified = self.notify.notified();
        tokio::pin!(notified);
        // Register the waiter before re-checking the flag, so a stop() that
        // lands between the check and the await still wakes us.
        notified.as_mut().enable();
        if self.stopped.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        notified.await;
    }
}

/// A bidirectional in-memory connection handle.
///
/// Each side owns a sender and a receiver. `close()` shuts down both
/// directions for this side: outgoing sends keep working (the peer may still
/// want to reply) but local reads stop.
#[derive(Clone, Debug)]
pub struct Connection {
    sender: SenderKind,
    receiver: Arc<Mutex<Receiver>>,
    /// Guards the local read side.
    read_shutdown: Arc<Shutdown>,
    /// Guards the send side; dropped sender marks this stopped.
    send_shutdown: Arc<Shutdown>,
}

#[derive(Clone, Debug)]
enum SenderKind {
    Channel(mpsc::Sender<WireMessage>),
    Socket(Arc<WsTransport>),
}

impl Connection {
    /// Create a paired in-memory connection. Side A's sent messages arrive on
    /// side B and vice versa.
    pub fn channel(capacity: usize) -> (Self, Self) {
        let (a_tx, b_rx) = mpsc::channel::<WireMessage>(capacity);
        let (b_tx, a_rx) = mpsc::channel::<WireMessage>(capacity);

        let a = Connection {
            sender: SenderKind::Channel(a_tx),
            receiver: Arc::new(Mutex::new(a_rx)),
            read_shutdown: Arc::new(Shutdown::default()),
            send_shutdown: Arc::new(Shutdown::default()),
        };
        let b = Connection {
            sender: SenderKind::Channel(b_tx),
            receiver: Arc::new(Mutex::new(b_rx)),
            read_shutdown: Arc::new(Shutdown::default()),
            send_shutdown: Arc::new(Shutdown::default()),
        };
        (a, b)
    }

    /// Wrap an existing sender/receiver pair. Used by the WebSocket adapter,
    /// where both directions are driven by one socket and share a shutdown.
    pub fn from_parts(
        sender: mpsc::Sender<WireMessage>,
        receiver: Receiver,
        shutdown: Arc<Shutdown>,
    ) -> Self {
        Self {
            sender: SenderKind::Channel(sender),
            receiver: Arc::new(Mutex::new(receiver)),
            read_shutdown: shutdown.clone(),
            send_shutdown: shutdown,
        }
    }

    /// Wrap a socket-backed sender with a channel receiver.
    ///
    /// Outgoing messages go straight to the socket; incoming messages are
    /// pumped into the receiver by the caller. Mixing the two directions
    /// through one channel would let a peer read its own messages back.
    ///
    /// `WsTransport` guards its sink and stream with separate locks, so the
    /// transport itself is the synchronization point; no outer mutex here.
    pub fn from_socket(
        transport: Arc<WsTransport>,
        receiver: Receiver,
        shutdown: Arc<Shutdown>,
    ) -> Self {
        Self {
            sender: SenderKind::Socket(transport),
            receiver: Arc::new(Mutex::new(receiver)),
            read_shutdown: shutdown.clone(),
            send_shutdown: shutdown,
        }
    }

    pub async fn send(&self, msg: WireMessage) -> Result<(), TransportError> {
        match &self.sender {
            SenderKind::Channel(tx) => tx.send(msg).await.map_err(|_| TransportError::Closed),
            SenderKind::Socket(transport) => transport.send_message(&msg).await,
        }
    }

    /// Read the next message. Returns `None` when the peer is gone or the
    /// connection was shut down.
    pub async fn recv(&self) -> Option<WireMessage> {
        let mut guard = self.receiver.lock().await;
        tokio::select! {
            biased;
            _ = self.read_shutdown.cancelled() => None,
            msg = guard.recv() => match msg {
                Some(m) => Some(m),
                None => {
                    // Peer's sender dropped: this direction is finished.
                    self.read_shutdown.stop().await;
                    None
                }
            },
        }
    }

    /// Shut down this side. Blocked `recv` calls wake and return `None`.
    /// Idempotent; safe to call from any task.
    pub async fn close(&self) {
        self.read_shutdown.stop().await;
        self.send_shutdown.stop().await;
    }

    pub fn sender(&self) -> Option<&mpsc::Sender<WireMessage>> {
        match &self.sender {
            SenderKind::Channel(tx) => Some(tx),
            SenderKind::Socket(_) => None,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("connection is closed")]
    Closed,
    #[error("serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("websocket error: {0}")]
    WebSocket(String),
    #[error("timeout")]
    Timeout,
}

/// Real WebSocket transport.
pub mod ws;
pub use ws::WsTransport;

#[cfg(test)]
mod tests {
    use super::*;
    use himan_proto::signing::SigningKey;
    use himan_proto::{DeviceId, Payload, WireMeta};

    fn msg(seq: u64, nonce: u64) -> WireMessage {
        let sk = SigningKey::generate();
        let meta = WireMeta {
            seq,
            ts: 1_700_000_000,
            from: DeviceId::new("pc-1"),
            to: "orchestrator".into(),
        };
        WireMessage::sign(meta, Payload::Ping { nonce }, &sk).unwrap()
    }

    #[tokio::test]
    async fn duplex_delivers_in_order() {
        let (a, b) = Connection::channel(8);
        for i in 0..5 {
            a.send(msg(i, i)).await.unwrap();
        }
        for i in 0..5 {
            let got = b.recv().await.expect("message");
            assert_eq!(got.meta.seq, i);
        }
    }

    #[tokio::test]
    async fn duplex_is_bidirectional() {
        let (a, b) = Connection::channel(8);
        a.send(msg(1, 1)).await.unwrap();
        b.send(msg(2, 2)).await.unwrap();
        assert_eq!(b.recv().await.unwrap().meta.seq, 1);
        assert_eq!(a.recv().await.unwrap().meta.seq, 2);
    }

    #[tokio::test]
    async fn recv_returns_none_when_peer_drops() {
        let (a, b) = Connection::channel(8);
        a.send(msg(1, 1)).await.unwrap();
        drop(a); // sender gone -> b's recv must end
        assert_eq!(b.recv().await.unwrap().meta.seq, 1);
        assert!(b.recv().await.is_none());
    }

    #[tokio::test]
    async fn close_unblocks_a_pending_recv() {
        // `_a` is held on purpose: dropping it would close the channel and
        // make the test pass for the wrong reason.
        let (_a, b) = Connection::channel(8);
        let reader = tokio::spawn({
            let b = b.clone();
            async move { b.recv().await }
        });
        tokio::task::yield_now().await;
        assert!(!reader.is_finished());

        b.close().await;
        let got = tokio::time::timeout(std::time::Duration::from_secs(2), reader)
            .await
            .expect("recv must unblock")
            .expect("task must not panic");
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn close_does_not_stop_the_peer_from_sending() {
        // Closing A stops A's local reads, but must not break B's ability to
        // send. B's send must succeed (the channel is still open).
        let (a, b) = Connection::channel(8);
        a.close().await;
        b.send(msg(7, 7)).await.expect("peer can still send");
        // A's reads are closed, so nothing is delivered to A.
        assert!(a.recv().await.is_none());
    }

    #[tokio::test]
    async fn bounded_channel_applies_backpressure() {
        let (a, b) = Connection::channel(1);
        a.send(msg(1, 1)).await.unwrap();
        let third = tokio::spawn({
            let a = a.clone();
            async move { a.send(msg(2, 2)).await }
        });
        tokio::task::yield_now().await;
        assert!(!third.is_finished());
        let _ = b.recv().await;
        tokio::time::timeout(std::time::Duration::from_secs(2), third)
            .await
            .expect("send should unblock")
            .expect("task should not panic")
            .expect("send should succeed");
    }

    #[tokio::test]
    async fn shutdown_is_idempotent() {
        let (a, _b) = Connection::channel(8);
        a.close().await;
        a.close().await;
        a.close().await;
        assert!(a.recv().await.is_none());
        // Still stopped after repeated calls.
        assert!(a.recv().await.is_none());
    }

    #[tokio::test]
    async fn close_is_safe_without_a_peer_reader() {
        let (a, _b) = Connection::channel(8);
        a.close().await;
        assert!(a.recv().await.is_none());
    }
}
