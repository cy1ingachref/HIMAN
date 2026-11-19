//! A small async TCP proxy that adds latency, jitter and loss.
//!
//! Used by the metrics run to measure the handoff beyond loopback. It is
//! deliberately portable: no `tc`, no root, no platform-specific sockets. It
//! sits between the agents and the orchestrator and delays or drops bytes on
//! the way through.
//!
//! Loss is modelled per chunk, not per TCP segment: dropping a chunk of a
//! WebSocket stream desynchronises the framing, which is what a real lossy link
//! does to a connection that has no retransmission at this layer. That is the
//! honest behaviour to measure — the handoff must either survive it or roll
//! back, and the metric records which.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// How the proxy perturbs the traffic.
#[derive(Debug, Clone, Copy)]
pub struct Impairment {
    /// One-way delay added to every chunk, in milliseconds.
    pub latency_ms: u64,
    /// Uniform random extra delay in `[0, jitter_ms]`.
    pub jitter_ms: u64,
    /// Fraction of chunks dropped, in `[0.0, 1.0]`.
    pub loss: f64,
}

impl Impairment {
    /// A clean link: the proxy still runs, so the comparison is apples to apples.
    pub fn none() -> Self {
        Self {
            latency_ms: 0,
            jitter_ms: 0,
            loss: 0.0,
        }
    }

    pub fn latency(ms: u64) -> Self {
        Self {
            latency_ms: ms,
            // A quarter of the base latency, so the jitter is visible but does
            // not dominate the measurement.
            jitter_ms: ms / 4,
            loss: 0.0,
        }
    }
}

/// A running proxy. Dropping it stops accepting; in-flight connections finish.
pub struct Proxy {
    pub port: u16,
    pub forwarded: Arc<AtomicU64>,
    pub dropped: Arc<AtomicU64>,
    shutdown: tokio::sync::watch::Sender<bool>,
}

impl Proxy {
    /// Listen on an ephemeral port and forward to `target_port`.
    pub async fn start(target_port: u16, impairment: Impairment) -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let forwarded = Arc::new(AtomicU64::new(0));
        let dropped = Arc::new(AtomicU64::new(0));
        let (shutdown, mut rx) = tokio::sync::watch::channel(false);

        let fwd = forwarded.clone();
        let drp = dropped.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = rx.changed() => break,
                    accepted = listener.accept() => {
                        let Ok((client, _)) = accepted else { continue };
                        let fwd = fwd.clone();
                        let drp = drp.clone();
                        tokio::spawn(async move {
                            let Ok(server) = TcpStream::connect(("127.0.0.1", target_port)).await
                            else { return };
                            let _ = pipe(client, server, impairment, fwd, drp).await;
                        });
                    }
                }
            }
        });

        Ok(Self {
            port,
            forwarded,
            dropped,
            shutdown,
        })
    }

    pub fn stop(&self) {
        let _ = self.shutdown.send(true);
    }
}

/// Bidirectional copy with the impairment applied to each chunk.
async fn pipe(
    client: TcpStream,
    server: TcpStream,
    impairment: Impairment,
    forwarded: Arc<AtomicU64>,
    dropped: Arc<AtomicU64>,
) -> std::io::Result<()> {
    let (mut cr, mut cw) = client.into_split();
    let (mut sr, mut sw) = server.into_split();

    let up = {
        let fwd = forwarded.clone();
        let drp = dropped.clone();
        tokio::spawn(async move { relay(&mut cr, &mut sw, impairment, fwd, drp).await })
    };
    let down = relay(&mut sr, &mut cw, impairment, forwarded, dropped).await;
    let _ = up.await;
    down
}

async fn relay<R, W>(
    from: &mut R,
    to: &mut W,
    impairment: Impairment,
    forwarded: Arc<AtomicU64>,
    dropped: Arc<AtomicU64>,
) -> std::io::Result<()>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    let mut buf = vec![0u8; 16 * 1024];
    // A cheap deterministic-enough PRNG: the seed varies per connection so two
    // runs are not identical, but a run is reproducible from its seed.
    let mut state = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9E3779B97F4A7C15)
        | 1;
    loop {
        let n = from.read(&mut buf).await?;
        if n == 0 {
            let _ = to.shutdown().await;
            return Ok(());
        }

        if impairment.latency_ms > 0 || impairment.jitter_ms > 0 {
            let jitter = if impairment.jitter_ms > 0 {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state % (impairment.jitter_ms + 1)
            } else {
                0
            };
            tokio::time::sleep(Duration::from_millis(impairment.latency_ms + jitter)).await;
        }

        if impairment.loss > 0.0 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let draw = (state % 10_000) as f64 / 10_000.0;
            if draw < impairment.loss {
                dropped.fetch_add(1, Ordering::Relaxed);
                continue;
            }
        }

        to.write_all(&buf[..n]).await?;
        forwarded.fetch_add(1, Ordering::Relaxed);
    }
}
