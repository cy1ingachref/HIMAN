//! Tracing setup shared by the HIMAN binaries.
//!
//! `tracing_subscriber::fmt::init()` reads `RUST_LOG`, so with the variable
//! unset it falls back to ERROR only. Every `info!` line was invisible unless
//! the operator remembered to set `RUST_LOG`, which made live debugging depend
//! on `println!` and HTTP polling instead of the log stream.
//!
//! This module defaults to `info` when `RUST_LOG` is unset, and always writes
//! to stderr so stdout stays reserved for program output.

use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// Initialise logging: `RUST_LOG` if set, otherwise `info`.
///
/// Writes to stderr. Never panics; a logging failure must not stop the agent.
pub fn init() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(
            fmt::layer()
                .with_writer(std::io::stderr)
                .with_target(true)
                .with_level(true),
        )
        .try_init();
}
