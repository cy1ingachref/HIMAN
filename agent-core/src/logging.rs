//! Tracing setup shared by the HIMAN binaries.
//!
//! `tracing_subscriber::fmt::init()` reads `RUST_LOG`, so with the variable
//! unset it falls back to ERROR only. Every `info!` line was invisible unless
//! the operator remembered to set `RUST_LOG`, which made live debugging depend
//! on `println!` and HTTP polling instead of the log stream.
//!
//! This module defaults to `info` when `RUST_LOG` is unset, and always writes
//! to stderr so stdout stays reserved for program output.

use std::io::IsTerminal;

use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// Initialise logging: `RUST_LOG` if set, otherwise `info`.
///
/// Writes to stderr, with colour only when stderr is a terminal. A piped or
/// redirected log (CI, journal, a file) must stay plain text so it remains
/// greppable and free of escape sequences.
///
/// Never panics; a logging failure must not stop the agent.
pub fn init() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    // `IsTerminal` is available on std's stdout/stderr since Rust 1.70.
    let ansi = std::io::stderr().is_terminal();

    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(
            fmt::layer()
                .with_writer(std::io::stderr)
                .with_target(true)
                .with_level(true)
                .with_ansi(ansi),
        )
        .try_init();
}
