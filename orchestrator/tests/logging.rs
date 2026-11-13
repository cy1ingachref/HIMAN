//! Both binaries must emit logs with RUST_LOG unset.
//!
//! Regression: `tracing_subscriber::fmt::init()` reads `RUST_LOG`, so with the
//! variable unset it falls back to ERROR only. Every `info!` line in the agent
//! and orchestrator was invisible, which made live debugging depend on
//! `println!` and HTTP polling instead of the log stream.

use std::process::{Command, Stdio};
use std::time::Duration;

fn binary(name: &str) -> String {
    let exe = if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_string()
    };
    let candidates = [
        format!("../target/debug/{exe}"),
        format!("./target/debug/{exe}"),
        format!("target/debug/{exe}"),
    ];
    for c in &candidates {
        if std::path::Path::new(c).exists() {
            return c.to_string();
        }
    }
    panic!("binary {name} not found; run `cargo build --workspace` first");
}

/// Spawn a binary with RUST_LOG unset, wait briefly, then kill it and return
/// whatever it wrote to stderr.
fn run_and_capture(name: &str, args: &[(&str, &str)]) -> String {
    let mut cmd = Command::new(binary(name));
    for (flag, value) in args {
        cmd.arg(flag).arg(value);
    }
    // Run from a scratch directory. Without this the binary inherits the crate
    // dir and writes its default key file (himan-orchestrator.key,
    // himan-agent.key) into the repository.
    let scratch = tempfile::tempdir().expect("scratch dir");
    cmd.current_dir(scratch.path());
    // Drop any inherited HIMAN_* so this test is hermetic, but keep the OS
    // variables needed to bind a socket.
    for (k, v) in std::env::vars() {
        if !k.starts_with("HIMAN_") {
            cmd.env(k, v);
        }
    }
    cmd.env_remove("RUST_LOG");

    // The orchestrator now fails closed without these, which would make the
    // "startup logs INFO" assertion meaningless.
    if name.contains("orchestrator") {
        cmd.env("HIMAN_INSECURE_DEV", "1");
    }

    cmd.stdout(Stdio::null()).stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("spawn");
    // Give the process time to attempt the connection and log the outcome.
    std::thread::sleep(Duration::from_millis(2500));
    let _ = child.kill();
    let output = child.wait_with_output().expect("wait");
    String::from_utf8_lossy(&output.stderr).to_string()
}

/// The agent must log its failure at ERROR level with RUST_LOG unset.
#[test]
fn agent_logs_info_without_rust_log() {
    let out = run_and_capture("himan-agent-pc", &[("--ws", "ws://127.0.0.1:1/nope")]);
    assert!(
        out.contains("ERROR") || out.contains("INFO") || out.contains("WARN"),
        "agent must log to stderr with RUST_LOG unset, got:\n{out}"
    );
    assert!(
        out.contains("connection failed"),
        "agent must log the connection failure, got:\n{out}"
    );
}

/// The orchestrator must log its startup at INFO level with RUST_LOG unset.
#[test]
fn orchestrator_logs_info_without_rust_log() {
    let out = run_and_capture("himan-orchestrator", &[]);
    assert!(
        out.contains("INFO"),
        "orchestrator must log INFO lines with RUST_LOG unset, got:\n{out}"
    );
    assert!(
        out.contains("listening"),
        "orchestrator must log that it is listening, got:\n{out}"
    );
}
