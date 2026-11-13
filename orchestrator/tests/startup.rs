//! Fail-closed startup checks.
//!
//! The orchestrator must refuse to start unless both `HIMAN_API_TOKEN` and
//! `HIMAN_ENROLLED_FILE` are set, or `HIMAN_INSECURE_DEV=1` is set. An
//! operator who forgets a protection must get a hard failure, not a warning.

use std::process::{Command, Stdio};

fn binary() -> String {
    let exe = if cfg!(windows) {
        "himan-orchestrator.exe".to_string()
    } else {
        "himan-orchestrator".to_string()
    };
    for c in [
        format!("../target/debug/{exe}"),
        format!("./target/debug/{exe}"),
        format!("target/debug/{exe}"),
    ] {
        if std::path::Path::new(&c).exists() {
            return c;
        }
    }
    panic!("orchestrator binary not found; run `cargo build --workspace` first");
}

/// Run the orchestrator with a controlled environment and return (exit code, output).
///
/// Security-relevant variables are removed so a developer's own shell cannot
/// accidentally satisfy a check. System variables needed to bind a socket are
/// kept: clearing everything makes Windows socket init fail with error 10106.
fn run_with(envs: &[(&str, &str)], timeout_secs: u64) -> (Option<i32>, String) {
    let mut cmd = Command::new(binary());
    // Keep the default key file out of the repository. Setting current_dir
    // instead would break the relative binary path on Unix.
    let scratch = tempfile::tempdir().expect("scratch dir");
    cmd.env(
        "HIMAN_ORCH_KEY_FILE",
        scratch.path().join("himan-orchestrator.key"),
    );
    // Keep only what the OS needs; drop every HIMAN_* variable.
    for (k, v) in std::env::vars() {
        if !k.starts_with("HIMAN_") {
            cmd.env(k, v);
        }
    }
    cmd.env("RUST_LOG", "info");
    for (k, v) in envs {
        cmd.env(k, v);
    }
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("spawn orchestrator");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    loop {
        if let Some(status) = child.try_wait().expect("wait") {
            let out = child.wait_with_output().expect("output");
            let mut text = String::from_utf8_lossy(&out.stdout).to_string();
            text.push_str(&String::from_utf8_lossy(&out.stderr));
            return (status.code(), text);
        }
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            let out = child.wait_with_output().expect("output");
            let mut text = String::from_utf8_lossy(&out.stdout).to_string();
            text.push_str(&String::from_utf8_lossy(&out.stderr));
            return (None, text);
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

const TOKEN: &str = "test-api-token";

/// An OS-assigned free port, so the server genuinely binds and starts.
fn free_port() -> String {
    let s = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    s.local_addr().expect("addr").port().to_string()
}

/// Create a temporary enrollment file so the "both protections present" case is
/// genuinely satisfied.
fn temp_enrollment() -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("enrolled.json");
    std::fs::write(&path, r#"{"pc-1":"AAAA"}"#).expect("write");
    (dir, path.display().to_string())
}

#[test]
fn refuses_to_start_without_a_token() {
    let (_d, enrolled) = temp_enrollment();
    let (code, out) = run_with(&[("HIMAN_ENROLLED_FILE", &enrolled)], 10);
    assert_eq!(
        code,
        Some(1),
        "must exit 1 without HIMAN_API_TOKEN, got {code:?}\n{out}"
    );
    assert!(
        out.contains("HIMAN_API_TOKEN"),
        "the error must name the missing variable:\n{out}"
    );
}

#[test]
fn refuses_to_start_without_an_enrollment_file() {
    let (code, out) = run_with(&[("HIMAN_API_TOKEN", TOKEN)], 10);
    assert_eq!(
        code,
        Some(1),
        "must exit 1 without HIMAN_ENROLLED_FILE, got {code:?}\n{out}"
    );
    assert!(
        out.contains("HIMAN_ENROLLED_FILE"),
        "the error must name the missing variable:\n{out}"
    );
}

#[test]
fn starts_with_insecure_dev_when_protections_are_missing() {
    // No token, no enrollment file, but explicitly insecure: it must start.
    let port = free_port();
    let (code, out) = run_with(&[("HIMAN_INSECURE_DEV", "1"), ("HIMAN_PORT", &port)], 8);
    assert_ne!(
        code,
        Some(1),
        "HIMAN_INSECURE_DEV=1 must permit startup, got {code:?}\n{out}"
    );
    assert!(
        out.to_uppercase().contains("INSECURE"),
        "a loud warning must be logged:\n{out}"
    );
}

#[test]
fn starts_normally_with_both_protections() {
    let (_d, enrolled) = temp_enrollment();
    let port = free_port();
    let (code, out) = run_with(
        &[
            ("HIMAN_API_TOKEN", TOKEN),
            ("HIMAN_ENROLLED_FILE", &enrolled),
            ("HIMAN_PORT", &port),
        ],
        5,
    );
    assert_ne!(
        code,
        Some(1),
        "both protections present must allow startup, got {code:?}\n{out}"
    );
    assert!(
        !out.contains("INSECURE DEV MODE"),
        "the normal path must not log an insecure-mode warning:\n{out}"
    );
}
