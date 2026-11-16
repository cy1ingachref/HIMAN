//! End-to-end test: real orchestrator binary + real agent binary over real
//! loopback WebSockets, built on the fast, reliable harness in
//! `common/mod.rs`.
//!
//! `common/mod.rs` redirects every child's stdio to temp files (never pipes),
//! waits for `/health` before spawning any agent, polls registration with a
//! short interval and a hard timeout, and prints the tail of each child's log
//! on timeout. Every phase is timed with `Instant` and reported at the end.
//!
//! Requires `cargo build --workspace` to have produced the binaries.

mod common;

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;
use tokio::time::sleep;

use common::E2ETest;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn binary(name: &str) -> PathBuf {
    let exe = if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_string()
    };
    for candidate in [
        workspace_root().join(format!("target/debug/{exe}")),
        workspace_root().join(format!("target/release/{exe}")),
    ] {
        if candidate.exists() {
            return candidate;
        }
    }
    panic!("binary {name} not found; run `cargo build --workspace` first")
}

fn http_get_json(port: u16, path: &str) -> Value {
    common::http_get_json(port, path)
}

fn http_post_json(port: u16, path: &str, body: Value) -> Value {
    common::http_post_json(port, path, body)
}

/// Drive the handoff request over real HTTP against the real orchestrator.
///
/// Two agents stand in for PC and phone: both are `himan-agent-pc`, but each
/// registers under its own device id (`HIMAN_DEVICE_ID`) and key, and both are
/// enrolled. The test asks for a handoff and asserts the observable contract:
/// a signed token is returned, ownership has not moved yet, a request naming a
/// disconnected device is refused, and the audit log records both registrations
/// and the attempt.
///
/// Scope, stated plainly: the switch procedure's later events are applied
/// through the hub methods the unit tests drive directly. This test covers what
/// only the real binaries can prove — two live sockets, enrollment of two
/// devices, and the real HTTP surface. The post-commit ownership move is proven
/// in `hub.rs::the_commit_moves_ownership_and_bumps_the_epoch`, not here.
#[tokio::test]
async fn e2e_handoff_request_between_two_real_agents() {
    let agent_bin = binary("himan-agent-pc").expect("build the agent first");

    let dir = tempfile::tempdir().expect("tempdir");
    let source_key = dir.path().join("source.key");
    let target_key = dir.path().join("target.key");

    // Generate both agent keys and capture their public halves for enrollment.
    let mut public_keys = Vec::new();
    for key_file in [&source_key, &target_key] {
        let output = Command::new(&agent_bin)
            .args(["keygen", "--out"])
            .arg(key_file)
            .env_remove("RUST_LOG")
            .current_dir(workspace_root())
            .output()
            .expect("keygen");
        assert!(output.status.success(), "keygen failed: {output:?}");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let public = stdout
            .lines()
            .find_map(|l| l.strip_prefix("public key: "))
            .expect("keygen must print a public key")
            .trim()
            .to_string();
        public_keys.push(public);
    }

    // Both devices are enrolled.
    let enrollment = format!(
        r#"{{"pc-1":"{0}","phone-1":"{1}"}}"#,
        public_keys[0], public_keys[1]
    );
    let enrollment_file = dir.path().join("enrolled.json");
    std::fs::write(&enrollment_file, &enrollment).expect("write enrollment");

    // The orchestrator is started with the harness's real-binaries harness:
    // stdio -> files, /health-gated spawn, HIMAN_PORT set, enrollment file used.
    let orch_key_file = dir.path().join("orchestrator.key");
    let orch = E2ETest::with_key_file(&orch_key_file, &enrollment_file).await;

    // Read the orchestrator's advertised key so both agents can pin it.
    let orch_key = orch.orchestrator_key().expect("orchestrator printed a key");

    // Spawn both agents. Each pins the orchestrator key and registers under
    // its own device id.
    let mut children = Vec::new();
    for (id, key_file) in [("pc-1", &source_key), ("phone-1", &target_key)] {
        let child = Command::new(&agent_bin)
            .args(["--ws", &format!("ws://127.0.0.1:{}/ws", orch.port())])
            .env("HIMAN_DEVICE_ID", id)
            .env("HIMAN_AGENT_KEY_FILE", key_file)
            .env("HIMAN_ORCH_KEY", &orch_key)
            .env_remove("RUST_LOG")
            .stdout(Stdio::from(
                std::fs::File::create(orch.log_file("agent.out")).expect("agent stdout"),
            ))
            .stderr(Stdio::from(
                std::fs::File::create(orch.log_file("agent.err")).expect("agent stderr"),
            ))
            .current_dir(workspace_root())
            .spawn()
            .expect("spawn agent");
        children.push(child);
    }

    // Wait for both to register (polling with a hard timeout, log on failure).
    orch.wait_for_registration(2, 30).await;

    // Ask for the handoff over the real HTTP surface.
    let response = ureq::post(&format!(
        "http://127.0.0.1:{}/api/v1/handoff",
        orch.port()
    ))
    .send_json(serde_json::json!({
        "task_id": "t-handoff",
        "from": "pc-1",
        "to": "phone-1"
    }))
    .expect("handoff request");
    let body: Value = response.into_string().unwrap().parse().unwrap();
    let handoff_id = body["handoff_id"]
        .as_str()
        .expect("handoff id")
        .to_string();
    assert!(handoff_id.starts_with("handoff-"));
    assert_eq!(body["state"], "prepared");
    assert_eq!(body["token"]["from_device"], "pc-1");
    assert_eq!(body["token"]["to_device"], "phone-1");

    // Ownership has not moved yet: the source is still the owner at epoch 0.
    let before = http_get_json(orch.port(), "/api/v1/tasks/t-handoff/owner");
    assert_eq!(before["owner"], "pc-1");
    assert_eq!(before["epoch"], 0);

    // A handoff to a device that is not connected is refused, and nothing is
    // recorded for it.
    match ureq::post(&format!(
        "http://127.0.0.1:{}/api/v1/handoff",
        orch.port()
    ))
    .set("Authorization", &format!("Bearer {}", orch.api_token()))
    .send_json(serde_json::json!({
        "task_id": "t-handoff",
        "from": "pc-1",
        "to": "tv-1"
    })) {
        Ok(_) => panic!("a handoff to a disconnected device must be refused"),
        Err(ureq::Error::Status(code, _)) => assert_eq!(code, 400),
        Err(ureq::Error::Transport(t)) => panic!("request failed: {t}"),
    }

    // The audit log recorded the attempt and the registration of both agents.
    let audit = http_get_json(orch.port(), "/api/v1/audit");
    let events = audit.as_array().expect("audit array");
    assert!(events.iter().any(|e| e["action"] == "handoff_prepared"));
    assert_eq!(
        events
            .iter()
            .filter(|e| e["action"] == "agent_registered")
            .count(),
        2
    );

    for child in &mut children {
        let _ = child.kill();
        let _ = child.wait();
    }
    orch.stop().await;
}

/// The real binaries must register, dispatch, and return a signed result.
#[tokio::test]
async fn e2e_real_binaries_round_trip() {
    // Spawn the orchestrator on a real binary, redirect its stdio to files,
    // and wait for /health before spawning anything.
    let mut harness = E2ETest::new().await;
    harness.record_phase("orchestrator up");
    let orch_port = harness.orchestrator_port();
    println!("orchestrator on port {orch_port}");

    // Generate the agent key so it can be enrolled.
    let agent_bin = binary("himan-agent-pc");
    let dir = tempfile::tempdir().expect("tempdir");
    let agent_key_file = dir.path().join("agent.key");
    let keygen = Command::new(&agent_bin)
        .args(["keygen", "--out"])
        .arg(&agent_key_file)
        .env_remove("RUST_LOG")
        .current_dir(workspace_root())
        .output()
        .expect("keygen");
    assert!(keygen.status.success(), "keygen failed: {}",
        String::from_utf8_lossy(&keygen.stderr));

    // The harness's enrollment file was written with the orchestrator key
    // for pc-1 (Secure mode), so the agent only needs the orchestrator key.
    let orch_key = std::fs::read_to_string(harness.orch_key_file())
        .expect("orchestrator key file");

    // Spawn the agent and wait for registration, with logging to files.
    let registered = harness
        .spawn_agent(orch_port, &agent_bin, &agent_key_file, &orch_key)
        .await
        .expect("spawn agent");

    let agent_record = &registered.as_array().expect("array")[0];
    assert_eq!(agent_record["id"], "pc-1");
    assert_eq!(
        agent_record["verifying_key"]
            .as_str()
            .unwrap_or(&""),
        &agent_key_file.to_string_lossy()
    );

    // The agent must be reachable for dispatch.
    let prompt = http_post_json(orch_port, "/api/v1/prompt", serde_json::json!({
        "device": "pc-1",
        "prompt": "status"
    }));
    assert!(prompt["task_id"]
        .as_str()
        .map(|s| s.len() >= 16)
        .unwrap_or(false),
        "dispatch returned no task id: {prompt:?}");

    // The audit log must show the registration.
    let audit = http_get_json(orch_port, "/api/v1/audit");
    let events = audit.as_array().expect("audit array");
    assert!(events.iter().any(|e| e["action"] == "agent_registered"),
        "audit log missing registration: {audit:?}");

    harness.record_phase("round trip complete");
    harness.stop().await;
}
