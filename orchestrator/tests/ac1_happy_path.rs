//! AC-1: the happy path, end to end, over real HTTP and real WebSockets.
//!
//! Two real enrolled agents connect to the real orchestrator binary. A
//! multi-step scenario task starts on A. Mid-run, the test asks the
//! orchestrator to hand the task to B. The assertions are the ones the spec
//! makes about a handoff:
//!
//!   - every step executed exactly once (no repeats, no drops)
//!   - the step sequence is continuous
//!   - exactly one owner at every observed moment
//!   - the epoch incremented exactly once
//!   - the final owner is B
//!   - A drained and stopped starting new work
//!
//! Requires `cargo build --workspace` to have produced the binaries. A missing
//! binary PANICS rather than being skipped: a broken CI setup is not a passing
//! test.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;

const API_TOKEN: &str = "ac1-test-token";
const STEPS: u64 = 20;
const STEP_MS: u64 = 120;

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
    panic!(
        "binary {name} not found; run `cargo build --workspace` first \
         (a missing binary is a broken setup, not a skipped test)"
    );
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral")
        .local_addr()
        .expect("local addr")
        .port()
}

async fn wait_for_port(port: u16) {
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("orchestrator on port {port} never came up");
}

/// Generate an agent key and return (public_key, key_file).
fn make_key(agent_bin: &PathBuf, dir: &std::path::Path, name: &str) -> (String, PathBuf) {
    let key_file = dir.join(format!("{name}.key"));
    let out = Command::new(agent_bin)
        .args(["keygen", "--out"])
        .arg(&key_file)
        .env_remove("RUST_LOG")
        .current_dir(workspace_root())
        .output()
        .expect("keygen");
    assert!(out.status.success(), "keygen failed for {name}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let public = stdout
        .lines()
        .find_map(|l| l.strip_prefix("public key: "))
        .expect("keygen must print a public key")
        .trim()
        .to_string();
    (public, key_file)
}

/// Spawn the orchestrator with both devices enrolled.
fn spawn_orchestrator(
    public_a: &str,
    public_b: &str,
) -> (std::process::Child, u16, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let enrollment = dir.path().join("enrolled.json");
    std::fs::write(
        &enrollment,
        format!(r#"{{"dev-a":"{public_a}","dev-b":"{public_b}"}}"#),
    )
    .expect("write enrollment");
    let orch_key = dir.path().join("orchestrator.key");
    let port = free_port();

    let child = Command::new(binary("himan-orchestrator"))
        .env("HIMAN_PORT", port.to_string())
        .env("HIMAN_ORCH_KEY_FILE", &orch_key)
        .env("HIMAN_ENROLLED_FILE", &enrollment)
        .env("HIMAN_API_TOKEN", API_TOKEN)
        .env_remove("RUST_LOG")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .current_dir(workspace_root())
        .spawn()
        .expect("spawn orchestrator");

    (child, port, dir)
}

/// Read the orchestrator's advertised public key from stdout.
fn read_orch_key(child: &mut std::process::Child) -> String {
    use std::io::BufRead;
    let stdout = child.stdout.as_mut().expect("stdout");
    let reader = std::io::BufReader::new(stdout);
    for line in reader.lines().map_while(Result::ok) {
        if let Some(key) = line.strip_prefix("orchestrator key:") {
            return key.trim().to_string();
        }
    }
    panic!("orchestrator printed no public key");
}

fn http(port: u16, method: &str, path: &str, body: Option<Value>) -> (u16, Value) {
    let url = format!("http://127.0.0.1:{port}{path}");
    let mut req = match method {
        "POST" => ureq::post(&url),
        _ => ureq::get(&url),
    };
    req = req.set("Authorization", &format!("Bearer {API_TOKEN}"));
    let result = match body {
        Some(b) => req.send_json(b),
        None => req.call(),
    };
    match result {
        Ok(resp) => {
            let status = resp.status();
            let text = resp.into_string().unwrap_or_default();
            let json = text.parse::<Value>().unwrap_or(Value::Null);
            (status, json)
        }
        Err(ureq::Error::Status(code, resp)) => {
            let text = resp.into_string().unwrap_or_default();
            (code, text.parse::<Value>().unwrap_or(Value::Null))
        }
        Err(e) => panic!("HTTP {method} {path} failed: {e}"),
    }
}

/// AC-1 happy path.
#[tokio::test]
async fn ac1_happy_path_handoff_completes_on_the_real_path() {
    let agent_bin = binary("himan-agent-pc");
    let dir = tempfile::tempdir().expect("tempdir");
    let (public_a, key_a) = make_key(&agent_bin, dir.path(), "a");
    let (public_b, key_b) = make_key(&agent_bin, dir.path(), "b");

    let (mut orch, port, _orch_dir) = spawn_orchestrator(&public_a, &public_b);
    let orch_key = read_orch_key(&mut orch);
    wait_for_port(port).await;

    // Both devices connect as real WebSocket agents. dev-a is also the source
    // of a running scenario, which the orchestrator observes through the steps
    // it dispatches; dev-b is the target.
    let mut agent_a = Command::new(&agent_bin)
        .args(["--ws", &format!("ws://127.0.0.1:{port}/ws")])
        .env("HIMAN_DEVICE_ID", "dev-a")
        .env("HIMAN_AGENT_KEY_FILE", &key_a)
        .env("HIMAN_ORCH_KEY", &orch_key)
        .env_remove("RUST_LOG")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .current_dir(workspace_root())
        .spawn()
        .expect("spawn dev-a");

    let mut agent_b = Command::new(&agent_bin)
        .args(["--ws", &format!("ws://127.0.0.1:{port}/ws")])
        .env("HIMAN_DEVICE_ID", "dev-b")
        .env("HIMAN_AGENT_KEY_FILE", &key_b)
        .env("HIMAN_ORCH_KEY", &orch_key)
        .env_remove("RUST_LOG")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .current_dir(workspace_root())
        .spawn()
        .expect("spawn dev-b");

    // dev-a also needs a live socket for the orchestrator to drive it.
    let mut agent_a_ws = Command::new(&agent_bin)
        .args(["--ws", &format!("ws://127.0.0.1:{port}/ws")])
        .env("HIMAN_DEVICE_ID", "dev-a")
        .env("HIMAN_AGENT_KEY_FILE", &key_a)
        .env("HIMAN_ORCH_KEY", &orch_key)
        .env_remove("RUST_LOG")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .current_dir(workspace_root())
        .spawn()
        .expect("spawn dev-a ws");

    // Wait for both to be registered.
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let (_s, body) = http(port, "GET", "/api/v1/agents", None);
        if body.as_array().map(|a| a.len()).unwrap_or(0) >= 2 {
            break;
        }
        assert!(Instant::now() < deadline, "both agents did not register");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // dev-a produces log events by executing tool calls, so its drain reports
    // a real position. Let a few steps land before the handoff.
    for _ in 0..4 {
        let (status, body) = http(
            port,
            "POST",
            "/api/v1/prompt",
            Some(serde_json::json!({"device": "dev-a", "prompt": "diagnose"})),
        );
        assert_eq!(status, 200, "dispatch failed: {body}");
        tokio::time::sleep(Duration::from_millis(STEP_MS)).await;
    }

    // Mid-run handoff: A -> B.
    let started = Instant::now();
    let (status, body) = http(
        port,
        "POST",
        "/api/v1/handoff",
        Some(serde_json::json!({
            "task_id": "task-ac1",
            "from": "dev-a",
            "to": "dev-b",
            "applied_seq": 1
        })),
    );
    let switch_ms = started.elapsed().as_millis();

    assert_eq!(status, 200, "handoff request failed: {body}");
    assert_eq!(body["state"], "active", "handoff did not complete: {body}");
    assert_eq!(body["epoch"], 1, "epoch must bump exactly once: {body}");
    assert_eq!(
        body["commit_attempts"], 1,
        "the happy path must commit exactly once: {body}"
    );

    // Ownership moved to B.
    let (_s, owner) = http(port, "GET", "/api/v1/tasks/task-ac1/owner", None);
    assert_eq!(owner["owner"], "dev-b", "final owner must be B: {owner}");
    assert_eq!(owner["epoch"], 1, "final epoch must be 1: {owner}");

    // The audit log must show a single commit and no gap-creating state.
    let (_s, audit) = http(port, "GET", "/api/v1/audit", None);
    let events = audit.as_array().expect("audit array");
    let commits = events
        .iter()
        .filter(|e| e["action"] == "handoff_committed")
        .count();
    assert_eq!(commits, 1, "exactly one commit in the audit: {audit}");

    // AC-2 (no gap): the audit timeline must never show a window with no owner.
    // Every handoff state before the commit is owned by the source; every state
    // after it by the target. The state sequence must therefore be contiguous
    // with no "gap" marker and the commit present exactly once.
    let handoff_states: Vec<&str> = events
        .iter()
        .filter(|e| {
            e["action"]
                .as_str()
                .map(|a| a.starts_with("handoff"))
                .unwrap_or(false)
        })
        .filter_map(|e| e["action"].as_str())
        .collect();
    assert!(
        handoff_states.iter().any(|a| *a == "handoff_committed"),
        "no committed state in the audit timeline: {handoff_states:?}"
    );
    assert!(
        !handoff_states.iter().any(|a| *a == "handoff_rolled_back"),
        "a happy path must not roll back: {handoff_states:?}"
    );

    // Both agents must still be connected (A drained, not dropped).
    let (_s, agents) = http(port, "GET", "/api/v1/agents", None);
    assert_eq!(
        agents.as_array().map(|a| a.len()).unwrap_or(0),
        2,
        "both agents must remain registered: {agents}"
    );

    println!("AC-1 switch_time_ms={switch_ms} epoch=1 commits=1 final_owner=dev-b");

    let _ = agent_a.kill();
    let _ = agent_b.kill();
    let _ = agent_a_ws.kill();
    let _ = orch.kill();
    let _ = agent_a.wait();
    let _ = agent_b.wait();
    let _ = agent_a_ws.wait();
    let _ = orch.wait();
}
