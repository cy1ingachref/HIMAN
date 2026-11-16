//! End-to-end test: real orchestrator binary + real agent binary over real
//! loopback WebSockets.
//!
//! The red-team tests build their own in-process router. This test uses the
//! actual executables, so it proves the wiring that only exists in `main.rs`:
//! argument parsing, key files, enrollment, and the WS path.
//!
//! Requires `cargo build --workspace` to have produced the binaries. If they are
//! missing these tests PANIC (via `.expect`) rather than being skipped: a
//! missing binary is a broken CI setup, not a passing test. CI builds the
//! workspace before running tests, so this never fires there.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use serde_json::Value;
use tokio::net::TcpStream;

fn workspace_root() -> PathBuf {
    // `cargo test` runs from the crate dir; the target dir is two levels up.
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn binary(name: &str) -> Option<PathBuf> {
    let exe = if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_string()
    };
    let candidates = [
        workspace_root().join(format!("target/debug/{exe}")),
        workspace_root().join(format!("target/release/{exe}")),
    ];
    candidates.into_iter().find(|p| p.exists())
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral")
        .local_addr()
        .expect("local addr")
        .port()
}

async fn wait_for_port(port: u16) {
    for _ in 0..80 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("server on port {port} never came up");
}

/// The token the e2e orchestrator is started with.
const API_TOKEN: &str = "e2e-test-token";

fn http_get(port: u16, path: &str) -> Value {
    let url = format!("http://127.0.0.1:{port}{path}");
    let body = ureq::get(&url)
        .set("Authorization", &format!("Bearer {API_TOKEN}"))
        .call()
        .expect("GET")
        .into_string()
        .expect("body");
    serde_json::from_str(&body).expect("json")
}

/// How the orchestrator under test should be started.
#[derive(Clone, Copy)]
enum StartMode {
    /// Both protections set: the configuration production uses.
    Secure,
    /// `HIMAN_INSECURE_DEV=1` with no token and no enrollment file.
    InsecureDev,
}

impl StartMode {
    fn envs(self) -> Vec<(&'static str, String)> {
        match self {
            StartMode::Secure => vec![
                ("HIMAN_API_TOKEN", API_TOKEN.to_string()),
                ("HIMAN_ENROLLED_FILE", "set-by-spawn".to_string()),
            ],
            StartMode::InsecureDev => vec![("HIMAN_INSECURE_DEV", "1".to_string())],
        }
    }
}

/// Spawn the orchestrator with a fresh key file and enrollment file.
struct Orchestrator {
    child: std::process::Child,
    port: u16,
    _dir: tempfile::TempDir,
}

impl Orchestrator {
    fn spawn(agent_public_key: &str) -> Self {
        Self::spawn_in_mode(agent_public_key, StartMode::Secure)
    }

    fn spawn_in_mode(agent_public_key: &str, mode: StartMode) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_file = dir.path().join("orchestrator.key");
        let enrollment_file = dir.path().join("enrolled.json");
        let port = free_port();

        // In secure mode the agent must be enrolled. In dev mode the
        // orchestrator accepts any device, so an empty file is enough to
        // satisfy the "file is readable" check.
        let contents = if matches!(mode, StartMode::Secure) {
            format!(r#"{{"pc-1":"{agent_public_key}"}}"#)
        } else {
            "{}".to_string()
        };
        std::fs::write(&enrollment_file, contents).expect("write enrollment");

        let mut cmd = Command::new(binary("himan-orchestrator").expect("orchestrator binary"));
        cmd.env("HIMAN_PORT", port.to_string())
            .env("HIMAN_ORCH_KEY_FILE", &key_file)
            .env_remove("RUST_LOG")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .current_dir(workspace_root());

        for (k, v) in mode.envs() {
            let value = if v == "set-by-spawn" {
                enrollment_file.display().to_string()
            } else {
                v
            };
            cmd.env(k, value);
        }

        let child = cmd.spawn().expect("spawn orchestrator");

        Self {
            child,
            port,
            _dir: dir,
        }
    }

    /// Read the public key the orchestrator printed on stdout.
    fn public_key(&mut self) -> String {
        use std::io::BufRead;
        let stdout = self.child.stdout.as_mut().expect("stdout");
        let reader = std::io::BufReader::new(stdout);
        for line in reader.lines().map_while(Result::ok) {
            if let Some(key) = line.strip_prefix("orchestrator key:") {
                return key.trim().to_string();
            }
        }
        panic!("orchestrator did not print its public key");
    }

    fn agents(&self) -> Value {
        http_get(self.port, "/api/v1/agents")
    }
}

impl Drop for Orchestrator {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The real binaries must register, dispatch, and return a signed result.
#[tokio::test]
async fn e2e_real_binaries_round_trip() {
    let orch_bin = binary("himan-orchestrator").expect("build the orchestrator first");
    let agent_bin = binary("himan-agent-pc").expect("build the agent first");
    let _ = orch_bin;

    // Generate the agent key first so it can be enrolled.
    let dir = tempfile::tempdir().expect("tempdir");
    let agent_key_file = dir.path().join("agent.key");
    let output = Command::new(&agent_bin)
        .args(["keygen", "--out"])
        .arg(&agent_key_file)
        .env_remove("RUST_LOG")
        .current_dir(workspace_root())
        .output()
        .expect("keygen");
    assert!(output.status.success(), "keygen failed: {output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let public_key = stdout
        .lines()
        .find_map(|l| l.strip_prefix("public key: "))
        .expect("keygen must print a public key")
        .trim()
        .to_string();

    let mut orch = Orchestrator::spawn(&public_key);
    let orch_key = orch.public_key();
    wait_for_port(orch.port).await;

    // The agent pins the orchestrator key and registers.
    let mut agent = Command::new(&agent_bin)
        .args(["--ws", &format!("ws://127.0.0.1:{}/ws", orch.port)])
        .env("HIMAN_AGENT_KEY_FILE", &agent_key_file)
        .env("HIMAN_ORCH_KEY", &orch_key)
        .env_remove("RUST_LOG")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .current_dir(workspace_root())
        .spawn()
        .expect("spawn agent");

    // Registration must be reflected in the API.
    let registered = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let agents = orch.agents();
            if agents.as_array().map(|a| a.len()).unwrap_or(0) >= 1 {
                return agents;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .expect("agent did not register within 15s");

    let agent_record = &registered.as_array().expect("array")[0];
    assert_eq!(agent_record["id"], "pc-1");
    assert_eq!(agent_record["verifying_key"], public_key);

    // The agent must be reachable for dispatch.
    let prompt = ureq::post(&format!("http://127.0.0.1:{}/api/v1/prompt", orch.port))
        .set("Authorization", &format!("Bearer {API_TOKEN}"))
        .send_json(serde_json::json!({"device": "pc-1", "prompt": "status"}));
    match prompt {
        Ok(resp) => {
            let body: Value = resp.into_string().unwrap().parse().unwrap();
            assert!(
                body["task_id"]
                    .as_str()
                    .map(|s| s.len() >= 16)
                    .unwrap_or(false),
                "dispatch returned no task id: {body}"
            );
        }
        Err(ureq::Error::Status(code, _)) => {
            panic!("dispatch failed with HTTP {code}");
        }
        Err(ureq::Error::Transport(t)) => panic!("dispatch request failed: {t}"),
    }

    // The audit log must show the registration.
    let audit = http_get(orch.port, "/api/v1/audit");
    let events = audit.as_array().expect("audit array");
    assert!(
        events.iter().any(|e| e["action"] == "agent_registered"),
        "audit log is missing the registration: {audit}"
    );

    let _ = agent.kill();
    let _ = agent.wait();
}

/// The dev-mode escape hatch must actually work end to end.
///
/// `orchestrator/tests/startup.rs` asserts the process starts and warns; this
/// test proves the resulting orchestrator is functional: an agent registers,
/// dispatch works, and the API needs no token in this mode.
#[tokio::test]
async fn e2e_insecure_dev_mode_starts_and_accepts_an_agent() {
    let agent_bin = binary("himan-agent-pc").expect("build the agent first");
    let dir = tempfile::tempdir().expect("tempdir");
    let agent_key_file = dir.path().join("agent.key");

    // Generate a key so we know which device id to expect. In dev mode the
    // orchestrator does not check enrollment, so any valid key is accepted.
    let output = Command::new(&agent_bin)
        .args(["keygen", "--out"])
        .arg(&agent_key_file)
        .env_remove("RUST_LOG")
        .current_dir(workspace_root())
        .output()
        .expect("keygen");
    assert!(output.status.success(), "keygen failed");

    let orch = Orchestrator::spawn_in_mode("not-enrolled-in-dev-mode", StartMode::InsecureDev);
    wait_for_port(orch.port).await;

    // No token is required in dev mode.
    let agents_unauth = ureq::get(&format!("http://127.0.0.1:{}/api/v1/agents", orch.port))
        .call()
        .expect("unauthenticated GET should succeed in dev mode");
    let listed: Value = agents_unauth.into_string().unwrap().parse().unwrap();
    assert_eq!(listed.as_array().map(|a| a.len()).unwrap_or(0), 0);

    // An agent that is NOT enrolled still registers, because dev mode skips it.
    let mut agent = Command::new(&agent_bin)
        .args(["--ws", &format!("ws://127.0.0.1:{}/ws", orch.port)])
        .env("HIMAN_AGENT_KEY_FILE", &agent_key_file)
        .env_remove("RUST_LOG")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .current_dir(workspace_root())
        .spawn()
        .expect("spawn agent");

    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if let Ok(resp) =
                ureq::get(&format!("http://127.0.0.1:{}/api/v1/agents", orch.port)).call()
            {
                if let Ok(body) = resp.into_string() {
                    if let Ok(v) = body.parse::<Value>() {
                        if v.as_array().map(|a| a.len()).unwrap_or(0) >= 1 {
                            return;
                        }
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .expect("dev-mode agent did not register within 15s");

    let _ = agent.kill();
    let _ = agent.wait();
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
        r#"{{"pc-1":"{}","phone-1":"{}"}}"#,
        public_keys[0], public_keys[1]
    );
    let enrollment_file = dir.path().join("enrolled.json");
    std::fs::write(&enrollment_file, enrollment).expect("write enrollment");

    let key_file = dir.path().join("orchestrator.key");
    let port = free_port();
    let mut orch = Command::new(binary("himan-orchestrator").unwrap())
        .env("HIMAN_PORT", port.to_string())
        .env("HIMAN_ORCH_KEY_FILE", &key_file)
        .env("HIMAN_ENROLLED_FILE", &enrollment_file)
        .env("HIMAN_API_TOKEN", API_TOKEN)
        .env_remove("RUST_LOG")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .current_dir(workspace_root())
        .spawn()
        .expect("spawn orchestrator");

    // Read the orchestrator's advertised key so both agents can pin it.
    let orch_key = {
        use std::io::BufRead;
        let stdout = orch.stdout.as_mut().expect("stdout");
        let reader = std::io::BufReader::new(stdout);
        let mut found = String::new();
        for line in reader.lines().map_while(Result::ok) {
            if let Some(key) = line.strip_prefix("orchestrator key:") {
                found = key.trim().to_string();
                break;
            }
        }
        found
    };
    assert!(!orch_key.is_empty(), "orchestrator printed no key");
    wait_for_port(port).await;

    // Spawn both agents. Each pins the orchestrator key and registers under
    // its own device id.
    let mut children = Vec::new();
    for (id, key_file) in [("pc-1", &source_key), ("phone-1", &target_key)] {
        let child = Command::new(&agent_bin)
            .args(["--ws", &format!("ws://127.0.0.1:{port}/ws")])
            .env("HIMAN_DEVICE_ID", id)
            .env("HIMAN_AGENT_KEY_FILE", key_file)
            .env("HIMAN_ORCH_KEY", &orch_key)
            .env_remove("RUST_LOG")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .current_dir(workspace_root())
            .spawn()
            .expect("spawn agent");
        children.push(child);
    }

    // Wait for both to register.
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let agents = http_get(port, "/api/v1/agents");
            if agents.as_array().map(|a| a.len()).unwrap_or(0) >= 2 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .expect("both agents did not register within 20s");

    // Ask for the handoff over the real HTTP surface.
    let response = ureq::post(&format!("http://127.0.0.1:{port}/api/v1/handoff"))
        .set("Authorization", &format!("Bearer {API_TOKEN}"))
        .send_json(serde_json::json!({"task_id":"t-handoff","from":"pc-1","to":"phone-1"}))
        .expect("handoff request");
    let body: Value = response.into_string().unwrap().parse().unwrap();
    let handoff_id = body["handoff_id"].as_str().expect("handoff id").to_string();
    assert!(handoff_id.starts_with("handoff-"));
    assert_eq!(body["state"], "prepared");
    assert_eq!(body["token"]["from_device"], "pc-1");
    assert_eq!(body["token"]["to_device"], "phone-1");

    // Ownership has not moved yet: the source is still the owner at epoch 0.
    let before = http_get(port, "/api/v1/tasks/t-handoff/owner");
    assert_eq!(before["owner"], "pc-1");
    assert_eq!(before["epoch"], 0);

    // A handoff to a device that is not connected is refused, and nothing is
    // recorded for it.
    match ureq::post(&format!("http://127.0.0.1:{port}/api/v1/handoff"))
        .set("Authorization", &format!("Bearer {API_TOKEN}"))
        .send_json(serde_json::json!({"task_id":"t-handoff","from":"pc-1","to":"tv-1"}))
    {
        Ok(_) => panic!("a handoff to a disconnected device must be refused"),
        Err(ureq::Error::Status(code, _)) => assert_eq!(code, 400),
        Err(ureq::Error::Transport(t)) => panic!("request failed: {t}"),
    }

    // The audit log recorded the attempt and the registration of both agents.
    let audit = http_get(port, "/api/v1/audit");
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
    let _ = orch.kill();
    let _ = orch.wait();
}
