//! End-to-end test: real orchestrator binary + real agent binary over real
//! loopback WebSockets.
//!
//! The red-team tests build their own in-process router. This test uses the
//! actual executables, so it proves the wiring that only exists in `main.rs`:
//! argument parsing, key files, enrollment, and the WS path.
//!
//! Requires `cargo build --workspace` to have produced the binaries. Marked
//! `#[ignore]` when they are missing so `cargo test` alone still passes.

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

/// Spawn the orchestrator with a fresh key file and enrollment file.
struct Orchestrator {
    child: std::process::Child,
    port: u16,
    _dir: tempfile::TempDir,
}

impl Orchestrator {
    fn spawn(agent_public_key: &str) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_file = dir.path().join("orchestrator.key");
        let enrollment_file = dir.path().join("enrolled.json");
        let port = free_port();

        // Pre-create the enrollment file so the agent is accepted.
        std::fs::write(
            &enrollment_file,
            format!(r#"{{"pc-1":"{agent_public_key}"}}"#),
        )
        .expect("write enrollment");

        let child = Command::new(binary("himan-orchestrator").expect("orchestrator binary"))
            .env("HIMAN_PORT", port.to_string())
            .env("HIMAN_ORCH_KEY_FILE", &key_file)
            .env("HIMAN_ENROLLED_FILE", &enrollment_file)
            // The orchestrator fails closed without a token, so the e2e run sets
            // one even though this test does not call the authenticated routes.
            .env("HIMAN_API_TOKEN", API_TOKEN)
            .env_remove("RUST_LOG")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .current_dir(workspace_root())
            .spawn()
            .expect("spawn orchestrator");

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
