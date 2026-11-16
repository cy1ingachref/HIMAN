//! Fast, reliable helpers for the real-binaries end-to-end test harness.
//!
//! The red-team suites build their own in-process router. This file runs the
//! *real* Orchestrator and Agent binaries exactly the way `src/bin/orchestrator.rs`
//! and `agent-pc/src/main.rs` do: forked processes whose stdio goes to temp
//! files (never pipes, which back up the children), started on ephemeral
//! loopback ports, communicated over real HTTP and WebSocket sockets.
//!
//! Design rules that make these tests fast and reliable:
//!   - stdio -> temp files, never pipes (a pipe back-ups the child and can
//!     make a benign run look like it is hanging);
//!   - the orchestrator must answer `/health` before ANY agent is spawned
//!     (agents currently sit in backoff while they cannot reach the server);
//!   - every poll has a hard timeout and prints the tail of each child's log
//!     in the failure message;
//!   - every phase is timed with `Instant` and reported at the end.
//!
//! Usage:
//!
//! ```ignore
//! let mut harness = common::E2ETest::new().await?;
//! let orch_port = harness.orchestrator_port();
//! // spawn agents, drive the scenario, then:
//! harness.stop().await;
//! ```

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;
use tokio::time::timeout;

/// Hard ceiling for every poll/registration/health wait in this harness.
pub const HARD_TIMEOUT: Duration = Duration::from_secs(60);

/// Where a child's stdout/stderr are dumped so a timeout can print the tail.
pub struct ChildLog {
    pub out: PathBuf,
    pub err: PathBuf,
    pub dir: tempfile::TempDir,
}

impl ChildLog {
    pub fn new(cwd: &Path) -> Self {
        let dir = tempfile::tempdir().expect("tempdir for child logs");
        let out = dir.path().join(format!("{}_{}.out", std::process::id(), "orch"));
        let err = dir.path().join(format!("{}_{}.err", std::process::id(), "orch"));
        Self { out, err, dir }
    }

    pub fn tail(&self, n: usize) -> String {
        let mut chunks = Vec::new();
        if let Ok(mut f) = std::fs::File::open(&self.out) {
            let mut buf = [0u8; 4096];
            let _ = f.read(&mut buf).ok();
            chunks.push(format!("--- stdout ---\n{}", String::from_utf8_lossy(&buf)));
        }
        if let Ok(mut f) = std::fs::File::open(&self.err) {
            let mut buf = [0u8; 4096];
            let _ = f.read(&mut buf).ok();
            chunks.push(format!("--- stderr ---\n{}", String::from_utf8_lossy(&buf)));
        }
        chunks.reverse();
        chunks.truncate(n);
        chunks.reverse();
        chunks.join("\n")
    }
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

pub fn binary(name: &str) -> PathBuf {
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

pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral")
        .local_addr()
        .expect("local addr")
        .port()
}

/// A single named phase, printed at the end with the wall time.
#[derive(Default)]
pub struct Phase {
    pub name: &'static str,
    pub start: Option<Instant>,
}

impl Phase {
    pub fn start(&mut self) {
        self.start = Some(Instant::now());
    }

    pub fn elapsed(&self) -> Option<Duration> {
        self.start.map(|s| s.elapsed())
    }
}

impl Phase {
    pub fn report_all() -> PhaseReporter {
        PhaseReporter::default()
    }
}

/// Prints every recorded phase at drop time so `cargo test` prints a
/// summary under the test result line.
pub struct PhaseReporter {
    phases: Vec<(String, Duration)>,
}

impl Default for PhaseReporter {
    fn default() -> Self {
        Self { phases: Vec::new() }
    }
}

impl Drop for PhaseReporter {
    fn drop(&mut self) {
        if self.phases.is_empty() {
            return;
        }
        eprintln!(
            "=== e2e phase timings (total {:.1}s) ===",
            self.phases.iter().map(|(_, d)| d.as_secs_f64()).sum::<f64>()
        );
        for (name, d) in &self.phases {
            eprintln!("  {name:<40} {:.1}s", d.as_secs_f64());
        }
        eprintln!("=== end timings ===");
    }
}

/// The real-binaries e2e harness.
pub struct E2ETest {
    orch_bin: PathBuf,
    agent_bin: PathBuf,
    orch_port: u16,
    orch_log: ChildLog,
    orch_dir: tempfile::TempDir,
    orch_child: Option<std::process::Child>,
    phases: Vec<Phase>,
}

impl E2ETest {
    /// Build the harness (spawns the orchestrator) and wait until /health
    /// answers before returning. The orchestrator's stdio is redirected to
    /// temp files, never pipes.
    pub async fn new() -> Self {
        let orch_bin = binary("himan-orchestrator");
        let agent_bin = binary("himan-agent-pc");

        let orch_dir = tempfile::tempdir().expect("orch tempdir");
        let orch_port = free_port();
        let orch_log = ChildLog::new(orch_dir.path());

        let mut cmd = Command::new(&orch_bin);
        cmd.env("HIMAN_PORT", orch_port.to_string())
            .env(
                "HIMAN_ORCH_KEY_FILE",
                orch_dir.path().join("orchestrator.key"),
            )
            .env(
                "HIMAN_ENROLLED_FILE",
                orch_dir.path().join("enrolled.json"),
            )
            .env_remove("RUST_LOG")
            .current_dir(workspace_root())
            .stdout(Stdio::from(
                std::fs::File::create(&orch_log.out).expect("orch stdout file"),
            ))
            .stderr(Stdio::from(
                std::fs::File::create(&orch_log.err).expect("orch stderr file"),
            ));

        let orch_child = cmd.spawn().expect("spawn orchestrator");
        // Wait for /health before spawning any agent.
        wait_for_health(orch_port).await;

        Self {
            orch_bin,
            agent_bin,
            orch_port,
            orch_log,
            orch_dir,
            orch_child: Some(orch_child),
            phases: Vec::new(),
        }
    }

    /// Spawn the orchestrator with explicit key and enrollment files, so
    /// the agent-side enrollment file is written exactly as the real
    /// deployment would write it.
    pub async fn with_key_file(key_file: &PathBuf, enrollment_file: &PathBuf) -> Self {
        let orch_bin = binary("himan-orchestrator");

        let orch_dir = tempfile::tempdir().expect("orch tempdir");
        let orch_port = free_port();
        let orch_log = ChildLog::new(orch_dir.path());

        let mut cmd = Command::new(&orch_bin);
        cmd.env("HIMAN_PORT", orch_port.to_string())
            .env("HIMAN_ORCH_KEY_FILE", key_file)
            .env("HIMAN_ENROLLED_FILE", enrollment_file)
            .env_remove("RUST_LOG")
            .current_dir(workspace_root())
            .stdout(Stdio::from(
                std::fs::File::create(&orch_log.out).expect("orch stdout file"),
            ))
            .stderr(Stdio::from(
                std::fs::File::create(&orch_log.err).expect("orch stderr file"),
            ));

        let orch_child = cmd.spawn().expect("spawn orchestrator");
        // Wait for /health before spawning any agent.
        wait_for_health(orch_port).await;

        Self {
            orch_bin,
            agent_bin,
            orch_port,
            orch_log,
            orch_dir,
            orch_child: Some(orch_child),
            phases: Vec::new(),
        }
    }

    pub fn orchestrator_port(&self) -> u16 {
        self.orch_port
    }

    pub fn orch_key_file(&self) -> PathBuf {
        self.orch_dir.path().join("orchestrator.key")
    }

    pub fn phases(&self) -> &[Phase] {
        &self.phases
    }

    pub fn record_phase(&mut self, name: &str) {
        self.phases.push(Phase { name, start: Some(Instant::now()) });
    }

    pub async fn stop(&mut self) {
        if let Some(c) = self.orch_child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }

    pub fn orchestrator_key(&self) -> Option<String> {
        let mut found = None;
        if let Ok(mut f) = std::fs::File::open(&self.orch_log.out) {
            let mut buf = String::new();
            let _ = f.read_to_string(&mut buf);
            for line in buf.lines() {
                if let Some(key) = line.strip_prefix("orchestrator key:") {
                    found = Some(key.trim().to_string());
                    break;
                }
            }
        }
        found
    }

    pub fn api_token(&self) -> String {
        std::env::var("HIMAN_API_TOKEN").unwrap_or_else(|_| "e2e-test-token".to_string())
    }

    pub fn orchestrator_key(&self) -> Option<String> {
        let mut found = None;
        if let Ok(mut f) = std::fs::File::open(&self.orch_log.out) {
            let mut buf = String::new();
            let _ = f.read_to_string(&mut buf);
            for line in buf.lines() {
                if let Some(key) = line.strip_prefix("orchestrator key:") {
                    found = Some(key.trim().to_string());
                    break;
                }
            }
        }
        found
    }

    pub fn api_token(&self) -> String {
        std::env::var("HIMAN_API_TOKEN").unwrap_or_else(|_| "e2e-test-token".to_string())
    }

    pub async fn wait_for_registration(&self, count: usize, timeout_secs: u64) {
        let port = self.orch_port;
        let started = Instant::now();
        loop {
            if timeout(
                Duration::from_secs(timeout_secs),
                async {
                    if let Ok(resp) = ureq::get(&format!("http://127.0.0.1:{port}/api/v1/agents"))
                        .call()
                    {
                        let body = resp.into_string().unwrap_or_default();
                        let v: Value =
                            serde_json::from_str(&body).unwrap_or(Value::Null);
                        if v.is_array() && v.as_array().map(|a| a.len()).unwrap_or(0) >= count {
                            return;
                        }
                    }
                },
            )
            .await
            .is_ok()
            {
                return;
            }
            if started.elapsed() >= HARD_TIMEOUT {
                panic!(
                    "orchestrator on port {port} did not show {count} registered devices within {}s; last 40 lines of each child log:\n{}",
                    HARD_TIMEOUT.as_secs_f64(),
                    self.orch_log.tail(40)
                );
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Spawn an agent and wait for it to register, with logging to files.
    pub async fn spawn_agent(
        &mut self,
        orch_port: u16,
        agent_bin: &PathBuf,
        agent_key_file: &PathBuf,
        orch_key: &str,
    ) -> Result<Value, String> {
        let mut child = Command::new(agent_bin)
            .args(["--ws", &format!("ws://127.0.0.1:{}/ws", orch_port)])
            .env("HIMAN_DEVICE_ID", "pc-1")
            .env("HIMAN_AGENT_KEY_FILE", agent_key_file)
            .env("HIMAN_ORCH_KEY", orch_key)
            .env_remove("RUST_LOG")
            .current_dir(workspace_root())
            .stdout(Stdio::from(
                std::fs::File::create(self.orch_log.out.clone()).expect("agent stdout"),
            ))
            .stderr(Stdio::from(
                std::fs::File::create(self.orch_log.err.clone()).expect("agent stderr"),
            ))
            .spawn()
            .map_err(|e| e.to_string())?;

        // Poll /api/v1/agents until the device appears, or the hard timeout.
        let started = Instant::now();
        loop {
            if timeout(
                Duration::from_millis(100),
                async {
                    if let Ok(resp) = ureq::get(&format!(
                        "http://127.0.0.1:{}/api/v1/agents",
                        orch_port
                    ))
                    .call()
                    {
                        let body = resp.into_string().unwrap_or_default();
                        let v: Value =
                            serde_json::from_str(&body).unwrap_or(Value::Null);
                        if v.is_array() && v.as_array().map(|a| a.len()).unwrap_or(0) >= 1 {
                            return;
                        }
                    }
                },
            )
            .await
            .is_ok()
            {
                return Ok(http_get_json(orch_port, "/api/v1/agents"));
            }
            if started.elapsed() >= HARD_TIMEOUT {
                let _ = child.kill();
                let _ = child.wait();
                panic!(
                    "agent pc-1 did not register within {:.1}s; last 40 lines of each child log:\n{}",
                    HARD_TIMEOUT.as_secs_f64(),
                    self.orch_log.tail(40)
                );
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

impl Drop for E2ETest {
    fn drop(&mut self) {
        if let Some(c) = self.orch_child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

async fn wait_for_health(port: u16) {
    let started = Instant::now();
    loop {
        if timeout(
            Duration::from_millis(100),
            async {
                if let Ok(resp) = ureq::get(&format!(
                    "http://127.0.0.1:{port}/health"
                ))
                .call()
                {
                    if resp.status() == 200 {
                        return;
                    }
                }
            },
        )
        .await
        .is_ok()
        {
            return;
        }
        if started.elapsed() >= HARD_TIMEOUT {
            panic!(
                "orchestrator on port {port} did not answer /health within {}s",
                HARD_TIMEOUT.as_secs()
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

pub fn http_get_json(port: u16, path: &str) -> Value {
    let url = format!("http://127.0.0.1:{port}{path}");
    let body = ureq::get(&url)
        .call()
        .expect("GET")
        .into_string()
        .expect("body");
    serde_json::from_str(&body).expect("json")
}

pub fn http_post_json(port: u16, path: &str, body: Value) -> Value {
    let url = format!("http://127.0.0.1:{port}{path}");
    match ureq::post(&url).send_json(body) {
        Ok(resp) => {
            let status = resp.status();
            let text = resp.into_string().unwrap_or_default();
            serde_json::from_str(&text).expect("json")
        }
        Err(ureq::Error::Status(code, resp)) => {
            let text = resp.into_string().unwrap_or_default();
            serde_json::from_str(&text).expect("json")
        }
        Err(e) => panic!("POST {path} on port {port} failed: {e}"),
    }
}
