//! Fast, reliable helpers for the real-binaries end-to-end test harness.
//!
//! The red-team suites build their own in-process router. This file runs the
//! *real* Orchestrator and Agent binaries exactly the way `src/bin/orchestrator.rs`
//! and `agent-pc/src/main.rs` do: forked processes on ephemeral loopback ports,
//! driven over real HTTP and WebSocket sockets.
//!
//! The rules that make these tests fast and reliable, and the ones that were
//! biting the older harness:
//!   - child stdout and stderr go to temp files, NEVER to pipes. A pipe that
//!     nobody drains backs up the child, and the child blocks on a full pipe
//!     while the test waits blind; `Stdio::null()` would swallow the very
//!     diagnostics a failure needs. Temp files keep both problems away.
//!   - the orchestrator must answer `GET /health` before ANY agent is spawned.
//!     Spawning earlier puts the agent in its reconnect backoff, so
//!     registration takes seconds instead of milliseconds.
//!   - every wait (health, registration) polls every 100 ms under a hard
//!     timeout, and a timeout prints the last 40 lines of every child log.
//!   - every phase is timed with `Instant` and reported at the end.
//!
//! Usage:
//!
//! ```ignore
//! let mut harness = common::E2ETest::new().await;
//! let port = harness.port();
//! let agents = harness
//!     .spawn_agent(port, &agent_bin, &key_file, &orch_key)
//!     .await
//!     .expect("agent registers");
//! harness.stop().await;
//! ```

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;

/// Hard ceiling for every poll/registration/health wait in this harness.
pub const HARD_TIMEOUT: Duration = Duration::from_secs(60);

/// How often registration and health are polled.
pub const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// How many lines of each child log a timeout prints.
pub const LOG_TAIL_LINES: usize = 40;

/// The token the harness starts the orchestrator with.
///
/// `orchestrator/src/bin/orchestrator.rs` refuses to start without
/// `HIMAN_API_TOKEN` unless `HIMAN_INSECURE_DEV=1`, so the harness always sets
/// it: the test then proves the token-gated `/api/v1/*` routes for real.
pub const API_TOKEN: &str = "e2e-test-token";

fn workspace_root() -> PathBuf {
    // `CARGO_MANIFEST_DIR` is `<root>/orchestrator`, so the target dir is one
    // level up.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

/// Resolve a workspace binary, returning `None` when it has not been built
/// yet. The tests require `cargo build --workspace` first; a missing binary is
/// a broken setup, and the caller decides how to report it.
pub fn binary(name: &str) -> Option<PathBuf> {
    let exe = if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_string()
    };
    let root = workspace_root();
    [
        root.join(format!("target/debug/{exe}")),
        root.join(format!("target/release/{exe}")),
    ]
    .into_iter()
    .find(|candidate| candidate.exists())
}

/// Bind an ephemeral port on loopback and return it.
///
/// The listener is dropped before the caller binds it, so a fast restart can
/// reuse the port; every test here starts its own orchestrator, so collisions
/// are not expected.
pub fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    listener.local_addr().expect("local addr").port()
}

/// One named phase, reported with its wall time at the end of the test.
#[derive(Debug, Clone)]
pub struct Phase {
    pub name: String,
    pub elapsed: Duration,
}

/// A child process whose stdout and stderr go to files, never pipes.
pub struct Child {
    child: std::process::Child,
    out: PathBuf,
    err: PathBuf,
    _dir: tempfile::TempDir,
}

impl Child {
    /// Spawn `program` with `args`/`envs` and redirect both streams to files.
    pub fn spawn<A, E>(program: &Path, args: A, envs: E) -> Self
    where
        A: IntoIterator<Item = String>,
        E: IntoIterator<Item = (String, String)>,
    {
        let dir = tempfile::tempdir().expect("tempdir for child logs");
        let out = dir.path().join("stdout.log");
        let err = dir.path().join("stderr.log");
        // Children are native Windows binaries. When the test harness runs
        // under an MSYS/git-bash shell, MSYS rewrites `/c/Users/...` arguments
        // into `C:\Users\...`; when it does not (or rewrites them twice), the
        // child sees a path it cannot resolve and fails with "The system cannot
        // find the path specified". Disabling the conversion keeps the native
        // path we pass intact.
        let mut cmd = Command::new(program);
        cmd.args(args)
            .envs(envs)
            .env_remove("RUST_LOG")
            .env("MSYS2_ARG_CONV_EXCL", "*")
            .env("MSYS_NO_PATHCONV", "1")
            .current_dir(workspace_root())
            .stdout(Stdio::from(
                std::fs::File::create(&out).expect("create child stdout file"),
            ))
            .stderr(Stdio::from(
                std::fs::File::create(&err).expect("create child stderr file"),
            ));
        let child = cmd.spawn().expect("spawn child process");
        Self {
            child,
            out,
            err,
            _dir: dir,
        }
    }

    /// Kill the child if it is still running and reap it.
    pub fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    /// The last `n` lines of the child's stdout and stderr, for failure output.
    pub fn tail(&self, n: usize) -> String {
        let mut text = String::new();
        for (label, path) in [("stdout", &self.out), ("stderr", &self.err)] {
            let contents = std::fs::read_to_string(path).unwrap_or_default();
            let lines: Vec<&str> = contents.lines().collect();
            let start = lines.len().saturating_sub(n);
            text.push_str(&format!("--- child {label} (last {n} lines) ---\n"));
            for line in &lines[start..] {
                text.push_str(line);
                text.push('\n');
            }
        }
        text
    }
}

/// The real-binaries e2e harness: one orchestrator process plus any agents.
#[allow(dead_code)] // several accessors exist for the e2e suite, not this test
pub struct E2ETest {
    orch: Child,
    agents: Vec<Child>,
    port: u16,
    orch_key: String,
    agent_key_file: Option<PathBuf>,
    agent_public_key: Option<String>,
    /// Owns the temp dirs backing `agent_key_file` / `orch_key_file`. Dropping
    /// this would delete the files while the agent still needs them, so it must
    /// outlive the child processes.
    _dirs: Vec<tempfile::TempDir>,
    log_dir: tempfile::TempDir,
    phase_start: Instant,
    phases: Vec<Phase>,
}

impl E2ETest {
    /// Spawn a real orchestrator in Secure mode with a freshly generated
    /// `pc-1` agent key, already enrolled, and wait for `GET /health` before
    /// returning.
    ///
    /// The generated agent key is available through [`E2ETest::agent_key_file`]
    /// and its public half through [`E2ETest::agent_public_key`], so a test can
    /// go straight from `new()` to a real registered agent.
    pub async fn new() -> Self {
        let dir = tempfile::tempdir().expect("orch tempdir");
        let key_file = dir.path().join("orchestrator.key");
        let agent_key_file = dir.path().join("agent.key");

        let agent_bin = binary("himan-agent-pc").expect("build himan-agent-pc first");
        let (agent_public_key, agent_key_file) = generate_agent_key(&agent_bin, &agent_key_file);

        let enrollment_file = dir.path().join("enrolled.json");
        std::fs::write(
            &enrollment_file,
            format!(r#"{{"pc-1":"{agent_public_key}"}}"#),
        )
        .expect("write enrollment file");

        let mut harness = Self::spawn_orchestrator(key_file, enrollment_file).await;
        harness.agent_key_file = Some(agent_key_file);
        harness.agent_public_key = Some(agent_public_key);
        harness._dirs.push(dir);
        harness
    }

    /// Spawn a real orchestrator with explicit key and enrollment files, so a
    /// test can enroll exactly the devices it needs.
    #[allow(dead_code)] // used by the e2e suite, not by fast_roundtrip
    pub async fn with_key_file(key_file: &Path, enrollment_file: &Path) -> Self {
        Self::spawn_orchestrator(key_file.to_path_buf(), enrollment_file.to_path_buf()).await
    }

    async fn spawn_orchestrator(key_file: PathBuf, enrollment_file: PathBuf) -> Self {
        let port = free_port();
        let log_dir = tempfile::tempdir().expect("log dir");
        let mut orch = Child::spawn(
            &binary("himan-orchestrator").expect("build himan-orchestrator first"),
            Vec::<String>::new(),
            vec![
                ("HIMAN_PORT".to_string(), port.to_string()),
                (
                    "HIMAN_ORCH_KEY_FILE".to_string(),
                    key_file.display().to_string(),
                ),
                (
                    "HIMAN_ENROLLED_FILE".to_string(),
                    enrollment_file.display().to_string(),
                ),
                ("HIMAN_API_TOKEN".to_string(), API_TOKEN.to_string()),
            ],
        );

        // Health must answer BEFORE any agent is spawned.
        match wait_for_health(port).await {
            Ok(orch_key) => Self {
                orch,
                agents: Vec::new(),
                port,
                orch_key,
                agent_key_file: None,
                agent_public_key: None,
                _dirs: Vec::new(),
                log_dir,
                phase_start: Instant::now(),
                phases: Vec::new(),
            },
            Err(message) => {
                let tail = orch.tail(LOG_TAIL_LINES);
                orch.kill();
                panic!("{message}\n{tail}");
            }
        }
    }

    /// The orchestrator's HTTP port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Alias for [`E2ETest::port`], kept for the existing e2e test wording.
    #[allow(dead_code)] // used by the e2e suite, not by fast_roundtrip
    pub fn orchestrator_port(&self) -> u16 {
        self.port
    }

    /// A file holding the orchestrator's advertised verifying key (base64),
    /// suitable for an agent to pin via `HIMAN_ORCH_KEY`.
    #[allow(dead_code)] // used by the e2e suite, not by fast_roundtrip
    pub fn orch_key_file(&self) -> PathBuf {
        self.log_dir.path().join("orchestrator.pub")
    }

    /// The agent key file [`E2ETest::new`] generated, if that constructor was
    /// used.
    pub fn agent_key_file(&self) -> Option<PathBuf> {
        self.agent_key_file.clone()
    }

    /// The public half of the agent key [`E2ETest::new`] generated.
    pub fn agent_public_key(&self) -> Option<String> {
        self.agent_public_key.clone()
    }

    /// The API token the orchestrator was started with.
    #[allow(dead_code)] // used by the e2e suite, not by fast_roundtrip
    pub fn api_token(&self) -> &str {
        API_TOKEN
    }

    /// The orchestrator's advertised verifying key (base64), as `/health`
    /// reports it. Agents pin this.
    pub fn orchestrator_key(&self) -> Option<String> {
        Some(self.orch_key.clone())
    }

    /// Record a named phase. Phases are printed together at `stop`, each with
    /// the wall time since the previous phase was recorded.
    pub fn record_phase(&mut self, name: &str) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.phase_start);
        self.phases.push(Phase {
            name: name.to_string(),
            elapsed,
        });
        self.phase_start = now;
    }

    /// The recorded phases, in order.
    #[allow(dead_code)] // used by the e2e suite, not by fast_roundtrip
    pub fn phases(&self) -> &[Phase] {
        &self.phases
    }

    /// Print the phase report. Called by `stop` and by `Drop`, so the timings
    /// appear even when a test panics.
    fn report(&self) {
        if self.phases.is_empty() {
            return;
        }
        let total: Duration = self.phases.iter().map(|p| p.elapsed).sum();
        eprintln!(
            "=== e2e phase timings (total {:.2}s) ===",
            total.as_secs_f64()
        );
        for phase in &self.phases {
            eprintln!("  {:<40} {:>7.3}s", phase.name, phase.elapsed.as_secs_f64());
        }
        eprintln!("=== end timings ===");
    }

    /// Spawn a real agent as `pc-1` and wait until the orchestrator reports it
    /// in `/api/v1/agents`, polling every 100 ms under a hard timeout.
    ///
    /// On timeout the child is killed and the last 40 lines of the agent's
    /// stdout/stderr are included in the error.
    pub async fn spawn_agent(
        &mut self,
        orch_port: u16,
        agent_bin: &Path,
        agent_key_file: &Path,
        orch_key: &str,
    ) -> Result<Value, String> {
        let mut child = Child::spawn(
            agent_bin,
            vec!["--ws".to_string(), format!("ws://127.0.0.1:{orch_port}/ws")],
            vec![
                ("HIMAN_DEVICE_ID".to_string(), "pc-1".to_string()),
                (
                    "HIMAN_AGENT_KEY_FILE".to_string(),
                    agent_key_file.display().to_string(),
                ),
                ("HIMAN_ORCH_KEY".to_string(), orch_key.to_string()),
            ],
        );

        let expected = self.agents.len() + 1;
        match wait_for_registration(orch_port, expected, HARD_TIMEOUT).await {
            Ok(agents) => {
                self.agents.push(child);
                Ok(agents)
            }
            Err(message) => {
                let tail = child.tail(LOG_TAIL_LINES);
                child.kill();
                Err(format!("{message}\n{tail}"))
            }
        }
    }

    /// Wait until `/api/v1/agents` reports at least `count` registered
    /// devices, polling every 100 ms under `timeout_secs` (capped at
    /// [`HARD_TIMEOUT`]). On timeout the last 40 lines of every child log are
    /// included in the panic message.
    #[allow(dead_code)] // used by the e2e suite, not by fast_roundtrip
    pub async fn wait_for_registration(&mut self, count: usize, timeout_secs: u64) {
        let hard = Duration::from_secs(timeout_secs.min(HARD_TIMEOUT.as_secs()));
        if let Err(message) = wait_for_registration(self.port, count, hard).await {
            let mut tail = String::new();
            for child in &self.agents {
                tail.push_str(&child.tail(LOG_TAIL_LINES));
            }
            tail.push_str(&self.orch.tail(LOG_TAIL_LINES));
            panic!("{message}\n{tail}");
        }
    }

    /// Kill the orchestrator (and every spawned agent) and report the phases.
    pub async fn stop(&mut self) {
        for child in &mut self.agents {
            child.kill();
        }
        self.agents.clear();
        self.orch.kill();
        self.report();
    }
}

impl Drop for E2ETest {
    fn drop(&mut self) {
        self.report();
        for child in &mut self.agents {
            child.kill();
        }
        self.orch.kill();
    }
}

/// Run `himan-agent-pc keygen --out <file>` and return its public key (base64)
/// plus the key file path.
fn generate_agent_key(agent_bin: &Path, key_file: &Path) -> (String, PathBuf) {
    let output = Command::new(agent_bin)
        .args(["keygen", "--out"])
        .arg(key_file)
        .env_remove("RUST_LOG")
        .env("MSYS2_ARG_CONV_EXCL", "*")
        .env("MSYS_NO_PATHCONV", "1")
        .current_dir(workspace_root())
        .output()
        .expect("run himan-agent-pc keygen");
    assert!(
        output.status.success(),
        "agent keygen failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let public_key = stdout
        .lines()
        .find_map(|line| line.strip_prefix("public key: "))
        .expect("agent keygen must print a public key")
        .trim()
        .to_string();
    (public_key, key_file.to_path_buf())
}

/// Poll `GET /health` every 100 ms until it answers 200, then return the
/// orchestrator's advertised verifying key from the same response.
async fn wait_for_health(port: u16) -> Result<String, String> {
    let deadline = Instant::now() + HARD_TIMEOUT;
    loop {
        let url = format!("http://127.0.0.1:{port}/health");
        if let Ok(response) = ureq::get(&url).call() {
            if response.status() == 200 {
                let body = response.into_string().unwrap_or_default();
                let value: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
                let key = value["orchestrator_key"].as_str().unwrap_or("").to_string();
                if !key.is_empty() {
                    return Ok(key);
                }
            }
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "orchestrator on port {port} did not answer GET /health within {}s",
                HARD_TIMEOUT.as_secs()
            ));
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Poll `/api/v1/agents` every 100 ms until it reports at least `count`
/// devices, and return the parsed agent list.
async fn wait_for_registration(port: u16, count: usize, hard: Duration) -> Result<Value, String> {
    let deadline = Instant::now() + hard;
    loop {
        let url = format!("http://127.0.0.1:{port}/api/v1/agents");
        if let Ok(response) = ureq::get(&url)
            .set("Authorization", &format!("Bearer {API_TOKEN}"))
            .call()
        {
            let body = response.into_string().unwrap_or_default();
            let value: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
            let registered = value.as_array().map(|a| a.len()).unwrap_or(0);
            if registered >= count {
                return Ok(value);
            }
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "orchestrator on port {port} showed fewer than {count} registered device(s) \
                 within {:.1}s",
                hard.as_secs_f64()
            ));
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// `GET` a JSON route on the test orchestrator with the harness token.
pub fn http_get_json(port: u16, path: &str) -> Value {
    let url = format!("http://127.0.0.1:{port}{path}");
    let body = ureq::get(&url)
        .set("Authorization", &format!("Bearer {API_TOKEN}"))
        .call()
        .expect("GET")
        .into_string()
        .expect("body");
    serde_json::from_str(&body).expect("json")
}

/// `POST` a JSON body to a route on the test orchestrator with the harness
/// token and return the parsed response.
pub fn http_post_json(port: u16, path: &str, body: Value) -> Value {
    let url = format!("http://127.0.0.1:{port}{path}");
    match ureq::post(&url)
        .set("Authorization", &format!("Bearer {API_TOKEN}"))
        .send_json(body)
    {
        Ok(response) => {
            let text = response.into_string().unwrap_or_default();
            serde_json::from_str(&text).expect("json")
        }
        Err(ureq::Error::Status(code, response)) => {
            panic!("POST {path} on port {port} returned HTTP {code}: {response:?}");
        }
        Err(error) => panic!("POST {path} on port {port} failed: {error}"),
    }
}
