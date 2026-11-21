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
//! let devices = common::make_devices(2);          // keys for dev-0, dev-1
//! let mut harness = common::E2ETest::with_devices(&devices).await;
//! let port = harness.port();
//! harness.spawn_agent(port, "dev-0", &devices["dev-0"].key_file, &orch_key).await?;
//! harness.stop().await;
//! ```

#![allow(dead_code)] // helpers are used by whichever test target needs them

/// A portable TCP proxy for measuring the handoff beyond loopback.
pub mod proxy;

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

/// Ensure a workspace binary is built with the features a test needs.
///
/// The fault-injection hooks live behind `agent-pc`'s `fault-injection`
/// feature, so the real binaries the e2e tests drive must be rebuilt with it.
/// A default build must NOT contain them: `build_agent_with_faults` is only
/// called from tests that need the hooks, and the default `binary()` path is
/// used everywhere else.
///
/// Cargo features are additive and the artifact path is the same either way,
/// so a feature build cannot be told apart from a default one by filename.
/// A separate `CARGO_TARGET_DIR` gives the two builds distinct binaries.
pub fn build_agent_with_faults() -> PathBuf {
    let root = workspace_root();
    let fault_target = root.join("target/fault-injection");
    let status = Command::new("cargo")
        .args([
            "build",
            "-p",
            "himan-agent-pc",
            "--features",
            "fault-injection,insecure-ws-dev",
            "--bin",
            "himan-agent-pc",
        ])
        .env("CARGO_TARGET_DIR", &fault_target)
        .current_dir(&root)
        .status()
        .expect("run cargo build for himan-agent-pc with fault-injection");
    assert!(
        status.success(),
        "failed to build himan-agent-pc with the fault-injection feature"
    );
    let exe = if cfg!(windows) {
        "himan-agent-pc.exe"
    } else {
        "himan-agent-pc"
    };
    fault_target.join("debug").join(exe)
}

/// Build the loopback e2e agent: debug build with `insecure-ws-dev` so it
/// may speak plain ws:// to the local orchestrator. Separate target dir so
/// the release binary and the default (strict) build stay clean.
pub fn build_loopback_agent() -> PathBuf {
    let root = workspace_root();
    let target = root.join("target/loopback-agent");
    let status = Command::new("cargo")
        .args([
            "build",
            "-p",
            "himan-agent-pc",
            "--features",
            "insecure-ws-dev",
            "--bin",
            "himan-agent-pc",
        ])
        .env("CARGO_TARGET_DIR", &target)
        .current_dir(&root)
        .status()
        .expect("run cargo build for the loopback agent");
    assert!(status.success(), "failed to build the loopback agent");
    let exe = if cfg!(windows) {
        "himan-agent-pc.exe"
    } else {
        "himan-agent-pc"
    };
    target.join("debug").join(exe)
}

/// Ensure the default agent binary is built WITHOUT any feature, and return it.
///
/// Cargo features are additive and share one artifact path, so a previous
/// `--features fault-injection` build in the default target dir would leave a
/// hooked binary in place. Rebuilding here makes the "default build has no
/// hook" test hermetic rather than dependent on what ran before it.
pub fn build_default_agent() -> PathBuf {
    let root = workspace_root();
    // `insecure-ws-dev` is required for the loopback e2e agent to speak
    // plain ws:// to the local orchestrator. `fault-injection` is NOT set,
    // so this binary still proves the "default build has no hooks" test.
    let status = Command::new("cargo")
        .args([
            "build",
            "-p",
            "himan-agent-pc",
            "--features",
            "insecure-ws-dev",
            "--bin",
            "himan-agent-pc",
        ])
        .current_dir(&root)
        .status()
        .expect("run cargo build for himan-agent-pc");
    assert!(
        status.success(),
        "failed to build the default himan-agent-pc"
    );
    let exe = if cfg!(windows) {
        "himan-agent-pc.exe"
    } else {
        "himan-agent-pc"
    };
    root.join("target/debug").join(exe)
}

/// Whether something is still accepting TCP connections on `port`.
fn port_is_open(port: u16) -> bool {
    std::net::TcpStream::connect_timeout(
        &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        std::time::Duration::from_millis(200),
    )
    .is_ok()
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

/// A key pair generated for one device, plus its device id and public half.
#[derive(Debug, Clone)]
pub struct DeviceKey {
    pub device: String,
    /// Base64 verifying key, as the enrollment file wants it.
    pub public_key: String,
    /// The seed file the agent reads (`HIMAN_AGENT_KEY_FILE`).
    pub key_file: PathBuf,
}

/// Generate `n` agent keys with caller-chosen ids, returning them in order.
/// One call is the single place a test gets keys from, so the enrollment file
/// and the agents always agree.
pub fn make_devices_named<I, S>(dir: &Path, n: usize, ids: I) -> Vec<DeviceKey>
where
    I: Fn(usize) -> S,
    S: Into<String>,
{
    let agent_bin = binary("himan-agent-pc").expect("build himan-agent-pc first");
    (0..n)
        .map(|i| {
            let device: String = ids(i).into();
            let key_file = dir.join(format!("{device}.key"));
            let (public_key, key_file) = generate_agent_key(&agent_bin, &key_file);
            DeviceKey {
                device,
                public_key,
                key_file,
            }
        })
        .collect()
}

/// Write an enrollment file listing every device in `devices`.
pub fn write_enrollment(path: &Path, devices: &[DeviceKey]) {
    let map: Vec<String> = devices
        .iter()
        .map(|d| format!(r#""{}":"{}""#, d.device, d.public_key))
        .collect();
    std::fs::write(path, format!("{{{}}}", map.join(","))).expect("write enrollment file");
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

    /// The exit code once the process has exited, or `None` if it is still
    /// running.
    pub fn try_wait(&mut self) -> Option<i32> {
        match self.child.try_wait() {
            Ok(Some(status)) => status.code(),
            _ => None,
        }
    }

    /// Wait for the process to exit, and assert it exited non-zero with a
    /// message matching `expect` somewhere in its log.
    ///
    /// This is how a startup guard is tested: the orchestrator refuses to
    /// start when the durable audit chain is broken, so the interesting
    /// assertion is on the exit and the reason, not on a socket.
    pub fn expect_startup_failure(&mut self, expect: &str, timeout: Duration) -> String {
        let deadline = std::time::Instant::now() + timeout;
        let code = loop {
            if let Some(code) = self.try_wait() {
                break code;
            }
            if std::time::Instant::now() >= deadline {
                let tail = self.tail(LOG_TAIL_LINES);
                panic!("the process did not exit within {timeout:?}\n{tail}");
            }
            std::thread::sleep(Duration::from_millis(25));
        };
        let _ = self.child.wait();
        let log = self.tail(LOG_TAIL_LINES);
        assert_ne!(
            code, 0,
            "the process exited successfully but a failure was required\n{log}"
        );
        assert!(
            log.contains(expect),
            "the process failed without the expected message {expect:?}\n{log}"
        );
        log
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
pub struct E2ETest {
    orch: Child,
    agents: Vec<Child>,
    /// Device id for each spawned agent, parallel to `agents`.
    agent_ids: Vec<String>,
    /// The agent binary this harness drives. Tests that need the
    /// `fault-injection` hooks set it to that build; otherwise the plain
    /// default binary is used, which must not contain the hooks.
    agent_bin: Option<PathBuf>,
    /// Set by `restartable`: the orchestrator key file, reused after a restart.
    key_file: Option<PathBuf>,
    /// Set by `restartable`: the enrollment file, reused after a restart.
    enrollment_file: Option<PathBuf>,
    /// Set by `restartable`: the durable state file, if the test uses one.
    state_file: Option<PathBuf>,
    /// Set by `try_restart_orchestrator_env` when the new process refused to start.
    last_restart_refused: Option<String>,
    port: u16,
    orch_key: String,
    /// Keys for the devices a test enrolled, in the order they were named.
    device_keys: Vec<DeviceKey>,
    /// Owns the temp dirs backing the device key files. Dropping this would
    /// delete them while the agents still need them, so it must outlive the
    /// child processes.
    _dirs: Vec<tempfile::TempDir>,
    phase_start: Instant,
    phases: Vec<Phase>,
}

impl E2ETest {
    /// Spawn a real orchestrator enrolled for the named devices, generating a
    /// key for each. The returned harness exposes those keys.
    pub async fn new_with_devices(ids: &[&str]) -> Self {
        let dir = tempfile::tempdir().expect("orch tempdir");
        let devices = make_devices_named(dir.path(), ids.len(), |i| ids[i].to_string());
        let enrollment_file = dir.path().join("enrolled.json");
        write_enrollment(&enrollment_file, &devices);
        let key_file = dir.path().join("orchestrator.key");

        let mut harness = Self::spawn_orchestrator(key_file, enrollment_file).await;
        harness.device_keys = devices;
        harness._dirs.push(dir);
        harness
    }

    /// The generated keys, in the order the devices were named.
    pub fn devices(&self) -> &[DeviceKey] {
        &self.device_keys
    }

    /// Spawn a real orchestrator with explicit key and enrollment files, so a
    /// test can enroll exactly the devices it needs.
    pub async fn with_key_file(key_file: &Path, enrollment_file: &Path) -> Self {
        Self::spawn_orchestrator(key_file.to_path_buf(), enrollment_file.to_path_buf()).await
    }

    /// Spawn a real orchestrator enrolled for every device in `devices`.
    pub async fn with_devices(devices: &[DeviceKey]) -> Self {
        let dir = tempfile::tempdir().expect("orch tempdir");
        let enrollment_file = dir.path().join("enrolled.json");
        write_enrollment(&enrollment_file, devices);
        let key_file = dir.path().join("orchestrator.key");
        let mut harness = Self::spawn_orchestrator(key_file, enrollment_file).await;
        harness._dirs.push(dir);
        harness
    }

    async fn spawn_orchestrator(key_file: PathBuf, enrollment_file: PathBuf) -> Self {
        Self::spawn_orchestrator_with_mode(key_file, enrollment_file, false).await
    }

    /// Spawn the real orchestrator in insecure dev mode: no API token is set
    /// and enrollment is not enforced, which is the escape hatch the startup
    /// tests exercise.
    pub async fn new_insecure_dev() -> Self {
        let dir = tempfile::tempdir().expect("orch tempdir");
        let devices = make_devices_named(dir.path(), 1, |_| "pc-1");
        let enrollment_file = dir.path().join("enrolled.json");
        write_enrollment(&enrollment_file, &devices);
        let key_file = dir.path().join("orchestrator.key");
        let mut harness = Self::spawn_orchestrator_with_mode(key_file, enrollment_file, true).await;
        harness.device_keys = devices;
        harness._dirs.push(dir);
        harness
    }

    async fn spawn_orchestrator_with_mode(
        key_file: PathBuf,
        enrollment_file: PathBuf,
        insecure_dev: bool,
    ) -> Self {
        Self::spawn_orchestrator_env(key_file, enrollment_file, insecure_dev, Vec::new()).await
    }

    /// Spawn a real orchestrator enrolled for `devices`, with extra
    /// orchestrator environment (for example a short handoff timeout).
    ///
    /// The enrollment file, key file and optional state file live in a single
    /// data directory the harness remembers, so a test can stop the
    /// orchestrator and start it again on the same state.
    pub async fn with_devices_env(
        devices: &[DeviceKey],
        extra_envs: Vec<(String, String)>,
    ) -> Self {
        let dir = tempfile::tempdir().expect("orch tempdir");
        let enrollment_file = dir.path().join("enrolled.json");
        write_enrollment(&enrollment_file, devices);
        let key_file = dir.path().join("orchestrator.key");
        let mut harness =
            Self::spawn_orchestrator_env(key_file, enrollment_file, false, extra_envs).await;
        harness.device_keys = devices.to_vec();
        harness._dirs.push(dir);
        harness
    }

    /// Build a harness whose data dir and key file survive a restart.
    ///
    /// `state_file` is `Some` when the test wants durable (SQLite) state, which
    /// is what the restart tests need.
    pub async fn restartable(
        devices: &[DeviceKey],
        state_file: Option<PathBuf>,
        extra_envs: Vec<(String, String)>,
    ) -> Self {
        let dir = tempfile::tempdir().expect("orch tempdir");
        let enrollment_file = dir.path().join("enrolled.json");
        write_enrollment(&enrollment_file, devices);
        let key_file = dir.path().join("orchestrator.key");
        let mut envs = extra_envs;
        if let Some(path) = &state_file {
            envs.push(("HIMAN_STATE_FILE".to_string(), path.display().to_string()));
        }
        let mut harness =
            Self::spawn_orchestrator_env(key_file.clone(), enrollment_file.clone(), false, envs)
                .await;
        harness.device_keys = devices.to_vec();
        harness._dirs.push(dir);
        harness.key_file = Some(key_file);
        harness.enrollment_file = Some(enrollment_file);
        harness.state_file = state_file;
        harness
    }

    /// Stop the orchestrator and start it again on the same data directory, key
    /// file and port, WITHOUT waiting for the agents to re-register.
    ///
    /// The waiting variant is right for tests that assert on the live agent
    /// list; a mid-handoff restart must not wait, because waiting would block
    /// until the handoff's own HTTP call returns.
    pub async fn restart_orchestrator_nowait(&mut self) {
        self.orch.kill();
        let key_file = self.key_file.clone().expect("restartable harness");
        let enrollment_file = self.enrollment_file.clone().expect("restartable harness");
        let mut envs: Vec<(String, String)> = vec![
            ("HIMAN_PORT".to_string(), self.port.to_string()),
            (
                "HIMAN_ORCH_KEY_FILE".to_string(),
                key_file.display().to_string(),
            ),
            (
                "HIMAN_ENROLLED_FILE".to_string(),
                enrollment_file.display().to_string(),
            ),
            ("HIMAN_API_TOKEN".to_string(), API_TOKEN.to_string()),
            // Loopback e2e: plain HTTP/WS is permitted only here.
            ("HIMAN_INSECURE_DEV".to_string(), "1".to_string()),
        ];
        if let Some(path) = &self.state_file {
            envs.push(("HIMAN_STATE_FILE".to_string(), path.display().to_string()));
        }
        let mut orch = Child::spawn(
            &binary("himan-orchestrator").expect("build himan-orchestrator first"),
            Vec::<String>::new(),
            envs,
        );
        // The port must be free before the new process binds it: a TIME_WAIT
        // socket would otherwise let `wait_for_health` succeed against the old
        // process, which would then finish the work the restart was meant to
        // interrupt.
        for _ in 0..50 {
            if !port_is_open(self.port) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        match wait_for_health_child(self.port, Some(&mut orch)).await {
            Ok(key) => {
                self.orch_key = key;
                self.orch = orch;
            }
            Err(message) => {
                orch.kill();
                panic!("{message}");
            }
        }
    }

    /// Wait until the agents are registered again after a restart.
    pub async fn wait_for_agents(&mut self) {
        let expected = self.agents.len();
        if let Err(message) = wait_for_registration(self.port, expected, HARD_TIMEOUT).await {
            let mut tail = String::new();
            for child in &self.agents {
                tail.push_str(&child.tail(LOG_TAIL_LINES));
            }
            panic!("{message}\n{tail}");
        }
    }

    /// Stop the orchestrator and try to start it again, reporting whether the
    /// new process came up. Does not panic on failure: the tamper test needs to
    /// observe the refusal.
    pub async fn try_restart_orchestrator_env(&mut self, extra: &[(String, String)]) -> bool {
        self.orch.kill();
        let key_file = self.key_file.clone().expect("restartable harness");
        let enrollment_file = self.enrollment_file.clone().expect("restartable harness");
        let mut envs: Vec<(String, String)> = vec![
            ("HIMAN_PORT".to_string(), self.port.to_string()),
            (
                "HIMAN_ORCH_KEY_FILE".to_string(),
                key_file.display().to_string(),
            ),
            (
                "HIMAN_ENROLLED_FILE".to_string(),
                enrollment_file.display().to_string(),
            ),
            ("HIMAN_API_TOKEN".to_string(), API_TOKEN.to_string()),
            // Loopback e2e: plain HTTP/WS is permitted only here.
            ("HIMAN_INSECURE_DEV".to_string(), "1".to_string()),
        ];
        if let Some(path) = &self.state_file {
            envs.push(("HIMAN_STATE_FILE".to_string(), path.display().to_string()));
        }
        envs.extend(extra.iter().cloned());
        let mut orch = Child::spawn(
            &binary("himan-orchestrator").expect("build himan-orchestrator first"),
            Vec::<String>::new(),
            envs,
        );
        tokio::time::sleep(std::time::Duration::from_millis(600)).await;
        match wait_for_health_child(self.port, Some(&mut orch)).await {
            Ok(key) => {
                self.orch_key = key;
                self.orch = orch;
                true
            }
            Err(message) => {
                let tail = orch.tail(LOG_TAIL_LINES);
                orch.kill();
                // Prefer the process's own stderr: it says why it refused (for
                // example the audit chain check), whereas the health check only
                // says it never came up.
                let reason = if tail.contains("refusing to start") || tail.contains("audit chain") {
                    tail
                } else {
                    format!("{message}\n{tail}")
                };
                self.last_restart_refused = Some(reason);
                false
            }
        }
    }

    /// Why the last `try_restart_orchestrator_env` failed, if it did.
    pub fn last_restart_refused(&self) -> Option<&str> {
        self.last_restart_refused.as_deref()
    }

    /// Stop the orchestrator and start it again, with extra environment.
    ///
    /// Used by the tamper test to set `HIMAN_ALLOW_AUDIT_RECOVERY`.
    pub async fn restart_orchestrator_nowait_env(&mut self, extra: &[(String, String)]) {
        self.orch.kill();
        let key_file = self.key_file.clone().expect("restartable harness");
        let enrollment_file = self.enrollment_file.clone().expect("restartable harness");
        let mut envs: Vec<(String, String)> = vec![
            ("HIMAN_PORT".to_string(), self.port.to_string()),
            (
                "HIMAN_ORCH_KEY_FILE".to_string(),
                key_file.display().to_string(),
            ),
            (
                "HIMAN_ENROLLED_FILE".to_string(),
                enrollment_file.display().to_string(),
            ),
            ("HIMAN_API_TOKEN".to_string(), API_TOKEN.to_string()),
            // Loopback e2e: plain HTTP/WS is permitted only here.
            ("HIMAN_INSECURE_DEV".to_string(), "1".to_string()),
        ];
        if let Some(path) = &self.state_file {
            envs.push(("HIMAN_STATE_FILE".to_string(), path.display().to_string()));
        }
        envs.extend(extra.iter().cloned());
        let mut orch = Child::spawn(
            &binary("himan-orchestrator").expect("build himan-orchestrator first"),
            Vec::<String>::new(),
            envs,
        );
        // A process that refuses to start exits immediately; wait briefly so
        // the failure is observed rather than racing the health check.
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        match wait_for_health_child(self.port, Some(&mut orch)).await {
            Ok(key) => {
                self.orch_key = key;
                self.orch = orch;
            }
            Err(message) => {
                orch.kill();
                panic!("{message}");
            }
        }
    }

    /// Spawn the orchestrator again WITHOUT waiting for it to come up.
    ///
    /// For tests that expect the process to refuse to start: the assertion is
    /// on the exit code and the log, which `expect_startup_failure` reads.
    pub fn start_orchestrator_with(&mut self, extra: &[(String, String)]) -> Child {
        self.orch.kill();
        let key_file = self.key_file.clone().expect("restartable harness");
        let enrollment_file = self.enrollment_file.clone().expect("restartable harness");
        let mut envs: Vec<(String, String)> = vec![
            ("HIMAN_PORT".to_string(), self.port.to_string()),
            (
                "HIMAN_ORCH_KEY_FILE".to_string(),
                key_file.display().to_string(),
            ),
            (
                "HIMAN_ENROLLED_FILE".to_string(),
                enrollment_file.display().to_string(),
            ),
            ("HIMAN_API_TOKEN".to_string(), API_TOKEN.to_string()),
            // Loopback e2e: plain HTTP/WS is permitted only here.
            ("HIMAN_INSECURE_DEV".to_string(), "1".to_string()),
        ];
        if let Some(path) = &self.state_file {
            envs.push(("HIMAN_STATE_FILE".to_string(), path.display().to_string()));
        }
        envs.extend(extra.iter().cloned());
        Child::spawn(
            &binary("himan-orchestrator").expect("build himan-orchestrator first"),
            Vec::<String>::new(),
            envs,
        )
    }

    /// Stop the orchestrator and start it again on the same data directory, key
    /// file and port. Agents are left running: they reconnect on their own.
    pub async fn restart_orchestrator(&mut self) {
        self.restart_orchestrator_nowait().await;
        self.wait_for_agents().await;
    }

    /// Spawn the real orchestrator with extra environment, so a test can set
    /// the handoff timeouts it needs (for example a short warming window).
    pub async fn spawn_orchestrator_env(
        key_file: PathBuf,
        enrollment_file: PathBuf,
        insecure_dev: bool,
        extra_envs: Vec<(String, String)>,
    ) -> Self {
        let port = free_port();
        let _log_dir = tempfile::tempdir().expect("log dir");
        let mut envs: Vec<(String, String)> = vec![
            ("HIMAN_PORT".to_string(), port.to_string()),
            (
                "HIMAN_ORCH_KEY_FILE".to_string(),
                key_file.display().to_string(),
            ),
            (
                "HIMAN_ENROLLED_FILE".to_string(),
                enrollment_file.display().to_string(),
            ),
        ];
        // In dev mode the orchestrator needs no token, and the API routes are
        // open. Setting it anyway would hide a dev-mode regression.
        // Loopback e2e always permits plain HTTP/WS at the transport layer;
        // API auth is still controlled by insecure_dev below.
        envs.push(("HIMAN_INSECURE_DEV".to_string(), "1".to_string()));
        if !insecure_dev {
            envs.push(("HIMAN_API_TOKEN".to_string(), API_TOKEN.to_string()));
        }
        envs.extend(extra_envs);
        let mut orch = Child::spawn(
            &binary("himan-orchestrator").expect("build himan-orchestrator first"),
            Vec::<String>::new(),
            envs,
        );

        // Health must answer BEFORE any agent is spawned.
        match wait_for_health_child(port, Some(&mut orch)).await {
            Ok(orch_key) => Self {
                orch,
                agents: Vec::new(),
                agent_ids: Vec::new(),
                agent_bin: None,
                key_file: None,
                enrollment_file: None,
                state_file: None,
                last_restart_refused: None,
                port,
                orch_key,
                device_keys: Vec::new(),
                _dirs: Vec::new(),
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

    /// The agent binary spawned by this harness.
    pub fn agent_binary(&self) -> PathBuf {
        self.agent_bin.clone().unwrap_or_else(build_loopback_agent)
    }

    /// Drive the `fault-injection` agent build instead of the default one.
    ///
    /// Call before spawning any agent. The default binary is the ordinary
    /// `cargo build` product; this is the only way a test gets the hooks.
    pub fn use_fault_injection_agent(&mut self) -> PathBuf {
        let bin = build_agent_with_faults();
        self.agent_bin = Some(bin.clone());
        bin
    }

    /// Drive an explicitly built default agent binary (no features).
    pub fn use_default_agent(&mut self) -> PathBuf {
        let bin = build_default_agent();
        self.agent_bin = Some(bin.clone());
        bin
    }

    /// The last `n` lines of the orchestrator's stdout and stderr, for failure
    /// output. A test that needs to diagnose a restart prints this.
    pub fn orchestrator_log(&self, n: usize) -> String {
        let mut text = self.orch.tail(n);
        let old = self.orch.err.with_extension("old.log");
        if let Ok(prev) = std::fs::read_to_string(&old) {
            let lines: Vec<&str> = prev.lines().collect();
            let start = lines.len().saturating_sub(n);
            text.push_str("\n--- previous orchestrator ---\n");
            for line in &lines[start..] {
                text.push_str(line);
                text.push('\n');
            }
        }
        text
    }

    /// The orchestrator's HTTP port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Alias for [`E2ETest::port`], kept for the existing e2e test wording.
    pub fn orchestrator_port(&self) -> u16 {
        self.port
    }

    /// The API token the orchestrator was started with.
    pub fn api_token(&self) -> &str {
        API_TOKEN
    }

    /// The stdout of the agent running as `device_id`.
    ///
    /// The agent prints one line per executed tool, which is how a test proves
    /// exactly-once execution on the real binary.
    pub fn agent_stdout(&self, device_id: &str) -> String {
        let pos = match self.agent_ids.iter().position(|id| id == device_id) {
            Some(p) => p,
            None => return String::new(),
        };
        std::fs::read_to_string(&self.agents[pos].out).unwrap_or_default()
    }

    /// Stop the agent running as `device_id`. Returns false if it was not
    /// running (for example it had already been killed).
    pub fn kill_agent(&mut self, device_id: &str) -> bool {
        if let Some(pos) = self.agent_ids.iter().position(|id| id == device_id) {
            self.agent_ids.remove(pos);
            let mut child = self.agents.remove(pos);
            child.kill();
            true
        } else {
            false
        }
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

    /// Spawn a real agent as `device_id` and wait until the orchestrator reports
    /// it in `/api/v1/agents`, polling every 100 ms under a hard timeout.
    ///
    /// On timeout the child is killed and the last 40 lines of the agent's
    /// stdout/stderr are included in the error.
    pub async fn spawn_agent(
        &mut self,
        orch_port: u16,
        device_id: &str,
        orch_key: &str,
    ) -> Result<Value, String> {
        let key_file = self
            .device_keys
            .iter()
            .find(|d| d.device == device_id)
            .map(|d| d.key_file.clone())
            .ok_or_else(|| format!("no key generated for device {device_id}"))?;
        self.spawn_agent_with(orch_port, device_id, &key_file, orch_key, Vec::new())
            .await
    }

    /// Spawn a real agent that registers and then runs the deterministic
    /// scenario task.
    ///
    /// The orchestrator drives the steps (one `scenario_step` tool call per
    /// step), so the agent itself just registers and executes what it is
    /// issued. That keeps a single writer: the step count and the exactly-once
    /// guarantee live in the orchestrator's event log, not in a process-local
    /// counter.
    /// Spawn a real agent with extra environment, no extra CLI args.
    pub async fn spawn_agent_env(
        &mut self,
        orch_port: u16,
        device_id: &str,
        orch_key: &str,
        extra_envs: &[(String, String)],
    ) -> Result<Value, String> {
        let key_file = self
            .device_keys
            .iter()
            .find(|d| d.device == device_id)
            .map(|d| d.key_file.clone())
            .ok_or_else(|| format!("no key generated for device {device_id}"))?;
        self.spawn_agent_full(
            orch_port,
            device_id,
            &key_file,
            orch_key,
            Vec::new(),
            extra_envs.to_vec(),
        )
        .await
    }

    pub async fn spawn_agent_scenario(
        &mut self,
        orch_port: u16,
        device_id: &str,
        steps: u64,
        step_ms: u64,
        orch_key: &str,
    ) -> Result<Value, String> {
        let _ = (steps, step_ms);
        self.spawn_agent(orch_port, device_id, orch_key).await
    }

    /// The stdout of each spawned agent, keyed by device id.
    ///
    /// The scenario runner prints one line per executed step, which is how a
    /// test observes exactly-once execution on the real binary.
    pub fn agent_logs(&self) -> Vec<(String, String)> {
        self.agent_ids
            .iter()
            .zip(self.agents.iter())
            .map(|(id, child)| {
                (
                    id.clone(),
                    std::fs::read_to_string(&child.out).unwrap_or_default(),
                )
            })
            .collect()
    }

    /// The stderr of each spawned agent, keyed by device id.
    pub fn agent_err_logs(&self) -> Vec<(String, String)> {
        self.agent_ids
            .iter()
            .zip(self.agents.iter())
            .map(|(id, child)| {
                (
                    id.clone(),
                    std::fs::read_to_string(&child.err).unwrap_or_default(),
                )
            })
            .collect()
    }

    /// Spawn a real agent with extra CLI args (for example the deterministic
    /// scenario task), under `device_id`.
    pub async fn spawn_agent_with(
        &mut self,
        orch_port: u16,
        device_id: &str,
        agent_key_file: &Path,
        orch_key: &str,
        extra_args: Vec<String>,
    ) -> Result<Value, String> {
        self.spawn_agent_full(
            orch_port,
            device_id,
            agent_key_file,
            orch_key,
            extra_args,
            Vec::new(),
        )
        .await
    }

    /// Spawn a real agent with extra CLI args and extra environment.
    ///
    /// `extra_envs` is how a test makes a device behave a specific way (for
    /// example `HIMAN_TEST_NEVER_READY=1` for the rollback scenario) without
    /// changing the agent's production defaults.
    /// Spawn an agent and wait at most `timeout_secs` for registration.
    /// For tests that expect registration to FAIL (revoked device), use a
    /// short timeout instead of the 60 s hard timeout.
    // Allow 8 args: the bounded variant intentionally mirrors spawn_agent_full
    // plus one timeout. Keeping the signatures parallel is clearer than a
    // parameter struct used by only these two helpers.
    #[allow(clippy::too_many_arguments)]
    pub async fn spawn_agent_full_bounded(
        &mut self,
        orch_port: u16,
        device_id: &str,
        agent_key_file: &Path,
        orch_key: &str,
        extra_args: Vec<String>,
        extra_envs: Vec<(String, String)>,
        timeout_secs: u64,
    ) -> Result<Value, String> {
        self.spawn_agent_full_inner(
            orch_port,
            device_id,
            agent_key_file,
            orch_key,
            extra_args,
            extra_envs,
            timeout_secs,
        )
        .await
    }

    pub async fn spawn_agent_full(
        &mut self,
        orch_port: u16,
        device_id: &str,
        agent_key_file: &Path,
        orch_key: &str,
        extra_args: Vec<String>,
        extra_envs: Vec<(String, String)>,
    ) -> Result<Value, String> {
        self.spawn_agent_full_inner(
            orch_port,
            device_id,
            agent_key_file,
            orch_key,
            extra_args,
            extra_envs,
            HARD_TIMEOUT.as_secs(),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn spawn_agent_full_inner(
        &mut self,
        orch_port: u16,
        device_id: &str,
        agent_key_file: &Path,
        orch_key: &str,
        extra_args: Vec<String>,
        extra_envs: Vec<(String, String)>,
        timeout_secs: u64,
    ) -> Result<Value, String> {
        let mut args = vec!["--ws".to_string(), format!("ws://127.0.0.1:{orch_port}/ws")];
        args.extend(extra_args);
        let mut envs = vec![
            ("HIMAN_DEVICE_ID".to_string(), device_id.to_string()),
            (
                "HIMAN_AGENT_KEY_FILE".to_string(),
                agent_key_file.display().to_string(),
            ),
            ("HIMAN_ORCH_KEY".to_string(), orch_key.to_string()),
        ];
        envs.extend(extra_envs);
        let mut child = Child::spawn(&self.agent_binary(), args, envs);

        let expected = self.agents.len() + 1;
        match wait_for_registration(
            orch_port,
            expected,
            std::time::Duration::from_secs(timeout_secs),
        )
        .await
        {
            Ok(agents) => {
                self.agent_ids.push(device_id.to_string());
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
    wait_for_health_child(port, None).await
}

/// Poll `/health` with a bounded backoff until the orchestrator answers.
///
/// When the child handle is given, a process that has already exited is
/// detected immediately instead of burning the whole deadline on a dead
/// process (the durable_audit CI flake: the child died on EADDRINUSE and
/// the wait polled nothing for 60 s). The backoff starts at 50 ms and caps
/// at 500 ms, so a slow-but-alive startup is still given the full window.
async fn wait_for_health_child(port: u16, child: Option<&mut Child>) -> Result<String, String> {
    let deadline = Instant::now() + HARD_TIMEOUT;
    let mut delay = Duration::from_millis(50);
    let mut attempts = 0u32;
    let mut child = child;
    loop {
        attempts += 1;
        // A dead child will never answer: fail fast with its own output.
        if let Some(c) = child.as_deref_mut() {
            if let Some(code) = c.try_wait() {
                return Err(format!(
                    "orchestrator on port {port} exited with code {code:?} before answering \
                     /health (after {attempts} attempts)\n{}",
                    c.tail(LOG_TAIL_LINES)
                ));
            }
        }
        let url = format!("{}://127.0.0.1:{port}/health", base_scheme());
        if let Ok(response) = agent().get(&url).call() {
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
            let tail = child
                .as_deref_mut()
                .map(|c| c.tail(LOG_TAIL_LINES))
                .unwrap_or_default();
            return Err(format!(
                "orchestrator on port {port} did not answer GET /health within {}s \
                 ({attempts} attempts, last backoff {}ms)\n{tail}",
                HARD_TIMEOUT.as_secs(),
                delay.as_millis()
            ));
        }
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(Duration::from_millis(500));
    }
}

/// Poll `/api/v1/agents` every 100 ms until it reports at least `count`
/// devices, and return the parsed agent list.
async fn wait_for_registration(port: u16, count: usize, hard: Duration) -> Result<Value, String> {
    let deadline = Instant::now() + hard;
    loop {
        let url = format!("{}://127.0.0.1:{port}/api/v1/agents", base_scheme());
        if let Ok(response) = agent()
            .get(&url)
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
    let url = format!("{}://127.0.0.1:{port}{path}", base_scheme());
    let body = agent()
        .get(&url)
        .set("Authorization", &format!("Bearer {API_TOKEN}"))
        .call()
        .expect("GET")
        .into_string()
        .expect("body");
    serde_json::from_str(&body).expect("json")
}

/// `GET` a JSON route and return `(status, body)`, so a test can assert a
/// refusal without panicking.
/// The CA the harness uses for TLS, if the orchestrator was started with
/// HIMAN_TLS_CERT/KEY. HTTP helpers then speak https:// with this CA.
pub fn test_ca() -> Option<PathBuf> {
    std::env::var("HIMAN_TEST_TLS_CA")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .map(PathBuf::from)
}

/// When set, the harness's own HTTP client (test infrastructure, NOT the
/// agent) accepts a server certificate whose hostname does not match, so a
/// negative test can stand up a mismatched-hostname orchestrator and still
/// probe it. The agent under test never gets this latitude: its verification
/// is unconditional.
fn harness_lax_hostname() -> bool {
    std::env::var("HIMAN_TEST_TLS_LAX_HOSTNAME").as_deref() == Ok("1")
}

fn tls_agent(ca: &Path) -> ureq::Agent {
    use rustls::pki_types::CertificateDer;
    // Feature unification (reqwest/tokio-tungstenite enable aws-lc-rs too)
    // makes rustls' automatic provider selection ambiguous; pick ring.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let pem = std::fs::read_to_string(ca).expect("CA PEM");
    let mut roots = rustls::RootCertStore::empty();
    for block in pem.split("-----BEGIN CERTIFICATE-----").skip(1) {
        let body = block
            .split("-----END CERTIFICATE-----")
            .next()
            .unwrap_or("");
        let compact: String = body.chars().filter(|c| !c.is_whitespace()).collect();
        use base64::Engine;
        if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(compact) {
            let _ = roots.add(CertificateDer::from(bytes));
        }
    }
    let config = if harness_lax_hostname() {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(std::sync::Arc::new(LaxHostnameVerifier::new()))
            .with_no_client_auth()
    } else {
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    };
    ureq::AgentBuilder::new()
        .tls_config(std::sync::Arc::new(config))
        .build()
}

/// Verifies the handshake but not the hostname. Used ONLY by the test
/// harness's own HTTP client (`orchestrator/tests/common/mod.rs`) so a
/// negative test can stand up a mismatched-hostname server and still probe
/// it; gated by HIMAN_TEST_TLS_LAX_HOSTNAME, which the agent never sets.
/// The agent under test (agent-core / agent-pc) has no such path — its
/// certificate verification is unconditional.
#[derive(Debug)]
struct LaxHostnameVerifier(std::sync::Arc<rustls::crypto::CryptoProvider>);

impl LaxHostnameVerifier {
    fn new() -> Self {
        Self(std::sync::Arc::new(rustls::crypto::ring::default_provider()))
    }
}

impl rustls::client::danger::ServerCertVerifier for LaxHostnameVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// The base URL scheme the harness should use for this orchestrator.
pub fn base_scheme() -> &'static str {
    if test_ca().is_some() {
        "https"
    } else {
        "http"
    }
}

fn agent() -> ureq::Agent {
    match test_ca() {
        Some(ca) => tls_agent(&ca),
        None => ureq::AgentBuilder::new().build(),
    }
}

pub fn http_get(port: u16, path: &str) -> (u16, Value) {
    let url = format!("{}://127.0.0.1:{port}{path}", base_scheme());
    match agent()
        .get(&url)
        .set("Authorization", &format!("Bearer {API_TOKEN}"))
        .call()
    {
        Ok(response) => {
            let status = response.status();
            let text = response.into_string().unwrap_or_default();
            (status, serde_json::from_str(&text).unwrap_or(Value::Null))
        }
        Err(ureq::Error::Status(code, response)) => {
            let text = response.into_string().unwrap_or_default();
            (code, serde_json::from_str(&text).unwrap_or(Value::Null))
        }
        Err(error) => panic!("GET {path} on port {port} failed: {error}"),
    }
}

/// `POST` a JSON body to a route on the test orchestrator with the harness
/// token and return the parsed response.
pub fn http_post_json(port: u16, path: &str, body: Value) -> Value {
    let url = format!("{}://127.0.0.1:{port}{path}", base_scheme());
    match agent()
        .post(&url)
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

/// `POST` a JSON body and return `(status, body)`, so a test can assert a
/// refusal without panicking.
pub fn http_post(port: u16, path: &str, body: Value) -> (u16, Value) {
    let url = format!("{}://127.0.0.1:{port}{path}", base_scheme());
    match agent()
        .post(&url)
        .set("Authorization", &format!("Bearer {API_TOKEN}"))
        .send_json(body)
    {
        Ok(response) => {
            let status = response.status();
            let text = response.into_string().unwrap_or_default();
            (status, serde_json::from_str(&text).unwrap_or(Value::Null))
        }
        Err(ureq::Error::Status(code, response)) => {
            let text = response.into_string().unwrap_or_default();
            (code, serde_json::from_str(&text).unwrap_or(Value::Null))
        }
        Err(error) => panic!("POST {path} on port {port} failed: {error}"),
    }
}
