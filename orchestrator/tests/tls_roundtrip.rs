//! RT-21: native TLS round trip with real certificates, and negative cases.
//!
//! Written FIRST. Against current code the agent has no TLS path at all:
//! `connect_ws_ca(_, _, Some(ca))` falls back to plain ws:// and the
//! orchestrator only validates PEM without terminating TLS. The tests below
//! drive the REAL orchestrator and agent binaries over wss:// with a
//! throwaway CA, then assert that a wrong CA and a mismatched hostname are
//! refused. Certificate verification is never disabled.
//!
//! Certificates are generated with the `openssl` binary (present on the dev
//! host and in CI) into a temp dir — not with a new Rust dependency.

mod common;

use serde_json::json;
use std::path::PathBuf;
use std::process::Command;

const A: &str = "dev-a";

/// Generate a throwaway CA and a server certificate for `127.0.0.1`.
struct Certs {
    _dir: tempfile::TempDir,
    ca_pem: PathBuf,
    server_cert: PathBuf,
    server_key: PathBuf,
}

fn run(cmd: &mut Command) {
    let out = cmd.output().expect("run openssl");
    assert!(
        out.status.success(),
        "openssl failed: {}\n{}",
        cmd.get_program().to_string_lossy(),
        String::from_utf8_lossy(&out.stderr)
    );
}

fn generate_certs() -> Certs {
    let dir = tempfile::tempdir().expect("cert dir");
    let ca_key = dir.path().join("ca.key");
    let ca_pem = dir.path().join("ca.pem");
    let srv_key = dir.path().join("server.key");
    let srv_csr = dir.path().join("server.csr");
    let srv_cert = dir.path().join("server.pem");
    let ext = dir.path().join("server.ext");
    std::fs::write(
        &ext,
        b"subjectAltName=IP:127.0.0.1\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n",
    )
    .expect("ext");

    run(Command::new("openssl").args([
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-days",
        "2",
        "-keyout",
        ca_key.to_str().unwrap(),
        "-out",
        ca_pem.to_str().unwrap(),
        "-subj",
        "/CN=himan-test-ca",
    ]));
    run(Command::new("openssl").args([
        "req",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        srv_key.to_str().unwrap(),
        "-out",
        srv_csr.to_str().unwrap(),
        "-subj",
        "/CN=127.0.0.1",
    ]));
    run(Command::new("openssl").args([
        "x509",
        "-req",
        "-in",
        srv_csr.to_str().unwrap(),
        "-CA",
        ca_pem.to_str().unwrap(),
        "-CAkey",
        ca_key.to_str().unwrap(),
        "-CAcreateserial",
        "-out",
        srv_cert.to_str().unwrap(),
        "-days",
        "2",
        "-extfile",
        ext.to_str().unwrap(),
    ]));

    Certs {
        _dir: dir,
        ca_pem,
        server_cert: srv_cert,
        server_key: srv_key,
    }
}

/// Generate a second, unrelated CA (the "wrong CA").
fn generate_wrong_ca() -> PathBuf {
    let dir = tempfile::tempdir().expect("wrong ca dir");
    let ca_pem = dir.path().join("wrong-ca.pem");
    run(Command::new("openssl").args([
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-days",
        "2",
        "-keyout",
        dir.path().join("wrong.key").to_str().unwrap(),
        "-out",
        ca_pem.to_str().unwrap(),
        "-subj",
        "/CN=wrong-ca",
    ]));
    // Keep the temp dir alive for the test's duration by leaking it.
    std::mem::forget(dir);
    ca_pem
}

/// Serialize the TLS tests: they set a process-global env var that the
/// harness HTTP helpers read, so they cannot run concurrently.
static TLS_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Make the harness HTTP helpers speak https with the test CA.
fn use_test_ca(ca: &std::path::Path) {
    std::env::set_var("HIMAN_TEST_TLS_CA", ca.display().to_string());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rt21_real_orchestrator_and_agent_over_wss() {
    let _guard = TLS_LOCK.lock().await;
    let certs = generate_certs();
    use_test_ca(&certs.ca_pem);
    // The harness may probe a server whose cert hostname does not match;
    // the agent under test still verifies it and must refuse.
    std::env::set_var("HIMAN_TEST_TLS_LAX_HOSTNAME", "1");
    let dir = tempfile::tempdir().expect("tempdir");
    let devices = common::make_devices_named(dir.path(), 1, |_| A.to_string());
    let mut harness = common::E2ETest::restartable(
        &devices,
        None,
        vec![
            (
                "HIMAN_TLS_CERT".to_string(),
                certs.server_cert.display().to_string(),
            ),
            (
                "HIMAN_TLS_KEY".to_string(),
                certs.server_key.display().to_string(),
            ),
        ],
    )
    .await;
    let port = harness.port();
    let orch_key = harness.orchestrator_key().expect("orchestrator key");

    // The agent connects over wss:// with the CA, so spawn it with the CA env.
    let key_a = harness
        .devices()
        .iter()
        .find(|d| d.device == A)
        .map(|d| d.key_file.clone())
        .expect("dev-a key");
    harness
        .spawn_agent_full_bounded(
            port,
            A,
            &key_a,
            &orch_key,
            Vec::new(),
            vec![
                (
                    "HIMAN_WS_URL".to_string(),
                    format!("wss://127.0.0.1:{port}/ws"),
                ),
                (
                    "HIMAN_TLS_CA_PEM".to_string(),
                    certs.ca_pem.display().to_string(),
                ),
            ],
            15,
        )
        .await
        .expect("dev-a registers over wss");

    // A signed ToolCall/ToolResult round trip through the TLS transport.
    let (status, body) = common::http_post(
        port,
        "/api/v1/prompt",
        json!({"device": A, "prompt": "run the deterministic scenario of 3 steps"}),
    );
    assert_eq!(status, 200, "dispatch refused: {body}");
    let task_id = body["task_id"].as_str().expect("task id").to_string();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    let record = loop {
        let r = common::http_get_json(port, &format!("/api/v1/tasks/{task_id}/record"));
        if r["state"] == json!("succeeded") || std::time::Instant::now() >= deadline {
            break r;
        }
        tokio::time::sleep(common::POLL_INTERVAL).await;
    };
    assert_eq!(
        record["state"],
        json!("succeeded"),
        "the TLS round trip did not complete: {record}"
    );

    // The agent's frame verification still runs on top of TLS: no pin means
    // it would refuse, and here it registered, proving pin + TLS together.
    harness.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rt21_wrong_ca_is_refused() {
    let _guard = TLS_LOCK.lock().await;
    let certs = generate_certs();
    let wrong_ca = generate_wrong_ca();
    use_test_ca(&certs.ca_pem);
    let dir = tempfile::tempdir().expect("tempdir");
    let devices = common::make_devices_named(dir.path(), 1, |_| A.to_string());
    let mut harness = common::E2ETest::restartable(
        &devices,
        None,
        vec![
            (
                "HIMAN_TLS_CERT".to_string(),
                certs.server_cert.display().to_string(),
            ),
            (
                "HIMAN_TLS_KEY".to_string(),
                certs.server_key.display().to_string(),
            ),
        ],
    )
    .await;
    let port = harness.port();
    let orch_key = harness.orchestrator_key().expect("orchestrator key");
    let key_a = harness
        .devices()
        .iter()
        .find(|d| d.device == A)
        .map(|d| d.key_file.clone())
        .expect("dev-a key");
    // Presenting a CA that did not sign the server certificate must fail.
    let rejected = harness
        .spawn_agent_full_bounded(
            port,
            A,
            &key_a,
            &orch_key,
            Vec::new(),
            vec![
                (
                    "HIMAN_WS_URL".to_string(),
                    format!("wss://127.0.0.1:{port}/ws"),
                ),
                (
                    "HIMAN_TLS_CA_PEM".to_string(),
                    wrong_ca.display().to_string(),
                ),
            ],
            3,
        )
        .await
        .is_err();
    assert!(
        rejected,
        "the agent accepted a server cert from the WRONG CA"
    );
    harness.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rt21_mismatched_hostname_is_refused() {
    let _guard = TLS_LOCK.lock().await;
    // A certificate for a different name, signed by the trusted CA, must be
    // refused because the agent connects to 127.0.0.1.
    let certs = generate_certs();
    use_test_ca(&certs.ca_pem);
    // The harness may probe a server whose cert hostname does not match;
    // the agent under test still verifies it and must refuse.
    std::env::set_var("HIMAN_TEST_TLS_LAX_HOSTNAME", "1");
    let dir = tempfile::tempdir().expect("tempdir");
    let srv_key = dir.path().join("other.key");
    let srv_csr = dir.path().join("other.csr");
    let srv_cert = dir.path().join("other.pem");
    let ext = dir.path().join("other.ext");
    std::fs::write(&ext, b"subjectAltName=DNS:wrong.example\n").expect("ext");
    run(Command::new("openssl").args([
        "req",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        srv_key.to_str().unwrap(),
        "-out",
        srv_csr.to_str().unwrap(),
        "-subj",
        "/CN=wrong.example",
    ]));
    // Sign with the same CA as the good cert.
    let ca_key = certs._dir.path().join("ca.key");
    let ca_pem = certs._dir.path().join("ca.pem");
    run(Command::new("openssl").args([
        "x509",
        "-req",
        "-in",
        srv_csr.to_str().unwrap(),
        "-CA",
        ca_pem.to_str().unwrap(),
        "-CAkey",
        ca_key.to_str().unwrap(),
        "-CAcreateserial",
        "-out",
        srv_cert.to_str().unwrap(),
        "-days",
        "2",
        "-extfile",
        ext.to_str().unwrap(),
    ]));

    let devices = common::make_devices_named(dir.path(), 1, |_| A.to_string());
    let mut harness = common::E2ETest::restartable(
        &devices,
        None,
        vec![
            ("HIMAN_TLS_CERT".to_string(), srv_cert.display().to_string()),
            ("HIMAN_TLS_KEY".to_string(), srv_key.display().to_string()),
        ],
    )
    .await;
    let port = harness.port();
    let orch_key = harness.orchestrator_key().expect("orchestrator key");
    let key_a = harness
        .devices()
        .iter()
        .find(|d| d.device == A)
        .map(|d| d.key_file.clone())
        .expect("dev-a key");
    let rejected = harness
        .spawn_agent_full_bounded(
            port,
            A,
            &key_a,
            &orch_key,
            Vec::new(),
            vec![
                (
                    "HIMAN_WS_URL".to_string(),
                    format!("wss://127.0.0.1:{port}/ws"),
                ),
                (
                    "HIMAN_TLS_CA_PEM".to_string(),
                    certs.ca_pem.display().to_string(),
                ),
            ],
            3,
        )
        .await
        .is_err();
    assert!(
        rejected,
        "the agent accepted a certificate for the wrong hostname"
    );
    harness.stop().await;
}
