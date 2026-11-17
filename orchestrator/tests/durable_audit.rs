//! The durable audit log: it survives a restart and a tampered row is caught.

mod common;

use serde_json::json;
use std::time::Duration;

const A: &str = "dev-a";
const B: &str = "dev-b";

/// A durable harness, both agents registered, one scenario task dispatched.
async fn durable() -> (common::E2ETest, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let devices = common::make_devices_named(dir.path(), 2, |i| [A, B][i].to_string());
    let state_file = dir.path().join("state.db");
    let mut harness = common::E2ETest::restartable(
        &devices,
        Some(state_file),
        vec![(
            "HIMAN_TEST_HANDOFF_TIMEOUT_SECS".to_string(),
            "10".to_string(),
        )],
    )
    .await;
    harness.use_fault_injection_agent();
    let port = harness.port();
    let orch_key = harness.orchestrator_key().expect("orchestrator key");
    harness
        .spawn_agent(port, A, &orch_key)
        .await
        .expect("dev-a registers");
    harness
        .spawn_agent(port, B, &orch_key)
        .await
        .expect("dev-b registers");
    (harness, dir)
}

fn audit_actions(port: u16) -> Vec<String> {
    let audit = common::http_get_json(port, "/api/v1/audit");
    audit
        .as_array()
        .expect("audit array")
        .iter()
        .map(|e| e["action"].as_str().unwrap_or_default().to_string())
        .collect()
}

#[tokio::test]
async fn audit_entries_survive_a_restart() {
    let (mut harness, _dir) = durable().await;
    let port = harness.port();

    // Produce a startup rollback, which is the interesting entry to survive.
    let (status, body) = common::http_post(
        port,
        "/api/v1/prompt",
        json!({"device": A, "prompt": "run the deterministic scenario of 40 steps"}),
    );
    assert_eq!(status, 200, "dispatch refused: {body}");
    let task_id = body["task_id"].as_str().expect("task id").to_string();

    let key_b = harness
        .devices()
        .iter()
        .find(|d| d.device == B)
        .map(|d| d.key_file.clone())
        .expect("dev-b key");
    harness.kill_agent(B);
    harness
        .spawn_agent_full(
            port,
            B,
            &key_b,
            &harness.orchestrator_key().expect("key"),
            Vec::new(),
            vec![("HIMAN_TEST_SLOW_READY_MS".to_string(), "15000".to_string())],
        )
        .await
        .expect("dev-b re-registers");

    let url = format!("http://127.0.0.1:{port}/api/v1/handoff");
    let task_for_request = task_id.clone();
    let request = tokio::spawn(async move {
        ureq::post(&url)
            .set("Authorization", &format!("Bearer {}", common::API_TOKEN))
            .send_json(json!({"task_id": task_for_request, "from": A, "to": B}))
            .map(|r| r.status())
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    harness.restart_orchestrator_nowait().await;
    let _ = request.await;
    harness.wait_for_agents().await;

    // The endpoint now reads from the durable log: the rollback entry from
    // before the restart is still there.
    let actions = audit_actions(port);
    assert!(
        actions.iter().any(|a| a == "handoff_rolled_back"),
        "the startup rollback did not survive the restart: {actions:?}"
    );
    // And it is the durable log, not a fresh in-memory one: the agent
    // registrations from before the restart are present too.
    assert!(
        actions.iter().any(|a| a == "agent_registered"),
        "entries from before the restart were lost: {actions:?}"
    );

    harness.stop().await;
}

#[tokio::test]
async fn a_tampered_audit_row_is_detected_at_startup() {
    let (mut harness, _dir) = durable().await;
    let port = harness.port();

    // Produce some durable audit entries.
    let _ = common::http_post(
        port,
        "/api/v1/prompt",
        json!({"device": A, "prompt": "run the deterministic scenario of 5 steps"}),
    );
    let before = audit_actions(port);
    assert!(before.len() >= 3, "too few audit entries: {before:?}");

    // Tamper with a row: flip the detail of the second entry and leave its
    // stored hash alone, so the chain no longer verifies.
    let state = _dir.path().join("state.db");
    tamper_audit_row(&state);

    // A restart without the recovery flag must refuse to start. The process
    // exits on its own, so the assertion is on the exit and the reason.
    let mut failed = harness.start_orchestrator_with(&[]);
    failed.expect_startup_failure("audit chain verification failed", Duration::from_secs(5));

    // With the explicit flag it starts, and records why.
    let started = harness
        .try_restart_orchestrator_env(&[(
            "HIMAN_ALLOW_AUDIT_RECOVERY".to_string(),
            "1".to_string(),
        )])
        .await;
    assert!(
        started,
        "the recovery restart failed: {}",
        harness.last_restart_refused().unwrap_or_default()
    );
    harness.wait_for_agents().await;
    let store = himan_orchestrator::durable::DurableStore::open(std::path::Path::new(&state))
        .expect("reopen the store");
    let recorded = store
        .meta_get("audit_chain_recovery")
        .expect("read the recovery meta")
        .expect("the recovery was not recorded");
    assert!(
        recorded.contains("does not match its hash") || recorded.contains("chain broken"),
        "unexpected recovery reason: {recorded}"
    );

    harness.stop().await;
}

/// Rewrite one audit row's detail, leaving `hash` and `prev_hash` untouched.
fn tamper_audit_row(path: &std::path::Path) {
    let conn = rusqlite::Connection::open(path).expect("open the db");
    let n = conn
        .execute("UPDATE audit SET detail = 'tampered' WHERE seq = 1", [])
        .expect("update");
    assert!(n > 0, "no audit row was tampered with");
}
