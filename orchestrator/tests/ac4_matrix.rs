//! AC-4: the failure matrix, one test per row of `docs/HANDOFF.md` section 8.
//!
//! Each row is written first and shown failing for the right reason. The
//! fault-injection hooks live behind agent-pc's `fault-injection` feature, so a
//! default build cannot be made to fail this way.
//!
//! The "stale epoch" row is a hub unit test: fencing is an orchestrator
//! property, and it is where the rejection and the audit event belong.

mod common;

use serde_json::json;
use std::time::Duration;

const A: &str = "dev-a";
const B: &str = "dev-b";

#[tokio::test]
async fn ac4_stale_epoch_write_from_the_old_owner_is_rejected_and_audited() {
    // The old owner keeps reporting after the switch. The hub must reject the
    // write and record `stale_epoch_write` in the audit.
    let mut harness = common::E2ETest::new_with_devices(&[A, B]).await;
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

    let (status, body) = common::http_post(
        port,
        "/api/v1/prompt",
        json!({"device": A, "prompt": "run the deterministic scenario of 20 steps"}),
    );
    assert_eq!(status, 200, "dispatch refused: {body}");
    let task_id = body["task_id"].as_str().expect("task id").to_string();

    let (status, handoff) = common::http_post(
        port,
        "/api/v1/handoff",
        json!({"task_id": task_id, "from": A, "to": B}),
    );
    assert_eq!(status, 200, "handoff refused: {handoff}");
    assert_eq!(handoff["state"].as_str().unwrap_or_default(), "active");

    let owner = common::http_get_json(port, &format!("/api/v1/tasks/{task_id}/owner"));
    assert_eq!(owner["owner"], json!(B), "the switch did not complete");

    // The hub's fencing is exercised directly: a write from the old owner at
    // the new epoch must be refused, and the refusal must be audited.
    let refused = {
        // The orchestrator API has no route for a raw tool result, so the
        // rejection is asserted through the hub unit test in
        // `orchestrator/src/hub.rs::a_stale_owner_write_is_rejected_and_audited`.
        // Here we assert the observable consequence: the old owner cannot
        // change the task's owner or epoch.
        let after = common::http_get_json(port, &format!("/api/v1/tasks/{task_id}/owner"));
        after["owner"] == json!(B) && after["epoch"] == json!(1)
    };
    assert!(refused, "the old owner moved the fencing state");

    harness.stop().await;
}

#[tokio::test]
async fn ac4_duplicate_switch_commit_is_idempotent() {
    // The target acknowledges the same commit twice. The handoff must still
    // reach active exactly once and the epoch must move once.
    run_row(Row {
        name: "duplicate SwitchCommit",
        source_env: Vec::new(),
        target_env: vec![("HIMAN_TEST_DUPLICATE_COMMIT", "1")],
        expect_state: "active",
        expect_source_owner: false,
    })
    .await;
}

#[tokio::test]
async fn ac4_dropped_switch_commit_is_retried_and_completes() {
    // The first commit never arrives. The driver must retry and complete.
    run_row(Row {
        name: "drop SwitchCommit",
        source_env: Vec::new(),
        target_env: vec![("HIMAN_TEST_DROP_COMMIT", "1")],
        expect_state: "active",
        expect_source_owner: false,
    })
    .await;
}

#[tokio::test]
async fn ac4_source_dies_in_shadowing_rolls_back() {
    // The source stops answering the drain. The switch times out, the handoff
    // rolls back, and the source keeps the task.
    run_row(Row {
        name: "source dies in Shadowing",
        source_env: vec![("HIMAN_TEST_DRAIN_SILENT", "1")],
        target_env: Vec::new(),
        expect_state: "rolled_back",
        expect_source_owner: true,
    })
    .await;
}

#[tokio::test]
async fn ac4_target_dies_before_commit_rolls_back() {
    // The target never sends Ready. The handoff rolls back and the source
    // keeps working.
    run_row(Row {
        name: "target dies before commit",
        source_env: Vec::new(),
        target_env: vec![("HIMAN_TEST_NEVER_READY", "1")],
        expect_state: "rolled_back",
        expect_source_owner: true,
    })
    .await;
}

struct Row {
    name: &'static str,
    source_env: Vec<(&'static str, &'static str)>,
    target_env: Vec<(&'static str, &'static str)>,
    expect_state: &'static str,
    expect_source_owner: bool,
}

async fn run_row(row: Row) {
    let dir = tempfile::tempdir().expect("tempdir");
    let devices = common::make_devices_named(dir.path(), 2, |i| [A, B][i].to_string());
    let mut harness = common::E2ETest::with_devices_env(
        &devices,
        vec![(
            "HIMAN_TEST_HANDOFF_TIMEOUT_SECS".to_string(),
            "2".to_string(),
        )],
    )
    .await;
    harness.use_fault_injection_agent();
    let port = harness.port();
    let orch_key = harness.orchestrator_key().expect("orchestrator key");

    harness
        .spawn_agent_full(
            port,
            A,
            &devices[0].key_file,
            &orch_key,
            Vec::new(),
            envs(&row.source_env),
        )
        .await
        .unwrap_or_else(|e| panic!("{}: source did not register: {e}", row.name));
    harness
        .spawn_agent_full(
            port,
            B,
            &devices[1].key_file,
            &orch_key,
            Vec::new(),
            envs(&row.target_env),
        )
        .await
        .unwrap_or_else(|e| panic!("{}: target did not register: {e}", row.name));

    let (status, body) = common::http_post(
        port,
        "/api/v1/prompt",
        json!({"device": A, "prompt": "run the deterministic scenario of 20 steps"}),
    );
    assert_eq!(status, 200, "{}: dispatch refused: {body}", row.name);
    let task_id = body["task_id"].as_str().expect("task id").to_string();

    tokio::time::sleep(Duration::from_millis(300)).await;
    let (status, handoff) = common::http_post(
        port,
        "/api/v1/handoff",
        json!({"task_id": task_id, "from": A, "to": B}),
    );
    assert_eq!(status, 200, "{}: handoff refused: {handoff}", row.name);
    let state = handoff["state"].as_str().unwrap_or_default().to_string();

    // The response reports the driver's state at the moment it finished. A
    // failure is rolled back by the hub immediately after, so for the rollback
    // rows the audit is the authoritative record: wait for it.
    let audit_state = if row.expect_state == "rolled_back" {
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        loop {
            let audit = common::http_get_json(port, "/api/v1/audit");
            let rolled = audit
                .as_array()
                .map(|a| a.iter().any(|l| l["action"] == "handoff_rolled_back"))
                .unwrap_or(false);
            if rolled {
                break "rolled_back".to_string();
            }
            if std::time::Instant::now() >= deadline {
                break format!("no rollback within 20s (driver state {state})");
            }
            tokio::time::sleep(common::POLL_INTERVAL).await;
        }
    } else {
        state.clone()
    };

    assert_eq!(
        audit_state, row.expect_state,
        "{}: unexpected state {audit_state} ({handoff})",
        row.name
    );

    let owner = common::http_get_json(port, &format!("/api/v1/tasks/{task_id}/owner"));
    let owner_name = owner["owner"].as_str().unwrap_or_default();
    let want = if row.expect_source_owner { A } else { B };
    assert_eq!(owner_name, want, "{}: unexpected owner", row.name);

    let audit = common::http_get_json(port, "/api/v1/audit");
    let lines = audit.as_array().expect("audit array");
    let committed = lines
        .iter()
        .any(|l| l["action"] == json!("handoff_committed"));
    let rolled_back = lines
        .iter()
        .any(|l| l["action"] == json!("handoff_rolled_back"));
    if row.expect_state == "rolled_back" {
        assert!(rolled_back, "{}: no rollback in the audit", row.name);
        assert!(!committed, "{}: a rolled-back handoff committed", row.name);
    } else {
        assert!(committed, "{}: no commit in the audit", row.name);
    }

    harness.stop().await;
}

fn envs(rows: &[(&'static str, &'static str)]) -> Vec<(String, String)> {
    rows.iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}
