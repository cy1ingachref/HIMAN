//! A task whose owner dies after the commit is stalled, fenced and offered.

mod common;

use serde_json::json;
use std::time::Duration;

const A: &str = "dev-a";
const B: &str = "dev-b";

#[tokio::test]
async fn an_owner_that_dies_after_the_commit_is_stalled_and_offered() {
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

    let (status, body) = common::http_post(
        port,
        "/api/v1/prompt",
        json!({"device": A, "prompt": "run the deterministic scenario of 40 steps"}),
    );
    assert_eq!(status, 200, "dispatch refused: {body}");
    let task_id = body["task_id"].as_str().expect("task id").to_string();

    // Hand dev-b the task. After this, dev-b owns it.
    let (status, handoff) = common::http_post(
        port,
        "/api/v1/handoff",
        json!({"task_id": task_id, "from": A, "to": B}),
    );
    assert_eq!(status, 200, "handoff refused: {handoff}");
    assert_eq!(handoff["state"].as_str().unwrap_or_default(), "active");
    let epoch_after_handoff = handoff["epoch"].as_u64().expect("epoch");

    // Kill dev-b: the owner dies after the commit.
    let killed = harness.kill_agent(B);
    assert!(killed, "dev-b was not running");

    // The orchestrator must notice the disconnect and stall the task.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let mut stalled;
    let mut offered;
    let mut epoch_stalled = None;
    loop {
        let audit = common::http_get_json(port, "/api/v1/audit");
        let lines = audit.as_array().expect("audit array");
        stalled = lines.iter().any(|l| l["action"] == "task_stalled");
        offered = lines.iter().any(|l| l["action"] == "task_offered");
        if stalled {
            epoch_stalled = lines
                .iter()
                .find(|l| l["action"] == "task_stalled")
                .and_then(|l| {
                    l["detail"]
                        .as_str()
                        .and_then(|d| d.split("epoch=").nth(1))
                        .and_then(|e| e.split(' ').next())
                        .and_then(|e| e.parse::<u64>().ok())
                });
        }
        if (stalled && offered) || std::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(common::POLL_INTERVAL).await;
    }

    assert!(
        stalled,
        "the task was not marked stalled after the owner died"
    );
    assert!(
        offered,
        "the stalled task was not offered to another device"
    );
    let epoch_stalled = epoch_stalled.expect("the stall's epoch");
    assert!(
        epoch_stalled > epoch_after_handoff,
        "the stall did not bump the epoch: {epoch_after_handoff} -> {epoch_stalled}"
    );

    // The task's owner must not still be the dead device: it is offered away.
    let owner = common::http_get_json(port, &format!("/api/v1/tasks/{task_id}/owner"));
    assert_ne!(
        owner["owner"],
        json!(B),
        "the dead device is still the owner"
    );

    // The non-idempotent call is marked Unknown, so it needs approval.
    let audit = common::http_get_json(port, "/api/v1/audit");
    let lines = audit.as_array().expect("audit array");
    assert!(
        lines
            .iter()
            .any(|l| l["action"] == "non_idempotent_call_unknown"),
        "no non-idempotent call was marked Unknown: {lines:?}"
    );

    harness.stop().await;
}
