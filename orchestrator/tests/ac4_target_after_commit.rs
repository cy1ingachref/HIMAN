//! AC-4 row 7: the target dies after the commit.
//!
//! The task has already moved to the new owner. When that owner dies, the task
//! must not stay owned by a dead device: it is stalled, the epoch is bumped and
//! it is offered to a live enrolled device (the original source here).

mod common;

use serde_json::json;
use std::time::Duration;

const A: &str = "dev-a";
const B: &str = "dev-b";

#[tokio::test]
async fn a_target_that_dies_after_the_commit_loses_the_task() {
    let dir = tempfile::tempdir().expect("tempdir");
    let devices = common::make_devices_named(dir.path(), 2, |i| [A, B][i].to_string());
    let mut harness = common::E2ETest::restartable(
        &devices,
        Some(dir.path().join("state.db")),
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

    // Hand the task to dev-b and let it complete: the commit happened.
    let (status, handoff) = common::http_post(
        port,
        "/api/v1/handoff",
        json!({"task_id": task_id, "from": A, "to": B}),
    );
    assert_eq!(status, 200, "handoff refused: {handoff}");
    assert_eq!(
        handoff["state"].as_str().unwrap_or_default(),
        "active",
        "the handoff did not complete: {handoff}"
    );
    let epoch_after_commit = handoff["epoch"].as_u64().expect("epoch");

    // The new owner dies.
    assert!(harness.kill_agent(B), "dev-b was not running");

    // The task must be stalled and fenced, then offered to a live device.
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    let mut stalled;
    let mut offered;
    let mut epoch_stalled = None;
    loop {
        let audit = common::http_get_json(port, "/api/v1/audit");
        let lines = audit.as_array().expect("audit array");
        stalled = lines.iter().any(|l| l["action"] == "task_stalled");
        offered = lines.iter().any(|l| {
            l["action"] == "task_offered" && l["detail"].as_str().unwrap_or("").contains(&task_id)
        });
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

    assert!(stalled, "the task was not stalled when its owner died");
    assert!(offered, "the stalled task was not offered to a live device");
    let epoch_stalled = epoch_stalled.expect("the stall epoch");
    assert!(
        epoch_stalled > epoch_after_commit,
        "the stall did not fence: {epoch_after_commit} -> {epoch_stalled}"
    );

    // The dead device must not still own it.
    let owner = common::http_get_json(port, &format!("/api/v1/tasks/{task_id}/owner"));
    assert_ne!(
        owner["owner"],
        json!(B),
        "a dead device still owns the task after the commit"
    );

    harness.stop().await;
}
