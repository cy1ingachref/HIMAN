//! A task whose owner dies with no device available stays stalled, and is
//! offered when an enrolled device connects.

mod common;

use serde_json::json;
use std::time::Duration;

const A: &str = "dev-a";
const B: &str = "dev-b";

#[tokio::test]
async fn a_stalled_task_with_no_device_is_offered_when_one_connects() {
    let dir = tempfile::tempdir().expect("tempdir");
    let devices = common::make_devices_named(dir.path(), 2, |i| [A, B][i].to_string());
    let state_file = dir.path().join("state.db");
    let mut harness = common::E2ETest::restartable(
        &devices,
        Some(state_file.clone()),
        vec![(
            "HIMAN_TEST_HANDOFF_TIMEOUT_SECS".to_string(),
            "10".to_string(),
        )],
    )
    .await;
    harness.use_fault_injection_agent();
    let port = harness.port();
    let orch_key = harness.orchestrator_key().expect("orchestrator key");

    // Only dev-a connects. There is no second device to take the task.
    harness
        .spawn_agent(port, A, &orch_key)
        .await
        .expect("dev-a registers");

    let (status, body) = common::http_post(
        port,
        "/api/v1/prompt",
        json!({"device": A, "prompt": "run the deterministic scenario of 40 steps"}),
    );
    assert_eq!(status, 200, "dispatch refused: {body}");
    let task_id = body["task_id"].as_str().expect("task id").to_string();

    // dev-a dies. With no other device online, the task cannot be offered.
    assert!(harness.kill_agent(A), "dev-a was not running");

    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let mut stalled;
    loop {
        let audit = common::http_get_json(port, "/api/v1/audit");
        let lines = audit.as_array().expect("audit array");
        stalled = lines.iter().any(|l| l["action"] == "task_stalled");
        if stalled || std::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(common::POLL_INTERVAL).await;
    }
    if !stalled {
        let audit = common::http_get_json(port, "/api/v1/audit");
        eprintln!(
            "{}",
            serde_json::to_string_pretty(&audit).unwrap_or_default()
        );
    }
    assert!(stalled, "the task was not marked stalled");

    // It is persisted as stalled, with no candidate. The SQLite write and
    // the audit write are separate; under parallel CI load the durable row
    // can land a little after the audit line, so poll with a bounded wait
    // rather than reading once (CI run 44847910233).
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let stalled_rows = loop {
        let store =
            himan_orchestrator::durable::DurableStore::open(std::path::Path::new(&state_file))
                .expect("reopen the store");
        let rows = store.stalled().expect("read stalled");
        if rows.iter().any(|r| r.task_id == task_id) || std::time::Instant::now() >= deadline {
            break rows;
        }
        tokio::time::sleep(common::POLL_INTERVAL).await;
    };
    assert!(
        stalled_rows.iter().any(|r| r.task_id == task_id),
        "the stall was not persisted: {stalled_rows:?}"
    );

    // The task still belongs to the dead device: nobody took it.
    let owner = common::http_get_json(port, &format!("/api/v1/tasks/{task_id}/owner"));
    assert_eq!(
        owner["owner"],
        json!(A),
        "a dead device was replaced too early"
    );

    // Now dev-b connects: the stalled task is offered to it.
    harness
        .spawn_agent(port, B, &orch_key)
        .await
        .expect("dev-b registers");

    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let mut offered;
    loop {
        let audit = common::http_get_json(port, "/api/v1/audit");
        let lines = audit.as_array().expect("audit array");
        offered = lines.iter().any(|l| {
            l["action"] == "task_offered" && l["detail"].as_str().unwrap_or("").contains(&task_id)
        });
        if offered || std::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(common::POLL_INTERVAL).await;
    }
    assert!(
        offered,
        "the stalled task was not offered to the connecting device"
    );

    // The task now has a live owner.
    let owner = common::http_get_json(port, &format!("/api/v1/tasks/{task_id}/owner"));
    assert_eq!(
        owner["owner"],
        json!(B),
        "the connecting device did not take the task"
    );

    harness.stop().await;
}
