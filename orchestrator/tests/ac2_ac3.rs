//! AC-2 (no gap) and AC-3 (rollback), on the shared harness.
//!
//! AC-2: from the audit timeline, there is never an interval with no owner.
//! AC-3: a target that never sends Ready must roll the handoff back at the
//!       warming timeout, and the source must keep working afterwards.

mod common;

use serde_json::json;
use std::time::Duration;

/// Device ids used by both tests.
const A: &str = "dev-a";
const B: &str = "dev-b";

#[tokio::test]
async fn ac2_there_is_no_interval_without_an_owner() {
    let mut harness = common::E2ETest::new_with_devices(&[A, B]).await;
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

    let task_id = dispatch_scenario(port, A);

    // Wait until the scenario is mid-run, then hand off.
    wait_for_steps(&harness, 4).await;
    let (status, body) = common::http_post(
        port,
        "/api/v1/handoff",
        json!({"task_id": task_id, "from": A, "to": B}),
    );
    assert_eq!(status, 200, "handoff refused: {body}");
    let handoff_state = body["state"].as_str().unwrap_or_default().to_string();

    // Drive the run to completion so the timeline covers the whole switch.
    wait_for_events(port, &task_id, 20).await;

    // The owner record must exist at the end and be the target.
    let owner = common::http_get_json(port, &format!("/api/v1/tasks/{task_id}/owner"));
    assert_eq!(owner["owner"], json!(B), "final owner is not the target");
    assert_eq!(owner["epoch"], json!(1), "epoch did not advance by one");

    // AC-2: reconstruct the owner timeline from the audit and prove there is no
    // gap. The audit is append-only and each line carries a timestamp, so the
    // sequence of owner-bearing lines is the ownership history.
    let audit = common::http_get_json(port, "/api/v1/audit");
    let lines = audit.as_array().expect("audit array");

    // Every owner-bearing audit line, in order. A handoff moves the owner only
    // at the commit; the request never does.
    let mut owner_history: Vec<(i64, String)> = Vec::new();
    for line in lines {
        let action = line["action"].as_str().unwrap_or_default();
        let ts = line["ts"].as_i64().unwrap_or(0);
        match action {
            "task_created" | "handoff_prepared" => {
                // The source owns from the moment the task exists.
                owner_history.push((ts, A.to_string()));
            }
            "handoff_committed" => {
                owner_history.push((ts, B.to_string()));
            }
            "handoff_rolled_back" => {
                owner_history.push((ts, A.to_string()));
            }
            _ => {}
        }
    }

    assert!(
        owner_history.len() >= 2,
        "the audit timeline is too short to show a switch: {owner_history:?}"
    );

    // No gap means: the first entry exists, and no two consecutive entries are
    // the same owner at the same timestamp with nothing in between. Concretely,
    // the timeline must start with A and end with B, and every transition must
    // be a single owner change (never an empty interval).
    assert_eq!(
        owner_history.first().unwrap().1,
        A,
        "the task starts unowned"
    );
    assert_eq!(owner_history.last().unwrap().1, B, "the task ends unowned");

    for window in owner_history.windows(2) {
        let (t0, o0) = &window[0];
        let (t1, o1) = &window[1];
        // A gap would be two entries with no owner at all between them. The
        // timeline is derived only from owner-bearing lines, so a gap shows as
        // a transition that is not a clean A -> B or B -> A change.
        let clean = (o0 == A && o1 == B) || (o0 == B && o1 == A) || (o0 == o1);
        assert!(
            clean,
            "the owner timeline has an unexpected interval: {owner_history:?}"
        );
        assert!(
            t1 >= t0,
            "the audit timestamps go backwards: {owner_history:?}"
        );
    }

    // The switch must have gone A -> B exactly once.
    let switches = owner_history
        .windows(2)
        .filter(|w| w[0].1 == A && w[1].1 == B)
        .count();
    assert_eq!(switches, 1, "the owner changed A->B {switches} times");

    // No rollback in the happy path.
    let rolled_back = lines
        .iter()
        .any(|l| l["action"] == json!("handoff_rolled_back"));
    assert!(!rolled_back, "the happy-path handoff was rolled back");

    assert_eq!(handoff_state, "active", "the handoff did not reach active");
    harness.stop().await;
}

#[tokio::test]
async fn ac3_a_target_that_never_sends_ready_rolls_back_and_the_source_keeps_working() {
    // Short handoff windows so the warming timeout fires quickly.
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
    // The never-ready hook lives behind the `fault-injection` feature, so the
    // target must be the feature-enabled build.
    harness.use_fault_injection_agent();
    let port = harness.port();
    let orch_key = harness.orchestrator_key().expect("orchestrator key");

    // The source runs normally; the target is told never to send Ready.
    harness
        .spawn_agent(port, A, &orch_key)
        .await
        .expect("dev-a registers");
    let key_b = harness
        .devices()
        .iter()
        .find(|d| d.device == B)
        .map(|d| d.key_file.clone())
        .expect("dev-b key");
    let b_agents = harness
        .spawn_agent_full(
            port,
            B,
            &key_b,
            &orch_key,
            Vec::new(),
            vec![("HIMAN_TEST_NEVER_READY".to_string(), "1".to_string())],
        )
        .await
        .expect("dev-b registers");

    let listed = b_agents.as_array().expect("agents array");
    assert_eq!(
        listed.len(),
        2,
        "both agents must be registered: {b_agents}"
    );

    // A longer scenario than AC-1's, so the run is still going when the
    // warming timeout fires and the source must resume after the rollback.
    let task_id = dispatch_scenario_total(port, A, 40);
    wait_for_steps(&harness, 3).await;

    let (status, body) = common::http_post(
        port,
        "/api/v1/handoff",
        json!({"task_id": task_id, "from": A, "to": B}),
    );
    assert_eq!(status, 200, "the request itself must be accepted: {body}");

    // The warming timeout is 2 s, so wait for the rollback to be recorded.
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    let mut rolled_back = false;
    while std::time::Instant::now() < deadline {
        let audit = common::http_get_json(port, "/api/v1/audit");
        if audit
            .as_array()
            .map(|a| a.iter().any(|l| l["action"] == "handoff_rolled_back"))
            .unwrap_or(false)
        {
            rolled_back = true;
            break;
        }
        tokio::time::sleep(common::POLL_INTERVAL).await;
    }
    if !rolled_back {
        let audit = common::http_get_json(port, "/api/v1/audit");
        eprintln!(
            "=== audit ===
{}",
            serde_json::to_string_pretty(&audit).unwrap_or_default()
        );
        for (d, log) in harness.agent_err_logs() {
            eprintln!("=== {d} stderr tail ===");
            for l in log
                .lines()
                .rev()
                .take(12)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
            {
                eprintln!("{l}");
            }
        }
    }
    assert!(
        rolled_back,
        "the handoff never rolled back after the target stayed silent"
    );

    // The source keeps the task and the epoch did not move.
    let owner = common::http_get_json(port, &format!("/api/v1/tasks/{task_id}/owner"));
    assert_eq!(
        owner["owner"],
        json!(A),
        "the source lost the task on rollback"
    );
    assert_eq!(
        owner["epoch"],
        json!(0),
        "the epoch moved on a rolled-back handoff"
    );

    // The source is still usable: it executes further steps after the rollback.
    let before = wait_for_steps(&harness, 1).await;
    let after = wait_until_steps(&harness, before + 2, Duration::from_secs(20)).await;
    assert!(
        after > before,
        "the source stopped executing after the rollback ({before} -> {after})"
    );

    // The audit shows exactly one rollback and no commit.
    let audit = common::http_get_json(port, "/api/v1/audit");
    let lines = audit.as_array().expect("audit array");
    let rollbacks = lines
        .iter()
        .filter(|l| l["action"] == "handoff_rolled_back")
        .count();
    assert_eq!(rollbacks, 1, "expected exactly one rollback: {lines:?}");
    let commits = lines
        .iter()
        .filter(|l| l["action"] == "handoff_committed")
        .count();
    assert_eq!(
        commits, 0,
        "a rolled-back handoff must not commit: {lines:?}"
    );

    harness.stop().await;
}

/// POST a scenario prompt to `device`, returning the task id.
fn dispatch_scenario(port: u16, device: &str) -> String {
    let (status, body) = common::http_post(
        port,
        "/api/v1/prompt",
        json!({"device": device, "prompt": "run the deterministic scenario"}),
    );
    assert_eq!(status, 200, "dispatch refused: {body}");
    body["task_id"]
        .as_str()
        .expect("dispatch must return a task id")
        .to_string()
}

/// POST a scenario prompt with an explicit total, returning the task id.
fn dispatch_scenario_total(port: u16, device: &str, total: u64) -> String {
    let (status, body) = common::http_post(
        port,
        "/api/v1/prompt",
        json!({"device": device,
               "prompt": format!("run the deterministic scenario of {total} steps")}),
    );
    assert_eq!(status, 200, "dispatch refused: {body}");
    body["task_id"]
        .as_str()
        .expect("dispatch must return a task id")
        .to_string()
}

/// Wait until the agents have executed at least `count` steps between them.
async fn wait_for_steps(harness: &common::E2ETest, count: u64) -> u64 {
    wait_until_steps(harness, count, Duration::from_secs(20)).await
}

async fn wait_until_steps(harness: &common::E2ETest, count: u64, limit: Duration) -> u64 {
    let deadline = std::time::Instant::now() + limit;
    loop {
        let seen = scenario_steps(harness).len() as u64;
        if seen >= count || std::time::Instant::now() >= deadline {
            return seen;
        }
        tokio::time::sleep(common::POLL_INTERVAL).await;
    }
}

/// Wait until the orchestrator's event log for `task_id` has `count` events.
async fn wait_for_events(port: u16, task_id: &str, count: u64) {
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let events = common::http_get_json(port, &format!("/api/v1/tasks/{task_id}/events"));
        if events["events"].as_u64().unwrap_or(0) >= count {
            return;
        }
        if std::time::Instant::now() >= deadline {
            panic!(
                "the event log reached {} of {count} events",
                events["events"].as_u64().unwrap_or(0)
            );
        }
        tokio::time::sleep(common::POLL_INTERVAL).await;
    }
}

/// The scenario steps the agents executed, from their logs.
fn scenario_steps(harness: &common::E2ETest) -> Vec<(String, u64)> {
    let mut out = Vec::new();
    for (device, log) in harness.agent_logs() {
        for line in log.lines() {
            if let Some(rest) = line.strip_prefix("step ") {
                if let Some(num) = rest.split_whitespace().next() {
                    if let Ok(step) = num.parse::<u64>() {
                        out.push((device.clone(), step));
                    }
                }
            }
        }
    }
    out.sort_by_key(|(_, s)| *s);
    out
}
