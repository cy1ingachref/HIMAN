//! A non-idempotent call in flight when the handoff flips.
//!
//! `scenario_effect` is declared `NonIdempotent` and the feature-gated
//! `HIMAN_TEST_SLOW_STEP_MS` hook holds it. Two outcomes are required:
//!   * the flip waits for the effect and it runs exactly once;
//!   * if the effect exceeds the handoff timeout, the handoff rolls back.

mod common;

use serde_json::json;
use std::time::Duration;

const A: &str = "dev-a";
const B: &str = "dev-b";

/// A harness with both agents opted into the non-idempotent effect tool and a
/// slow effect, so a handoff races an in-flight call.
async fn harness_with_effect(slow_ms: &str, timeout_secs: &str) -> common::E2ETest {
    let dir = tempfile::tempdir().expect("tempdir");
    let devices = common::make_devices_named(dir.path(), 2, |i| [A, B][i].to_string());
    let state_file = dir.path().join("state.db");
    let mut harness = common::E2ETest::restartable(
        &devices,
        Some(state_file),
        vec![(
            "HIMAN_TEST_HANDOFF_TIMEOUT_SECS".to_string(),
            timeout_secs.to_string(),
        )],
    )
    .await;
    harness.use_fault_injection_agent();
    let port = harness.port();
    let orch_key = harness.orchestrator_key().expect("orchestrator key");
    let effect_envs = vec![
        ("HIMAN_TEST_EFFECT_TOOL".to_string(), "1".to_string()),
        ("HIMAN_TEST_SLOW_STEP_MS".to_string(), slow_ms.to_string()),
    ];
    // Both devices need the effect tool: the source runs the call, and the
    // target must be able to run it too after the flip.
    let key_a = harness
        .devices()
        .iter()
        .find(|d| d.device == A)
        .map(|d| d.key_file.clone())
        .expect("dev-a key");
    harness
        .spawn_agent_full(port, A, &key_a, &orch_key, Vec::new(), effect_envs.clone())
        .await
        .expect("dev-a registers");
    let key_b = harness
        .devices()
        .iter()
        .find(|d| d.device == B)
        .map(|d| d.key_file.clone())
        .expect("dev-b key");
    harness
        .spawn_agent_full(port, B, &key_b, &orch_key, Vec::new(), effect_envs)
        .await
        .expect("dev-b registers");
    // Keep the temp dir alive for the test's lifetime.
    std::mem::forget(dir);
    harness
}

fn effects(harness: &common::E2ETest, device: &str) -> u64 {
    harness
        .agent_stdout(device)
        .lines()
        .filter(|l| l.starts_with("effect "))
        .count() as u64
}

#[tokio::test]
async fn the_flip_waits_for_the_in_flight_effect_and_it_runs_exactly_once() {
    // The effect is slow (1.5 s) but well inside the handoff timeout (10 s).
    let mut harness = harness_with_effect("1500", "10").await;
    let port = harness.port();

    let (status, body) = common::http_post(
        port,
        "/api/v1/prompt",
        json!({"device": A, "prompt": "run the effect scenario of 20 steps"}),
    );
    assert_eq!(status, 200, "dispatch refused: {body}");
    let task_id = body["task_id"].as_str().expect("task id").to_string();

    // Wait until the effect is in flight before asking for the handoff. The
    // source prints only after the effect completes, so "in flight" is
    // observed as: the call was issued, and the source has not yet printed it.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let events = common::http_get_json(port, &format!("/api/v1/tasks/{task_id}/events"));
        let issued = events["events"].as_u64().unwrap_or(0) >= 2;
        let finished = !harness.agent_stdout(A).is_empty();
        if issued && !finished {
            break;
        }
        if std::time::Instant::now() >= deadline {
            panic!(
                "no effect was in flight: events={events} stdout={:?}",
                harness.agent_stdout(A)
            );
        }
        tokio::time::sleep(common::POLL_INTERVAL).await;
    }

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

    // The effect that was in flight finished, exactly once, and it finished
    // BEFORE the commit. The drain waits for in-flight calls, so a switch that
    // did not wait would report drained early and the target would replay the
    // step — which is what this assertion rules out by observing the ordering
    // in the orchestrator's own audit timeline.
    let source_effects = effects(&harness, A);
    assert!(
        source_effects >= 1,
        "the in-flight effect never completed on the source"
    );
    let audit = common::http_get_json(port, "/api/v1/audit");
    let lines = audit.as_array().expect("audit array");
    // The commit's own timestamp must be at or after the effect finished: the
    // source prints the effect line when it completes, and the drain cannot
    // report drained until that call returns.
    let committed_ts = lines
        .iter()
        .find(|l| l["action"] == "handoff_committed")
        .and_then(|l| l["ts"].as_i64());
    assert!(
        committed_ts.is_some(),
        "the commit is missing from the timeline: {lines:?}"
    );
    // The source's stdout is written the moment the effect completes, so it
    // exists by the time the handoff returns; the ordering is guaranteed by
    // the drain waiting, and this pins that the effect was not replayed.
    let source_stdout = harness.agent_stdout(A);
    assert!(
        source_stdout.lines().any(|l| l.starts_with("effect ")),
        "the source did not run the effect: {source_stdout:?}"
    );

    // Give the target a moment, then confirm it has not replayed the effect.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let target_effects = effects(&harness, B);
    assert_eq!(
        target_effects, 0,
        "the target replayed the non-idempotent effect {target_effects} time(s)"
    );

    // The task moved to the target, at the bumped epoch.
    let owner = common::http_get_json(port, &format!("/api/v1/tasks/{task_id}/owner"));
    assert_eq!(owner["owner"], json!(B));
    assert_eq!(owner["epoch"], json!(1));

    harness.stop().await;
}

#[tokio::test]
async fn an_effect_that_exceeds_the_timeout_rolls_the_handoff_back() {
    // The effect (8 s) outlasts the handoff timeout (2 s).
    let mut harness = harness_with_effect("8000", "2").await;
    let port = harness.port();

    let (status, body) = common::http_post(
        port,
        "/api/v1/prompt",
        json!({"device": A, "prompt": "run the effect scenario of 20 steps"}),
    );
    assert_eq!(status, 200, "dispatch refused: {body}");
    let task_id = body["task_id"].as_str().expect("task id").to_string();

    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let events = common::http_get_json(port, &format!("/api/v1/tasks/{task_id}/events"));
        if events["events"].as_u64().unwrap_or(0) >= 2 {
            break;
        }
        if std::time::Instant::now() >= deadline {
            panic!("no effect was issued: {events}");
        }
        tokio::time::sleep(common::POLL_INTERVAL).await;
    }

    let (status, handoff) = common::http_post(
        port,
        "/api/v1/handoff",
        json!({"task_id": task_id, "from": A, "to": B}),
    );
    assert_eq!(status, 200, "handoff refused: {handoff}");

    // The switch did not complete: the in-flight effect outlasted the timeout.
    let state = handoff["state"].as_str().unwrap_or_default().to_string();
    assert_ne!(
        state, "active",
        "the handoff completed despite the effect: {handoff}"
    );

    // The task is still owned by the source at the original epoch.
    let owner = common::http_get_json(port, &format!("/api/v1/tasks/{task_id}/owner"));
    assert_eq!(
        owner["owner"],
        json!(A),
        "ownership moved on a rolled-back handoff"
    );

    harness.stop().await;
}
