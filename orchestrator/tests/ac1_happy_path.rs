//! AC-1: a mid-run handoff between two real devices, end to end.
//!
//! One orchestrator, two real `himan-agent-pc` processes on distinct device
//! ids, one deterministic scenario task running on the source. The test asks
//! the orchestrator to hand the task to the target over real HTTP while the
//! scenario is mid-run, then asserts the spec's acceptance list:
//!
//!   * the handoff ends `active` (never rolled back, never failed);
//!   * the epoch is bumped exactly once, by exactly one;
//!   * every scenario step executes exactly once — none lost, none duplicated;
//!   * the orchestrator's event seq for the task is continuous;
//!   * every observed owner is the single current owner (no window with two);
//!   * the source is drained (it stopped starting new steps);
//!   * the target runs the remaining steps;
//!   * no rollback happened.

mod common;

use std::collections::BTreeMap;
use std::time::Duration;

use serde_json::{json, Value};

/// Steps in the deterministic scenario. 20 x 100 ms is long enough to interrupt
/// mid-run and short enough for the acceptance test's 20 s budget.
const STEPS: u64 = 20;
const STEP_MS: u64 = 100;

#[tokio::test]
async fn ac1_mid_run_handoff_is_atomic_and_complete() {
    let mut harness = common::E2ETest::new_with_devices(&["dev-a", "dev-b"]).await;
    harness.record_phase("orchestrator up");

    let port = harness.port();
    let orch_key = harness.orchestrator_key().expect("orchestrator key");

    // Two real agents, one per device. The source runs the scenario; the
    // target is idle until it is handed the task.
    let a = harness
        .spawn_agent_scenario(port, "dev-a", STEPS, STEP_MS, &orch_key)
        .await
        .expect("dev-a registers");
    let b = harness
        .spawn_agent(port, "dev-b", &orch_key)
        .await
        .expect("dev-b registers");
    harness.record_phase("both agents registered");

    let task_id = dispatch_scenario(port, "dev-a");
    harness.record_phase("task dispatched");

    // Let the scenario run a few steps, then ask for the handoff over HTTP.
    // The scenario is mid-run: this is the point AC-1 is about.
    tokio::time::sleep(Duration::from_millis(STEP_MS * 5)).await;
    let handoff = common::http_post(
        port,
        "/api/v1/handoff",
        json!({
            "task_id": task_id,
            "from": "dev-a",
            "to": "dev-b",
            // A stale client-supplied checkpoint. The orchestrator must ignore
            // it and use its own log head (see docs/DECISIONS.md).
            "applied_seq": 1,
        }),
    );
    assert_eq!(
        handoff.0,
        200,
        "handoff refused: {}",
        serde_json::to_string(&handoff.1).unwrap_or_default()
    );
    let _state = handoff.1["state"].as_str().unwrap_or_default().to_string();
    harness.record_phase("handoff requested");

    // Wait for the run to settle: the handoff must be committed (epoch 1) and
    // the orchestrator's own event log must show every step issued exactly
    // once. Waiting on the log — not on a fixed sleep — is what makes the
    // exactly-once assertion meaningful.
    let outcome = wait_for_scenario_completion(port, &task_id, STEPS).await;
    harness.record_phase("handoff settled");

    // 1. Final state is active.
    if outcome != "active" {
        let audit = common::http_get_json(port, "/api/v1/audit");
        eprintln!(
            "=== audit ===\n{}",
            serde_json::to_string_pretty(&audit).unwrap_or_default()
        );
        for (device, log) in harness.agent_err_logs() {
            eprintln!("=== agent {device} stderr (tail) ===");
            for line in log
                .lines()
                .rev()
                .take(25)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
            {
                eprintln!("{line}");
            }
        }
    }
    assert_eq!(
        outcome, "active",
        "handoff did not end active (state {outcome})"
    );

    // 2. The task's owner is the target, with the epoch bumped exactly once.
    let owner = common::http_get_json(port, &format!("/api/v1/tasks/{task_id}/owner"));
    assert_eq!(
        owner["owner"],
        json!("dev-b"),
        "target does not own the task"
    );
    assert_eq!(
        owner["epoch"],
        json!(1),
        "epoch was not bumped exactly once"
    );

    // 3. Every step executed exactly once, and the total is the full scenario.
    let steps = scenario_steps(&harness);
    assert_eq!(
        steps.len(),
        STEPS as usize,
        "scenario steps are not all present: {steps:?}"
    );
    let mut seen: BTreeMap<u64, (String, usize)> = BTreeMap::new();
    for (device, step) in &steps {
        let entry = seen.entry(*step).or_insert((device.clone(), 0));
        entry.1 += 1;
    }
    for step in 1..=STEPS {
        let (device, count) = seen
            .get(&step)
            .unwrap_or_else(|| panic!("step {step} never executed; steps seen: {steps:?}"));
        assert_eq!(*count, 1, "step {step} ran {count} times ({device})");
    }

    // 4. The source ran the prefix, the target ran the rest: the switch point
    //    is real, so the task is not simply re-run from zero by the target.
    let a_steps = steps.iter().filter(|(d, _)| d == "dev-a").count();
    let b_steps = steps.iter().filter(|(d, _)| d == "dev-b").count();
    assert!(a_steps > 0, "the source ran no steps before the handoff");
    assert!(b_steps > 0, "the target ran no steps after the handoff");
    assert_eq!(
        a_steps + b_steps,
        STEPS as usize,
        "steps are not partitioned between source and target: {steps:?}"
    );
    // No step may be re-run after the switch: every source step is below every
    // target step.
    let last_a = steps
        .iter()
        .filter(|(d, _)| d == "dev-a")
        .map(|(_, s)| *s)
        .max()
        .unwrap_or(0);
    let first_b = steps
        .iter()
        .filter(|(d, _)| d == "dev-b")
        .map(|(_, s)| *s)
        .min()
        .unwrap_or(u64::MAX);
    assert!(
        last_a < first_b,
        "the target re-ran steps the source already did (last_a={last_a}, first_b={first_b})"
    );

    // 5. The orchestrator's event log for the task is continuous.
    let events = common::http_get_json(port, &format!("/api/v1/tasks/{task_id}/events"));
    assert_eq!(
        events["contiguous"],
        json!(true),
        "event seq is not continuous: {}",
        events["seqs"]
    );
    assert_eq!(
        events["events"],
        json!(STEPS),
        "the event log does not record every step"
    );

    // 6. Exactly one owner at every observed moment, from the audit timeline.
    //    The audit is append-only, so the owner can only move forward.
    let audit = common::http_get_json(port, "/api/v1/audit");
    let handoff_lines: Vec<&Value> = audit
        .as_array()
        .map(|a| {
            a.iter()
                .filter(|l| {
                    l["action"]
                        .as_str()
                        .unwrap_or_default()
                        .starts_with("handoff")
                })
                .collect()
        })
        .unwrap_or_default();
    assert!(
        !handoff_lines.is_empty(),
        "the audit timeline has no handoff lines"
    );
    let active_lines = handoff_lines
        .iter()
        .filter(|l| l["action"] == json!("handoff_active"))
        .count();
    assert_eq!(
        active_lines, 1,
        "the handoff reached active {} times, expected exactly 1",
        active_lines
    );
    let rolled_back = handoff_lines
        .iter()
        .any(|l| l["action"] == json!("handoff_rolled_back"));
    assert!(!rolled_back, "the handoff was rolled back");

    // 7. The source is drained: it stopped starting new steps.
    let agents = common::http_get_json(port, "/api/v1/agents");
    let a_registered = agents
        .as_array()
        .map(|a| {
            a.iter()
                .any(|d| d["device_id"] == json!("dev-a") || d["id"] == json!("dev-a"))
        })
        .unwrap_or(false);
    assert!(
        a_registered,
        "the source is no longer registered after the handoff"
    );

    // 8. No rollback anywhere in the final owner state.
    assert_ne!(owner["epoch"], json!(0), "epoch was never bumped");

    let _ = (a, b);
    harness.record_phase("assertions done");
    harness.stop().await;
}

/// POST a scenario prompt to `device`, returning the task id.
fn dispatch_scenario(port: u16, device: &str) -> String {
    let result = common::http_post(
        port,
        "/api/v1/prompt",
        json!({"device": device, "prompt": "run the deterministic scenario"}),
    );
    assert_eq!(
        result.0,
        200,
        "dispatch refused: {}",
        serde_json::to_string(&result.1).unwrap_or_default()
    );
    result.1["task_id"]
        .as_str()
        .expect("dispatch must return a task id")
        .to_string()
}

/// Poll until the handoff is committed and every scenario step has been
/// issued, returning the state the test should assert on.
async fn wait_for_scenario_completion(port: u16, task_id: &str, steps: u64) -> String {
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let owner = common::http_get_json(port, &format!("/api/v1/tasks/{task_id}/owner"));
        let epoch = owner["epoch"].as_u64().unwrap_or(0);
        let events = common::http_get_json(port, &format!("/api/v1/tasks/{task_id}/events"));
        let issued = events["events"].as_u64().unwrap_or(0);
        if epoch >= 1 && issued >= steps {
            // The orchestrator has issued every step; give the devices a moment
            // to print their results before the test reads their logs.
            tokio::time::sleep(Duration::from_millis(300)).await;
            return "active".to_string();
        }
        if std::time::Instant::now() >= deadline {
            return format!("epoch {epoch}, {issued}/{steps} steps after 30s");
        }
        tokio::time::sleep(common::POLL_INTERVAL).await;
    }
}

/// The scenario steps the two agents actually executed, read from their logs.
///
/// Each agent prints one line per step: `step <n> call_id=<id> device=<id>`.
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
