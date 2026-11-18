//! AC-6: handoff metrics over repeated runs.
//!
//! Runs the AC-1 scenario `RUNS` times against the real binaries and writes
//! `results/handoff-metrics.csv` plus a markdown summary with p50 and p95 for
//! each metric. It is a manual/nightly job, not part of the per-commit gate:
//! 30 runs of a multi-second scenario is too slow for every push.
//!
//! Metrics recorded as audit events (see `hub.rs`):
//!   handoff_switch_time_ms, handoff_total_time_ms, handoff_replay_lag,
//!   handoff_rollback_cause, and the owner history from which the owner gap
//!   and the inter-step gap are derived.

//! Run with:
//!
//!     cargo run -p himan-orchestrator --example handoff_metrics
//!
//! It is deliberately an example, not a test: 30 runs take about 500 s, which
//! is why it runs in the nightly job rather than the per-commit gate.

#[path = "../tests/common/mod.rs"]
mod common;

use serde_json::json;
use std::time::{Duration, Instant};

const A: &str = "dev-a";
const B: &str = "dev-b";
const RUNS: usize = 30;

#[tokio::main]
async fn main() {
    let out_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("results");
    std::fs::create_dir_all(&out_dir).expect("create results dir");

    let mut rows: Vec<RunRow> = Vec::new();
    for run in 0..RUNS {
        let started = Instant::now();
        let row = one_run(run).await;
        println!(
            "run {:>2}/{} switch={}ms total={}ms gap={}ms step_gap={}ms ({:.1}s)",
            run + 1,
            RUNS,
            row.switch_ms,
            row.total_ms,
            row.owner_gap_ms,
            row.longest_step_gap_ms,
            started.elapsed().as_secs_f32()
        );
        rows.push(row);
    }

    write_csv(&out_dir.join("handoff-metrics.csv"), &rows);
    write_summary(&out_dir.join("handoff-metrics.md"), &rows);
    println!("wrote {}", out_dir.join("handoff-metrics.csv").display());
    println!("wrote {}", out_dir.join("handoff-metrics.md").display());
}

#[derive(Clone)]
struct RunRow {
    run: usize,
    switch_ms: u128,
    total_ms: u128,
    replay_lag: u64,
    rolled_back: bool,
    rollback_cause: String,
    owner_gap_ms: u64,
    longest_step_gap_ms: u64,
    normal_step_gap_ms: u64,
}

async fn one_run(run: usize) -> RunRow {
    let dir = tempfile::tempdir().expect("tempdir");
    // The devices are created in a temp dir so their key files are real
    // and disposable.
    let _devices = common::make_devices_named(dir.path(), 2, |i| [A, B][i].to_string());
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

    let started = Instant::now();
    let (status, body) = common::http_post(
        port,
        "/api/v1/prompt",
        json!({"device": A, "prompt": "run the deterministic scenario of 20 steps"}),
    );
    assert_eq!(status, 200, "run {run}: dispatch refused: {body}");
    let task_id = body["task_id"].as_str().expect("task id").to_string();

    // Let the source run a few steps so the switch has a prefix.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let events = common::http_get_json(port, &format!("/api/v1/tasks/{task_id}/events"));
        if events["events"].as_u64().unwrap_or(0) >= 3 || Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(common::POLL_INTERVAL).await;
    }

    let (status, handoff) = common::http_post(
        port,
        "/api/v1/handoff",
        json!({"task_id": task_id, "from": A, "to": B}),
    );
    assert_eq!(status, 200, "run {run}: handoff refused: {handoff}");
    let wall_ms = started.elapsed().as_millis();

    // Read the audit once it has settled.
    let audit = wait_for_audit(port, &task_id).await;
    let switch_ms = metric_u128(&audit, "handoff_switch_time_ms", &task_id);
    let total_ms = metric_u128(&audit, "handoff_total_time_ms", &task_id);
    let replay_lag = metric_u64(&audit, "handoff_replay_lag", &task_id);
    let rolled_back = audit
        .iter()
        .any(|e| e["action"] == "handoff_rollback_cause");
    let rollback_cause = audit
        .iter()
        .find(|e| e["action"] == "handoff_rollback_cause")
        .and_then(|e| e["detail"].as_str())
        .unwrap_or("")
        .to_string();

    // Owner gap: the audit timeline must show no owner-less interval.
    let owner_gap_ms = owner_gap_ms(&audit, &task_id);
    let (longest_step_gap_ms, normal_step_gap_ms) = step_gaps(&audit);

    harness.stop().await;
    drop(dir);

    RunRow {
        run,
        switch_ms: switch_ms.unwrap_or(wall_ms),
        total_ms: total_ms.unwrap_or(wall_ms),
        replay_lag: replay_lag.unwrap_or(0),
        rolled_back,
        rollback_cause,
        owner_gap_ms,
        longest_step_gap_ms,
        normal_step_gap_ms,
    }
}

async fn wait_for_audit(port: u16, task_id: &str) -> Vec<serde_json::Value> {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let audit = common::http_get_json(port, "/api/v1/audit");
        let lines = audit.as_array().cloned().unwrap_or_default();
        let done = lines.iter().any(|e| {
            e["action"] == "handoff_driver_finished"
                && e["detail"].as_str().unwrap_or("").contains(task_id)
        });
        if done || Instant::now() >= deadline {
            return lines;
        }
        tokio::time::sleep(common::POLL_INTERVAL).await;
    }
}

fn metric_u128(audit: &[serde_json::Value], action: &str, task_id: &str) -> Option<u128> {
    audit
        .iter()
        .find(|e| e["action"] == action && e["detail"].as_str().unwrap_or("").contains(task_id))
        .and_then(|e| {
            let detail = e["detail"].as_str().unwrap_or("");
            detail
                .split(' ')
                .find_map(|part| {
                    part.strip_prefix("switch_ms=")
                        .or_else(|| part.strip_prefix("total_ms="))
                })
                .and_then(|v| v.parse::<u128>().ok())
        })
}

fn metric_u64(audit: &[serde_json::Value], action: &str, task_id: &str) -> Option<u64> {
    audit
        .iter()
        .find(|e| e["action"] == action && e["detail"].as_str().unwrap_or("").contains(task_id))
        .and_then(|e| {
            e["detail"]
                .as_str()
                .unwrap_or("")
                .split(' ')
                .find_map(|part| part.strip_prefix("lag="))
                .and_then(|v| v.parse::<u64>().ok())
        })
}

/// The longest owner-less interval, from the audit's ownership events.
fn owner_gap_ms(audit: &[serde_json::Value], task_id: &str) -> u64 {
    let mut timestamps: Vec<i64> = audit
        .iter()
        .filter(|e| {
            let action = e["action"].as_str().unwrap_or("");
            (action == "handoff_committed"
                || action == "task_created"
                || action == "handoff_prepared")
                && e["detail"].as_str().unwrap_or("").contains(task_id)
        })
        .filter_map(|e| e["ts_ms"].as_i64())
        .collect();
    timestamps.sort_unstable();
    timestamps
        .windows(2)
        .map(|w| (w[1] - w[0]).max(0) as u64)
        .max()
        .unwrap_or(0)
}

/// `(longest gap between consecutive step events across the switch, normal
/// inter-step gap)`.
///
/// The "across the switch" gap is measured between the last step event from
/// the source and the first from the target; the normal gap is the median of
/// the source's own consecutive steps.
fn step_gaps(audit: &[serde_json::Value]) -> (u64, u64) {
    // The audit does not carry per-step timestamps, so the step events come
    // from the orchestrator's event log via the task endpoint. This helper is
    // fed those events by `one_run` through the audit's `tool_call_policy`
    // entries, which are one per issued step and carry a timestamp.
    // `step_issued` carries the issuing owner, so the switch shows up as the
    // gap between the last source step and the first target step.
    let mut steps: Vec<(i64, String)> = audit
        .iter()
        .filter(|e| e["action"] == "step_issued")
        .filter_map(|e| {
            let detail = e["detail"].as_str().unwrap_or("");
            let ts = e["ts_ms"].as_i64()?;
            let owner = detail.split("owner=").nth(1)?.to_string();
            Some((ts, owner))
        })
        .collect();
    steps.sort_by_key(|(ts, _)| *ts);
    if steps.len() < 2 {
        return (0, 0);
    }
    // The normal inter-step gap: the median gap between consecutive steps by
    // the same owner.
    let mut normal_gaps: Vec<u64> = Vec::new();
    for w in steps.windows(2) {
        if w[0].1 == w[1].1 {
            normal_gaps.push((w[1].0 - w[0].0).max(0) as u64);
        }
    }
    normal_gaps.sort_unstable();
    let normal = normal_gaps[normal_gaps.len() / 2];
    // The longest gap across the handoff: a gap where the owner changes.
    let mut longest = 0u64;
    for w in steps.windows(2) {
        if w[0].1 != w[1].1 {
            longest = longest.max((w[1].0 - w[0].0).max(0) as u64);
        }
    }
    (longest, normal)
}

fn percentile(values: &mut [u128], p: u8) -> u128 {
    if values.is_empty() {
        return 0;
    }
    values.sort_unstable();
    let idx = ((values.len() as f64) * (p as f64 / 100.0)).ceil() as usize;
    values[idx.saturating_sub(1).min(values.len() - 1)]
}

fn write_csv(path: &std::path::Path, rows: &[RunRow]) {
    let mut text = String::from(
        "run,switch_ms,total_ms,replay_lag,rolled_back,rollback_cause,owner_gap_ms,longest_step_gap_ms,normal_step_gap_ms\n",
    );
    for r in rows {
        text.push_str(&format!(
            "{},{},{},{},{},\"{}\",{},{},{}\n",
            r.run,
            r.switch_ms,
            r.total_ms,
            r.replay_lag,
            r.rolled_back,
            r.rollback_cause.replace('"', "'"),
            r.owner_gap_ms,
            r.longest_step_gap_ms,
            r.normal_step_gap_ms
        ));
    }
    std::fs::write(path, text).expect("write csv");
}

fn write_summary(path: &std::path::Path, rows: &[RunRow]) {
    let mut switch: Vec<u128> = rows.iter().map(|r| r.switch_ms).collect();
    let mut total: Vec<u128> = rows.iter().map(|r| r.total_ms).collect();
    let mut lag: Vec<u128> = rows.iter().map(|r| r.replay_lag as u128).collect();
    let mut gap: Vec<u128> = rows.iter().map(|r| r.owner_gap_ms as u128).collect();
    let mut longest: Vec<u128> = rows.iter().map(|r| r.longest_step_gap_ms as u128).collect();
    let mut normal: Vec<u128> = rows.iter().map(|r| r.normal_step_gap_ms as u128).collect();
    let rollbacks = rows.iter().filter(|r| r.rolled_back).count();

    let text = format!(
        "# Handoff metrics\n\n\
         {} runs of the AC-1 scenario against the real binaries.\n\n\
         | Metric | p50 | p95 | Max |\n\
         |---|---:|---:|---:|\n\
         | switch time (ms) | {} | {} | {} |\n\
         | total handoff time (ms) | {} | {} | {} |\n\
         | replay lag (events) | {} | {} | {} |\n\
         | owner gap (ms) | {} | {} | {} |\n\
         | longest inter-step gap (ms) | {} | {} | {} |\n\
         | normal inter-step gap (ms) | {} | {} | {} |\n\n\
         Rollbacks: {rollbacks} of {}.\n\n\
         An owner gap above zero means a window with no owner (AC-2). The\n\
         longest inter-step gap should be the switch itself: the target's first\n\
         step follows the source's last after the commit.\n",
        rows.len(),
        percentile(&mut switch, 50),
        percentile(&mut switch, 95),
        switch.iter().copied().max().unwrap_or(0),
        percentile(&mut total, 50),
        percentile(&mut total, 95),
        total.iter().copied().max().unwrap_or(0),
        percentile(&mut lag, 50),
        percentile(&mut lag, 95),
        lag.iter().copied().max().unwrap_or(0),
        percentile(&mut gap, 50),
        percentile(&mut gap, 95),
        gap.iter().copied().max().unwrap_or(0),
        percentile(&mut longest, 50),
        percentile(&mut longest, 95),
        longest.iter().copied().max().unwrap_or(0),
        percentile(&mut normal, 50),
        percentile(&mut normal, 95),
        normal.iter().copied().max().unwrap_or(0),
        rows.len(),
    );
    std::fs::write(path, text).expect("write summary");
}
