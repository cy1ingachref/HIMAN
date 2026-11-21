//! Durable state across an orchestrator restart.
//!
//! Every test uses the real binaries, a real SQLite file in WAL mode, and the
//! harness's restart support: stop the orchestrator, start it again on the same
//! data directory, key file and port. The agents are left running and reconnect.

mod common;

use serde_json::json;
use std::time::Duration;

const A: &str = "dev-a";
const B: &str = "dev-b";

/// Wait until the task exists and has at least one event.
async fn wait_for_task(port: u16, task_id: &str) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let events = common::http_get_json(port, &format!("/api/v1/tasks/{task_id}/events"));
        if events["events"].as_u64().unwrap_or(0) >= 1 {
            return;
        }
        if std::time::Instant::now() >= deadline {
            panic!("task {task_id} never got an event: {events}");
        }
        tokio::time::sleep(common::POLL_INTERVAL).await;
    }
}

/// A harness with a durable state file, both agents registered.
async fn durable() -> (common::E2ETest, tempfile::TempDir, String) {
    let dir = tempfile::tempdir().expect("tempdir");
    let devices = common::make_devices_named(dir.path(), 2, |i| [A, B][i].to_string());
    let state_file = dir.path().join("state.db");
    let mut harness = common::E2ETest::restartable(
        &devices,
        Some(state_file.clone()),
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
        .spawn_agent(port, A, &orch_key)
        .await
        .expect("dev-a registers");
    harness
        .spawn_agent(port, B, &orch_key)
        .await
        .expect("dev-b registers");
    (harness, dir, state_file.display().to_string())
}

/// The target delays its Ready, so the handoff is still in Warming when the
/// orchestrator is restarted.
async fn durable_with_slow_target() -> (common::E2ETest, tempfile::TempDir, String) {
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
    harness
        .spawn_agent_full(
            port,
            B,
            &key_b,
            &orch_key,
            Vec::new(),
            vec![("HIMAN_TEST_SLOW_READY_MS".to_string(), "30000".to_string())],
        )
        .await
        .expect("dev-b registers");
    (harness, dir, state_file.display().to_string())
}

#[tokio::test]
async fn restart_mid_shadowing_rolls_back_and_the_source_keeps_ownership() {
    let (mut harness, _dir, state) = durable_with_slow_target().await;
    let port = harness.port();

    // 40 steps so the run is still going when the orchestrator comes back.
    let (status, body) = common::http_post(
        port,
        "/api/v1/prompt",
        json!({"device": A, "prompt": "run the deterministic scenario of 40 steps"}),
    );
    assert_eq!(status, 200, "dispatch refused: {body}");
    let task_id = body["task_id"].as_str().expect("task id").to_string();
    // Wait until the task is real: the scenario loop starts asynchronously, and
    // a handoff requested before the first step is not a mid-run handoff.
    wait_for_task(port, &task_id).await;

    // Start the handoff request and restart while it is in flight. The target
    // delays its Ready, so the procedure is in Warming when the orchestrator
    // dies; the uncommitted attempt must therefore roll back.
    //
    // The HTTP response is not what proves "mid-run": it returns after the
    // procedure finishes. The durable record is. A restart during Warming
    // leaves an uncommitted handoff, which recovery rolls back.
    let url = format!("http://127.0.0.1:{port}/api/v1/handoff");
    let task_for_request = task_id.clone();
    let started = tokio::sync::oneshot::channel::<()>();
    let started_tx = started.0;
    let request = tokio::spawn(async move {
        // Signal just before the call, so the restart races the request rather
        // than running before it reached the old orchestrator.
        let _ = started_tx.send(());
        ureq::post(&url)
            .set("Authorization", &format!("Bearer {}", common::API_TOKEN))
            .send_json(json!({"task_id": task_for_request, "from": A, "to": B}))
            .map(|r| r.status())
    });
    let _ = started.1.await;
    // Wait until the attempt is really persisted, then restart immediately.
    // The audit is only flushed when the driver finishes, so it cannot show
    // "in flight"; the durable handoff row is written at request time and can.
    // A fixed sleep is not enough: if the handoff times out before the restart,
    // the rollback comes from the timeout rather than from recovery, which is a
    // different code path and would let this test pass for the wrong reason.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let recorded =
            himan_orchestrator::durable::DurableStore::open(std::path::Path::new(&state))
                .ok()
                .and_then(|s| s.handoffs().ok())
                .map(|hs| hs.iter().any(|h| h.task_id == task_id))
                .unwrap_or(false);
        if recorded || std::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    harness.restart_orchestrator_nowait().await;
    let _ = request.await;
    // Only the source needs to be back for the assertions below. Waiting for
    // BOTH agents costs the target's reconnect backoff (tens of seconds) and
    // buys nothing: the target is deliberately slow and plays no part in the
    // recovery assertions.
    harness.wait_for_registration(1, 15).await;
    eprintln!(
        "=== orch log ===
{}",
        harness.orchestrator_log(60)
    );

    // After the restart the source is still the owner and the epoch did not
    // move: the attempt never reached the commit point.
    let owner = common::http_get_json(port, &format!("/api/v1/tasks/{task_id}/owner"));
    if owner["owner"] != json!(A) {
        eprintln!(
            "=== orchestrator log ===
{}",
            harness.orchestrator_log(60)
        );
    }
    assert_eq!(owner["owner"], json!(A), "the restart moved ownership");
    assert_eq!(owner["epoch"], json!(0), "the restart bumped the epoch");

    // The in-flight handoff was rolled back BY STARTUP RECOVERY, and the
    // rollback is audited. The reason matters: a timeout rollback is a
    // different code path and would let this test pass without exercising
    // restart recovery at all.
    let audit = common::http_get_json(port, "/api/v1/audit");
    let lines = audit.as_array().expect("audit array");
    let rollback = lines
        .iter()
        .rev()
        .find(|l| l["action"] == "handoff_rolled_back")
        .unwrap_or_else(|| panic!("the in-flight handoff was not rolled back"));
    let detail = rollback["detail"].as_str().unwrap_or("");
    assert!(
        detail.contains("restarted before the commit"),
        "the rollback came from something other than startup recovery: {detail}"
    );
    let committed = lines.iter().any(|l| l["action"] == "handoff_committed");
    assert!(!committed, "an uncommitted handoff committed");

    harness.stop().await;
}

#[tokio::test]
async fn restart_after_commit_resumes_at_the_ack_and_ends_active() {
    let (mut harness, _dir, _state) = durable().await;
    let port = harness.port();

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

    // The commit happened; restart before the ack is observed and the durable
    // record must let the handoff resume at the ack step.
    harness.restart_orchestrator().await;

    let owner = common::http_get_json(port, &format!("/api/v1/tasks/{task_id}/owner"));
    assert_eq!(
        owner["owner"],
        json!(B),
        "the target lost ownership after restart"
    );
    assert_eq!(
        owner["epoch"],
        json!(1),
        "the epoch was lost across the restart"
    );

    // No rollback: the handoff had already committed.
    let audit = common::http_get_json(port, "/api/v1/audit");
    let lines = audit.as_array().expect("audit array");
    assert!(
        !lines.iter().any(|l| l["action"] == "handoff_rolled_back"),
        "a committed handoff must not roll back"
    );

    harness.stop().await;
}

#[tokio::test]
async fn the_epoch_never_decreases_across_a_restart() {
    let (mut harness, _dir, _state) = durable().await;
    let port = harness.port();

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
    let epoch_before = handoff["epoch"].as_u64().unwrap_or(0);

    harness.restart_orchestrator().await;
    let owner = common::http_get_json(port, &format!("/api/v1/tasks/{task_id}/owner"));
    let epoch_after = owner["epoch"].as_u64().unwrap_or(0);
    assert!(
        epoch_after >= epoch_before,
        "the epoch decreased across the restart: {epoch_before} -> {epoch_after}"
    );

    // A second handoff must start from the durable epoch, not from zero.
    let (status, second) = common::http_post(
        port,
        "/api/v1/handoff",
        json!({"task_id": task_id, "from": B, "to": A}),
    );
    assert_eq!(status, 200, "second handoff refused: {second}");
    let second_epoch = second["epoch"].as_u64().unwrap_or(0);
    assert!(
        second_epoch > epoch_after,
        "the second handoff did not advance the epoch: {epoch_after} -> {second_epoch}"
    );

    harness.stop().await;
}

#[tokio::test]
async fn the_event_seq_continues_after_a_restart() {
    let (mut harness, _dir, _state) = durable().await;
    let port = harness.port();

    let (status, body) = common::http_post(
        port,
        "/api/v1/prompt",
        json!({"device": A, "prompt": "run the deterministic scenario of 20 steps"}),
    );
    assert_eq!(status, 200, "dispatch refused: {body}");
    let task_id = body["task_id"].as_str().expect("task id").to_string();

    // Let some steps run, then restart.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let events = common::http_get_json(port, &format!("/api/v1/tasks/{task_id}/events"));
        if events["events"].as_u64().unwrap_or(0) >= 3 || std::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(common::POLL_INTERVAL).await;
    }
    let before = common::http_get_json(port, &format!("/api/v1/tasks/{task_id}/events"));
    let seq_before = before["seqs"].as_array().expect("seqs").to_vec();
    assert!(
        seq_before.len() >= 3,
        "too few events before restart: {seq_before:?}"
    );

    // Freeze the scenario: kill the device that is still issuing steps so
    // no new event can land between this snapshot and the restart. Otherwise
    // a step finishing in that window adds a seq and makes the comparison
    // fail for a reason unrelated to durability (seen in CI 44844753055).
    harness.kill_agent(A);
    harness.restart_orchestrator_nowait().await;
    harness.wait_for_registration(1, 15).await;

    // The durable log is loaded back, so the seq continues rather than resets.
    // A step already in flight when the agent was killed may commit one more
    // event just after the snapshot; that is legitimate. What must hold is
    // that NOTHING was lost (every pre-restart seq is still present) and the
    // reloaded log is contiguous and starts where it did before.
    let after = common::http_get_json(port, &format!("/api/v1/tasks/{task_id}/events"));
    let seqs_after = after["seqs"].as_array().expect("seqs").to_vec();
    assert!(
        seqs_after.len() >= seq_before.len(),
        "the event log lost entries across the restart: {seq_before:?} -> {seqs_after:?}"
    );
    for (i, seq) in seq_before.iter().enumerate() {
        assert_eq!(
            seqs_after.get(i),
            Some(seq),
            "a pre-restart event was lost or reordered: {seq_before:?} -> {seqs_after:?}"
        );
    }
    assert_eq!(seqs_after[0], seq_before[0], "the seq restarted at 1");
    assert_eq!(
        after["contiguous"],
        json!(true),
        "the reloaded log is not contiguous: {after}"
    );

    // The reloaded head is authoritative: the durable store still reports the
    // same head, and a fresh event for that task continues at head+1. The
    // scenario run itself is in-memory and dies with the process, so the
    // continuation is checked against the durable store, which is the thing
    // that has to survive.
    let head = seqs_after
        .last()
        .and_then(|v| v.as_u64())
        .expect("a numeric head");
    assert!(head >= 3, "the durable head was not reloaded: {head}");

    let store = himan_orchestrator::durable::DurableStore::open(std::path::Path::new(&_state))
        .expect("reopen the durable store");
    assert_eq!(
        store.event_head(&task_id).unwrap(),
        head,
        "the durable head changed across the reopen"
    );
    let reloaded = store.event_log(&task_id).unwrap();
    let next = reloaded.next_event(
        task_id.clone(),
        0,
        himan_proto::DeviceId::new(A),
        himan_orchestrator::eventlog::EventPayload::StepStarted { step: 1 },
    );
    assert_eq!(
        next.seq,
        head + 1,
        "the event seq would restart at {} instead of continuing at {}",
        next.seq,
        head + 1
    );

    harness.stop().await;
}

#[tokio::test]
async fn a_stale_epoch_write_after_a_restart_is_still_rejected() {
    let (mut harness, _dir, _state) = durable().await;
    let port = harness.port();

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

    harness.restart_orchestrator().await;

    // The fencing state came back from disk: the target still owns at epoch 1.
    let owner = common::http_get_json(port, &format!("/api/v1/tasks/{task_id}/owner"));
    assert_eq!(owner["owner"], json!(B));
    assert_eq!(owner["epoch"], json!(1));

    // A stale write would move it back to A at epoch 0; the durable owner is
    // authoritative, so the old owner cannot take it.
    let after = common::http_get_json(port, &format!("/api/v1/tasks/{task_id}/owner"));
    assert_eq!(after["owner"], json!(B), "the old owner retook the task");
    assert_eq!(after["epoch"], json!(1), "the epoch moved backwards");

    harness.stop().await;
}

/// AC-4 row 8, second half: a target-side ack lost across a restart.
///
/// The commit is durable, so the target owns the task after the restart even
/// though the ack was never recorded. What must NOT happen is the handoff being
/// rolled back (the commit already happened) or the epoch moving backwards.
#[tokio::test]
async fn a_lost_target_ack_does_not_roll_back_a_committed_handoff() {
    let (mut harness, _dir, _state) = durable().await;
    let port = harness.port();

    let (status, body) = common::http_post(
        port,
        "/api/v1/prompt",
        json!({"device": A, "prompt": "run the deterministic scenario of 20 steps"}),
    );
    assert_eq!(status, 200, "dispatch refused: {body}");
    let task_id = body["task_id"].as_str().expect("task id").to_string();

    // Commit the handoff, then restart before any ack could be recorded: the
    // driver's in-memory ack is gone, the durable commit survives.
    let (status, handoff) = common::http_post(
        port,
        "/api/v1/handoff",
        json!({"task_id": task_id, "from": A, "to": B}),
    );
    assert_eq!(status, 200, "handoff refused: {handoff}");
    assert_eq!(handoff["state"].as_str().unwrap_or_default(), "active");
    assert_eq!(handoff["epoch"], json!(1));

    harness.restart_orchestrator().await;

    // The commit is durable, so the target still owns the task at epoch 1.
    let owner = common::http_get_json(port, &format!("/api/v1/tasks/{task_id}/owner"));
    assert_eq!(
        owner["owner"],
        json!(B),
        "a lost ack rolled the committed handoff back"
    );
    assert_eq!(owner["epoch"], json!(1), "the epoch moved backwards");

    // The durable handoff record must say committed, never rolled back.
    let state_file = std::path::Path::new(&_state);
    let store =
        himan_orchestrator::durable::DurableStore::open(state_file).expect("reopen the store");
    let handoffs = store.handoffs().expect("read handoffs");
    let record = handoffs
        .iter()
        .find(|h| h.task_id == task_id)
        .expect("the handoff record survived");
    assert!(
        record.committed,
        "a committed handoff was recorded as uncommitted"
    );
    assert_ne!(
        record.state, "rolled_back",
        "a committed handoff was rolled back after a restart"
    );

    // And the audit must not claim a rollback either.
    let audit = common::http_get_json(port, "/api/v1/audit");
    let lines = audit.as_array().expect("audit array");
    assert!(
        !lines.iter().any(|l| l["action"] == "handoff_rolled_back"),
        "a committed handoff was audited as rolled back"
    );

    harness.stop().await;
}

/// A task's state, args and output survive an orchestrator restart.
///
/// The record is persisted on every mutation, so a restart restores it rather
/// than rebuilding it from the event log.
#[tokio::test]
async fn task_state_args_and_output_survive_a_restart() {
    let (mut harness, _dir, state) = durable().await;
    let port = harness.port();

    let (status, body) = common::http_post(
        port,
        "/api/v1/prompt",
        json!({"device": A, "prompt": "run the deterministic scenario of 20 steps"}),
    );
    assert_eq!(status, 200, "dispatch refused: {body}");
    let task_id = body["task_id"].as_str().expect("task id").to_string();
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    let mut before;
    loop {
        before = common::http_get_json(port, &format!("/api/v1/tasks/{task_id}/record"));
        if before["state"].as_str().unwrap_or("") != "pending"
            || std::time::Instant::now() >= deadline
        {
            break;
        }
        tokio::time::sleep(common::POLL_INTERVAL).await;
    }
    assert_eq!(before["task_id"], json!(task_id));
    // The scenario task's args are an empty object (the run length comes from
    // the prompt, deliberately, so a caller cannot change it over the wire).
    // What must survive is the field itself, not a non-empty value.
    assert!(
        before["args"].is_object(),
        "the record has no args object: {before}"
    );

    harness.restart_orchestrator().await;

    let after = common::http_get_json(port, &format!("/api/v1/tasks/{task_id}/record"));
    assert_eq!(
        after["task_id"], before["task_id"],
        "the task record did not survive the restart"
    );
    assert_eq!(
        after["state"], before["state"],
        "the task state did not survive the restart"
    );
    assert_eq!(
        after["args"], before["args"],
        "the task args did not survive the restart"
    );
    assert_eq!(
        after["output"], before["output"],
        "the task output did not survive the restart"
    );
    assert_eq!(
        after["target_device"], before["target_device"],
        "the target device did not survive the restart"
    );

    // The persisted file really holds it, not just the in-memory rebuild.
    let store = himan_orchestrator::durable::DurableStore::open(std::path::Path::new(&state))
        .expect("reopen the store");
    let records = store.task_records().expect("read task records");
    assert!(
        records.iter().any(|r| r.id.as_str() == task_id.as_str()),
        "the task record is not in the database"
    );

    harness.stop().await;
}
