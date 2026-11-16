//! Fast real-binary round trip: one orchestrator, one agent, one dispatch.
//!
//! This is the timing reference for the shared harness. It asserts the harness
//! contract (stdio to files, health gate, 100 ms registration polling) and
//! prints a per-phase timing report, so a regression in the harness shows up
//! here before it shows up in the acceptance tests.

mod common;

use serde_json::Value;

#[tokio::test]
async fn fast_roundtrip_real_binaries() {
    let start = std::time::Instant::now();

    // Spawns the real orchestrator (stdio to files), waits for /health, and
    // generates + enrolls a real agent key for `pc-1`.
    let mut harness = common::E2ETest::new_with_devices(&["pc-1"]).await;
    let orch_port = harness.port();
    harness.record_phase("orchestrator up");

    let orch_key = harness
        .orchestrator_key()
        .expect("orchestrator advertises its verifying key");
    let agent = harness
        .devices()
        .iter()
        .find(|d| d.device == "pc-1")
        .expect("an enrolled pc-1 key");
    let agent_public_key = agent.public_key.clone();

    // The real agent registers over a real WebSocket.
    let agents: Value = harness
        .spawn_agent(orch_port, "pc-1", &orch_key)
        .await
        .expect("agent registers");
    harness.record_phase("agent registered");

    let registered = agents.as_array().expect("agents array");
    assert_eq!(registered.len(), 1, "one agent registered: {agents}");
    assert_eq!(registered[0]["id"], "pc-1");
    assert_eq!(
        registered[0]["verifying_key"].as_str().unwrap_or(""),
        agent_public_key,
        "the registered key is the enrolled one"
    );

    // A real dispatch over HTTP produces a real tool call on the agent.
    let result = common::http_post(
        orch_port,
        "/api/v1/prompt",
        serde_json::json!({"device": "pc-1", "prompt": "device status"}),
    );
    assert_eq!(
        result.0,
        200,
        "dispatch refused: {}",
        serde_json::to_string(&result.1).unwrap_or_default()
    );
    assert!(
        result.1["task_id"].as_str().is_some_and(|t| !t.is_empty()),
        "no task id: {result:?}"
    );
    harness.record_phase("dispatch accepted");

    // The audit trail records the dispatch.
    let audit = common::http_get_json(orch_port, "/api/v1/audit");
    let actions: Vec<&str> = audit
        .as_array()
        .map(|a| a.iter().filter_map(|l| l["action"].as_str()).collect())
        .unwrap_or_default();
    assert!(
        actions.contains(&"tool_call_policy"),
        "the dispatch was not audited: {actions:?}"
    );
    harness.record_phase("audit read");

    println!(
        "fast_roundtrip_real_binaries total: {:.2}s",
        start.elapsed().as_secs_f64()
    );
    harness.stop().await;
}
