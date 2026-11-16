//! Fast real-binary round trip, built on the shared harness in `common/mod.rs`.
//!
//! This is the timing reference for the harness: one real `himan-orchestrator`
//! process, one real `himan-agent-pc` process, one registration, one dispatch,
//! one audit read, over real loopback sockets. It must stay well under 20 s.
//!
//! The harness guarantees the two things that used to make this test slow:
//! child stdio goes to temp files (never pipes) and no agent is spawned until
//! the orchestrator answers `GET /health`.

mod common;

use std::time::Instant;

use serde_json::Value;

#[tokio::test]
async fn fast_roundtrip_real_binaries() {
    let started = Instant::now();

    // Spawns the real orchestrator (stdio to files), waits for /health, and
    // generates + enrolls a real agent key for `pc-1`.
    let mut harness = common::E2ETest::new().await;
    let orch_port = harness.port();
    harness.record_phase("orchestrator up");

    let agent_key_file = harness
        .agent_key_file()
        .expect("harness generates an enrolled agent key");
    let orch_key = harness
        .orchestrator_key()
        .expect("orchestrator advertises its verifying key");

    // The real agent registers over a real WebSocket.
    let agents: Value = harness
        .spawn_agent(
            orch_port,
            &common::binary("himan-agent-pc").expect("agent binary"),
            &agent_key_file,
            &orch_key,
        )
        .await
        .expect("agent registers");
    harness.record_phase("agent registered");

    let registered = agents.as_array().expect("agents array");
    assert_eq!(registered.len(), 1, "one agent registered: {agents}");
    assert_eq!(registered[0]["id"], "pc-1");
    assert_eq!(
        registered[0]["verifying_key"].as_str().unwrap_or(""),
        harness.agent_public_key().expect("agent public key")
    );

    // Dispatch over the real HTTP route, with the harness token.
    let prompt = common::http_post_json(
        orch_port,
        "/api/v1/prompt",
        serde_json::json!({"device": "pc-1", "prompt": "status"}),
    );
    harness.record_phase("dispatch accepted");
    assert!(
        prompt["task_id"]
            .as_str()
            .map(|s| s.len() >= 16)
            .unwrap_or(false),
        "dispatch returned no task id: {prompt}"
    );

    // The audit log must show the registration.
    let audit = common::http_get_json(orch_port, "/api/v1/audit");
    let events = audit.as_array().expect("audit array");
    assert!(
        events.iter().any(|e| e["action"] == "agent_registered"),
        "audit log missing registration: {audit}"
    );

    harness.record_phase("round trip complete");
    harness.stop().await;

    let elapsed = started.elapsed();
    println!(
        "fast_roundtrip_real_binaries total: {:.2}s",
        elapsed.as_secs_f64()
    );
    assert!(
        elapsed < std::time::Duration::from_secs(20),
        "round trip took {:.2}s, over the 20s target",
        elapsed.as_secs_f64()
    );
}
