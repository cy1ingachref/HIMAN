//! The default build must not contain fault-injection hooks.
//!
//! `agent-pc`'s `fault-injection` feature is off by default. These tests prove
//! it by behaviour, not by inspecting the binary: a default agent that is
//! asked never to send Ready must still answer a handoff, and the handoff must
//! still succeed.

mod common;

use serde_json::json;

#[tokio::test]
async fn a_default_build_has_no_fault_injection_hook() {
    let mut harness = common::E2ETest::new_with_devices(&["dev-a", "dev-b"]).await;
    // Deliberately NOT calling use_fault_injection_agent().
    let port = harness.port();
    let orch_key = harness.orchestrator_key().expect("orchestrator key");

    harness
        .spawn_agent(port, "dev-a", &orch_key)
        .await
        .expect("dev-a registers");
    let key_b = harness
        .devices()
        .iter()
        .find(|d| d.device == "dev-b")
        .map(|d| d.key_file.clone())
        .expect("dev-b key");

    // Ask the default-built target to misbehave. If the hook were compiled in,
    // it would stay silent and the handoff would time out; a default build
    // ignores the variable entirely.
    let agents = harness
        .spawn_agent_full(
            port,
            "dev-b",
            &key_b,
            &orch_key,
            Vec::new(),
            vec![("HIMAN_TEST_NEVER_READY".to_string(), "1".to_string())],
        )
        .await
        .expect("dev-b registers");
    assert_eq!(agents.as_array().map(|a| a.len()).unwrap_or(0), 2);

    let (status, body) = common::http_post(
        port,
        "/api/v1/prompt",
        json!({"device": "dev-a", "prompt": "run the deterministic scenario"}),
    );
    assert_eq!(status, 200, "dispatch refused: {body}");
    let task_id = body["task_id"].as_str().expect("task id").to_string();

    let (status, handoff) = common::http_post(
        port,
        "/api/v1/handoff",
        json!({"task_id": task_id, "from": "dev-a", "to": "dev-b"}),
    );
    assert_eq!(status, 200, "handoff refused: {handoff}");

    // The decisive assertion: the handoff reached active. With the hook
    // present it could not, because the target would never send Ready.
    assert_eq!(
        handoff["state"].as_str().unwrap_or_default(),
        "active",
        "a default build answered the handoff, so it has no never-ready hook: {handoff}"
    );

    let owner = common::http_get_json(port, &format!("/api/v1/tasks/{task_id}/owner"));
    assert_eq!(
        owner["owner"],
        json!("dev-b"),
        "the handoff did not complete"
    );

    let audit = common::http_get_json(port, "/api/v1/audit");
    let rolled_back = audit
        .as_array()
        .map(|a| a.iter().any(|l| l["action"] == "handoff_rolled_back"))
        .unwrap_or(false);
    assert!(
        !rolled_back,
        "a default build rolled the handoff back, which means the hook is compiled in"
    );

    harness.stop().await;
}
