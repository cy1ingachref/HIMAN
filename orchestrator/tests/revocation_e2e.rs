//! RT-18 (real binaries): device revocation is immediate, durable, audited.
//!
//! The HTTP-level tests in `revocation.rs` prove the endpoint and auth;
//! these drive the real orchestrator and agents to prove the security
//! properties: a revoked device loses its live session, cannot re-register
//! with the same key, and stays revoked after an orchestrator restart.

mod common;

use serde_json::json;

const A: &str = "dev-a";
const B: &str = "dev-b";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revocation_drops_the_session_survives_restart_and_is_audited() {
    let dir = tempfile::tempdir().expect("tempdir");
    let devices = common::make_devices_named(dir.path(), 2, |i| [A, B][i].to_string());
    let state_file = dir.path().join("state.db");
    let mut harness = common::E2ETest::restartable(&devices, Some(state_file), Vec::new()).await;
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
    harness.wait_for_agents().await;

    // Revoke dev-b through the authenticated API.
    let (status, body) = common::http_post(port, "/api/v1/devices/dev-b/revoke", json!({}));
    assert_eq!(status, 200, "revoke refused: {body}");

    // The live session is gone: only dev-a remains registered.
    let agents = common::http_get_json(port, "/api/v1/agents");
    let ids: Vec<&str> = agents
        .as_array()
        .expect("agents array")
        .iter()
        .filter_map(|a| a["id"].as_str())
        .collect();
    assert!(ids.contains(&A), "dev-a was dropped: {ids:?}");
    assert!(
        !ids.contains(&B),
        "a revoked device kept its live session: {ids:?}"
    );

    // The revocation is in the hash-chained audit log.
    let audit = common::http_get_json(port, "/api/v1/audit");
    let actions: Vec<&str> = audit
        .as_array()
        .expect("audit array")
        .iter()
        .map(|e| e["action"].as_str().unwrap_or(""))
        .collect();
    assert!(
        actions.contains(&"device_revoked"),
        "the revocation was not audited: {actions:?}"
    );

    // Restart: the revoked id must still be refused, from the durable table.
    harness.restart_orchestrator_nowait().await;
    harness.wait_for_registration(1, 15).await;
    let revoked = common::http_get_json(port, "/api/v1/devices/revoked");
    assert!(
        revoked
            .as_array()
            .map(|a| a.iter().any(|v| v.as_str() == Some(B)))
            .unwrap_or(false),
        "revocation was lost across restart: {revoked}"
    );
    // A revoked device's reconnect is refused by the hub.
    let key_b = harness
        .devices()
        .iter()
        .find(|d| d.device == B)
        .map(|d| d.key_file.clone())
        .expect("dev-b key");
    // Re-registration must FAIL: the harness waits for the device count and
    // times out because the hub refuses the revoked Hello.
    let rejected = harness
        .spawn_agent_full_bounded(port, B, &key_b, &orch_key, Vec::new(), Vec::new(), 3)
        .await
        .is_err();
    assert!(rejected, "a revoked device re-registered with the same key");
    // And it is audited as a rejection.
    let audit = common::http_get_json(port, "/api/v1/audit");
    let actions: Vec<&str> = audit
        .as_array()
        .expect("audit array")
        .iter()
        .map(|e| e["action"].as_str().unwrap_or(""))
        .collect();
    assert!(
        actions.contains(&"registration_rejected"),
        "the revoked re-registration was not audited: {actions:?}"
    );

    harness.stop().await;
}
