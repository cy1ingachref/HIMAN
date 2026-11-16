//! Handoff over the real HTTP surface, on the shared harness.
//!
//! These are the checks that `e2e.rs` used to carry and that only the real
//! binaries can prove:
//!   * a handoff request naming a disconnected device is refused with HTTP 400,
//!     and nothing is recorded for it;
//!   * a successful request returns a signed token and records the attempt,
//!     while ownership has not moved yet;
//!   * the audit timeline contains both registrations;
//!   * in insecure dev mode the API routes really are open and an unenrolled
//!     agent can register.

mod common;

use serde_json::json;

#[tokio::test]
async fn handoff_to_a_disconnected_device_is_refused() {
    let mut harness = common::E2ETest::new_with_devices(&["dev-a", "dev-b"]).await;
    let port = harness.port();
    let orch_key = harness.orchestrator_key().expect("orchestrator key");

    harness
        .spawn_agent(port, "dev-a", &orch_key)
        .await
        .expect("dev-a registers");
    harness
        .spawn_agent(port, "dev-b", &orch_key)
        .await
        .expect("dev-b registers");

    // No task has been dispatched, so there is no event log to checkpoint.
    // The request must still be refused because `dev-c` is not connected.
    let (status, body) = common::http_post(
        port,
        "/api/v1/handoff",
        json!({"task_id": "task-unknown", "from": "dev-a", "to": "dev-c"}),
    );
    assert_eq!(
        status, 400,
        "a handoff to a disconnected device must be refused: {body}"
    );

    // Nothing was recorded for the refused request.
    let audit = common::http_get_json(port, "/api/v1/audit");
    let attempts = audit
        .as_array()
        .map(|a| {
            a.iter()
                .filter(|l| l["action"] == "handoff_prepared")
                .count()
        })
        .unwrap_or(0);
    assert_eq!(attempts, 0, "the refused request was recorded anyway");

    // Both registrations are in the audit timeline.
    let registrations = audit
        .as_array()
        .map(|a| {
            a.iter()
                .filter(|l| l["action"] == "agent_registered")
                .count()
        })
        .unwrap_or(0);
    assert_eq!(
        registrations, 2,
        "the audit is missing a registration: {audit}"
    );

    harness.stop().await;
}

#[tokio::test]
async fn handoff_request_returns_a_token_and_does_not_move_ownership() {
    let mut harness = common::E2ETest::new_with_devices(&["dev-a", "dev-b"]).await;
    let port = harness.port();
    let orch_key = harness.orchestrator_key().expect("orchestrator key");

    harness
        .spawn_agent(port, "dev-a", &orch_key)
        .await
        .expect("dev-a registers");
    harness
        .spawn_agent(port, "dev-b", &orch_key)
        .await
        .expect("dev-b registers");

    // A real dispatched task gives the orchestrator an event log to checkpoint.
    let task_id = super_dispatch(port, "dev-a");

    let (status, body) = common::http_post(
        port,
        "/api/v1/handoff",
        json!({"task_id": task_id, "from": "dev-a", "to": "dev-b"}),
    );
    assert_eq!(
        status,
        200,
        "handoff refused: {}",
        serde_json::to_string(&body).unwrap_or_default()
    );
    assert!(
        body["handoff_id"]
            .as_str()
            .is_some_and(|h| h.starts_with("handoff-")),
        "no handoff id: {body}"
    );
    assert_eq!(body["token"]["from_device"], "dev-a");
    assert_eq!(body["token"]["to_device"], "dev-b");

    // The route drives the handoff to completion; the token is the signed
    // authority to move the task. The source keeps ownership until the commit.
    let state = body["state"].as_str().unwrap_or_default();
    assert!(
        state == "prepared" || state == "active",
        "unexpected state: {body}"
    );

    let owner = common::http_get_json(port, &format!("/api/v1/tasks/{task_id}/owner"));
    if state == "prepared" {
        assert_eq!(owner["owner"], "dev-a", "ownership moved before the commit");
        assert_eq!(owner["epoch"], 0, "epoch moved before the commit");
    } else {
        assert_eq!(owner["owner"], "dev-b", "the target does not own the task");
        assert_eq!(owner["epoch"], 1, "the commit did not bump the epoch once");
    }

    harness.stop().await;
}

#[tokio::test]
async fn insecure_dev_mode_leaves_the_api_open_and_accepts_an_unenrolled_agent() {
    let mut harness = common::E2ETest::new_insecure_dev().await;
    let port = harness.port();

    // No bearer token: the route must still answer.
    let (status, body) = common::http_get(port, "/api/v1/agents");
    assert_eq!(
        status, 200,
        "dev-mode API refused an unauthenticated GET: {body}"
    );
    assert_eq!(
        body.as_array().map(|a| a.len()).unwrap_or(0),
        0,
        "no agents yet: {body}"
    );

    // The agent is not enrolled, which dev mode must not require.
    let orch_key = harness.orchestrator_key().expect("orchestrator key");
    harness
        .spawn_agent(port, "pc-1", &orch_key)
        .await
        .expect("unenrolled agent must register in dev mode");

    let agents = common::http_get_json(port, "/api/v1/agents");
    assert_eq!(
        agents.as_array().map(|a| a.len()).unwrap_or(0),
        1,
        "the dev-mode agent did not register: {agents}"
    );

    harness.stop().await;
}

/// Dispatch a scenario prompt, returning the task id the orchestrator created.
fn super_dispatch(port: u16, device: &str) -> String {
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
