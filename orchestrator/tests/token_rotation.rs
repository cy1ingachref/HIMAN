//! RT-23: rotate the admin API token without a restart.
//!
//! Written FIRST against current code, where the token is a static env var
//! read once at startup: there is no rotation endpoint, so every request
//! below answered 404.

mod common;

use serde_json::json;

fn rotate(port: u16, current: &str) -> (u16, serde_json::Value) {
    let url = format!(
        "{}://127.0.0.1:{port}/api/v1/admin/token",
        common::base_scheme()
    );
    let agent = common::agent();
    let response = agent
        .post(&url)
        .set("Authorization", &format!("Bearer {current}"))
        .send_json(json!({}));
    match response {
        Ok(r) => {
            let status = r.status();
            let text = r.into_string().unwrap_or_default();
            (
                status,
                serde_json::from_str(&text).unwrap_or(serde_json::Value::Null),
            )
        }
        Err(ureq::Error::Status(code, r)) => {
            let text = r.into_string().unwrap_or_default();
            (
                code,
                serde_json::from_str(&text).unwrap_or(serde_json::Value::Null),
            )
        }
        Err(e) => (0, json!({"error": e.to_string()})),
    }
}

fn authorized(port: u16, token: &str) -> u16 {
    common::http_get_with_token(port, "/api/v1/agents", token).0
}

#[tokio::test]
async fn rt23_rotation_returns_a_new_token_immediately_accepted() {
    let mut harness = common::E2ETest::restartable(&[], None, vec![]).await;
    let port = harness.port();
    let (status, body) = rotate(port, common::API_TOKEN);
    assert_eq!(status, 200, "rotation failed: {body}");
    let new_token = body["token"].as_str().expect("new token").to_string();
    assert_ne!(
        new_token,
        common::API_TOKEN,
        "the new token equals the old one"
    );
    // The new token works immediately.
    assert_eq!(
        authorized(port, &new_token),
        200,
        "the new token was not accepted"
    );
    harness.stop().await;
}

#[tokio::test]
async fn rt23_old_token_has_a_bounded_grace_window() {
    let mut harness = common::E2ETest::restartable(
        &[],
        None,
        vec![("HIMAN_TOKEN_GRACE_SECS".to_string(), "1".to_string())],
    )
    .await;
    let port = harness.port();
    let (status, body) = rotate(port, common::API_TOKEN);
    assert_eq!(status, 200, "rotation failed: {body}");
    // Immediately after rotation the old token is still accepted (grace).
    assert_eq!(
        authorized(port, common::API_TOKEN),
        200,
        "the old token was refused inside the grace window"
    );
    // The grace window is bounded: wait it out, then the old token is refused.
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    assert_eq!(
        authorized(port, common::API_TOKEN),
        401,
        "the old token was still accepted after the grace window"
    );
    harness.stop().await;
}

#[tokio::test]
async fn rt23_rotation_requires_the_current_token() {
    let mut harness = common::E2ETest::restartable(&[], None, vec![]).await;
    let port = harness.port();
    // A wrong token cannot rotate.
    let (status, _) = rotate(port, "not-the-token");
    assert_eq!(status, 401, "rotation with a wrong token was accepted");
    // No token cannot rotate either.
    let (status, _) = rotate(port, "");
    assert_eq!(status, 401, "rotation without a token was accepted");
    harness.stop().await;
}

#[tokio::test]
async fn rt23_rotation_is_audited_and_survives_restart() {
    let state = std::env::temp_dir().join(format!("himan-rt23-{}.sqlite", std::process::id()));
    let _ = std::fs::remove_file(&state);
    let mut harness = common::E2ETest::restartable(
        &[],
        Some(state.clone()),
        vec![("HIMAN_TOKEN_GRACE_SECS".to_string(), "1".to_string())],
    )
    .await;
    let port = harness.port();
    let (status, body) = rotate(port, common::API_TOKEN);
    assert_eq!(status, 200, "rotation failed: {body}");
    let new_token = body["token"].as_str().expect("new token").to_string();

    // Audited in the hash-chained log.
    let audit = common::http_get_json(port, "/api/v1/audit");
    let actions: Vec<&str> = audit
        .as_array()
        .expect("audit")
        .iter()
        .map(|l| l["action"].as_str().unwrap_or(""))
        .collect();
    assert!(
        actions.contains(&"api_token_rotated"),
        "the rotation was not audited: {actions:?}"
    );

    // Survives a restart: the rotated token is still the valid one.
    harness.restart_orchestrator_nowait().await;
    assert_eq!(
        authorized(port, &new_token),
        200,
        "the rotated token did not survive a restart"
    );
    harness.stop().await;
    let _ = std::fs::remove_file(&state);
}
