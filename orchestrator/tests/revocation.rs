//! RT-18: device revocation takes effect immediately and survives restart.
//!
//! Written FIRST against current code, where no revocation endpoint or
//! registry exists: the requests below answer 404 and these tests fail.
//! The required defense: revoke a device key, reject its future Hello,
//! drop its live session, persist the revocation durably, and record it
//! in the hash-chained audit log.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use himan_orchestrator::api_auth::ApiToken;
use himan_orchestrator::server::production_router;
use himan_orchestrator::{Hub, HubConfig};
use tower::ServiceExt;

const TOKEN: &str = "revocation-test-token";

fn app() -> axum::Router {
    let hub = Hub::new(HubConfig::default());
    production_router(hub, ApiToken::from_raw(TOKEN), String::new())
}

async fn call(router: &axum::Router, method: &str, path: &str, body: &str) -> (StatusCode, String) {
    let req = Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", format!("Bearer {TOKEN}"))
        .header("content-type", "application/json")
        .body(Body::from(body.to_owned()))
        .expect("request");
    let resp = router.clone().oneshot(req).await.expect("response");
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .expect("body");
    (status, String::from_utf8_lossy(&bytes).to_string())
}

#[tokio::test]
async fn rt18_revoke_endpoint_exists_and_lists_the_device() {
    let router = app();
    let (s, body) = call(&router, "POST", "/api/v1/devices/dev-bad/revoke", "").await;
    assert_eq!(s, StatusCode::OK, "no revocation endpoint: {s} {body}");

    let (s, body) = call(&router, "GET", "/api/v1/devices/revoked", "").await;
    assert_eq!(s, StatusCode::OK, "no revocation listing: {s} {body}");
    assert!(
        body.contains("dev-bad"),
        "the revoked device is not listed: {body}"
    );
}

#[tokio::test]
async fn rt18_revoke_requires_auth() {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/devices/dev-bad/revoke")
        .header("content-type", "application/json")
        .body(Body::empty())
        .expect("request");
    let s = app().oneshot(req).await.expect("response").status();
    assert_eq!(
        s,
        StatusCode::UNAUTHORIZED,
        "the revocation endpoint is not behind auth: {s}"
    );
}
