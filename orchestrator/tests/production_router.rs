//! The production router: every documented route exists and requires auth.
//!
//! `serve` picks the router via `production_router`; this test builds THE
//! SAME router with a token, so the route table and the auth layer under test
//! are the code the binary runs — not a copy that can drift (the /record route
//! was once added to two routers and missed the production one; this test is
//! the regression guard for exactly that class of bug).

use axum::body::Body;
use axum::http::{Request, StatusCode};
use himan_orchestrator::api_auth::ApiToken;
use himan_orchestrator::server::production_router;
use himan_orchestrator::{Hub, HubConfig};
use tower::ServiceExt;

/// (method, path) for every documented API route.
const API_ROUTES: &[(&str, &str)] = &[
    ("GET", "/api/v1/agents"),
    ("GET", "/api/v1/audit"),
    ("POST", "/api/v1/prompt"),
    ("POST", "/api/v1/handoff"),
    ("GET", "/api/v1/tasks/t1/owner"),
    ("GET", "/api/v1/tasks/t1/record"),
    ("GET", "/api/v1/tasks/t1/events"),
];

fn app() -> axum::Router {
    let hub = Hub::new(HubConfig::default());
    let token = ApiToken::from_raw("test-token-for-the-production-router").expect("token");
    production_router(hub, Some(token), String::new())
}

async fn response(method: &str, path: &str, auth: Option<&str>) -> (StatusCode, String) {
    let mut req = Request::builder().method(method).uri(path);
    if let Some(token) = auth {
        req = req.header("authorization", format!("Bearer {token}"));
    }
    if method == "POST" {
        req = req.header("content-type", "application/json");
    }
    let body = if method == "POST" { "{}" } else { "" };
    let resp = app()
        .oneshot(req.body(Body::from(body)).expect("request"))
        .await
        .expect("response");
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .expect("body");
    (status, String::from_utf8_lossy(&bytes).to_string())
}

async fn status(method: &str, path: &str, auth: Option<&str>) -> StatusCode {
    response(method, path, auth).await.0
}

/// Every documented route exists AND refuses an unauthenticated call.
///
/// A missing route answers 404; an unprotected route answers something other
/// than 401. Requiring exactly 401 catches both failure modes at once.
#[tokio::test]
async fn every_documented_route_exists_and_requires_auth() {
    for (method, path) in API_ROUTES {
        let unauthenticated = status(method, path, None).await;
        assert_eq!(
            unauthenticated,
            StatusCode::UNAUTHORIZED,
            "{method} {path}: expected 401 without a token (404 means the route \
             is missing from the production router; anything else means it is \
             not behind the auth layer)"
        );
        let wrong_token = status(method, path, Some("wrong-token")).await;
        assert_eq!(
            wrong_token,
            StatusCode::UNAUTHORIZED,
            "{method} {path}: a wrong token was not refused"
        );
    }
}

/// With the right token the routes are reachable: not 401, and a 404 must be
/// the HANDLER's own error body (unknown task), not the router's empty-body
/// route-miss. That distinction is what catches a route dropped from the
/// production router while the handler still exists elsewhere.
#[tokio::test]
async fn with_the_token_the_routes_are_reachable() {
    for (method, path) in API_ROUTES {
        let (s, body) = response(method, path, Some("test-token-for-the-production-router")).await;
        assert_ne!(
            s,
            StatusCode::UNAUTHORIZED,
            "{method} {path}: valid token refused"
        );
        if s == StatusCode::NOT_FOUND {
            assert!(
                body.contains("error"),
                "{method} {path}: 404 with no handler error body — the route is \
                 missing from the production router: {body:?}"
            );
        }
    }
}

/// /health stays open: it is the liveness probe, documented as unauthenticated.
#[tokio::test]
async fn health_is_open() {
    assert_eq!(status("GET", "/health", None).await, StatusCode::OK);
}
