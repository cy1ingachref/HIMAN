//! RT-17: online brute force against the API token is throttled.
//!
//! The constant-time compare stops timing attacks, not online guessing.
//! These tests drive the production router with repeated wrong tokens and
//! require a lockout (429) per source IP and per presented token, with
//! bounded memory. Written FIRST: against the unthrottled router every
//! wrong attempt answers 401 forever and these tests fail.

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use himan_orchestrator::api_auth::ApiToken;
use himan_orchestrator::server::production_router;
use himan_orchestrator::{Hub, HubConfig};
use std::net::SocketAddr;
use tower::ServiceExt;

const TOKEN: &str = "the-real-token";

fn app() -> axum::Router {
    let hub = Hub::new(HubConfig::default());
    production_router(hub, ApiToken::from_raw(TOKEN))
}

fn ip(last: u8) -> SocketAddr {
    format!("10.0.0.{last}:40000").parse().expect("addr")
}

async fn attempt(router: &axum::Router, from: SocketAddr, token: &str) -> StatusCode {
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/agents")
        .header("authorization", format!("Bearer {token}"))
        .extension(ConnectInfo(from))
        .body(Body::empty())
        .expect("request");
    router
        .clone()
        .oneshot(req)
        .await
        .expect("response")
        .status()
}

/// Repeated wrong tokens from one IP are locked out with 429, and the
/// lockout holds even for a request that would otherwise be refused 401.
#[tokio::test]
async fn rt17_wrong_tokens_from_one_ip_are_locked_out() {
    let router = app();
    let attacker = ip(1);
    let mut saw_429 = false;
    for i in 0..40 {
        let s = attempt(&router, attacker, &format!("guess-{i}")).await;
        if s == StatusCode::TOO_MANY_REQUESTS {
            saw_429 = true;
            break;
        }
        assert_eq!(s, StatusCode::UNAUTHORIZED, "attempt {i}: unexpected {s}");
    }
    assert!(
        saw_429,
        "40 wrong tokens from one IP never triggered a lockout — online brute force is unthrottled"
    );
    // Once locked out, even the CORRECT token from that IP is refused for
    // the lockout window: the lockout is on the source, not the guess.
    let s = attempt(&router, attacker, TOKEN).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "lockout did not hold");
}

/// A different IP is not affected by another source's lockout.
#[tokio::test]
async fn rt17_lockout_is_per_source() {
    let router = app();
    let attacker = ip(2);
    for i in 0..40 {
        let _ = attempt(&router, attacker, &format!("guess-{i}")).await;
    }
    // The legitimate operator from another IP still gets in.
    let s = attempt(&router, ip(3), TOKEN).await;
    assert_ne!(
        s,
        StatusCode::TOO_MANY_REQUESTS,
        "an unrelated IP was locked out"
    );
    assert_ne!(s, StatusCode::UNAUTHORIZED, "the real token was refused");
}

/// The same wrong token from MANY IPs is also throttled: a distributed
/// guess against one token must not bypass the per-IP limit.
#[tokio::test]
async fn rt17_one_token_from_many_ips_is_throttled() {
    let router = app();
    let mut saw_429 = false;
    for i in 0..200u16 {
        let from: SocketAddr = format!("10.1.{}.{}:40000", i / 250, i % 250)
            .parse()
            .expect("addr");
        let s = attempt(&router, from, "the-same-wrong-guess").await;
        if s == StatusCode::TOO_MANY_REQUESTS {
            saw_429 = true;
            break;
        }
    }
    assert!(
        saw_429,
        "one wrong token tried from 200 IPs was never throttled — the per-token limit is missing"
    );
}

/// Bounded memory: hammering distinct IPs must not grow the tracker
/// without bound. The limiter exposes its entry count for this assertion.
#[tokio::test]
async fn rt17_tracker_memory_is_bounded() {
    let limiter = himan_orchestrator::api_auth::RateLimiter::new();
    for i in 0..5000u32 {
        let from: SocketAddr = format!("10.9.{}.{}:40000", i / 250, i % 250)
            .parse()
            .expect("addr");
        limiter.record_failure(from.ip(), "some-guess");
    }
    // Each of the two maps (IP, token) is individually capped; the
    // combined count is therefore at most 2 * MAX_TRACKED.
    assert!(
        limiter.entries() <= 2 * himan_orchestrator::api_auth::MAX_TRACKED,
        "tracker grew past its bound: {} entries (cap {})",
        limiter.entries(),
        2 * himan_orchestrator::api_auth::MAX_TRACKED
    );
}
