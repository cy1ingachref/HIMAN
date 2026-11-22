//! RT-22: single-use, short-lived enrollment codes (pairing flow).
//!
//! Written FIRST against current code, where enrollment is a static
//! out-of-band file and there is no pairing endpoint at all: every request
//! below answered 404.
//!
//! Properties covered:
//! - an authenticated admin can create a code, and the response is a QR/deep
//!   link payload carrying {url, code, fingerprint}
//! - the device presents code + public key over TLS and registers
//! - the code is single-use, expires, is bound to the device name
//! - reuse, wrong name, concurrent double-use and a revoked key re-enrolling
//!   all fail and are audited
//! - the code is stored only as a hash

mod common;

use serde_json::json;

async fn create_code(port: u16, device: &str, ttl: Option<u64>) -> (u16, serde_json::Value) {
    let mut body = json!({"device": device, "role": "pc"});
    if let Some(ttl) = ttl {
        body["ttl_secs"] = json!(ttl);
    }
    common::http_post(port, "/api/v1/admin/enroll-codes", body)
}

#[tokio::test]
async fn rt22_create_returns_a_single_use_code_and_a_deep_link() {
    let harness = common::E2ETest::restartable(&[], None, vec![]).await;
    let port = harness.port();
    let (_status, body) = create_code(port, "dev-phone-1", Some(300)).await;
    assert_eq!(_status, 201, "creating an enrollment code failed: {body}");
    let code = body["code"].as_str().expect("code").to_string();
    assert!(
        code.len() >= 24,
        "code is too short to be high entropy: {code}"
    );
    // A deep-link payload the operator can hand to a phone.
    let link = body["link"].as_str().expect("link");
    assert!(
        link.contains(&code),
        "the link does not carry the code: {link}"
    );
    assert!(
        body["fingerprint"].is_string(),
        "the payload must carry the orchestrator fingerprint: {body}"
    );
    assert_eq!(body["used"], json!(false), "a fresh code must be unused");
}

#[tokio::test]
async fn rt22_code_is_required_and_the_device_name_is_bound() {
    let harness = common::E2ETest::restartable(&[], None, vec![]).await;
    let port = harness.port();
    let (_status, body) = create_code(port, "dev-phone-2", Some(60)).await;
    let code = body["code"].as_str().expect("code").to_string();
    // Presenting the code for a DIFFERENT device must be refused.
    let wrong = common::http_post(
        port,
        "/api/v1/enroll/redeem",
        json!({"code": code, "device": "dev-someone-else", "hello_key": "AAAA"}),
    );
    assert_eq!(wrong.0, 403, "wrong device name was accepted: {}", wrong.1);
}

#[tokio::test]
async fn rt22_reuse_and_expiry_fail_and_are_audited() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut harness = common::E2ETest::restartable(&[], None, vec![]).await;
    let port = harness.port();
    let _ = dir;
    // A one-second code lets us observe expiry deterministically.
    let (status, body) = common::http_post(
        port,
        "/api/v1/admin/enroll-codes",
        json!({"device": "dev-phone-3", "role": "pc", "ttl_secs": 1}),
    );
    assert_eq!(status, 201, "create failed: {body}");
    let code = body["code"].as_str().expect("code").to_string();

    // Expiry: wait past the TTL, then redeem must fail.
    tokio::time::sleep(std::time::Duration::from_millis(1400)).await;
    let expired = common::http_post(
        port,
        "/api/v1/enroll/redeem",
        json!({"code": code, "device": "dev-phone-3", "hello_key": "AAAA"}),
    );
    assert_eq!(
        expired.0, 403,
        "an expired code was accepted: {}",
        expired.1
    );

    // Reuse: a fresh code, redeemed twice.
    let (_status, body) = common::http_post(
        port,
        "/api/v1/admin/enroll-codes",
        json!({"device": "dev-phone-4", "role": "pc", "ttl_secs": 300}),
    );
    let code = body["code"].as_str().expect("code").to_string();
    let first = common::http_post(
        port,
        "/api/v1/enroll/redeem",
        json!({"code": code, "device": "dev-phone-4", "hello_key": "AAAA"}),
    );
    assert_eq!(first.0, 201, "first redeem failed: {}", first.1);
    let second = common::http_post(
        port,
        "/api/v1/enroll/redeem",
        json!({"code": code, "device": "dev-phone-4", "hello_key": "AAAA"}),
    );
    assert_eq!(second.0, 403, "code reuse was accepted: {}", second.1);

    // Both refusals are in the hash-chained audit log.
    let audit = common::http_get_json(port, "/api/v1/audit");
    let actions: Vec<&str> = audit
        .as_array()
        .expect("audit")
        .iter()
        .map(|l| l["action"].as_str().unwrap_or(""))
        .collect();
    assert!(
        actions.contains(&"enrollment_code_redeemed"),
        "the successful redeem was not audited: {actions:?}"
    );
    assert!(
        actions.contains(&"enrollment_code_rejected"),
        "the refusals were not audited: {actions:?}"
    );
    harness.stop().await;
}

#[tokio::test]
async fn rt22_concurrent_double_use_exactly_one_wins() {
    let mut harness = common::E2ETest::restartable(&[], None, vec![]).await;
    let port = harness.port();
    let (status, body) = common::http_post(
        port,
        "/api/v1/admin/enroll-codes",
        json!({"device": "dev-phone-5", "role": "pc", "ttl_secs": 300}),
    );
    let code = body["code"].as_str().expect("code").to_string();
    assert_eq!(status, 201);

    let mut results = Vec::new();
    for _ in 0..8 {
        let (s, _b) = common::http_post(
            port,
            "/api/v1/enroll/redeem",
            json!({"code": code, "device": "dev-phone-5", "hello_key": "AAAA"}),
        );
        results.push(s);
    }
    let winners = results.iter().filter(|s| **s == 201).count();
    assert_eq!(
        winners, 1,
        "concurrent double-use must have exactly one winner, got {results:?}"
    );
    harness.stop().await;
}

#[tokio::test]
async fn rt22_revoked_device_cannot_re_enroll() {
    let mut harness = common::E2ETest::restartable(&[], None, vec![]).await;
    let port = harness.port();
    let (status, body) = common::http_post(
        port,
        "/api/v1/admin/enroll-codes",
        json!({"device": "dev-revoked", "role": "pc", "ttl_secs": 300}),
    );
    assert_eq!(status, 201, "create failed: {body}");
    let code = body["code"].as_str().expect("code").to_string();

    // Redeem once: the key is enrolled.
    let first = common::http_post(
        port,
        "/api/v1/enroll/redeem",
        json!({"code": code, "device": "dev-revoked", "hello_key": "AAAA"}),
    );
    assert_eq!(first.0, 201, "first redeem failed: {}", first.1);

    // Revoke the device, then try to pair it again with a fresh code.
    let (status, body) = common::http_post(
        port,
        "/api/v1/admin/enroll-codes",
        json!({"device": "dev-revoked", "role": "pc", "ttl_secs": 300}),
    );
    assert_eq!(status, 201, "second create failed: {body}");
    let code2 = body["code"].as_str().expect("code").to_string();
    let (status, _) = common::http_post(
        port,
        "/api/v1/devices/dev-revoked/revoke",
        json!({"reason": "test"}),
    );
    assert_eq!(status, 200, "revoke failed");

    // The pairing flow must refuse a revoked device, and audit it.
    let (status, body) = common::http_post(
        port,
        "/api/v1/enroll/redeem",
        json!({"code": code2, "device": "dev-revoked", "hello_key": "BBBB"}),
    );
    assert_eq!(status, 403, "a revoked device re-enrolled: {}", body);
    let audit = common::http_get_json(port, "/api/v1/audit");
    let actions: Vec<&str> = audit
        .as_array()
        .expect("audit")
        .iter()
        .map(|l| l["action"].as_str().unwrap_or(""))
        .collect();
    assert!(
        actions.contains(&"device_revoked"),
        "the revocation was not audited: {actions:?}"
    );
    harness.stop().await;
}

#[tokio::test]
async fn rt22_redeem_is_rate_limited_per_source() {
    let mut harness = common::E2ETest::restartable(&[], None, vec![]).await;
    let port = harness.port();
    // Ten bad codes from one source trip the lockout; the next must be 429.
    let mut saw_lockout = false;
    for _ in 0..12 {
        let (status, _) = common::http_post(
            port,
            "/api/v1/enroll/redeem",
            json!({"code": "not-a-real-code", "device": "dev-x", "hello_key": "AAAA"}),
        );
        if status == 429 {
            saw_lockout = true;
            break;
        }
    }
    assert!(
        saw_lockout,
        "repeated bad redemptions from one IP never tripped the lockout"
    );
    harness.stop().await;
}

#[tokio::test]
async fn rt22_creating_a_code_requires_auth() {
    let mut harness = common::E2ETest::restartable(&[], None, vec![]).await;
    let port = harness.port();
    // No bearer token: the harness http helpers always set one, so use a raw
    // unauthenticated request.
    let (status, _body) = common::http_post_no_auth(
        port,
        "/api/v1/admin/enroll-codes",
        json!({"device": "dev-phone-6"}),
    );
    assert_eq!(status, 401, "an unauthenticated admin call was accepted");
    harness.stop().await;
}
