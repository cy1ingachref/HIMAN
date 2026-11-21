//! RT-19: plain ws:// is refused unless an explicit dev flag is set, and
//! that dev flag is rejected in release builds.
//!
//! Written FIRST against current code: `connect_ws` accepts any ws:// URL
//! unconditionally and no release-build guard exists, so these tests fail.

use himan_agent_pc::client::connect_ws;
use std::sync::Arc;

/// Plain ws:// must be refused by the client unless
/// HIMAN_ALLOW_INSECURE_WS=1 is set. (The flag itself is rejected in release
/// builds by the compile-time guard tested below.)
#[tokio::test]
async fn rt19_plain_ws_is_refused_without_an_explicit_dev_flag() {
    std::env::remove_var("HIMAN_ALLOW_INSECURE_WS");
    let device = himan_proto::DeviceId::new("pc-1");
    let key = himan_proto::SigningKey::generate();
    let result = connect_ws(device, key, "ws://127.0.0.1:1/ws").await;
    assert!(
        result.is_err(),
        "a plain ws:// URL was accepted without the dev flag"
    );
    let err = format!("{:?}", result.err().expect("error"));
    assert!(
        err.contains("insecure") || err.contains("wss") || err.contains("TLS"),
        "the refusal does not explain that TLS is required: {err}"
    );
}

/// The dev flag must not even be accepted by a release build. This is a
/// compile-time (feature/cfg) guard: in release mode the constant is false,
/// so a release binary can never enable plain ws. The test reads the
/// exported constant rather than spawning a build (no ad-hoc scripts).
#[test]
fn rt19_release_build_rejects_the_insecure_dev_flag() {
    // himan_agent_pc::INSECURE_WS_ALLOWED is cfg-gated: true only in debug
    // builds AND when the `insecure-ws-dev` feature is explicitly enabled.
    // In a release build it must be false regardless of the feature.
    let allowed = himan_agent_pc::INSECURE_WS_ALLOWED;
    let debug_assertions = cfg!(debug_assertions);
    if !debug_assertions {
        assert!(
            !allowed,
            "a release build allowed plain ws:// via the dev flag"
        );
    }
    // The flag is never allowed by default, even in debug builds.
    assert!(
        !allowed,
        "plain ws:// is allowed by default (the dev feature must be opt-in)"
    );
    // Keep the import of Arc meaningful: the guard is about client setup.
    let _: Option<Arc<()>> = None;
}
