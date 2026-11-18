//! The one-active-handoff guard's HTTP status.
//!
//! The guard itself (`Hub::request_handoff`) is unit-tested in `hub::tests`.
//! `POST /api/v1/handoff` drives the procedure to completion before it
//! responds, so two HTTP requests for one task never overlap and the route
//! cannot be made to return the guard's error on its own. The mapping is
//! therefore asserted against the route's own function, with the guard's
//! message and with unrelated messages, so a future change that maps every
//! policy error to 409 cannot pass.

use axum::http::StatusCode;
use himan_orchestrator::server::handoff_error_status;
use himan_proto::ProtoError;

#[test]
fn the_guard_message_maps_to_409() {
    let error = ProtoError::Policy("task t already has an active handoff h1".to_string());
    assert_eq!(handoff_error_status(&error), StatusCode::CONFLICT);
}

#[test]
fn unrelated_messages_stay_400() {
    for message in [
        "target device pc-2 is not connected",
        "device pc-1 is not the owner of task t",
        "target device pc-2 is not registered",
    ] {
        let error = ProtoError::Policy(message.to_string());
        assert_eq!(
            handoff_error_status(&error),
            StatusCode::BAD_REQUEST,
            "unexpected status for: {message}"
        );
    }
}
