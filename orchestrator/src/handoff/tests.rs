use super::*;
use himan_proto::DeviceId;

fn handoff() -> Handoff {
    Handoff::new(
        "h1",
        TaskId::new("t1"),
        DeviceId::new("pc-1"),
        DeviceId::new("phone-1"),
        7,
        0,
    )
}

/// Drive a handoff to Switching with the happy-path events.
fn to_switching(h: &mut Handoff) {
    h.apply(
        HandoffEvent::Approved {
            checkpoint_seq: 10,
            epoch: 7,
        },
        0,
        &HandoffTimeouts::default(),
    )
    .unwrap();
    h.apply(
        HandoffEvent::PrepareAccepted,
        1,
        &HandoffTimeouts::default(),
    )
    .unwrap();
    h.apply(
        HandoffEvent::TargetReady {
            applied_seq: 10,
            capabilities: "full".into(),
        },
        2,
        &HandoffTimeouts::default(),
    )
    .unwrap();
    // The source produced seq 11 and 12; the target applies them before the
    // source is allowed to drain, or the switch guard refuses.
    h.apply(
        HandoffEvent::ShadowProgress { applied_seq: 12 },
        3,
        &HandoffTimeouts::default(),
    )
    .unwrap();
    h.apply(
        HandoffEvent::SourceDrained { last_seq: 12 },
        4,
        &HandoffTimeouts::default(),
    )
    .unwrap();
}

#[test]
fn starts_requested_with_the_source_as_owner() {
    let h = handoff();
    assert_eq!(h.state, HandoffState::Requested);
    assert_eq!(h.owner().as_str(), "pc-1");
    assert_eq!(h.epoch, 7);
}

#[test]
fn happy_path_reaches_active() {
    let mut h = handoff();
    to_switching(&mut h);
    assert_eq!(h.state, HandoffState::Switching);
    assert_eq!(h.owner().as_str(), "pc-1");

    h.apply(
        HandoffEvent::Committed { epoch: 8 },
        5,
        &HandoffTimeouts::default(),
    )
    .unwrap();
    // The commit lands in Committed, not Active: the target must ack first.
    assert_eq!(h.state, HandoffState::Committed);
    assert!(h.committed);
    assert_eq!(h.owner().as_str(), "phone-1");

    h.apply(HandoffEvent::SwitchAcked, 6, &HandoffTimeouts::default())
        .unwrap();
    assert_eq!(h.state, HandoffState::Active);
}

#[test]
fn owner_flips_only_at_the_commit_point() {
    let mut h = handoff();
    let t = HandoffTimeouts::default();

    // Walk the happy path step by step, asserting the owner before each move.
    assert_eq!(h.state, HandoffState::Requested);
    assert_eq!(h.owner().as_str(), "pc-1");
    h.apply(
        HandoffEvent::Approved {
            checkpoint_seq: 10,
            epoch: 7,
        },
        0,
        &t,
    )
    .unwrap();

    assert_eq!(h.state, HandoffState::Prepared);
    assert_eq!(h.owner().as_str(), "pc-1");
    h.apply(HandoffEvent::PrepareAccepted, 1, &t).unwrap();

    assert_eq!(h.state, HandoffState::Warming);
    assert_eq!(h.owner().as_str(), "pc-1");
    h.apply(
        HandoffEvent::TargetReady {
            applied_seq: 10,
            capabilities: String::new(),
        },
        2,
        &t,
    )
    .unwrap();

    assert_eq!(h.state, HandoffState::Shadowing);
    assert_eq!(h.owner().as_str(), "pc-1");
    h.apply(HandoffEvent::ShadowProgress { applied_seq: 12 }, 3, &t)
        .unwrap();
    h.apply(HandoffEvent::SourceDrained { last_seq: 12 }, 4, &t)
        .unwrap();

    // Switching: the commit has not happened, so the source still owns.
    assert_eq!(h.state, HandoffState::Switching);
    assert_eq!(h.owner().as_str(), "pc-1");

    h.apply(HandoffEvent::Committed { epoch: 8 }, 5, &t)
        .unwrap();
    assert_eq!(h.owner().as_str(), "phone-1");
}

#[test]
fn every_illegal_transition_is_refused() {
    let mut h = handoff();
    // TargetReady in Requested is not a legal entry into the machine.
    let err = h
        .apply(
            HandoffEvent::TargetReady {
                applied_seq: 1,
                capabilities: String::new(),
            },
            0,
            &HandoffTimeouts::default(),
        )
        .unwrap_err();
    assert!(matches!(err, HandoffError::IllegalTransition { .. }));
    // The state is unchanged, so a later legal path still works.
    assert_eq!(h.state, HandoffState::Requested);
}

#[test]
fn committed_is_terminal_for_a_second_commit() {
    let mut h = handoff();
    to_switching(&mut h);
    h.apply(
        HandoffEvent::Committed { epoch: 8 },
        4,
        &HandoffTimeouts::default(),
    )
    .unwrap();
    let err = h
        .apply(
            HandoffEvent::Committed { epoch: 9 },
            5,
            &HandoffTimeouts::default(),
        )
        .unwrap_err();
    // A second commit is not a legal transition from Committed: the epoch was
    // already bumped by the first one.
    assert_eq!(
        err,
        HandoffError::IllegalTransition {
            from: "committed",
            event: "committed",
        }
    );
}

#[test]
fn rollback_before_commit_returns_ownership_to_the_source() {
    let mut h = handoff();
    to_switching(&mut h);
    let line = h
        .apply(
            HandoffEvent::Rollback {
                reason: "target went away".into(),
            },
            4,
            &HandoffTimeouts::default(),
        )
        .unwrap();
    assert_eq!(line.action, "handoff_rolled_back");
    assert_eq!(h.state, HandoffState::RolledBack);
    assert_eq!(h.owner().as_str(), "pc-1");
    assert_eq!(h.end_reason.as_deref(), Some("target went away"));
}

#[test]
fn rollback_after_commit_is_refused() {
    let mut h = handoff();
    to_switching(&mut h);
    h.apply(
        HandoffEvent::Committed { epoch: 8 },
        5,
        &HandoffTimeouts::default(),
    )
    .unwrap();
    let err = h
        .apply(
            HandoffEvent::Rollback {
                reason: "too late".into(),
            },
            6,
            &HandoffTimeouts::default(),
        )
        .unwrap_err();
    assert!(matches!(err, HandoffError::Guard(_)));
    // Ownership stays with the target; the commit is irreversible.
    assert_eq!(h.owner().as_str(), "phone-1");
}

#[test]
fn timeout_in_shadowing_rolls_back_and_refuses_the_late_event() {
    let mut h = handoff();
    h.apply(
        HandoffEvent::Approved {
            checkpoint_seq: 10,
            epoch: 7,
        },
        0,
        &HandoffTimeouts::default(),
    )
    .unwrap();
    h.apply(
        HandoffEvent::PrepareAccepted,
        1,
        &HandoffTimeouts::default(),
    )
    .unwrap();
    h.apply(
        HandoffEvent::TargetReady {
            applied_seq: 10,
            capabilities: String::new(),
        },
        2,
        &HandoffTimeouts::default(),
    )
    .unwrap();
    assert_eq!(h.state, HandoffState::Shadowing);

    // The shadowing deadline is 20s; 21s later the late SourceDrained must be
    // refused and the handoff rolled back.
    let err = h
        .apply(
            HandoffEvent::SourceDrained { last_seq: 12 },
            23,
            &HandoffTimeouts::default(),
        )
        .unwrap_err();
    assert_eq!(err, HandoffError::Timeout);
    assert_eq!(h.state, HandoffState::RolledBack);
    assert_eq!(h.owner().as_str(), "pc-1");
}

#[test]
fn timed_out_is_false_before_the_deadline() {
    let mut h = handoff();
    h.apply(
        HandoffEvent::Approved {
            checkpoint_seq: 10,
            epoch: 7,
        },
        0,
        &HandoffTimeouts::default(),
    )
    .unwrap();
    // Prepared deadline is 5s. At exactly 5s it has not exceeded the limit.
    assert!(!h.timed_out(5, &HandoffTimeouts::default()));
    assert!(h.timed_out(6, &HandoffTimeouts::default()));
}

#[test]
fn switch_guard_requires_the_target_to_have_applied_last_seq() {
    let mut h = handoff();
    h.apply(
        HandoffEvent::Approved {
            checkpoint_seq: 10,
            epoch: 7,
        },
        0,
        &HandoffTimeouts::default(),
    )
    .unwrap();
    h.apply(
        HandoffEvent::PrepareAccepted,
        1,
        &HandoffTimeouts::default(),
    )
    .unwrap();
    h.apply(
        HandoffEvent::TargetReady {
            applied_seq: 10,
            capabilities: String::new(),
        },
        2,
        &HandoffTimeouts::default(),
    )
    .unwrap();
    // Source produced seq 12 but the target only applied 10.
    let err = h
        .apply(
            HandoffEvent::SourceDrained { last_seq: 12 },
            3,
            &HandoffTimeouts::default(),
        )
        .unwrap_err();
    assert!(matches!(err, HandoffError::Guard(_)));
    assert_eq!(h.state, HandoffState::Shadowing);
}

#[test]
fn applied_seq_never_goes_backwards() {
    let mut h = handoff();
    h.apply(
        HandoffEvent::Approved {
            checkpoint_seq: 10,
            epoch: 7,
        },
        0,
        &HandoffTimeouts::default(),
    )
    .unwrap();
    h.apply(
        HandoffEvent::PrepareAccepted,
        1,
        &HandoffTimeouts::default(),
    )
    .unwrap();
    h.apply(
        HandoffEvent::TargetReady {
            applied_seq: 10,
            capabilities: String::new(),
        },
        2,
        &HandoffTimeouts::default(),
    )
    .unwrap();
    h.apply(
        HandoffEvent::ShadowProgress { applied_seq: 11 },
        3,
        &HandoffTimeouts::default(),
    )
    .unwrap();
    let err = h
        .apply(
            HandoffEvent::ShadowProgress { applied_seq: 9 },
            4,
            &HandoffTimeouts::default(),
        )
        .unwrap_err();
    assert!(matches!(err, HandoffError::Guard(_)));
    assert_eq!(h.applied_seq, 11);
}

#[test]
fn commit_must_increment_the_epoch_by_exactly_one() {
    let mut h = handoff();
    to_switching(&mut h);
    let err = h
        .apply(
            HandoffEvent::Committed { epoch: 9 },
            5,
            &HandoffTimeouts::default(),
        )
        .unwrap_err();
    assert!(matches!(err, HandoffError::Guard(_)));
    // A correct commit then succeeds, proving the refusal was the guard.
    h.apply(
        HandoffEvent::Committed { epoch: 8 },
        5,
        &HandoffTimeouts::default(),
    )
    .unwrap();
    assert_eq!(h.epoch, 8);
}

#[test]
fn failed_is_terminal_and_keeps_the_source_as_owner() {
    let mut h = handoff();
    let line = h
        .apply(
            HandoffEvent::Failed {
                reason: "log store unavailable".into(),
            },
            0,
            &HandoffTimeouts::default(),
        )
        .unwrap();
    assert_eq!(line.action, "handoff_failed");
    assert_eq!(h.state, HandoffState::Failed);
    assert_eq!(h.owner().as_str(), "pc-1");
    assert!(h.state.is_terminal());
}

#[test]
fn every_terminal_state_refuses_further_events() {
    let mut h = handoff();
    h.apply(
        HandoffEvent::Failed {
            reason: "boom".into(),
        },
        0,
        &HandoffTimeouts::default(),
    )
    .unwrap();
    for event in [
        HandoffEvent::PrepareAccepted,
        HandoffEvent::SwitchAcked,
        HandoffEvent::Rollback { reason: "x".into() },
    ] {
        let err = h.apply(event, 1, &HandoffTimeouts::default()).unwrap_err();
        assert_eq!(err, HandoffError::AlreadyTerminal("failed"));
    }
}

#[test]
fn a_duplicate_switch_ack_is_idempotent() {
    let mut h = handoff();
    to_switching(&mut h);
    h.apply(
        HandoffEvent::Committed { epoch: 8 },
        5,
        &HandoffTimeouts::default(),
    )
    .unwrap();
    h.apply(HandoffEvent::SwitchAcked, 6, &HandoffTimeouts::default())
        .unwrap();
    // A redelivered ack must not be an error: the commit already happened and
    // retrying the ack is the documented recovery path.
    let line = h
        .apply(HandoffEvent::SwitchAcked, 7, &HandoffTimeouts::default())
        .unwrap();
    assert_eq!(line.action, "handoff_active");
    assert_eq!(h.state, HandoffState::Active);
}

#[test]
fn audit_lines_name_the_handoff_and_the_epoch() {
    let mut h = handoff();
    let line = h
        .apply(
            HandoffEvent::Approved {
                checkpoint_seq: 10,
                epoch: 7,
            },
            0,
            &HandoffTimeouts::default(),
        )
        .unwrap();
    assert_eq!(line.action, "handoff_prepared");
    assert!(line.detail.contains("handoff=h1"));
    assert!(line.detail.contains("epoch=7"));
    assert!(line.detail.contains("checkpoint_seq=10"));
}

#[test]
fn timeout_defaults_match_the_spec_table() {
    let t = HandoffTimeouts::default();
    assert_eq!(t.prepared.as_secs(), 5);
    assert_eq!(t.warming.as_secs(), 5);
    assert_eq!(t.shadowing.as_secs(), 20);
    assert_eq!(t.switching.as_secs(), 10);
}

#[test]
fn short_timeouts_make_the_machine_testable() {
    let mut h = handoff();
    let fast = HandoffTimeouts {
        prepared: Duration::from_secs(1),
        warming: Duration::from_secs(1),
        shadowing: Duration::from_secs(1),
        switching: Duration::from_secs(1),
    };
    h.apply(
        HandoffEvent::Approved {
            checkpoint_seq: 1,
            epoch: 7,
        },
        0,
        &fast,
    )
    .unwrap();
    assert!(!h.timed_out(1, &fast));
    assert!(h.timed_out(2, &fast));
}
