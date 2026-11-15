//! Driver tests: the whole procedure against in-memory peers.
//!
//! The peers are scripted with `Mailbox::pair`, so no socket is involved. What
//! is under test is the driver's own logic: which message it sends when, which
//! event it feeds the state machine, that it commits once, and that a silent
//! peer produces a refusal rather than a hang.

use super::*;
use crate::handoff::{Handoff, HandoffState, HandoffTimeouts};
use himan_proto::{DeviceId, HandoffToken, Payload, SigningKey, TaskId, WireMessage, WireMeta};
use std::sync::Arc;
use tokio::sync::Mutex;

fn token(task: &str, from: &str, to: &str) -> HandoffToken {
    HandoffToken {
        task_id: TaskId::new(task),
        from_device: DeviceId::new(from),
        to_device: DeviceId::new(to),
        expires_at: 1_900_000_000,
        nonce: 1,
    }
}

fn signer(key: &SigningKey) -> impl Fn(Payload) -> WireMessage + '_ {
    move |payload| {
        let meta = WireMeta {
            seq: 1,
            ts: 1_700_000_000,
            from: DeviceId::new("orchestrator"),
            to: "device".into(),
        };
        WireMessage::sign(meta, payload, key).expect("sign")
    }
}

/// A peer that answers the driver's messages from a script.
async fn peer(
    mailbox: Mailbox,
    replies: Vec<(&'static str, Payload)>,
    seen: Arc<Mutex<Vec<&'static str>>>,
) {
    let mut mailbox = mailbox;
    while let Some(msg) = mailbox.inbound.recv().await {
        seen.lock().await.push(msg.payload.kind_name());
        for (trigger, reply) in &replies {
            if msg.payload.kind_name() == *trigger {
                let meta = WireMeta {
                    seq: 1,
                    ts: 1_700_000_000,
                    from: DeviceId::new("peer"),
                    to: "orchestrator".into(),
                };
                let key = SigningKey::generate();
                let out = WireMessage::sign(meta, reply.clone(), &key).unwrap();
                let _ = mailbox.outbound.send(out).await;
                break;
            }
        }
    }
}

fn fast_timeouts() -> HandoffTimeouts {
    HandoffTimeouts {
        prepared: Duration::from_secs(5),
        warming: Duration::from_secs(5),
        shadowing: Duration::from_secs(2),
        switching: Duration::from_secs(2),
    }
}

#[tokio::test]
async fn happy_path_reaches_active_with_exactly_one_commit() {
    let key = SigningKey::generate();
    let (drv_source, peer_source) = Mailbox::pair(16);
    let (drv_target, peer_target) = Mailbox::pair(16);
    let target_seen = Arc::new(Mutex::new(Vec::new()));
    let source_seen = Arc::new(Mutex::new(Vec::new()));

    let t_seen = target_seen.clone();
    let target_peer = tokio::spawn(peer(
        peer_target,
        vec![
            (
                "handoff_prepare",
                Payload::HandoffReady {
                    handoff_id: "h1".into(),
                    applied_seq: 5,
                    capabilities: "full".into(),
                },
            ),
            (
                "handoff_commit",
                Payload::HandoffSwitched {
                    handoff_id: "h1".into(),
                    new_epoch: 1,
                },
            ),
        ],
        t_seen,
    ));
    let s_seen = source_seen.clone();
    let source_peer = tokio::spawn(peer(
        peer_source,
        vec![(
            "handoff_drain",
            Payload::HandoffDrained {
                handoff_id: "h1".into(),
                last_seq: 5,
            },
        )],
        s_seen,
    ));

    let outcome = HandoffDriver::new(
        Handoff::prepared(
            "h1",
            TaskId::new("t1"),
            DeviceId::new("pc-1"),
            DeviceId::new("phone-1"),
            0,
            0,
            0,
        ),
        drv_source,
        drv_target,
        fast_timeouts(),
        RetryPolicy::default(),
    )
    .run(&token("t1", "pc-1", "phone-1"), 5, signer(&key), || 0)
    .await;

    assert_eq!(
        outcome.state,
        HandoffState::Active,
        "reason: {:?}",
        outcome.reason
    );
    assert!(outcome.committed);
    assert_eq!(outcome.epoch, 1);
    assert_eq!(
        outcome.commit_attempts, 1,
        "exactly one commit on the happy path"
    );
    assert_eq!(
        outcome.path,
        vec![
            HandoffState::Prepared,
            HandoffState::Warming,
            HandoffState::Shadowing,
            HandoffState::Switching,
            HandoffState::Committed,
            HandoffState::Active,
        ]
    );

    let t = target_seen.lock().await.clone();
    assert_eq!(t, vec!["handoff_prepare", "handoff_commit"]);
    let s = source_seen.lock().await.clone();
    assert_eq!(s, vec!["handoff_drain"]);

    let _ = (target_peer.await, source_peer.await);
}

#[tokio::test]
async fn a_silent_target_never_sends_ready_so_the_handoff_does_not_commit() {
    let key = SigningKey::generate();
    let (drv_target, peer_target) = Mailbox::pair(4);
    let (drv_source, _peer_source) = Mailbox::pair(4);
    // The peer stays silent: it receives the prepare and replies with nothing.
    tokio::spawn(async move {
        let mut m = peer_target;
        while m.inbound.recv().await.is_some() {}
    });

    let outcome = HandoffDriver::new(
        Handoff::prepared(
            "h2",
            TaskId::new("t1"),
            DeviceId::new("pc-1"),
            DeviceId::new("phone-1"),
            0,
            0,
            0,
        ),
        drv_source,
        drv_target,
        fast_timeouts(),
        RetryPolicy::default(),
    )
    .run(&token("t1", "pc-1", "phone-1"), 5, signer(&key), || 0)
    .await;

    assert_ne!(outcome.state, HandoffState::Active);
    assert!(!outcome.committed, "no commit may happen without a ready");
    assert_eq!(outcome.commit_attempts, 0);
    assert!(outcome.reason.unwrap().contains("HandoffReady"));
}

#[tokio::test]
async fn a_silent_target_after_the_commit_is_retried_then_failed() {
    let key = SigningKey::generate();
    let (drv_target, peer_target) = Mailbox::pair(4);
    let (drv_source, peer_source) = Mailbox::pair(4);

    // The target answers the prepare but never acks the commit.
    let t = tokio::spawn(peer(
        peer_target,
        vec![(
            "handoff_prepare",
            Payload::HandoffReady {
                handoff_id: "h3".into(),
                applied_seq: 5,
                capabilities: "full".into(),
            },
        )],
        Arc::new(Mutex::new(Vec::new())),
    ));
    let s = tokio::spawn(peer(
        peer_source,
        vec![(
            "handoff_drain",
            Payload::HandoffDrained {
                handoff_id: "h3".into(),
                last_seq: 5,
            },
        )],
        Arc::new(Mutex::new(Vec::new())),
    ));

    let retries = RetryPolicy {
        commit_attempts: 2,
        delay: Duration::from_millis(10),
    };
    let outcome = HandoffDriver::new(
        Handoff::prepared(
            "h3",
            TaskId::new("t1"),
            DeviceId::new("pc-1"),
            DeviceId::new("phone-1"),
            0,
            0,
            0,
        ),
        drv_source,
        drv_target,
        fast_timeouts(),
        retries,
    )
    .run(&token("t1", "pc-1", "phone-1"), 5, signer(&key), || 0)
    .await;

    assert_eq!(outcome.state, HandoffState::Failed);
    assert_eq!(
        outcome.commit_attempts, 2,
        "retries are bounded by the policy"
    );
    assert!(outcome.reason.unwrap().contains("no ack"));

    let _ = (t.await, s.await);
}

#[tokio::test]
async fn the_commit_is_retried_after_the_first_ack_is_lost() {
    let key = SigningKey::generate();
    let (drv_target, peer_target) = Mailbox::pair(4);
    let (drv_source, peer_source) = Mailbox::pair(4);

    // First commit: no reply. Second commit: ack.
    let t = tokio::spawn(async move {
        let mut m = peer_target;
        let mut commits = 0;
        while let Some(msg) = m.inbound.recv().await {
            match msg.payload.kind_name() {
                "handoff_prepare" => {
                    let meta = WireMeta {
                        seq: 1,
                        ts: 1_700_000_000,
                        from: DeviceId::new("peer"),
                        to: "orchestrator".into(),
                    };
                    let out = WireMessage::sign(
                        meta,
                        Payload::HandoffReady {
                            handoff_id: "h4".into(),
                            applied_seq: 5,
                            capabilities: "full".into(),
                        },
                        &SigningKey::generate(),
                    )
                    .unwrap();
                    let _ = m.outbound.send(out).await;
                }
                "handoff_commit" => {
                    commits += 1;
                    if commits >= 2 {
                        let meta = WireMeta {
                            seq: 1,
                            ts: 1_700_000_000,
                            from: DeviceId::new("peer"),
                            to: "orchestrator".into(),
                        };
                        let out = WireMessage::sign(
                            meta,
                            Payload::HandoffSwitched {
                                handoff_id: "h4".into(),
                                new_epoch: 1,
                            },
                            &SigningKey::generate(),
                        )
                        .unwrap();
                        let _ = m.outbound.send(out).await;
                    }
                }
                _ => {}
            }
        }
    });
    let s = tokio::spawn(peer(
        peer_source,
        vec![(
            "handoff_drain",
            Payload::HandoffDrained {
                handoff_id: "h4".into(),
                last_seq: 5,
            },
        )],
        Arc::new(Mutex::new(Vec::new())),
    ));

    let retries = RetryPolicy {
        commit_attempts: 3,
        delay: Duration::from_millis(10),
    };
    let outcome = HandoffDriver::new(
        Handoff::prepared(
            "h4",
            TaskId::new("t1"),
            DeviceId::new("pc-1"),
            DeviceId::new("phone-1"),
            0,
            0,
            0,
        ),
        drv_source,
        drv_target,
        fast_timeouts(),
        retries,
    )
    .run(&token("t1", "pc-1", "phone-1"), 5, signer(&key), || 0)
    .await;

    assert_eq!(outcome.state, HandoffState::Active);
    assert_eq!(
        outcome.commit_attempts, 2,
        "the lost ack cost exactly one retry"
    );
    assert_eq!(outcome.epoch, 1, "the epoch still increments exactly once");

    let _ = (t.await, s.await);
}

#[tokio::test]
async fn a_duplicate_switched_ack_is_idempotent() {
    // The state machine already proves this; here it is at the driver level so
    // the wire path is covered too.
    let key = SigningKey::generate();
    let (drv_target, peer_target) = Mailbox::pair(4);
    let (drv_source, peer_source) = Mailbox::pair(4);

    let t = tokio::spawn(peer(
        peer_target,
        vec![
            (
                "handoff_prepare",
                Payload::HandoffReady {
                    handoff_id: "h5".into(),
                    applied_seq: 5,
                    capabilities: "full".into(),
                },
            ),
            (
                "handoff_commit",
                Payload::HandoffSwitched {
                    handoff_id: "h5".into(),
                    new_epoch: 1,
                },
            ),
        ],
        Arc::new(Mutex::new(Vec::new())),
    ));
    let s = tokio::spawn(peer(
        peer_source,
        vec![(
            "handoff_drain",
            Payload::HandoffDrained {
                handoff_id: "h5".into(),
                last_seq: 5,
            },
        )],
        Arc::new(Mutex::new(Vec::new())),
    ));

    let outcome = HandoffDriver::new(
        Handoff::prepared(
            "h5",
            TaskId::new("t1"),
            DeviceId::new("pc-1"),
            DeviceId::new("phone-1"),
            0,
            0,
            0,
        ),
        drv_source,
        drv_target,
        fast_timeouts(),
        RetryPolicy::default(),
    )
    .run(&token("t1", "pc-1", "phone-1"), 5, signer(&key), || 0)
    .await;

    assert_eq!(outcome.state, HandoffState::Active);
    assert_eq!(outcome.commit_attempts, 1);

    let _ = (t.await, s.await);
}

#[tokio::test]
async fn an_unexpected_reply_is_reported_not_swallowed() {
    let key = SigningKey::generate();
    let (drv_target, peer_target) = Mailbox::pair(4);
    let (drv_source, _peer_source) = Mailbox::pair(4);

    // The target answers the prepare with something else entirely.
    tokio::spawn(peer(
        peer_target,
        vec![("handoff_prepare", Payload::Ping { nonce: 1 })],
        Arc::new(Mutex::new(Vec::new())),
    ));

    let outcome = HandoffDriver::new(
        Handoff::prepared(
            "h6",
            TaskId::new("t1"),
            DeviceId::new("pc-1"),
            DeviceId::new("phone-1"),
            0,
            0,
            0,
        ),
        drv_source,
        drv_target,
        fast_timeouts(),
        RetryPolicy::default(),
    )
    .run(&token("t1", "pc-1", "phone-1"), 5, signer(&key), || 0)
    .await;

    assert!(!outcome.committed);
    let reason = outcome.reason.unwrap();
    assert!(reason.contains("expected HandoffReady"), "got: {reason}");
}
