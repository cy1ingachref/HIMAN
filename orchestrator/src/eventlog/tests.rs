use super::*;
use himan_proto::{DeviceId, Idempotency};
use serde_json::json;

fn issued(call_id: &str, idem: Idempotency) -> EventPayload {
    EventPayload::ToolCallIssued {
        call_id: call_id.to_owned(),
        tool: "device_status".into(),
        args: json!({}),
        idempotency: idem,
    }
}

fn result(call_id: &str) -> EventPayload {
    EventPayload::ToolResultRecorded {
        call_id: call_id.to_owned(),
        result: "ok".into(),
        ok: true,
    }
}

fn log_with(task: &str) -> EventLog {
    let mut log = EventLog::new();
    log.append(TaskEvent {
        task_id: task.to_owned(),
        seq: 1,
        epoch: 0,
        device: DeviceId::new("pc-1"),
        payload: EventPayload::TaskCreated {
            goal: "demo".into(),
        },
    });
    log
}

#[test]
fn seq_starts_at_one_and_is_contiguous() {
    let log = log_with("t1");
    assert_eq!(log.head(), 1);
    assert!(log.is_contiguous());
}

#[test]
fn next_event_assigns_the_following_seq() {
    let log = log_with("t1");
    let event = log.next_event(
        "t1".into(),
        0,
        DeviceId::new("pc-1"),
        EventPayload::StepStarted { step: 1 },
    );
    assert_eq!(event.seq, 2);
}

#[test]
fn since_returns_only_events_after_the_checkpoint() {
    let mut log = log_with("t1");
    for step in 1..=3 {
        let event = log.next_event(
            "t1".into(),
            0,
            DeviceId::new("pc-1"),
            EventPayload::StepStarted { step },
        );
        log.append(event);
    }
    assert_eq!(log.since(0).len(), 4);
    assert_eq!(log.since(2).len(), 2);
    assert!(log.since(4).is_empty());
}

#[test]
fn apply_stream_appends_in_order() {
    let mut log = log_with("t1");
    let incoming: Vec<TaskEvent> = (2..=4)
        .map(|seq| TaskEvent {
            task_id: "t1".into(),
            seq,
            epoch: 0,
            device: DeviceId::new("pc-1"),
            payload: EventPayload::StepStarted { step: seq },
        })
        .collect();
    log.apply_stream(&incoming).unwrap();
    assert_eq!(log.head(), 4);
    assert!(log.is_contiguous());
}

#[test]
fn apply_stream_rejects_a_gap() {
    let mut log = log_with("t1");
    let gap = vec![TaskEvent {
        task_id: "t1".into(),
        seq: 3, // head is 1, so 2 is missing
        epoch: 0,
        device: DeviceId::new("pc-1"),
        payload: EventPayload::StepStarted { step: 3 },
    }];
    let err = log.apply_stream(&gap).unwrap_err();
    assert!(err.contains("does not follow head"), "got: {err}");
    // The rejected batch must not be partially applied.
    assert_eq!(log.head(), 1);
}

#[test]
fn apply_stream_rejects_another_tasks_event() {
    let mut log = log_with("t1");
    let wrong = vec![TaskEvent {
        task_id: "t2".into(),
        seq: 2,
        epoch: 0,
        device: DeviceId::new("pc-1"),
        payload: EventPayload::StepStarted { step: 2 },
    }];
    let err = log.apply_stream(&wrong).unwrap_err();
    assert!(err.contains("expected t1"), "got: {err}");
}

#[test]
fn non_idempotent_calls_block_the_switch_until_resolved() {
    let mut log = log_with("t1");
    log.append(log.next_event(
        "t1".into(),
        0,
        DeviceId::new("pc-1"),
        issued("call-1", Idempotency::NonIdempotent),
    ));
    assert_eq!(log.unresolved_non_idempotent(), &["call-1".to_owned()]);

    // An idempotent call in flight does not block.
    log.append(log.next_event(
        "t1".into(),
        0,
        DeviceId::new("pc-1"),
        issued("call-2", Idempotency::Idempotent),
    ));
    assert_eq!(log.unresolved_non_idempotent().len(), 1);
    assert_eq!(log.unresolved_idempotent(), vec!["call-2".to_owned()]);

    // Resolving the non-idempotent call clears the block.
    log.append(log.next_event("t1".into(), 0, DeviceId::new("pc-1"), result("call-1")));
    assert!(log.unresolved_non_idempotent().is_empty());
}

#[test]
fn a_result_for_an_idempotent_call_stops_it_being_reissued() {
    let mut log = log_with("t1");
    log.append(log.next_event(
        "t1".into(),
        0,
        DeviceId::new("pc-1"),
        issued("call-2", Idempotency::Idempotent),
    ));
    assert_eq!(log.unresolved_idempotent().len(), 1);
    log.append(log.next_event("t1".into(), 0, DeviceId::new("pc-1"), result("call-2")));
    assert!(log.unresolved_idempotent().is_empty());
}

#[test]
fn call_ids_lists_every_issued_call() {
    let mut log = log_with("t1");
    log.append(log.next_event(
        "t1".into(),
        0,
        DeviceId::new("pc-1"),
        issued("call-1", Idempotency::NonIdempotent),
    ));
    log.append(log.next_event("t1".into(), 0, DeviceId::new("pc-1"), result("call-1")));
    assert_eq!(log.call_ids(), vec!["call-1".to_owned()]);
}

#[test]
fn owner_changed_is_recorded_as_an_event() {
    let mut log = log_with("t1");
    let event = log.next_event(
        "t1".into(),
        1,
        DeviceId::new("phone-1"),
        EventPayload::OwnerChanged {
            from: "pc-1".into(),
            to: "phone-1".into(),
            epoch: 1,
        },
    );
    log.append(event);
    assert_eq!(log.head(), 2);
    assert!(log.events()[1].payload.kind_name() == "owner_changed");
}

#[test]
fn events_round_trip_through_json() {
    let log = log_with("t1");
    let event = log.next_event(
        "t1".into(),
        0,
        DeviceId::new("pc-1"),
        EventPayload::ToolCallIssued {
            call_id: "call-1".into(),
            tool: "device_status".into(),
            args: json!({"deep": true}),
            idempotency: Idempotency::Idempotent,
        },
    );
    let json = serde_json::to_string(&event).unwrap();
    let back: TaskEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back, event);
    assert_eq!(back.payload.kind_name(), "tool_call_issued");
}
