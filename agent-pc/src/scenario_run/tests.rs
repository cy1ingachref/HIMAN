use super::*;

#[tokio::test]
async fn a_run_reports_every_step_in_order() {
    let mut run = ScenarioRun::spawn("pc-1".into(), 5, Duration::ZERO);
    let mut steps = Vec::new();
    while let Some(report) = run.reports.recv().await {
        steps.push(report.step);
    }
    assert_eq!(steps, vec![1, 2, 3, 4, 5]);
    assert_eq!(executions("pc-1"), 5);
}

#[tokio::test]
async fn a_run_stops_early_when_asked() {
    // The source must stop starting new steps when a handoff drains it, so the
    // stop path is part of the contract, not an implementation detail.
    let mut run = ScenarioRun::spawn("pc-1".into(), 100, Duration::from_millis(20));
    tokio::time::sleep(Duration::from_millis(50)).await;
    let before = run.steps_started();
    assert!(before > 0, "the run should have started some steps");

    run.request_stop().await;
    while run.reports.recv().await.is_some() {}

    let after = run.steps_started();
    assert!(after >= before);
    assert!(
        after < 100,
        "the run must stop before completing all 100 steps"
    );
    assert_eq!(executions("pc-1"), after);
}

#[tokio::test]
async fn each_step_has_a_stable_unique_call_id() {
    // The acceptance test asserts exactly-once by call_id, so the id must be
    // deterministic per device and step rather than random.
    let mut run = ScenarioRun::spawn("pc-1".into(), 3, Duration::ZERO);
    let mut ids = Vec::new();
    while let Some(report) = run.reports.recv().await {
        ids.push(report.call_id);
    }
    assert_eq!(
        ids,
        vec![
            "pc-1-step-1".to_owned(),
            "pc-1-step-2".to_owned(),
            "pc-1-step-3".to_owned()
        ]
    );
}
