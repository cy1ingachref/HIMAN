use super::*;
use std::sync::Arc;

fn backend() -> Arc<ScenarioBackend> {
    Arc::new(ScenarioBackend::new())
}

#[tokio::test]
async fn the_backend_always_requests_the_step_tool() {
    let backend = backend();
    for step in 1..=20 {
        let resp = backend.chat(step_request(step, 20)).await.unwrap();
        assert_eq!(resp.tool_calls, vec!["scenario_step".to_owned()]);
    }
    assert_eq!(backend.calls(), 20);
}

#[tokio::test]
async fn each_step_executes_once_and_reports_its_number() {
    let tool = ScenarioStepTool::new(Duration::ZERO);
    let out = tool
        .run(&DeviceId::new("pc-1"), serde_json::json!({"step": 7}))
        .await
        .unwrap();
    assert!(out.ok);
    assert_eq!(out.data["step"], 7);
    assert_eq!(out.data["execution"], 1);
    assert_eq!(tool.executions(), 1);
}

#[tokio::test]
async fn step_delays_are_honoured() {
    let tool = ScenarioStepTool::new(Duration::from_millis(20));
    let start = std::time::Instant::now();
    tool.run(&DeviceId::new("pc-1"), serde_json::json!({"step": 1}))
        .await
        .unwrap();
    assert!(start.elapsed() >= Duration::from_millis(15));
}

#[tokio::test]
async fn the_tool_is_read_only_by_default() {
    // Read-only keeps the scenario out of the approval path, so a handoff is
    // the only thing that can interrupt a run.
    let tool = ScenarioStepTool::new(Duration::ZERO);
    assert_eq!(tool.risk_tier(), RiskTier::ReadOnly);
    assert_eq!(tool.name(), "scenario_step");
}

#[tokio::test]
async fn twenty_steps_run_in_order() {
    // The shape AC-1 depends on: 20 deterministic steps, each executed once.
    let backend = backend();
    let tool = ScenarioStepTool::new(Duration::ZERO);
    let mut recorded = Vec::new();
    for step in 1..=20u64 {
        let resp = backend.chat(step_request(step, 20)).await.unwrap();
        let name = himan_proto::ToolName::new(resp.tool_calls[0].clone());
        assert_eq!(name.as_str(), "scenario_step");
        let out = tool
            .run(&DeviceId::new("pc-1"), serde_json::json!({"step": step}))
            .await
            .unwrap();
        recorded.push(RecordedStep {
            step,
            call_id: out.data["execution"].to_string(),
        });
    }
    assert_eq!(recorded.len(), 20);
    assert_eq!(tool.executions(), 20);
    assert_eq!(backend.calls(), 20);
}
