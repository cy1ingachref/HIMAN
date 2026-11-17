//! Deterministic multi-step scenario task (Phase 3, AC-3).
//!
//! A handoff has to happen *mid-run* to be meaningful, so the test task must be
//! long enough to interrupt but fully deterministic. This module builds that
//! task: N steps, each one a tool call through a [`ChatBackend`] stub, each
//! taking a bounded slice of wall-clock time.
//!
//! It is deliberately not an LLM. The stub returns the same tool call for a
//! given prompt every time, so a 20-step run produces exactly 20 recorded
//! steps and nothing else — which is what the acceptance tests assert on.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use himan_agent_core::llm::{ChatBackend, ChatError, ChatMessage, ChatRequest, ChatResponse, Role};
use himan_agent_core::tool::{Tool, ToolError, ToolOutput};
use himan_proto::{DeviceId, RiskTier};
use serde_json::Value;

/// A backend that always asks for `step_tool`.
///
/// The real backend would decide which tool to call from the model output; the
/// scenario only needs a stable, reproducible choice so the step count is
/// exact. `step_count` counts how many times it was asked, which lets a test
/// assert that no step was silently dropped or repeated.
#[derive(Default)]
pub struct ScenarioBackend {
    calls: AtomicU64,
}

impl ScenarioBackend {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl ChatBackend for ScenarioBackend {
    async fn chat(&self, _request: ChatRequest) -> Result<ChatResponse, ChatError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(ChatResponse {
            content: "next step".to_owned(),
            tool_calls: vec!["scenario_step".to_owned()],
        })
    }
}

/// The per-step tool. Each execution takes `step_delay` so a 20-step run lasts
/// long enough to interrupt, and records nothing itself — the *caller* appends
/// the log event, which keeps "what ran" and "what is recorded" separate.
pub struct ScenarioStepTool {
    delay: Duration,
    executions: AtomicU64,
}

impl ScenarioStepTool {
    pub fn new(delay: Duration) -> Self {
        Self {
            delay,
            executions: AtomicU64::new(0),
        }
    }

    pub fn executions(&self) -> u64 {
        self.executions.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl Tool for ScenarioStepTool {
    fn name(&self) -> &str {
        "scenario_step"
    }

    fn risk_tier(&self) -> RiskTier {
        RiskTier::ReadOnly
    }

    fn description(&self) -> &str {
        "Advance the deterministic scenario by one step."
    }

    fn args_schema(&self) -> Value {
        serde_json::json!({"type": "object", "properties": {"step": {"type": "integer"}}})
    }

    async fn run(&self, _device: &DeviceId, args: Value) -> Result<ToolOutput, ToolError> {
        let step = args.get("step").and_then(Value::as_u64).unwrap_or(0);
        if !self.delay.is_zero() {
            tokio::time::sleep(self.delay).await;
        }
        let n = self.executions.fetch_add(1, Ordering::SeqCst) + 1;
        Ok(ToolOutput {
            ok: true,
            summary: format!("step {step} done"),
            data: serde_json::json!({"step": step, "execution": n}),
        })
    }
}

/// Build the chat request the scenario loop sends for each step.
pub fn step_request(step: u64, total: u64) -> ChatRequest {
    ChatRequest {
        messages: vec![
            ChatMessage {
                role: Role::System,
                content: "You are running the deterministic HIMAN scenario.".into(),
            },
            ChatMessage {
                role: Role::User,
                content: format!("run scenario step {step} of {total}"),
            },
        ],
        tools: Vec::new(),
        temperature: 0.0,
    }
}

/// A step the scenario recorded, for assertions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedStep {
    pub step: u64,
    pub call_id: String,
}

#[cfg(test)]
mod tests;
