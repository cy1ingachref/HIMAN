use std::sync::Arc;

use himan_agent_core::llm::{ChatBackend, ChatMessage, ChatRequest, ChatResponse, Role};
use himan_agent_core::tool::{ToolError, ToolOutput, ToolRegistry};
use himan_proto::{DeviceId, RiskTier, TaskId, ToolCall, ToolName};
use serde_json::json;

/// A single exchange: a text prompt becomes a tool call and a result.
///
/// Phase 1 loop. It is intentionally naive — no retry, no multi-step planning,
/// no tool-result feedback into the model. That is Phase 2 work. What matters
/// here is that the shape is right and testable.
pub struct AgentLoop {
    device: DeviceId,
    llm: Arc<dyn ChatBackend>,
    registry: ToolRegistry,
}

/// Outcome of one loop iteration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoopOutcome {
    pub task_id: TaskId,
    pub tool_called: Option<ToolName>,
    pub output: Option<ToolOutput>,
    pub planner_reply: String,
}

impl AgentLoop {
    pub fn new(device: DeviceId, llm: Arc<dyn ChatBackend>, registry: ToolRegistry) -> Self {
        Self {
            device,
            llm,
            registry,
        }
    }

    /// Run one iteration: prompt -> tool call -> result.
    pub async fn step(&self, task_id: TaskId, prompt: &str) -> Result<LoopOutcome, ToolError> {
        let schemas = self.registry.schemas();
        let request = ChatRequest {
            messages: vec![
                ChatMessage {
                    role: Role::System,
                    content: "You are the HIMAN device agent. Use tools when asked.".into(),
                },
                ChatMessage {
                    role: Role::User,
                    content: prompt.to_owned(),
                },
            ],
            tools: schemas,
            temperature: 0.0,
        };

        let ChatResponse {
            content,
            tool_calls,
        } = self.llm.chat(request).await?;

        if tool_calls.is_empty() {
            return Ok(LoopOutcome {
                task_id,
                tool_called: None,
                output: None,
                planner_reply: content,
            });
        }

        // Phase 1: act on the first tool the model asked for.
        let tool_name = ToolName::new(tool_calls[0].clone());
        let tool = self.registry.resolve(&tool_name)?;
        let call = ToolCall {
            task_id: task_id.clone(),
            tool: tool_name.clone(),
            args: json!({}),
            risk_tier: tool.risk_tier(),
            target_device: self.device.clone(),
            nonce: 1,
        };

        let output = tool.run(&self.device, call.args).await?;

        Ok(LoopOutcome {
            task_id,
            tool_called: Some(tool_name),
            output: Some(output),
            planner_reply: content,
        })
    }

    /// Convenience: does this tool call need a human approval?
    pub fn needs_approval(&self, tool: &ToolName) -> bool {
        self.registry
            .resolve(tool)
            .map(|t| t.risk_tier() == RiskTier::Destructive)
            .unwrap_or(true)
    }

    pub fn device(&self) -> &DeviceId {
        &self.device
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use himan_agent_core::llm::ScriptedBackend;

    fn loop_with(rules: ScriptedBackend) -> AgentLoop {
        AgentLoop::new(
            DeviceId::new("pc-1"),
            Arc::new(rules),
            crate::tools::registry(),
        )
    }

    #[tokio::test]
    async fn prompt_becomes_tool_call_and_result() {
        let agent = loop_with(ScriptedBackend::demo());
        let outcome = agent
            .step(TaskId::new("t1"), "please diagnose the network")
            .await
            .unwrap();

        assert_eq!(
            outcome.tool_called.map(|t| t.as_str().to_string()),
            Some("run_diagnostic".to_string())
        );
        let output = outcome.output.expect("tool should have run");
        assert!(output.ok);
        assert_eq!(output.data["dns_ok"], json!(true));
    }

    #[tokio::test]
    async fn no_tool_call_when_no_rule_matches() {
        let agent = loop_with(ScriptedBackend::demo());
        let outcome = agent
            .step(TaskId::new("t2"), "tell me a joke")
            .await
            .unwrap();

        assert!(outcome.tool_called.is_none());
        assert!(outcome.output.is_none());
        assert!(!outcome.planner_reply.is_empty());
    }

    #[tokio::test]
    async fn destructive_tool_is_flagged_for_approval() {
        let agent = loop_with(ScriptedBackend::demo());
        assert!(agent.needs_approval(&ToolName::new("run_diagnostic")));
        assert!(!agent.needs_approval(&ToolName::new("device_status")));
    }

    #[tokio::test]
    async fn unknown_tool_is_flagged_for_approval() {
        let agent = loop_with(ScriptedBackend::demo());
        assert!(agent.needs_approval(&ToolName::new("rm_rf")));
    }
}
