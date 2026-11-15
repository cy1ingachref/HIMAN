use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;

use himan_proto::{DeviceId, Idempotency, RiskTier, ToolName};

use crate::llm::ChatError;

/// A capability a device exposes to the orchestrator.
#[async_trait]
pub trait Tool: Send + Sync {
    /// Tool name as it appears in `ToolCall`.
    fn name(&self) -> &str;

    /// Default risk tier. The policy engine may raise it, never lower it.
    fn risk_tier(&self) -> RiskTier;

    /// Whether a re-issued call with the same `call_id` may run twice.
    ///
    /// Used by the handoff switch to decide what must finish on the old owner
    /// before ownership moves. Defaults to `NonIdempotent` — the safe answer —
    /// so a tool that does not declare otherwise is never replayed.
    fn idempotency(&self) -> Idempotency {
        Idempotency::NonIdempotent
    }

    /// Human-readable description for the planner's tool schema.
    fn description(&self) -> &str;

    /// JSON schema for the arguments object.
    fn args_schema(&self) -> serde_json::Value;

    /// Execute the tool. `device` is the device the tool runs on.
    async fn run(
        &self,
        device: &DeviceId,
        args: serde_json::Value,
    ) -> Result<ToolOutput, ToolError>;
}

/// Result of a tool run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolOutput {
    /// Machine-readable outcome.
    pub ok: bool,
    /// Text suitable for the audit log and the UI.
    pub summary: String,
    /// Structured data, if any.
    pub data: serde_json::Value,
}

impl ToolOutput {
    pub fn ok(summary: impl Into<String>) -> Self {
        Self {
            ok: true,
            summary: summary.into(),
            data: serde_json::Value::Null,
        }
    }

    pub fn failed(summary: impl Into<String>) -> Self {
        Self {
            ok: false,
            summary: summary.into(),
            data: serde_json::Value::Null,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ToolError {
    #[error("tool not permitted on this device: {0}")]
    NotPermitted(String),
    #[error("invalid arguments: {0}")]
    BadArgs(String),
    #[error("execution failed: {0}")]
    Execution(String),
    #[error("backend error: {0}")]
    Backend(#[from] ChatError),
}

/// Registry of tools available on a device, with a whitelist.
///
/// The whitelist is the security boundary: even if the planner asks for a tool
/// that exists in the registry, a device not in the whitelist cannot run it.
pub struct ToolRegistry {
    tools: HashMap<String, Arc<dyn Tool>>,
    whitelist: Vec<String>,
}

impl ToolRegistry {
    pub fn new() -> Self {
        Self {
            tools: HashMap::new(),
            whitelist: Vec::new(),
        }
    }

    pub fn with_tool(mut self, tool: Arc<dyn Tool>) -> Self {
        self.tools.insert(tool.name().to_owned(), tool);
        self
    }

    pub fn with_whitelist<I, S>(mut self, allowed: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.whitelist = allowed.into_iter().map(Into::into).collect();
        self
    }

    /// Resolve a tool name against the whitelist.
    pub fn resolve(&self, name: &ToolName) -> Result<Arc<dyn Tool>, ToolError> {
        if !self.whitelist.iter().any(|w| w == name.as_str()) {
            return Err(ToolError::NotPermitted(name.to_string()));
        }
        self.tools
            .get(name.as_str())
            .cloned()
            .ok_or_else(|| ToolError::NotPermitted(format!("{name} not installed")))
    }

    pub fn whitelist(&self) -> &[String] {
        &self.whitelist
    }

    /// Build the JSON tool schema list sent to the LLM.
    pub fn schemas(&self) -> Vec<serde_json::Value> {
        self.tools
            .values()
            .filter(|t| self.whitelist.iter().any(|w| w == t.name()))
            .map(|t| {
                serde_json::json!({
                    "name": t.name(),
                    "description": t.description(),
                    "risk_tier": t.risk_tier().as_str(),
                    "idempotency": t.idempotency().as_str(),
                    "args": t.args_schema(),
                })
            })
            .collect()
    }
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use himan_proto::{RiskTier, ToolName};
    use serde_json::json;

    struct DummyTool {
        name: &'static str,
        tier: RiskTier,
    }

    #[async_trait]
    impl Tool for DummyTool {
        fn name(&self) -> &str {
            self.name
        }
        fn risk_tier(&self) -> RiskTier {
            self.tier
        }
        fn description(&self) -> &str {
            "dummy"
        }
        fn args_schema(&self) -> serde_json::Value {
            json!({"type": "object"})
        }
        async fn run(
            &self,
            _device: &DeviceId,
            _args: serde_json::Value,
        ) -> Result<ToolOutput, ToolError> {
            Ok(ToolOutput::ok("done"))
        }
    }

    fn registry() -> ToolRegistry {
        ToolRegistry::new()
            .with_tool(Arc::new(DummyTool {
                name: "device_status",
                tier: RiskTier::ReadOnly,
            }))
            .with_tool(Arc::new(DummyTool {
                name: "run_diagnostic",
                tier: RiskTier::Destructive,
            }))
            .with_whitelist(["device_status", "run_diagnostic"])
    }

    #[tokio::test]
    async fn whitelisted_tool_runs() {
        let reg = registry();
        let tool = reg.resolve(&ToolName::new("device_status")).unwrap();
        let out = tool.run(&DeviceId::new("pc-1"), json!({})).await.unwrap();
        assert!(out.ok);
    }

    #[tokio::test]
    async fn non_whitelisted_tool_is_rejected() {
        let reg = registry();
        assert!(reg.resolve(&ToolName::new("rm_rf")).is_err());
    }

    #[test]
    fn schemas_include_risk_tier() {
        let reg = registry();
        let schemas = reg.schemas();
        assert_eq!(schemas.len(), 2);
        assert!(schemas
            .iter()
            .any(|s| s["name"] == "device_status" && s["risk_tier"] == "read_only"));
    }

    #[test]
    fn schemas_expose_idempotency() {
        let reg = registry();
        let schemas = reg.schemas();
        // The dummy tool does not override `idempotency`, so it must fall back
        // to the safe default rather than claiming to be replayable.
        assert!(schemas.iter().all(|s| s["idempotency"] == "non_idempotent"));
    }

    struct IdempotentDummy {
        name: &'static str,
    }

    #[async_trait]
    impl Tool for IdempotentDummy {
        fn name(&self) -> &str {
            self.name
        }
        fn risk_tier(&self) -> RiskTier {
            RiskTier::ReadOnly
        }
        fn idempotency(&self) -> Idempotency {
            Idempotency::Idempotent
        }
        fn description(&self) -> &str {
            "safe to re-issue"
        }
        fn args_schema(&self) -> serde_json::Value {
            json!({"type": "object"})
        }
        async fn run(
            &self,
            _device: &DeviceId,
            _args: serde_json::Value,
        ) -> Result<ToolOutput, ToolError> {
            Ok(ToolOutput::ok("done"))
        }
    }

    #[test]
    fn a_tool_can_declare_itself_idempotent() {
        let reg = ToolRegistry::new()
            .with_tool(Arc::new(IdempotentDummy {
                name: "device_status",
            }))
            .with_whitelist(["device_status"]);
        let schema = &reg.schemas()[0];
        assert_eq!(schema["idempotency"], "idempotent");
    }

    #[tokio::test]
    async fn whitelist_can_exclude_registered_tool() {
        let reg = ToolRegistry::new()
            .with_tool(Arc::new(DummyTool {
                name: "run_diagnostic",
                tier: RiskTier::Destructive,
            }))
            .with_whitelist(["device_status"]);
        assert!(reg.resolve(&ToolName::new("run_diagnostic")).is_err());
    }
}
