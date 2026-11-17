//! The scenario tool a device runs when the orchestrator dispatches a
//! `scenario_step` call to it.
//!
//! AC-1 needs a task that is long enough to interrupt mid-run, fully
//! deterministic, and *orchestrator-driven*: the orchestrator issues one call
//! per step, and this tool executes it. The orchestrator's own event log is the
//! arbiter of exactly-once; this tool's job is to make each execution visible
//! and to report which step it ran.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use himan_agent_core::tool::{Tool, ToolError, ToolOutput};
use himan_proto::{DeviceId, Idempotency, RiskTier, ToolName};
use serde_json::Value;

/// Advance the deterministic scenario by one step.
///
/// The step number comes from the call's arguments, which the orchestrator sets.
/// `execution` is this process's own count, reported back so a test can see
/// that the device ran the steps it was issued — not more, not fewer.
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

    /// How many steps this device has executed.
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

    /// Idempotent: the orchestrator re-issues a step with the same `call_id`
    /// only when it must, and the device's nonce cache refuses a duplicate.
    fn idempotency(&self) -> Idempotency {
        Idempotency::Idempotent
    }
    fn description(&self) -> &str {
        "Advance the deterministic scenario by one step."
    }

    fn args_schema(&self) -> Value {
        serde_json::json!({"type": "object", "properties": {
            "step": {"type": "integer"},
            "total": {"type": "integer"}
        }})
    }

    async fn run(&self, device: &DeviceId, args: Value) -> Result<ToolOutput, ToolError> {
        let step = args.get("step").and_then(Value::as_u64).unwrap_or(0);
        let total = args.get("total").and_then(Value::as_u64).unwrap_or(0);
        // Fault-injection only: hold the step so a handoff races an in-flight
        // non-idempotent call. A production device has no such switch.
        #[cfg(feature = "fault-injection")]
        if let Ok(ms) = std::env::var("HIMAN_TEST_SLOW_STEP_MS") {
            if let Ok(ms) = ms.parse::<u64>() {
                tokio::time::sleep(Duration::from_millis(ms)).await;
            }
        }
        if !self.delay.is_zero() {
            tokio::time::sleep(self.delay).await;
        }
        let n = self.executions.fetch_add(1, Ordering::SeqCst) + 1;
        // One line per step, on stdout, so the harness can observe exactly-once
        // execution on the real binary.
        println!(
            "step {step} total={total} execution={n} device={}",
            device.as_str()
        );
        Ok(ToolOutput {
            ok: true,
            summary: format!("step {step} done"),
            data: serde_json::json!({"step": step, "total": total, "execution": n,
                                      "device": device.as_str()}),
        })
    }
}

/// A step that is NOT idempotent.
///
/// The scenario driver marks a tool call `Idempotent` or `NonIdempotent` based
/// on the tool's declared `idempotency()`. A non-idempotent call in flight when
/// the handoff flips is the dangerous case: replaying it could apply an effect
/// twice, so the orchestrator must wait for it to finish rather than switch
/// underneath it.
pub struct NonIdempotentStepTool {
    executions: AtomicU64,
}

impl NonIdempotentStepTool {
    pub fn new() -> Self {
        Self {
            executions: AtomicU64::new(0),
        }
    }

    pub fn executions(&self) -> u64 {
        self.executions.load(Ordering::SeqCst)
    }
}

impl Default for NonIdempotentStepTool {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Tool for NonIdempotentStepTool {
    fn name(&self) -> &str {
        "scenario_effect"
    }

    fn risk_tier(&self) -> RiskTier {
        RiskTier::Destructive
    }

    /// Deliberately non-idempotent: the orchestrator must not replay it.
    fn idempotency(&self) -> Idempotency {
        Idempotency::NonIdempotent
    }

    fn description(&self) -> &str {
        "Apply one irreversible scenario effect."
    }

    fn args_schema(&self) -> Value {
        serde_json::json!({"type": "object", "properties": {
            "step": {"type": "integer"}
        }})
    }

    async fn run(&self, device: &DeviceId, args: Value) -> Result<ToolOutput, ToolError> {
        let step = args.get("step").and_then(Value::as_u64).unwrap_or(0);
        // Fault-injection only: hold the effect so a handoff races it.
        #[cfg(feature = "fault-injection")]
        if let Ok(ms) = std::env::var("HIMAN_TEST_SLOW_STEP_MS") {
            if let Ok(ms) = ms.parse::<u64>() {
                tokio::time::sleep(Duration::from_millis(ms)).await;
            }
        }
        let n = self.executions.fetch_add(1, Ordering::SeqCst) + 1;
        println!("effect {step} execution={n} device={}", device.as_str());
        Ok(ToolOutput {
            ok: true,
            summary: format!("effect {step} applied"),
            data: serde_json::json!({"step": step, "execution": n,
                                      "device": device.as_str()}),
        })
    }
}

/// The registry the agent's WS loop uses, including the scenario tool.
pub fn scenario_registry(delay: Duration) -> himan_agent_core::tool::ToolRegistry {
    himan_agent_core::tool::ToolRegistry::new()
        .with_tool(std::sync::Arc::new(crate::tools::DeviceStatusTool))
        .with_tool(std::sync::Arc::new(crate::tools::RunDiagnosticTool))
        .with_tool(std::sync::Arc::new(ScenarioStepTool::new(delay)))
        .with_whitelist(["device_status", "run_diagnostic", "scenario_step"])
}

/// The registry including the non-idempotent effect tool, for the tests that
/// exercise a non-idempotent call in flight at the switch.
pub fn scenario_registry_with_effect(delay: Duration) -> himan_agent_core::tool::ToolRegistry {
    scenario_registry(delay)
        .with_tool(std::sync::Arc::new(NonIdempotentStepTool::new()))
        .with_whitelist([
            "device_status",
            "run_diagnostic",
            "scenario_step",
            "scenario_effect",
        ])
}

/// Keep `ToolName` imported for callers that construct a name from a tool.
#[allow(dead_code)]
fn _tool_name(name: &str) -> ToolName {
    ToolName::new(name)
}
