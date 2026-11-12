//! Policy engine: risk tiers, permission checks, approval requirements.
//!
//! The engine is deliberately small in Phase 1. It answers one question:
//! "may this tool call run on this device, and if so does it need a human
//! approval first?" Everything else (per-user overrides, device trust levels,
//! time-of-day rules) is Phase 5 work.

use himan_proto::{DeviceId, DeviceInfo, ToolCall};

/// Why a call is allowed or denied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    /// Allowed, but a human must approve before execution.
    RequireApproval,
    Deny(String),
}

/// Configuration for the policy engine.
#[derive(Debug, Clone, Default)]
pub struct PolicyConfig {
    /// Tools that always require approval, regardless of tier.
    pub always_approve: Vec<String>,
    /// Tools that are never allowed, regardless of tier.
    pub never_allow: Vec<String>,
    /// Devices allowed to run destructive tools at all.
    pub destructive_capable: Vec<String>,
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new(PolicyConfig::default())
    }
}

pub struct PolicyEngine {
    config: PolicyConfig,
}

impl PolicyEngine {
    pub fn new(config: PolicyConfig) -> Self {
        Self { config }
    }

    /// Evaluate a tool call against the policy.
    pub fn evaluate(&self, call: &ToolCall, device: &DeviceInfo) -> Decision {
        if self
            .config
            .never_allow
            .iter()
            .any(|t| t == call.tool.as_str())
        {
            return Decision::Deny(format!("tool {} is blacklisted", call.tool));
        }

        if call.risk_tier.requires_approval() {
            if !self
                .config
                .destructive_capable
                .iter()
                .any(|d| d == device.id.as_str())
            {
                return Decision::Deny(format!(
                    "device {} is not cleared for destructive tools",
                    device.id
                ));
            }
            return Decision::RequireApproval;
        }

        if self
            .config
            .always_approve
            .iter()
            .any(|t| t == call.tool.as_str())
        {
            return Decision::RequireApproval;
        }

        Decision::Allow
    }

    /// A handoff is allowed if the target device exists and the token is valid.
    /// Token signature verification is done by the caller; this checks policy.
    pub fn evaluate_handoff(
        &self,
        from: &DeviceId,
        to: &DeviceId,
        target: Option<&DeviceInfo>,
    ) -> Decision {
        if from == to {
            return Decision::Deny("handoff to the same device is a no-op".into());
        }
        match target {
            Some(info) => {
                // A device that is not the requested target cannot be handed to.
                if info.id != *to {
                    return Decision::Deny(format!(
                        "target mismatch: requested {}, got {}",
                        to, info.id
                    ));
                }
                Decision::Allow
            }
            None => Decision::Deny(format!("target device {} is not registered", to)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use himan_proto::{DeviceClass, RiskTier, TaskId, ToolName};
    use serde_json::json;

    fn device(id: &str, class: DeviceClass) -> DeviceInfo {
        DeviceInfo {
            id: DeviceId::new(id),
            class,
            label: id.to_owned(),
            verifying_key: "unused".into(),
        }
    }

    fn call(tool: &str, tier: RiskTier) -> ToolCall {
        ToolCall {
            task_id: TaskId::new("t1"),
            tool: ToolName::new(tool),
            args: json!({}),
            risk_tier: tier,
            target_device: DeviceId::new("pc-1"),
            nonce: 1,
        }
    }

    #[test]
    fn read_only_is_allowed() {
        let engine = PolicyEngine::default();
        let d = device("pc-1", DeviceClass::Pc);
        assert_eq!(
            engine.evaluate(&call("device_status", RiskTier::ReadOnly), &d),
            Decision::Allow
        );
    }

    #[test]
    fn destructive_requires_approval_when_cleared() {
        let config = PolicyConfig {
            destructive_capable: vec!["pc-1".into()],
            ..Default::default()
        };
        let engine = PolicyEngine::new(config);
        let d = device("pc-1", DeviceClass::Pc);
        assert_eq!(
            engine.evaluate(&call("run_diagnostic", RiskTier::Destructive), &d),
            Decision::RequireApproval
        );
    }

    #[test]
    fn destructive_is_denied_on_uncleared_device() {
        let engine = PolicyEngine::default();
        let d = device("phone-1", DeviceClass::Phone);
        let decision = engine.evaluate(&call("run_diagnostic", RiskTier::Destructive), &d);
        assert!(matches!(decision, Decision::Deny(_)));
    }

    #[test]
    fn blacklisted_tool_is_denied_even_if_read_only() {
        let config = PolicyConfig {
            never_allow: vec!["run_diagnostic".into()],
            ..Default::default()
        };
        let engine = PolicyEngine::new(config);
        let d = device("pc-1", DeviceClass::Pc);
        let decision = engine.evaluate(&call("run_diagnostic", RiskTier::ReadOnly), &d);
        assert!(matches!(decision, Decision::Deny(_)));
    }

    #[test]
    fn always_approve_overrides_tier() {
        let config = PolicyConfig {
            always_approve: vec!["show_notification".into()],
            ..Default::default()
        };
        let engine = PolicyEngine::new(config);
        let d = device("phone-1", DeviceClass::Phone);
        assert_eq!(
            engine.evaluate(&call("show_notification", RiskTier::Reversible), &d),
            Decision::RequireApproval
        );
    }

    #[test]
    fn handoff_to_unregistered_device_is_denied() {
        let engine = PolicyEngine::default();
        let from = DeviceId::new("pc-1");
        let to = DeviceId::new("phone-1");
        let decision = engine.evaluate_handoff(&from, &to, None);
        assert!(matches!(decision, Decision::Deny(_)));
    }

    #[test]
    fn handoff_to_same_device_is_denied() {
        let engine = PolicyEngine::default();
        let from = DeviceId::new("pc-1");
        let decision = engine.evaluate_handoff(&from, &from, None);
        assert!(matches!(decision, Decision::Deny(_)));
    }

    #[test]
    fn handoff_to_registered_device_is_allowed() {
        let engine = PolicyEngine::default();
        let from = DeviceId::new("pc-1");
        let to = DeviceId::new("phone-1");
        let target = device("phone-1", DeviceClass::Phone);
        assert_eq!(
            engine.evaluate_handoff(&from, &to, Some(&target)),
            Decision::Allow
        );
    }

    #[test]
    fn handoff_target_mismatch_is_denied() {
        let engine = PolicyEngine::default();
        let from = DeviceId::new("pc-1");
        let to = DeviceId::new("phone-1");
        let wrong = device("pc-2", DeviceClass::Pc);
        let decision = engine.evaluate_handoff(&from, &to, Some(&wrong));
        assert!(matches!(decision, Decision::Deny(_)));
    }
}
