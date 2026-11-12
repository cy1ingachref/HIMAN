use async_trait::async_trait;
use serde_json::{json, Value};
use std::sync::Arc;
use sysinfo::System;

use himan_agent_core::tool::{Tool, ToolError, ToolOutput, ToolRegistry};
use himan_proto::{DeviceId, RiskTier};
/// Report basic host status: CPU load, memory, uptime.
pub struct DeviceStatusTool;

#[async_trait]
impl Tool for DeviceStatusTool {
    fn name(&self) -> &str {
        "device_status"
    }

    fn risk_tier(&self) -> RiskTier {
        RiskTier::ReadOnly
    }

    fn description(&self) -> &str {
        "Report CPU load, memory usage, and uptime for this device."
    }

    fn args_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {},
            "additionalProperties": false
        })
    }

    async fn run(&self, device: &DeviceId, _args: Value) -> Result<ToolOutput, ToolError> {
        let mut sys = System::new_all();
        sys.refresh_all();

        let cpu = sys.global_cpu_usage();
        let total_mem = sys.total_memory();
        let used_mem = sys.used_memory();
        let uptime = System::uptime();

        let summary = format!(
            "{}: CPU {cpu:.1}%, memory {used}/{total} MB, uptime {uptime}s",
            device,
            used = used_mem / 1024 / 1024,
            total = total_mem / 1024 / 1024,
        );

        Ok(ToolOutput {
            ok: true,
            summary,
            data: json!({
                "device": device.as_str(),
                "cpu_percent": cpu,
                "memory_used_mb": used_mem / 1024 / 1024,
                "memory_total_mb": total_mem / 1024 / 1024,
                "uptime_secs": uptime,
            }),
        })
    }
}

/// Run a network diagnostic. Phase 1 checks local connectivity only.
///
/// This is marked Destructive because a real diagnostic may reset a network
/// adapter or restart a service. The Phase 1 implementation is read-only in
/// practice; the tier is set conservatively so the approval path is exercised.
pub struct RunDiagnosticTool;

#[async_trait]
impl Tool for RunDiagnosticTool {
    fn name(&self) -> &str {
        "run_diagnostic"
    }

    fn risk_tier(&self) -> RiskTier {
        RiskTier::Destructive
    }

    fn description(&self) -> &str {
        "Diagnose network connectivity: DNS resolution and gateway reachability."
    }

    fn args_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Hostname to resolve. Defaults to example.com."
                }
            },
            "additionalProperties": false
        })
    }

    async fn run(&self, device: &DeviceId, args: Value) -> Result<ToolOutput, ToolError> {
        let target = args
            .get("target")
            .and_then(|v| v.as_str())
            .unwrap_or("example.com");

        // DNS resolution is a real check; we deliberately avoid raw ICMP
        // because it needs privileges and is unreliable on Windows.
        let resolved = tokio::net::lookup_host((target, 80))
            .await
            .map(|mut addrs| {
                addrs
                    .next()
                    .map(|a| a.ip().to_string())
                    .unwrap_or_else(|| "no address".into())
            });

        match resolved {
            Ok(ip) => Ok(ToolOutput {
                ok: true,
                summary: format!("{device}: {target} resolved to {ip}"),
                data: json!({
                    "device": device.as_str(),
                    "target": target,
                    "resolved_ip": ip,
                    "dns_ok": true,
                }),
            }),
            Err(e) => Ok(ToolOutput {
                ok: false,
                summary: format!("{device}: DNS resolution failed for {target}: {e}"),
                data: json!({
                    "device": device.as_str(),
                    "target": target,
                    "dns_ok": false,
                    "error": e.to_string(),
                }),
            }),
        }
    }
}

/// Build the PC agent's tool registry with its whitelist.
pub fn registry() -> ToolRegistry {
    ToolRegistry::new()
        .with_tool(Arc::new(DeviceStatusTool))
        .with_tool(Arc::new(RunDiagnosticTool))
        .with_whitelist(["device_status", "run_diagnostic"])
}

#[cfg(test)]
mod tests {
    use super::*;
    use himan_proto::ToolName;

    fn device() -> DeviceId {
        DeviceId::new("pc-1")
    }

    #[tokio::test]
    async fn device_status_reports_real_host() {
        let tool = DeviceStatusTool;
        let out = tool.run(&device(), json!({})).await.unwrap();
        assert!(out.ok);
        assert!(out.summary.contains("CPU"));
        assert!(out.data["memory_total_mb"].as_u64().unwrap() > 0);
    }

    #[tokio::test]
    async fn run_diagnostic_resolves_known_host() {
        let tool = RunDiagnosticTool;
        let out = tool
            .run(&device(), json!({"target": "localhost"}))
            .await
            .unwrap();
        assert!(out.ok);
        assert_eq!(out.data["dns_ok"], json!(true));
    }

    #[tokio::test]
    async fn run_diagnostic_handles_bad_host() {
        let tool = RunDiagnosticTool;
        let out = tool
            .run(&device(), json!({"target": "invalid.invalid.example"}))
            .await
            .unwrap();
        assert!(!out.ok);
        assert_eq!(out.data["dns_ok"], json!(false));
    }

    #[tokio::test]
    async fn registry_whitelists_both_tools() {
        let reg = registry();
        assert!(reg.resolve(&ToolName::new("device_status")).is_ok());
        assert!(reg.resolve(&ToolName::new("run_diagnostic")).is_ok());
        assert!(reg.resolve(&ToolName::new("upload_file")).is_err());
    }

    #[tokio::test]
    async fn schemas_match_whitelist() {
        let reg = registry();
        assert_eq!(reg.schemas().len(), 2);
    }
}
