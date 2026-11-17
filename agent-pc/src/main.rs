use std::sync::Arc;

use himan_agent_core::llm::ScriptedBackend;
use himan_agent_pc::agent_loop::AgentLoop;
use himan_proto::{DeviceId, TaskId};

#[tokio::main]
async fn main() {
    himan_agent_core::init_logging();

    let args: Vec<String> = std::env::args().collect();

    // Modes:
    //   himan-agent-pc                      local demo loop (no network)
    //   himan-agent-pc --ws <url>           connect to an orchestrator
    //   himan-agent-pc --ws <url> --orchestrator-key <b64>
    //   himan-agent-pc keygen --out <file>  write a new key, print its public key
    //   himan-agent-pc --scenario <steps> [--step-ms <n>]  run a scenario task
    if args.len() >= 2 && args[1] == "keygen" {
        run_keygen(&args);
        return;
    }
    if let Some(pos) = args.iter().position(|a| a == "--scenario") {
        run_scenario(&args, pos).await;
        return;
    }
    if args.len() >= 3 && args[1] == "--ws" {
        run_ws_with_reconnect(&args).await;
        return;
    }

    let device = DeviceId::new("pc-1");
    let llm: Arc<dyn himan_agent_core::llm::ChatBackend> = Arc::new(ScriptedBackend::demo());
    let agent = AgentLoop::new(device.clone(), llm, himan_agent_pc::tools::registry());

    println!("HIMAN PC agent ({}), Phase 1 demo loop", device);
    println!("tools: device_status, run_diagnostic");
    println!();

    for prompt in [
        "hello",
        "please diagnose my network",
        "what is my device status?",
    ] {
        println!("> {prompt}");
        match agent.step(TaskId::new(format!("t-{prompt}")), prompt).await {
            Ok(outcome) => {
                if let Some(tool) = &outcome.tool_called {
                    println!("  tool call: {tool}");
                }
                if let Some(out) = &outcome.output {
                    println!("  ok={} {}", out.ok, out.summary);
                    println!("  data: {}", out.data);
                } else {
                    println!("  reply: {}", outcome.planner_reply);
                }
            }
            Err(e) => println!("  error: {e}"),
        }
        println!();
    }
}

/// Write a new key file, printing only the derived public key.
fn run_keygen(args: &[String]) {
    let mut out = None;
    let mut i = 2;
    while i < args.len() {
        if args[i] == "--out" && i + 1 < args.len() {
            out = Some(args[i + 1].clone());
            i += 2;
        } else {
            eprintln!("usage: himan-agent-pc keygen --out <file>");
            std::process::exit(2);
        }
    }

    let path = match out {
        Some(p) => std::path::PathBuf::from(p),
        None => himan_agent_pc::key::default_path(),
    };

    if let Err(e) = himan_agent_pc::keygen(&path) {
        eprintln!("keygen failed: {e}");
        std::process::exit(1);
    }
}

/// Run the deterministic multi-step scenario task.
///
/// Each step is printed on its own line so the acceptance test can observe the
/// exact execution order and which device ran which step. The process exits
/// non-zero if it was stopped before completing all steps, so a test can tell a
/// clean finish from an interrupted one.
async fn run_scenario(args: &[String], pos: usize) {
    let total: u64 = args.get(pos + 1).and_then(|v| v.parse().ok()).unwrap_or(20);
    let step_ms: u64 = args
        .iter()
        .position(|a| a == "--step-ms")
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(100);
    let device = std::env::var("HIMAN_DEVICE_ID")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "pc-1".to_owned());

    tracing::info!(device = %device, total, step_ms, "scenario starting");

    let mut run = himan_agent_pc::scenario_run::ScenarioRun::spawn(
        device.clone(),
        total,
        std::time::Duration::from_millis(step_ms),
    );

    let mut done = 0u64;
    while let Some(report) = run.reports.recv().await {
        println!(
            "step {} call_id={} device={}",
            report.step, report.call_id, report.device
        );
        done = report.step;
    }

    let executed = himan_agent_pc::scenario_run::executions(&device);
    tracing::info!(device = %device, executed, total, "scenario finished");
    println!("executed={executed} total={total} device={device}");

    if executed < total {
        std::process::exit(1);
    }
    let _ = done;
}

/// Reconnect loop: re-register when the orchestrator drops the connection.
///
/// The keepalive turns a silent peer into a visible failure, so a dropped
/// connection should be retried rather than treated as a clean exit.
async fn run_ws_with_reconnect(args: &[String]) {
    let url = args[2].clone();

    // The orchestrator's public key, pinned out of band. A Welcome is accepted
    // only if it is signed by this key. Without pinning, any server can sign
    // its own Welcome and impersonate the orchestrator.
    let pinned = std::env::var("HIMAN_ORCH_KEY")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .or_else(|| {
            args.iter()
                .position(|a| a == "--orchestrator-key")
                .and_then(|i| args.get(i + 1).cloned())
        });

    // The device id this agent registers under. Two agents on one host need
    // distinct ids to stand in for PC and phone, so it is overridable; the
    // default keeps single-agent setups working unchanged.
    let device = std::env::var("HIMAN_DEVICE_ID")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .map(|v| DeviceId::new(v.trim()))
        .unwrap_or_else(|| DeviceId::new("pc-1"));

    let key = match himan_agent_pc::load_or_generate() {
        Ok(k) => k,
        Err(e) => {
            tracing::error!(error = %e, "failed to load the agent key");
            std::process::exit(1);
        }
    };

    if pinned.is_some() {
        tracing::info!("orchestrator key pinned");
    } else {
        tracing::warn!(
            "no orchestrator key pinned: HIMAN_ORCH_KEY or --orchestrator-key not set, \
             any server can impersonate the orchestrator"
        );
    }

    let mut attempt: u32 = 0;
    loop {
        attempt += 1;
        tracing::info!(url = %url, attempt, "connecting to orchestrator");

        let mut client = match himan_agent_pc::connect_ws(device.clone(), key.clone(), &url).await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error = %e, "connection failed");
                backoff(attempt).await;
                continue;
            }
        };

        if let Some(pinned_b64) = &pinned {
            client = match client.with_pinned_orchestrator_key(pinned_b64) {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!(error = %e, "invalid orchestrator key");
                    std::process::exit(1);
                }
            };
        }

        match client.register().await {
            Ok(info) => tracing::info!(
                device = %info.id,
                class = info.class.as_str(),
                "agent registered with orchestrator"
            ),
            Err(e) => {
                tracing::error!(error = %e, "registration failed");
                backoff(attempt).await;
                continue;
            }
        }

        tracing::info!("agent running, waiting for tool calls");
        client.run().await;
        tracing::warn!("connection lost; reconnecting");
        backoff(attempt).await;
    }
}

/// Compute the backoff delay for a reconnect attempt.
///
/// Exponential with the exponent capped at 5 (so a long outage does not grow
/// the wait without bound), plus +/-50% jitter so agents that lose their
/// connection together do not retry together. Never below 1s.
fn backoff_delay_secs(attempt: u32, jitter_percent: u64) -> u64 {
    let base_secs = 2u64.saturating_pow(attempt.min(5));
    // `jitter_percent` is expressed as a percentage of the base; the caller
    // passes a random value in 50..=150.
    let clamped = jitter_percent.clamp(1, 1000);
    ((base_secs as u128 * clamped as u128) / 100).max(1) as u64
}

async fn backoff(attempt: u32) {
    use rand::Rng;

    // Jitter up to +/-50% of the base.
    let jitter_percent = rand::thread_rng().gen_range(50..=150);
    let secs = backoff_delay_secs(attempt, jitter_percent);

    tracing::info!(wait_secs = secs, attempt, "retrying after a delay");
    tokio::time::sleep(std::time::Duration::from_secs(secs)).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_grows_with_the_attempt() {
        assert_eq!(backoff_delay_secs(1, 100), 2);
        assert_eq!(backoff_delay_secs(2, 100), 4);
        assert_eq!(backoff_delay_secs(3, 100), 8);
    }

    #[test]
    fn backoff_exponent_is_capped() {
        // attempt 5 -> 32s; attempt 10 must not exceed that.
        let capped = backoff_delay_secs(5, 100);
        assert_eq!(backoff_delay_secs(10, 100), capped);
        assert_eq!(backoff_delay_secs(999, 100), capped);
    }

    #[test]
    fn backoff_jitter_stays_within_half() {
        // At 50% the delay is half the base; at 150% it is one and a half.
        assert_eq!(backoff_delay_secs(3, 50), 4); // 8 * 0.5
        assert_eq!(backoff_delay_secs(3, 150), 12); // 8 * 1.5
    }

    #[test]
    fn backoff_never_drops_below_one_second() {
        // Even a degenerate jitter must not produce a zero-second spin.
        assert!(backoff_delay_secs(1, 1) >= 1);
    }
}
