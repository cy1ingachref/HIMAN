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
    if args.len() >= 2 && args[1] == "keygen" {
        run_keygen(&args);
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

    let device = DeviceId::new("pc-1");
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

/// Exponential backoff with a cap, so a downed orchestrator is not hammered.
async fn backoff(attempt: u32) {
    let secs = 2u64.saturating_pow(attempt.min(5));
    tracing::info!(wait_secs = secs, "retrying after a delay");
    tokio::time::sleep(std::time::Duration::from_secs(secs)).await;
}
