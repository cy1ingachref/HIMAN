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
    //   himan-agent-pc keygen --out <file>  write a new key, print its public key
    if args.len() >= 2 && args[1] == "keygen" {
        run_keygen(&args);
        return;
    }
    if args.len() >= 3 && args[1] == "--ws" {
        run_ws(&args[2]).await;
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

async fn run_ws(url: &str) {
    let device = DeviceId::new("pc-1");
    let key = match himan_agent_pc::load_or_generate() {
        Ok(k) => k,
        Err(e) => {
            tracing::error!(error = %e, "failed to load the agent key");
            std::process::exit(1);
        }
    };

    tracing::info!(%device, url, "connecting to orchestrator");

    let client = match himan_agent_pc::client::connect_ws(device, key, url).await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "connection failed");
            std::process::exit(1);
        }
    };

    let mut client = client;
    match client.register().await {
        Ok(info) => tracing::info!(
            device = %info.id,
            class = info.class.as_str(),
            "agent registered with orchestrator"
        ),
        Err(e) => {
            tracing::error!(error = %e, "registration failed");
            std::process::exit(1);
        }
    }

    tracing::info!("agent running, waiting for tool calls");
    client.run().await;
    tracing::info!("agent stopped");
}
