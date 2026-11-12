use std::sync::Arc;

use himan_agent_core::llm::ScriptedBackend;
use himan_agent_pc::agent_loop::AgentLoop;
use himan_proto::{DeviceId, SigningKey, TaskId};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = std::env::args().collect();

    // Two modes:
    //   himan-agent-pc                local demo loop (no network)
    //   himan-agent-pc --ws <url>     connect to an orchestrator over WebSocket
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

async fn run_ws(url: &str) {
    let device = DeviceId::new("pc-1");
    // Phase 1: the agent generates a fresh key per run and registers it via
    // Hello. Phase 3 will restore the key from the Windows keystore/TPM.
    let key = SigningKey::generate();

    println!("connecting to {url} as {device}");
    let client = match himan_agent_pc::client::connect_ws(device, key, url).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("connection failed: {e}");
            std::process::exit(1);
        }
    };

    let mut client = client;
    match client.register().await {
        Ok(info) => println!("registered: {} ({})", info.id, info.class.as_str()),
        Err(e) => {
            eprintln!("registration failed: {e}");
            std::process::exit(1);
        }
    }

    println!("agent running, waiting for tool calls");
    client.run().await;
    println!("agent stopped");
}
