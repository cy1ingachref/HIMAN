use std::sync::Arc;

use himan_agent_core::llm::ScriptedBackend;
use himan_agent_pc::agent_loop::AgentLoop;
use himan_proto::TaskId;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let device = himan_proto::DeviceId::new("pc-1");
    let llm: Arc<dyn himan_agent_core::llm::ChatBackend> = Arc::new(ScriptedBackend::demo());
    let agent = AgentLoop::new(device.clone(), llm, himan_agent_pc::tools::registry());

    println!("HIMAN PC agent ({}), Phase 1 demo loop", device);
    println!("tools: {:?}", agent_registry_names());
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

fn agent_registry_names() -> Vec<&'static str> {
    vec!["device_status", "run_diagnostic"]
}
