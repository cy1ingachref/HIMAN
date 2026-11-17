//! Windows PC agent.
//!
//! - `tools`: real implementations of `device_status` and `run_diagnostic`
//! - `agent_loop`: a single prompt -> tool call -> result exchange
//! - `client`: connects to the orchestrator, registers, runs tools on demand

pub mod agent_loop;
pub mod client;
pub mod keepalive;
pub mod key;
pub mod scenario;
pub mod scenario_run;
pub mod scenario_tool;
pub mod tools;

pub use agent_loop::{AgentLoop, LoopOutcome};
pub use client::{connect_ws, AgentClient};
pub use keepalive::{configured_interval, default_interval, parse_interval};
pub use key::{keygen, load_from_file, load_or_generate, save_to_file};
pub use scenario::{step_request, RecordedStep, ScenarioBackend, ScenarioStepTool};
pub use scenario_tool::{scenario_registry, scenario_registry_with_effect};
pub use tools::{DeviceStatusTool, RunDiagnosticTool};
