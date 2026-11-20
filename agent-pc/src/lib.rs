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
pub use client::{connect_ws, token_matches, AgentClient};
pub use keepalive::{configured_interval, default_interval, parse_interval};
pub use key::{keygen, load_from_file, load_or_generate, save_to_file};
pub use scenario::{step_request, RecordedStep, ScenarioBackend, ScenarioStepTool};
pub use scenario_tool::{scenario_registry, scenario_registry_with_effect};
pub use tools::{DeviceStatusTool, RunDiagnosticTool};

/// Whether plain `ws://` is permitted.
///
/// False by default and ALWAYS false in a release build. Only a debug build
/// compiled with the optional `insecure-ws-dev` feature can turn it on, for
/// local development against a loopback orchestrator without a certificate.
/// The release CI job greps the release binary for this constant's marker so
/// a dev build cannot accidentally ship with the flag enabled.
pub const INSECURE_WS_ALLOWED: bool = cfg!(all(debug_assertions, feature = "insecure-ws-dev"));
