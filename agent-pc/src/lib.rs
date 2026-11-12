//! Windows PC agent.
//!
//! - `tools`: real implementations of `device_status` and `run_diagnostic`
//! - `agent_loop`: a single prompt -> tool call -> result exchange
//! - `client`: connects to the orchestrator, registers, runs tools on demand

pub mod agent_loop;
pub mod client;
pub mod tools;

pub use agent_loop::{AgentLoop, LoopOutcome};
pub use client::{connect_ws, AgentClient};
pub use tools::{DeviceStatusTool, RunDiagnosticTool};
