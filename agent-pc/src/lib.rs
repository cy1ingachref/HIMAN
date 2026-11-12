//! Windows PC agent.
//!
//! Phase 1: connects (conceptually — the WebSocket hub lands next), registers
//! itself, and exposes two tools: `device_status` and `run_diagnostic`.
//! Both are real implementations against the host, not stubs, so the Phase 1
//! exit check can prove an end-to-end tool call actually did something.

pub mod agent_loop;
pub mod tools;

pub use agent_loop::{AgentLoop, LoopOutcome};
pub use tools::{DeviceStatusTool, RunDiagnosticTool};
