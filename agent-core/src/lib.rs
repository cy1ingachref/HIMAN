//! Agent-side primitives shared by every device agent.
//!
//! Contains:
//! - [`tool`]: the `Tool` trait every device capability implements, plus the
//!   registry that enforces the per-device whitelist.
//! - [`llm`]: the `ChatBackend` trait and a deterministic scripted stub. No
//!   network, no API key, no Ollama. Swap in a real backend later.

pub mod llm;
pub mod tool;

pub use llm::{ChatBackend, ChatMessage, ChatRequest, ChatResponse, ScriptedBackend};
pub use tool::{Tool, ToolError, ToolRegistry};
