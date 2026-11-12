//! Agent-side primitives shared by every device agent.
//!
//! Contains:
//! - [`tool`]: the `Tool` trait every device capability implements, plus the
//!   registry that enforces the per-device whitelist.
//! - [`llm`]: the `ChatBackend` trait and a deterministic scripted stub. No
//!   network, no API key, no Ollama. Swap in a real backend later.
//! - [`transport`]: the `Connection` abstraction plus an in-memory duplex for
//!   tests and a real WebSocket transport for production.
//! - [`logging`]: tracing setup shared by the binaries.

pub mod llm;
pub mod logging;
pub mod tool;
pub mod transport;

pub use llm::{ChatBackend, ChatMessage, ChatRequest, ChatResponse, ScriptedBackend};
pub use logging::init as init_logging;
pub use tool::{Tool, ToolError, ToolOutput, ToolRegistry};
pub use transport::{Connection, TransportError, WsTransport};
