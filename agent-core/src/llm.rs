use async_trait::async_trait;
use serde_json::Value;

/// A single turn in a chat conversation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatMessage {
    pub role: Role,
    pub content: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    System,
    User,
    Assistant,
}

impl Role {
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::System => "system",
            Role::User => "user",
            Role::Assistant => "assistant",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ChatRequest {
    pub messages: Vec<ChatMessage>,
    /// Optional tool schemas the backend may expose. The stub ignores them.
    pub tools: Vec<Value>,
    /// 0.0 = deterministic, 1.0 = creative. The stub ignores it.
    pub temperature: f32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatResponse {
    /// Text content, also used as the scripted stub's output.
    pub content: String,
    /// Names of tools the backend wants called, if any.
    pub tool_calls: Vec<String>,
}

/// Pluggable LLM backend. Implement this to connect a real model (Ollama,
/// OpenAI-compatible endpoint, on-device GGUF) without changing callers.
#[async_trait]
pub trait ChatBackend: Send + Sync {
    async fn chat(&self, request: ChatRequest) -> Result<ChatResponse, ChatError>;
}

#[derive(Debug, thiserror::Error)]
pub enum ChatError {
    #[error("backend unavailable: {0}")]
    Unavailable(String),
    #[error("request rejected: {0}")]
    Rejected(String),
    #[error("timeout after {0}ms")]
    Timeout(u64),
}

/// Deterministic offline backend.
///
/// Matches on the last user message and returns a canned response. This keeps
/// the whole pipeline runnable without network access and makes tests
/// reproducible. It is intentionally not an LLM.
pub struct ScriptedBackend {
    /// (substring to match, response text, optional tool calls)
    rules: Vec<(String, String, Vec<String>)>,
}

impl Default for ScriptedBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl ScriptedBackend {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn with_rule(mut self, trigger: &str, reply: &str, tools: Vec<String>) -> Self {
        self.rules
            .push((trigger.to_lowercase(), reply.to_owned(), tools));
        self
    }

    /// The rules used by the Phase 1 demo: enough to show a text prompt
    /// becoming a tool call and a result, without any model.
    pub fn demo() -> Self {
        Self::new()
            .with_rule(
                "diagnose",
                "I will run the network diagnostic on this device.",
                vec!["run_diagnostic".into()],
            )
            .with_rule(
                "status",
                "Let me check the device status.",
                vec!["device_status".into()],
            )
            .with_rule("hello", "Hello. I am online and ready.", vec![])
    }
}

#[async_trait]
impl ChatBackend for ScriptedBackend {
    async fn chat(&self, request: ChatRequest) -> Result<ChatResponse, ChatError> {
        let last = request
            .messages
            .iter()
            .rev()
            .find(|m| m.role == Role::User)
            .map(|m| m.content.to_lowercase())
            .unwrap_or_default();

        for (trigger, reply, tools) in &self.rules {
            if last.contains(trigger.as_str()) {
                return Ok(ChatResponse {
                    content: reply.clone(),
                    tool_calls: tools.clone(),
                });
            }
        }

        Ok(ChatResponse {
            content: format!(
                "Acknowledged: {} characters received. No rule matched, so no tool call.",
                last.len()
            ),
            tool_calls: Vec::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(text: &str) -> ChatRequest {
        ChatRequest {
            messages: vec![ChatMessage {
                role: Role::User,
                content: text.to_owned(),
            }],
            tools: Vec::new(),
            temperature: 0.0,
        }
    }

    #[tokio::test]
    async fn matches_rule_case_insensitively() {
        let backend = ScriptedBackend::demo();
        let resp = backend
            .chat(request("Please DIAGNOSE my network"))
            .await
            .unwrap();
        assert_eq!(resp.tool_calls, vec!["run_diagnostic".to_string()]);
    }

    #[tokio::test]
    async fn no_rule_returns_no_tool_call() {
        let backend = ScriptedBackend::demo();
        let resp = backend.chat(request("what is the weather")).await.unwrap();
        assert!(resp.tool_calls.is_empty());
        assert!(resp.content.contains("Acknowledged"));
    }

    #[tokio::test]
    async fn matches_last_user_message() {
        let backend = ScriptedBackend::demo();
        let req = ChatRequest {
            messages: vec![
                ChatMessage {
                    role: Role::User,
                    content: "hello".into(),
                },
                ChatMessage {
                    role: Role::Assistant,
                    content: "hi there".into(),
                },
                ChatMessage {
                    role: Role::User,
                    content: "status please".into(),
                },
            ],
            tools: Vec::new(),
            temperature: 0.0,
        };
        let resp = backend.chat(req).await.unwrap();
        assert_eq!(resp.tool_calls, vec!["device_status".to_string()]);
    }
}
