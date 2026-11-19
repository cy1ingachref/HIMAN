//! Ollama backend for the `ChatBackend` trait.
//!
//! HTTP to a local Ollama (`POST /api/chat`, non-streaming). The model is
//! untrusted input: this module parses its answer into a proposed tool call
//! and nothing more. Validation against the whitelist and the tool schema,
//! and the allow/deny decision, happen in the orchestrator's policy path —
//! never here and never by the model.
//!
//! Bounds: a request timeout, a connect timeout, and a hard cap on the
//! response body. A slow or oversized answer is an error, not a hang or an
//! allocation.

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;

use crate::llm::{ChatBackend, ChatError, ChatRequest, ChatResponse};

/// Configuration for a local Ollama endpoint.
#[derive(Debug, Clone)]
pub struct OllamaConfig {
    /// Base URL, e.g. `http://127.0.0.1:11434`.
    pub base_url: String,
    /// Model tag, e.g. `qwen2.5:3b`.
    pub model: String,
    /// Whole-request timeout.
    pub timeout_ms: u64,
    /// Hard cap on the response body, in bytes.
    pub max_response_bytes: usize,
}

impl Default for OllamaConfig {
    fn default() -> Self {
        Self {
            base_url: "http://127.0.0.1:11434".into(),
            model: "qwen2.5:3b".into(),
            timeout_ms: 30_000,
            max_response_bytes: 1024 * 1024,
        }
    }
}

impl OllamaConfig {
    /// From the environment: `HIMAN_OLLAMA_URL`, `HIMAN_OLLAMA_MODEL`,
    /// `HIMAN_OLLAMA_TIMEOUT_MS`, `HIMAN_OLLAMA_MAX_BYTES`.
    pub fn from_env() -> Self {
        let mut cfg = Self::default();
        if let Ok(v) = std::env::var("HIMAN_OLLAMA_URL") {
            cfg.base_url = v;
        }
        if let Ok(v) = std::env::var("HIMAN_OLLAMA_MODEL") {
            cfg.model = v;
        }
        if let Ok(v) = std::env::var("HIMAN_OLLAMA_TIMEOUT_MS") {
            if let Ok(ms) = v.parse() {
                cfg.timeout_ms = ms;
            }
        }
        if let Ok(v) = std::env::var("HIMAN_OLLAMA_MAX_BYTES") {
            if let Ok(n) = v.parse() {
                cfg.max_response_bytes = n;
            }
        }
        cfg
    }
}

pub struct OllamaBackend {
    config: OllamaConfig,
    client: reqwest::Client,
}

/// The subset of Ollama's /api/chat response we accept.
#[derive(Debug, Deserialize)]
struct OllamaChatResponse {
    message: OllamaMessage,
}

#[derive(Debug, Deserialize)]
struct OllamaMessage {
    #[serde(default)]
    content: String,
    /// Ollama's native tool calls: function name + arguments object.
    #[serde(default)]
    tool_calls: Vec<OllamaToolCall>,
}

#[derive(Debug, Deserialize)]
struct OllamaToolCall {
    function: OllamaFunction,
}

#[derive(Debug, Deserialize)]
struct OllamaFunction {
    name: String,
    #[serde(default)]
    arguments: Value,
}

/// A tool call proposed by the model. UNTRUSTED: the name may not be
/// whitelisted and the arguments may violate the tool's schema. The caller
/// must validate both before anything executes.
#[derive(Debug, Clone, PartialEq)]
pub struct ProposedToolCall {
    pub name: String,
    pub args: Value,
}

impl OllamaBackend {
    pub fn new(config: OllamaConfig) -> Result<Self, ChatError> {
        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_millis(
                config.timeout_ms.min(5_000),
            ))
            .timeout(std::time::Duration::from_millis(config.timeout_ms))
            .build()
            .map_err(|e| ChatError::Unavailable(e.to_string()))?;
        Ok(Self { config, client })
    }

    pub fn config(&self) -> &OllamaConfig {
        &self.config
    }

    /// Ask the model and parse its answer into text plus proposed tool calls.
    ///
    /// The response body is read with a hard cap: a server that streams
    /// forever cannot exhaust memory. Malformed JSON is a `Rejected` error,
    /// never a panic and never a partial interpretation.
    pub async fn propose(
        &self,
        request: ChatRequest,
    ) -> Result<(String, Vec<ProposedToolCall>), ChatError> {
        let messages: Vec<Value> = request
            .messages
            .iter()
            .map(|m| serde_json::json!({"role": m.role.as_str(), "content": m.content}))
            .collect();
        let mut body = serde_json::json!({
            "model": self.config.model,
            "messages": messages,
            "stream": false,
            "options": {"temperature": request.temperature},
        });
        if !request.tools.is_empty() {
            // Ollama expects OpenAI-style function tools.
            let tools: Vec<Value> = request
                .tools
                .iter()
                .map(|t| {
                    serde_json::json!({
                        "type": "function",
                        "function": {
                            "name": t["name"],
                            "description": t["description"],
                            "parameters": t["args"],
                        }
                    })
                })
                .collect();
            body["tools"] = Value::Array(tools);
        }

        let url = format!("{}/api/chat", self.config.base_url.trim_end_matches('/'));
        let resp = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    ChatError::Timeout(self.config.timeout_ms)
                } else {
                    ChatError::Unavailable(e.to_string())
                }
            })?;
        if !resp.status().is_success() {
            return Err(ChatError::Rejected(format!(
                "ollama answered HTTP {}",
                resp.status()
            )));
        }

        // Bounded read: Content-Length is a claim, not a bound, so the cap is
        // enforced on the actual bytes too.
        if let Some(len) = resp.content_length() {
            if len as usize > self.config.max_response_bytes {
                return Err(ChatError::Rejected(format!(
                    "response too large: {len} bytes (cap {})",
                    self.config.max_response_bytes
                )));
            }
        }
        let mut buf: Vec<u8> = Vec::new();
        let mut resp = resp;
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|e| ChatError::Unavailable(e.to_string()))?
        {
            if buf.len() + chunk.len() > self.config.max_response_bytes {
                return Err(ChatError::Rejected(format!(
                    "response exceeded the {} byte cap",
                    self.config.max_response_bytes
                )));
            }
            buf.extend_from_slice(&chunk);
        }

        let parsed: OllamaChatResponse = serde_json::from_slice(&buf)
            .map_err(|e| ChatError::Rejected(format!("malformed model response: {e}")))?;
        let calls = parsed
            .message
            .tool_calls
            .into_iter()
            .map(|c| ProposedToolCall {
                name: c.function.name,
                args: c.function.arguments,
            })
            .collect();
        Ok((parsed.message.content, calls))
    }
}

#[async_trait]
impl ChatBackend for OllamaBackend {
    async fn chat(&self, request: ChatRequest) -> Result<ChatResponse, ChatError> {
        let (content, calls) = self.propose(request).await?;
        // The trait's tool_calls are names; the arguments travel separately
        // via `propose` for callers that validate them. A name-only view must
        // never be executed without the schema check.
        Ok(ChatResponse {
            content,
            tool_calls: calls.into_iter().map(|c| c.name).collect(),
        })
    }
}

/// Validate a proposed call against a tool schema (the registry's own
/// `args_schema` output). This is a deliberately small JSON-Schema subset:
/// `type: object`, `properties` with primitive types, `required`, and
/// `additionalProperties: false`. Anything the subset cannot express is
/// rejected rather than guessed.
pub fn validate_args(schema: &Value, args: &Value) -> Result<(), String> {
    if schema.get("type").and_then(Value::as_str) != Some("object") {
        return Err("schema is not an object schema".into());
    }
    let obj = args
        .as_object()
        .ok_or_else(|| "arguments are not a JSON object".to_string())?;
    let props = schema
        .get("properties")
        .and_then(Value::as_object)
        .ok_or_else(|| "schema has no properties".to_string())?;
    let additional = schema
        .get("additionalProperties")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    for (key, value) in obj {
        let Some(prop) = props.get(key) else {
            if !additional {
                return Err(format!("unknown argument {key:?}"));
            }
            continue;
        };
        if let Some(t) = prop.get("type").and_then(Value::as_str) {
            let ok = match t {
                "string" => value.is_string(),
                "integer" => value.as_i64().is_some(),
                "number" => value.is_number(),
                "boolean" => value.is_boolean(),
                "object" => value.is_object(),
                "array" => value.is_array(),
                other => return Err(format!("unsupported schema type {other:?}")),
            };
            if !ok {
                return Err(format!("argument {key:?} is not a {t}"));
            }
        }
    }
    if let Some(required) = schema.get("required").and_then(Value::as_array) {
        for r in required {
            if let Some(name) = r.as_str() {
                if !obj.contains_key(name) {
                    return Err(format!("missing required argument {name:?}"));
                }
            }
        }
    }
    Ok(())
}
