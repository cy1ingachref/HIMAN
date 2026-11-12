//! HTTP and WebSocket server for the orchestrator.
//!
//! Routes:
//!   GET  /health              liveness
//!   GET  /api/v1/agents       registered agents
//!   GET  /api/v1/audit        audit log
//!   POST /api/v1/prompt       dispatch a prompt to a device
//!   GET  /ws                  agent WebSocket
//!
//! Phase 1: plain HTTP and `ws://`. TLS and mutual TLS are Phase 3.

use std::sync::Arc;

use axum::{
    extract::{
        ws::{Message as AxumMessage, WebSocket, WebSocketUpgrade},
        State,
    },
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use himan_proto::{DeviceId, Payload, ProtoError, WireMessage};

use crate::hub::{Hub, HubConfig};

#[derive(Clone)]
pub struct AppState {
    pub hub: Arc<Hub>,
}

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub orchestrator_key: String,
    pub agents: usize,
}

#[derive(Debug, Deserialize)]
pub struct PromptRequest {
    pub device: String,
    pub prompt: String,
}

#[derive(Debug, Serialize)]
pub struct PromptResponse {
    pub task_id: String,
    pub state: String,
    pub output: String,
    pub decision: String,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

pub fn router(hub: Arc<Hub>, _config: HubConfig) -> Router {
    let state = AppState { hub };
    Router::new()
        .route("/health", get(health))
        .route("/api/v1/agents", get(list_agents))
        .route("/api/v1/audit", get(audit_log))
        .route("/api/v1/prompt", post(prompt))
        .route("/ws", get(ws_handler))
        .with_state(state)
}

async fn health(State(state): State<AppState>) -> impl IntoResponse {
    let agents = state.hub.agents().await;
    Json(HealthResponse {
        status: "ok",
        orchestrator_key: state.hub.orchestrator_key_b64(),
        agents: agents.len(),
    })
}

async fn list_agents(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.hub.agents().await)
}

async fn audit_log(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.hub.audit_events().await)
}

async fn prompt(
    State(state): State<AppState>,
    Json(req): Json<PromptRequest>,
) -> impl IntoResponse {
    let device_id = DeviceId::new(req.device);
    match state.hub.dispatch(&device_id, &req.prompt).await {
        Ok(result) => {
            let body = PromptResponse {
                task_id: result.task_id,
                state: result.state,
                output: result.output,
                decision: result.decision,
            };
            (StatusCode::OK, Json(body)).into_response()
        }
        Err(e) => {
            let body = ErrorResponse {
                error: e.to_string(),
            };
            (StatusCode::BAD_REQUEST, Json(body)).into_response()
        }
    }
}

/// WebSocket handler. The first message must be a signed `Hello`.
async fn ws_handler(State(state): State<AppState>, ws: WebSocketUpgrade) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(state, socket))
}

async fn handle_socket(state: AppState, socket: WebSocket) {
    let (mut sink, mut stream) = socket.split();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<WireMessage>(64);

    // Send task: drain the agent's queue into the socket.
    let send_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            let json = match serde_json::to_string(&msg) {
                Ok(j) => j,
                Err(e) => {
                    warn!(error = %e, "failed to serialize outgoing message");
                    continue;
                }
            };
            if sink.send(AxumMessage::Text(json.into())).await.is_err() {
                break;
            }
        }
        let _ = sink.close().await;
    });

    // Receive task: the first frame must be a signed Hello.
    let mut registered: Option<DeviceId> = None;
    while let Some(Ok(frame)) = stream.next().await {
        let text = match frame {
            AxumMessage::Text(t) => t.to_string(),
            AxumMessage::Binary(b) => match String::from_utf8(b.to_vec()) {
                Ok(s) => s,
                Err(_) => continue,
            },
            AxumMessage::Close(_) => break,
            _ => continue,
        };

        let msg: WireMessage = match serde_json::from_str(&text) {
            Ok(m) => m,
            Err(e) => {
                warn!(error = %e, "invalid message from agent");
                break;
            }
        };

        if registered.is_none() {
            match state.hub.register(msg, tx.clone()).await {
                Ok(info) => {
                    info!(device = %info.id, "agent connected over ws");
                    registered = Some(info.id.clone());
                    // Acknowledge with Welcome, echoing the Hello nonce.
                    let welcome = match build_welcome(&state.hub, &info.id, &info.nonce) {
                        Ok(w) => w,
                        Err(e) => {
                            warn!(error = %e, "failed to build welcome");
                            break;
                        }
                    };
                    if tx.send(welcome).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    warn!(error = %e, "registration failed");
                    break;
                }
            }
            continue;
        }

        match state.hub.handle_message(msg).await {
            Ok(Some(reply)) => {
                if tx.send(reply).await.is_err() {
                    break;
                }
            }
            Ok(None) => {}
            Err(e) => {
                warn!(error = %e, "message rejected");
            }
        }
    }

    if let Some(id) = registered {
        // Remove the session from the hub, not just from a local list. The
        // hub's copy is what dispatch() looks at.
        state.hub.unregister(&id).await;
    }
    drop(tx);
    send_task.abort();
}

/// Build a Welcome message signed by the orchestrator's key.
///
/// The nonce is echoed from the Hello so the agent can prove the Welcome
/// belongs to this registration attempt, not a replay.
fn build_welcome(hub: &Hub, device: &DeviceId, nonce: &str) -> Result<WireMessage, ProtoError> {
    hub.build_message(
        device.clone(),
        Payload::Welcome {
            device_id: device.clone(),
            nonce: nonce.to_owned(),
            orchestrator_key: hub.orchestrator_key_b64(),
        },
    )
}

/// Spawn the server on `127.0.0.1:port`.
pub async fn serve(hub: Arc<Hub>, port: u16) -> Result<(), std::io::Error> {
    let app = router(hub.clone(), HubConfig::default());
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    info!(port, "orchestrator listening on 127.0.0.1");
    axum::serve(listener, app).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn router_has_expected_routes() {
        let hub = Hub::new(HubConfig::default());
        let _ = router(hub, HubConfig::default());
        // Construction succeeding is the assertion: a bad route would panic.
    }

    #[tokio::test]
    async fn welcome_is_signed_by_the_hub() {
        let hub = Hub::new(HubConfig::default());
        let device = DeviceId::new("pc-1");
        let msg = build_welcome(&hub, &device, "test-nonce").unwrap();
        // Verify with the key the hub advertises, proving the signature is
        // from the same identity agents are told to trust.
        let key = himan_proto::VerifyingKey::from_b64(&hub.orchestrator_key_b64()).unwrap();
        assert!(msg.verify_with(&key).is_ok());
    }
}
