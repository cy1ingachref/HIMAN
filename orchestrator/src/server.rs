//! HTTP and WebSocket server for the orchestrator.
//!
//! Routes:
//!   GET  /health                    liveness
//!   GET  /api/v1/agents             registered agents
//!   GET  /api/v1/audit              audit log
//!   POST /api/v1/prompt             dispatch a prompt to a device
//!   POST /api/v1/handoff            request a handoff of a task
//!   GET  /api/v1/tasks/{id}/owner   owner and epoch for a task
//!   GET  /ws                        agent WebSocket
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

use himan_proto::{DeviceId, HandoffToken, Payload, ProtoError, TaskId, WireMessage};

use crate::hub::{Hub, HubConfig};
/// Application state shared across routes.
#[derive(Clone)]
pub struct AppState {
    pub hub: Arc<Hub>,
    /// Limits applied to every WebSocket connection.
    pub ws_limits: WsLimits,
    /// Caps concurrent WebSocket connections.
    pub ws_semaphore: Arc<tokio::sync::Semaphore>,
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

#[derive(Debug, Deserialize)]
pub struct HandoffRequest {
    pub task_id: String,
    pub from: String,
    pub to: String,
    /// Deprecated and ignored: the checkpoint is the orchestrator's own log
    /// head, never a client-supplied position.
    ///
    /// A handoff is a request to move a task, not a request to pick which log
    /// prefix the target must apply. If the HTTP caller could set
    /// `applied_seq`, it could make the switch commit at a position that drops
    /// events (too low) or stall waiting for a position the source never
    /// reached (too high). The orchestrator therefore derives the checkpoint
    /// from its own append-only log and ignores anything the client sends.
    #[serde(default)]
    #[allow(dead_code)]
    pub applied_seq: u64,
}

/// What a handoff attempt produced, for the HTTP response.
#[derive(Debug, Serialize)]
pub struct HandoffResponse {
    pub handoff_id: String,
    pub state: String,
    pub token: HandoffToken,
    pub epoch: u64,
    pub commit_attempts: u32,
    pub reason: Option<String>,
}

pub fn router(hub: Arc<Hub>, _config: HubConfig) -> Router {
    let state = AppState {
        hub,
        ws_limits: WsLimits::default(),
        ws_semaphore: Arc::new(tokio::sync::Semaphore::new(
            WsLimits::default().max_connections,
        )),
    };
    Router::new()
        .route("/health", get(health))
        .route("/api/v1/agents", get(list_agents))
        .route("/api/v1/audit", get(audit_log))
        .route("/api/v1/prompt", post(prompt))
        .route("/api/v1/handoff", post(handoff))
        .route("/api/v1/tasks/{task_id}/owner", get(task_owner))
        .route("/api/v1/tasks/{task_id}/events", get(task_events))
        .route("/ws", get(ws_handler))
        .with_state(state)
}
/// Build the router with API authentication applied.
///
/// When `HIMAN_API_TOKEN` is set, every `/api/v1/*` route requires a bearer
/// token. `/health` stays open so a load balancer can probe without one, and
/// `/ws` is unaffected because agents authenticate by signature.
pub fn router_with_auth(
    hub: Arc<Hub>,
    _config: HubConfig,
    token: crate::api_auth::ApiToken,
) -> Router {
    // One state instance, cloned into both routers, so the semaphore is shared.
    let state = AppState {
        hub: hub.clone(),
        ws_limits: WsLimits::default(),
        ws_semaphore: Arc::new(tokio::sync::Semaphore::new(
            WsLimits::default().max_connections,
        )),
    };

    let api = Router::new()
        .route("/agents", get(list_agents))
        .route("/audit", get(audit_log))
        .route("/prompt", post(prompt))
        .route("/handoff", post(handoff))
        .route("/tasks/{task_id}/owner", get(task_owner))
        .route("/tasks/{task_id}/events", get(task_events))
        .route_layer(axum::middleware::from_fn_with_state(
            token,
            crate::api_auth::require_token,
        ))
        .with_state(state.clone());

    Router::new()
        .route("/health", get(health))
        .route("/ws", get(ws_handler))
        .nest("/api/v1", api)
        .with_state(state)
}

/// Build a router with custom WebSocket limits and no API token.
///
/// Used by tests to exercise the hardening limits (a short handshake timeout
/// keeps them fast).
pub fn router_with_limits(hub: Arc<Hub>, limits: WsLimits) -> Router {
    let state = AppState {
        hub,
        ws_limits: limits.clone(),
        ws_semaphore: Arc::new(tokio::sync::Semaphore::new(limits.max_connections)),
    };
    Router::new()
        .route("/health", get(health))
        .route("/api/v1/agents", get(list_agents))
        .route("/api/v1/audit", get(audit_log))
        .route("/api/v1/prompt", post(prompt))
        .route("/api/v1/handoff", post(handoff))
        .route("/api/v1/tasks/{task_id}/owner", get(task_owner))
        .route("/api/v1/tasks/{task_id}/events", get(task_events))
        .route("/ws", get(ws_handler))
        .with_state(state)
}

/// Load the enrollment file from `HIMAN_ENROLLED_FILE` and attach it.
///
/// Returns an error when the variable is set but the file cannot be read or
/// parsed: a broken enrollment file must not silently disable enrollment.
pub fn load_enrollment(hub: Arc<Hub>) -> Result<Arc<Hub>, crate::enrollment::EnrollmentError> {
    match crate::enrollment::load_from_env()? {
        Some(file) => Ok(hub.with_enrollment(file)),
        None => Ok(hub),
    }
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

/// Request a handoff of a task from one device to another.
///
/// This is the entry point the UI or planner uses. It does not move ownership
/// by itself; it records the attempt and returns the signed token that the
/// target must receive. The commit happens later, through `advance_handoff`.
async fn handoff(
    State(state): State<AppState>,
    Json(req): Json<HandoffRequest>,
) -> axum::response::Response {
    let task_id = TaskId::new(req.task_id);
    let from = DeviceId::new(req.from);
    let to = DeviceId::new(req.to);

    // Drive the real procedure over the live sockets. This is the path AC-1
    // exercises: the driver sends HandoffPrepare, waits for HandoffReady,
    // drains the source, commits, and acks.
    match state.hub.drive_handoff(&task_id, &from, &to).await {
        Ok(outcome) => {
            info!(
                "handoff driver finished: state={} epoch={} commits={} reason={:?}",
                outcome.state.as_str(),
                outcome.epoch,
                outcome.commit_attempts,
                outcome.reason
            );
            let body = HandoffResponse {
                handoff_id: outcome.handoff_id,
                state: outcome.state.as_str().to_string(),
                token: outcome.token,
                epoch: outcome.epoch,
                commit_attempts: outcome.commit_attempts,
                reason: outcome.reason,
            };
            (StatusCode::OK, Json(body)).into_response()
        }
        Err(e) => {
            warn!("handoff driver error: {e}");
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
                .into_response()
        }
    }
}

/// Report the orchestrator's own event log for a task, with its continuity.
async fn task_events(
    State(state): State<AppState>,
    axum::extract::Path(task_id): axum::extract::Path<String>,
) -> impl IntoResponse {
    let events: Vec<_> = state
        .hub
        .task_events()
        .await
        .into_iter()
        .filter(|e| e.task_id == task_id)
        .collect();
    let seqs: Vec<u64> = events.iter().map(|e| e.seq).collect();
    let contiguous = seqs.iter().enumerate().all(|(i, s)| *s == i as u64 + 1);
    let devices: Vec<String> = events
        .iter()
        .map(|e| e.device.as_str().to_string())
        .collect();
    Json(serde_json::json!({
        "task_id": task_id,
        "events": events.len(),
        "seqs": seqs,
        "contiguous": contiguous,
        "devices": devices,
    }))
    .into_response()
}

/// Report the owner and epoch recorded for a task (fencing state).
async fn task_owner(
    State(state): State<AppState>,
    axum::extract::Path(task_id): axum::extract::Path<String>,
) -> impl IntoResponse {
    match state.hub.owner(&task_id).await {
        Some(o) => Json(serde_json::json!({
            "task_id": task_id,
            "owner": o.owner.as_str(),
            "epoch": o.epoch,
        }))
        .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("task {task_id} has no recorded owner"),
            }),
        )
            .into_response(),
    }
}

/// Hardening limits for a WebSocket connection.
///
/// These are resource-exhaustion defenses, not confidentiality ones: a silent
/// or oversized connection consumes a task and a socket indefinitely.
#[derive(Debug, Clone)]
pub struct WsLimits {
    /// Seconds allowed for the first message (the Hello).
    pub handshake_timeout_secs: u64,
    /// Seconds a registered connection may stay silent before being closed.
    ///
    /// Must be much larger than the handshake timeout: a healthy agent only
    /// speaks when dispatched, so a short idle timeout would disconnect every
    /// working agent.
    pub idle_timeout_secs: u64,
    /// Maximum accepted text/binary frame size, in bytes.
    pub max_frame_bytes: usize,
    /// Maximum concurrent WebSocket connections.
    pub max_connections: usize,
    /// Invalid or unparseable messages tolerated before closing.
    pub max_invalid_messages: usize,
}

impl Default for WsLimits {
    fn default() -> Self {
        Self {
            handshake_timeout_secs: 10,
            idle_timeout_secs: 300,
            max_frame_bytes: 64 * 1024,
            max_connections: 256,
            max_invalid_messages: 8,
        }
    }
}

/// A connection permit, released when the socket closes.
pub struct ConnectionGuard(
    /// Held for the lifetime of the connection, then dropped to release the
    /// slot. The field is never read; its existence is the point.
    #[allow(dead_code)]
    tokio::sync::OwnedSemaphorePermit,
);

pub async fn acquire_connection(
    semaphore: &std::sync::Arc<tokio::sync::Semaphore>,
) -> Option<ConnectionGuard> {
    let permit = std::sync::Arc::clone(semaphore)
        .acquire_owned()
        .await
        .ok()?;
    Some(ConnectionGuard(permit))
}

/// WebSocket handler. The first message must be a signed `Hello`.
async fn ws_handler(State(state): State<AppState>, ws: WebSocketUpgrade) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(state, socket))
}

async fn handle_socket(state: AppState, socket: WebSocket) {
    // Refuse to start when the connection table is full.
    let _permit = match acquire_connection(&state.ws_semaphore).await {
        Some(p) => p,
        None => {
            tracing::warn!("WebSocket connection refused: too many open connections");
            return;
        }
    };

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
    let mut invalid_messages = 0usize;
    let limits = state.ws_limits.clone();

    loop {
        // Before registration the connection must speak quickly, otherwise it
        // is a silent scanner. After registration the agent only speaks when
        // dispatched, so the idle timeout is much longer.
        let timeout = if registered.is_some() {
            limits.idle_timeout_secs
        } else {
            limits.handshake_timeout_secs
        };
        let next =
            tokio::time::timeout(std::time::Duration::from_secs(timeout), stream.next()).await;

        let frame = match next {
            Err(_) => {
                tracing::warn!(
                    timeout_secs = timeout,
                    registered = registered.is_some(),
                    "WebSocket connection closed: no message within the timeout"
                );
                break;
            }
            Ok(Some(Ok(f))) => f,
            Ok(Some(Err(e))) => {
                tracing::warn!(error = %e, "WebSocket read error");
                break;
            }
            Ok(None) => break,
        };

        let text = match frame {
            AxumMessage::Text(t) => t.to_string(),
            AxumMessage::Binary(b) => {
                if b.len() > limits.max_frame_bytes {
                    tracing::warn!(len = b.len(), "oversized binary frame rejected");
                    break;
                }
                match String::from_utf8(b.to_vec()) {
                    Ok(s) => s,
                    Err(_) => continue,
                }
            }
            AxumMessage::Close(_) => break,
            _ => continue,
        };

        if text.len() > limits.max_frame_bytes {
            tracing::warn!(len = text.len(), "oversized text frame rejected");
            break;
        }

        let msg: WireMessage = match serde_json::from_str(&text) {
            Ok(m) => m,
            Err(e) => {
                warn!(error = %e, "invalid message from agent");
                invalid_messages += 1;
                if invalid_messages >= limits.max_invalid_messages {
                    warn!("too many invalid messages, closing connection");
                    break;
                }
                continue;
            }
        };

        if registered.is_none() {
            match state.hub.register(msg, tx.clone()).await {
                Ok(info) => {
                    info!(
                        device = %info.id,
                        class = info.class.as_str(),
                        nonce = %info.nonce,
                        "agent connected over ws"
                    );
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

        // Agent messages go to two consumers: the hub, which verifies and acts
        // on them, and the session's inbound channel, which the handoff driver
        // reads. A message is never copied; the hub sees the original and the
        // driver gets a clone, so neither blocks the other.
        if let Some(sender) = state.hub.inbound_sender(&msg.meta.from).await {
            let _ = sender.send(msg.clone());
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
/// Serve the orchestrator.
///
/// When `HIMAN_API_TOKEN` is set, the HTTP API requires a bearer token.
/// The token is never printed; only whether auth is enabled.
pub async fn serve(hub: Arc<Hub>, port: u16) -> Result<(), std::io::Error> {
    let token = crate::api_auth::ApiToken::from_env();
    let app = match token {
        Some(t) => {
            tracing::info!("API authentication enabled");
            router_with_auth(hub.clone(), HubConfig::default(), t)
        }
        None => {
            tracing::warn!(
                "HIMAN_API_TOKEN is not set: the HTTP API is open. \
                 Set it before exposing the port."
            );
            router(hub.clone(), HubConfig::default())
        }
    };
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    info!(port, "orchestrator listening on 127.0.0.1");
    axum::serve(listener, app).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;
    use tower::ServiceExt;

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

    /// Register a device directly so a test can focus on the HTTP routes.
    async fn hub_with_device(hub: &Arc<Hub>, id: &str) {
        let sk = himan_proto::SigningKey::generate();
        let dev = himan_proto::DeviceInfo::new(
            DeviceId::new(id),
            himan_proto::DeviceClass::Pc,
            id.to_owned(),
            sk.verifying_key().to_b64(),
        );
        let (tx, rx) = mpsc::channel(8);
        // Keep the receiver alive: dropping it makes sends fail.
        std::mem::forget(rx);
        hub.register_device(dev, tx).await;
    }

    #[tokio::test]
    async fn handoff_route_returns_a_token_and_records_the_attempt() {
        let hub = Hub::new(HubConfig::default());
        hub_with_device(&hub, "pc-1").await;
        hub_with_device(&hub, "phone-1").await;
        let app = router(hub.clone(), HubConfig::default());

        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/api/v1/handoff")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        r#"{"task_id":"t1","from":"pc-1","to":"phone-1"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["handoff_id"].as_str().unwrap().starts_with("handoff-"));
        assert_eq!(json["state"], "prepared");
        assert_eq!(json["token"]["from_device"], "pc-1");
        assert_eq!(json["token"]["to_device"], "phone-1");

        let attempts = hub.handoffs_snapshot().await;
        assert_eq!(attempts.len(), 1);
    }

    #[tokio::test]
    async fn handoff_route_ignores_a_client_supplied_applied_seq() {
        // A client-supplied checkpoint must not be able to move the switch
        // point. The orchestrator derives it from its own event log
        // (docs/DECISIONS.md), so a bogus value is ignored rather than trusted.
        let hub = Hub::new(HubConfig::default());
        hub_with_device(&hub, "pc-1").await;
        hub_with_device(&hub, "phone-1").await;
        let app = router(hub.clone(), HubConfig::default());

        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/api/v1/handoff")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        r#"{"task_id":"t1","from":"pc-1","to":"phone-1","applied_seq":999}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // The attempt was recorded, and its checkpoint is the orchestrator's
        // own log head (0 here — no events yet), not the caller's 999.
        let attempts = hub.handoffs_snapshot().await;
        assert_eq!(attempts.len(), 1);
        assert_eq!(attempts[0].checkpoint_seq, 0);
    }

    #[tokio::test]
    async fn handoff_route_rejects_an_unknown_target() {
        let hub = Hub::new(HubConfig::default());
        hub_with_device(&hub, "pc-1").await;
        let app = router(hub.clone(), HubConfig::default());

        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/api/v1/handoff")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        r#"{"task_id":"t1","from":"pc-1","to":"ghost"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        // No attempt may be recorded for a refused request.
        assert!(hub.handoffs_snapshot().await.is_empty());
    }

    #[tokio::test]
    async fn owner_route_reports_the_recorded_owner() {
        let hub = Hub::new(HubConfig::default());
        hub_with_device(&hub, "pc-1").await;
        hub_with_device(&hub, "phone-1").await;
        hub.request_handoff(
            &TaskId::new("t1"),
            &DeviceId::new("pc-1"),
            &DeviceId::new("phone-1"),
        )
        .await
        .unwrap();
        let app = router(hub.clone(), HubConfig::default());

        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/v1/tasks/t1/owner")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["owner"], "pc-1");
        assert_eq!(json["epoch"], 0);
    }

    #[tokio::test]
    async fn owner_route_is_404_for_an_unknown_task() {
        let hub = Hub::new(HubConfig::default());
        let app = router(hub.clone(), HubConfig::default());
        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/v1/tasks/nope/owner")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn handoff_route_requires_the_bearer_token() {
        // The handoff route must not be reachable without a token when auth is
        // on: it is the endpoint that moves ownership.
        let hub = Hub::new(HubConfig::default());
        hub_with_device(&hub, "pc-1").await;
        hub_with_device(&hub, "phone-1").await;
        let token = crate::api_auth::ApiToken::from_raw("test-token").expect("non-empty token");
        let app = router_with_auth(hub.clone(), HubConfig::default(), token);

        let unauth = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/api/v1/handoff")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        r#"{"task_id":"t1","from":"pc-1","to":"phone-1"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);
        assert!(hub.handoffs_snapshot().await.is_empty());

        let auth = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/api/v1/handoff")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer test-token")
                    .body(axum::body::Body::from(
                        r#"{"task_id":"t1","from":"pc-1","to":"phone-1"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(auth.status(), StatusCode::OK);
    }
}
