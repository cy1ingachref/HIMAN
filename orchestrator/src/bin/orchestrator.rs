use himan_orchestrator::{serve, Hub, HubConfig};

#[tokio::main]
async fn main() {
    // Exactly one rustls provider must be installed: feature unification
    // with tokio-tungstenite/reqwest enables both ring and aws-lc-rs, which
    // makes rustls' automatic selection ambiguous.
    let _ = rustls::crypto::ring::default_provider().install_default();
    himan_orchestrator::init_logging();

    // Fail closed: refuse to start with the API open or no enrollment unless
    // HIMAN_INSECURE_DEV=1 is set explicitly.
    if let Err(e) =
        himan_orchestrator::enforce_startup(&himan_orchestrator::StartupRequirements::default())
    {
        tracing::error!(error = %e, "refusing to start");
        std::process::exit(1);
    }
    himan_orchestrator::log_posture();

    let port: u16 = std::env::var("HIMAN_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8787);

    // The orchestrator key is persisted so it survives restarts. Agents pin
    // this public key; regenerating it would invalidate every pinned agent.
    let orchestrator_key = match himan_orchestrator::load_or_generate_orchestrator_key() {
        Ok(k) => k,
        Err(e) => {
            tracing::error!(error = %e, "failed to load the orchestrator key");
            std::process::exit(1);
        }
    };

    // The per-device inbound queue size. A small queue is what makes a lag
    // reachable, so it is configurable rather than hard-coded; the default is
    // the production value.
    let agent_queue: usize = std::env::var("HIMAN_AGENT_QUEUE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(64);

    let hub = Hub::with_key(
        HubConfig {
            agent_queue,
            ..HubConfig::default()
        },
        orchestrator_key,
    );
    let hub = match himan_orchestrator::server::load_enrollment(hub) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!(error = %e, "failed to load device enrollment");
            std::process::exit(1);
        }
    };

    // Durable state. Unset means in-memory only (the tests and local runs);
    // a set path is a SQLite file in WAL mode.
    let durable_path = std::env::var("HIMAN_STATE_FILE").ok();
    if let Some(path) = &durable_path {
        if let Err(e) =
            himan_orchestrator::durable::attach(hub.clone(), std::path::Path::new(path)).await
        {
            tracing::error!(error = %e, path = %path, "failed to open durable state");
            std::process::exit(1);
        }
    }

    tracing::info!(port, "orchestrator starting");
    println!("orchestrator key: {}", hub.orchestrator_key_b64());
    println!("listening on 127.0.0.1:{port}");
    println!(
        "routes: /health /api/v1/agents /api/v1/audit /api/v1/prompt \
         /api/v1/handoff /api/v1/tasks/:id/owner /ws"
    );

    if let Err(e) = serve(hub, port).await {
        tracing::error!(error = %e, "server error");
        std::process::exit(1);
    }
}
