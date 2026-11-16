use himan_orchestrator::{serve, Hub, HubConfig};

#[tokio::main]
async fn main() {
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

    let hub = Hub::with_key(HubConfig::default(), orchestrator_key);
    let hub = match himan_orchestrator::server::load_enrollment(hub) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!(error = %e, "failed to load device enrollment");
            std::process::exit(1);
        }
    };

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
