use himan_orchestrator::{serve, Hub, HubConfig};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let port: u16 = std::env::var("HIMAN_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8787);

    let hub = Hub::new(HubConfig::default());
    println!("orchestrator key: {}", hub.orchestrator_key_b64());
    println!("listening on 127.0.0.1:{port}");
    println!("routes: /health /api/v1/agents /api/v1/audit /api/v1/prompt /ws");

    if let Err(e) = serve(hub, port).await {
        eprintln!("server error: {e}");
        std::process::exit(1);
    }
}
