//! Phase 2 exit check: a natural-language prompt becomes a planner-driven
//! tool call and a result, with the audit trail — against the real binaries
//! and a fake Ollama over real HTTP.
//!
//! The orchestrator is started with HIMAN_OLLAMA_URL pointing at the fake
//! server, so the planner path is the model path, not the stub. The model's
//! answer is untrusted: the test also drives a malicious answer (unknown
//! tool) and asserts it is refused before anything executes.

mod common;

use serde_json::json;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const A: &str = "dev-a";

/// A fake Ollama that answers every request with `body`.
async fn fake_ollama(body: String) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let body = body.clone();
            tokio::spawn(async move {
                // Read until the end of the headers. The body may be
                // chunked (reqwest streams JSON), so waiting for a
                // content-length body would hang; answering after the
                // headers is enough for a fake.
                let mut buf = vec![0u8; 64 * 1024];
                let mut received = Vec::new();
                loop {
                    let Ok(n) = sock.read(&mut buf).await else {
                        return;
                    };
                    if n == 0 {
                        break;
                    }
                    received.extend_from_slice(&buf[..n]);
                    if received.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let resp = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                eprintln!(
                    "FAKE: headers done, received {} bytes, answering",
                    received.len()
                );
                eprintln!(
                    "FAKE: request head: {:?}",
                    String::from_utf8_lossy(&received[..received.len().min(300)])
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    port
}

// Multi-thread: the fake Ollama runs in THIS process, and the prompt call is
// blocking ureq. A current-thread runtime would freeze the fake while ureq
// waits, deadlocking until the orchestrator's model timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_natural_language_prompt_becomes_a_tool_call_and_a_result() {
    let answer = json!({
        "message": {
            "content": "I will check the device status for you.",
            "tool_calls": [{"function": {"name": "device_status", "arguments": {}}}]
        }
    })
    .to_string();
    let ollama_port = fake_ollama(answer).await;

    let dir = tempfile::tempdir().expect("tempdir");
    let devices = common::make_devices_named(dir.path(), 1, |_| A.to_string());
    let mut harness = common::E2ETest::restartable(
        &devices,
        None,
        vec![
            (
                "HIMAN_OLLAMA_URL".to_string(),
                format!("http://127.0.0.1:{ollama_port}"),
            ),
            ("HIMAN_OLLAMA_MODEL".to_string(), "fake-model".to_string()),
        ],
    )
    .await;
    let port = harness.port();
    let orch_key = harness.orchestrator_key().expect("orchestrator key");
    harness
        .spawn_agent(port, A, &orch_key)
        .await
        .expect("dev-a registers");

    // Natural language: no "status" keyword shortcut would be needed even if
    // one existed — the planner is the model here.
    let (status, body) = common::http_post(
        port,
        "/api/v1/prompt",
        json!({"device": A, "prompt": "how is my machine doing right now?"}),
    );
    assert_eq!(status, 200, "dispatch refused: {body}");
    let task_id = body["task_id"].as_str().expect("task id").to_string();
    assert_ne!(task_id, "none", "the planner proposed no tool: {body}");
    assert_eq!(body["decision"], json!("allow"));

    // The result comes back from the real agent.
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    let record = loop {
        let r = common::http_get_json(port, &format!("/api/v1/tasks/{task_id}/record"));
        if r["state"] == json!("succeeded") || std::time::Instant::now() >= deadline {
            break r;
        }
        tokio::time::sleep(common::POLL_INTERVAL).await;
    };
    assert_eq!(
        record["state"],
        json!("succeeded"),
        "the tool call did not complete: {record}"
    );
    assert_eq!(record["tool"], json!("device_status"));
    assert!(
        record["output"]
            .as_str()
            .map(|o| !o.is_empty())
            .unwrap_or(false),
        "no result output: {record}"
    );

    // The audit trail: planner proposed -> policy decided -> result.
    let audit = common::http_get_json(port, "/api/v1/audit");
    let lines = audit.as_array().expect("audit array");
    let actions: Vec<&str> = lines
        .iter()
        .map(|l| l["action"].as_str().unwrap_or(""))
        .collect();
    assert!(
        actions.contains(&"planner_proposed"),
        "no planner_proposed: {actions:?}"
    );
    assert!(
        actions.contains(&"tool_call_policy"),
        "no policy decision: {actions:?}"
    );
    assert!(
        actions.contains(&"tool_result"),
        "no tool result: {actions:?}"
    );
    // Order matters: the proposal precedes the policy decision.
    let proposed_at = actions
        .iter()
        .position(|a| *a == "planner_proposed")
        .expect("checked");
    let policy_at = actions
        .iter()
        .position(|a| *a == "tool_call_policy")
        .expect("checked");
    assert!(
        proposed_at < policy_at,
        "policy ran before the planner proposal"
    );

    harness.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_malicious_model_answer_is_refused_before_execution() {
    // The model proposes a tool outside the whitelist. Nothing may execute.
    let answer = json!({
        "message": {
            "content": "Sure, deleting everything now.",
            "tool_calls": [{"function": {"name": "delete_everything", "arguments": {}}}]
        }
    })
    .to_string();
    let ollama_port = fake_ollama(answer).await;

    let dir = tempfile::tempdir().expect("tempdir");
    let devices = common::make_devices_named(dir.path(), 1, |_| A.to_string());
    let mut harness = common::E2ETest::restartable(
        &devices,
        None,
        vec![(
            "HIMAN_OLLAMA_URL".to_string(),
            format!("http://127.0.0.1:{ollama_port}"),
        )],
    )
    .await;
    let port = harness.port();
    let orch_key = harness.orchestrator_key().expect("orchestrator key");
    harness
        .spawn_agent(port, A, &orch_key)
        .await
        .expect("dev-a registers");

    let (status, body) = common::http_post(
        port,
        "/api/v1/prompt",
        json!({"device": A, "prompt": "please tidy up my files"}),
    );
    assert_eq!(status, 200);
    assert_eq!(
        body["task_id"],
        json!("none"),
        "a non-whitelisted tool was dispatched: {body}"
    );
    assert_eq!(body["state"], json!("no_tool"));

    let audit = common::http_get_json(port, "/api/v1/audit");
    let lines = audit.as_array().expect("audit array");
    assert!(
        lines.iter().any(|l| l["action"] == "planner_rejected"
            && l["detail"]
                .as_str()
                .unwrap_or("")
                .contains("not_whitelisted")),
        "the rejection was not audited: {:?}",
        lines.iter().map(|l| &l["action"]).collect::<Vec<_>>()
    );
    // No tool call was issued.
    assert!(
        !lines.iter().any(|l| l["action"] == "tool_call_policy"),
        "a refused proposal still reached the policy engine"
    );

    harness.stop().await;
}
