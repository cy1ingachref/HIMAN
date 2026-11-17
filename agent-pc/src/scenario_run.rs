//! Scenario agent mode: a real, long-running multi-step task.
//!
//! AC-1 needs a task that is *still running* when the handoff happens, so the
//! demo prompt path is not enough. This module runs N deterministic steps and
//! reports each one over a channel, so the acceptance test can observe exactly
//! which steps executed, on which device, and in what order.
//!
//! It deliberately knows nothing about handoffs. It runs steps; the
//! orchestrator moves ownership. Keeping the two apart is what makes
//! "exactly once" a meaningful assertion rather than a tautology.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;

use himan_agent_core::llm::ChatBackend;
use himan_agent_core::tool::Tool;
use himan_proto::DeviceId;

use crate::scenario::{step_request, ScenarioBackend, ScenarioStepTool};

/// A boxed, `'static` future returned by a drain hook.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// One executed step, as reported by a running scenario.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepReport {
    pub step: u64,
    pub call_id: String,
    pub device: String,
}

/// A running scenario task: the handle the caller holds.
pub struct ScenarioRun {
    pub device: String,
    pub total: u64,
    pub reports: mpsc::Receiver<StepReport>,
    /// Steps completed so far, readable without consuming the report stream.
    pub started: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    shutdown_tx: mpsc::Sender<()>,
}

impl ScenarioRun {
    /// Spawn a run. `step_delay` is the per-step wall-clock cost, which is what
    /// makes the run long enough to interrupt mid-way.
    pub fn spawn(device: String, total: u64, step_delay: Duration) -> Self {
        let (report_tx, reports) = mpsc::channel(64);
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel(1);
        let stop = Arc::new(AtomicBool::new(false));
        let started = Arc::new(AtomicU64::new(0));

        let stop_task = stop.clone();
        let started_task = started.clone();
        let device_task = device.clone();

        tokio::spawn(async move {
            let backend = ScenarioBackend::new();
            let tool = ScenarioStepTool::new(step_delay);
            let mut executed = 0u64;

            for step in 1..=total {
                if stop_task.load(Ordering::SeqCst) {
                    break;
                }
                // A shutdown request may arrive between steps; a blocking recv
                // here would stall the run, so drain it without waiting.
                if shutdown_rx.try_recv().is_ok() {
                    break;
                }

                let response = match backend.chat(step_request(step, total)).await {
                    Ok(r) => r,
                    Err(_) => break,
                };
                let tool_name = response.tool_calls.first().cloned().unwrap_or_default();

                let device_id = DeviceId::new(device_task.clone());
                if tool
                    .run(
                        &device_id,
                        serde_json::json!({ "step": step, "tool": tool_name }),
                    )
                    .await
                    .is_err()
                {
                    break;
                }

                executed += 1;
                started_task.store(executed, Ordering::SeqCst);
                if report_tx
                    .send(StepReport {
                        step,
                        call_id: format!("{device_task}-step-{step}"),
                        device: device_task.clone(),
                    })
                    .await
                    .is_err()
                {
                    break;
                }
            }

            EXECUTIONS.with(|m| {
                m.borrow_mut().insert(device_task.clone(), executed);
            });
        });

        Self {
            device,
            total,
            reports,
            started,
            stop,
            shutdown_tx,
        }
    }

    /// A boxed `async` handle that stops the run between steps.
    ///
    /// The agent installs this as its drain hook, so a handoff drains the
    /// scenario exactly where the spec wants: at a step boundary. It shares
    /// the run's stop flag and sender rather than cloning the handle, because
    /// the report receiver is single-consumer.
    pub fn stop_handle(&self) -> impl Fn() -> BoxFuture<'static, ()> + Send + Sync + 'static {
        let stop = self.stop.clone();
        let tx = self.shutdown_tx.clone();
        move || {
            let stop = stop.clone();
            let tx = tx.clone();
            Box::pin(async move {
                let _ = tx.send(()).await;
                stop.store(true, Ordering::SeqCst);
            })
        }
    }

    /// Ask the run to stop between steps. Used when a handoff needs the source
    /// to stop starting new work.
    pub async fn request_stop(&self) {
        let _ = self.shutdown_tx.send(()).await;
        self.stop.store(true, Ordering::SeqCst);
    }

    pub fn steps_started(&self) -> u64 {
        self.started.load(Ordering::SeqCst)
    }
}

thread_local! {
    /// Executed-step counts per device, for exactly-once assertions.
    static EXECUTIONS: std::cell::RefCell<std::collections::HashMap<String, u64>> =
        std::cell::RefCell::new(std::collections::HashMap::new());
}

/// How many steps a device completed in this process.
pub fn executions(device: &str) -> u64 {
    EXECUTIONS.with(|m| m.borrow().get(device).copied().unwrap_or(0))
}

#[cfg(test)]
mod tests;
