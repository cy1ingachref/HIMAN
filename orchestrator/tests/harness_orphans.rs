//! RT-24: child processes spawned by the harness die with the harness.
//!
//! Written FIRST. Before this, `E2ETest` held `std::process::Child` handles
//! and only killed them in `stop()`. A test that panicked, or a health wait
//! that timed out, dropped the struct without stopping, leaving
//! `himan-orchestrator.exe` / `himan-agent-pc.exe` alive holding
//! `target/debug/himan-orchestrator.exe` — the orphaned processes that locked
//! the build output and broke subsequent test runs.
//!
//! The property asserted here: when the harness value is dropped (including
//! on a panic path simulated by a scope exit), the child is gone.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};

/// A child that must be killed when its owning harness is dropped.
struct Harness {
    child: std::process::Child,
    dropped: &'static AtomicUsize,
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.dropped.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn rt24_child_dies_when_the_harness_is_dropped() {
    static DROPPED: AtomicUsize = AtomicUsize::new(0);
    let bin = common::binary("himan-agent-pc").expect("agent binary");
    let child = std::process::Command::new(bin)
        .arg("--demo")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn");
    let pid = child.id();
    {
        let _harness = Harness {
            child,
            dropped: &DROPPED,
        };
        // Dropped at the end of this scope, as a panicking test would drop it.
    }
    assert_eq!(DROPPED.load(Ordering::SeqCst), 1, "the guard did not run");
    // Give the OS a moment to reap the killed child before asserting.
    for _ in 0..50 {
        if !common::pid_is_alive(pid) {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    panic!("pid {pid} is still alive after the harness was dropped");
}

/// The same property for the real E2ETest harness: build one, drop it
/// without calling stop(), and assert no orchestrator process remains.
#[tokio::test]
async fn rt24_e2e_harness_drop_kills_the_orchestrator() {
    let dir = tempfile::tempdir().expect("tempdir");
    let devices = common::make_devices_named(dir.path(), 1, |i| format!("dev-{i}"));
    let before = common::count_orchestrators();
    {
        let harness = common::E2ETest::with_devices_env(&devices, vec![]).await;
        let _ = harness.port();
        // Intentionally no harness.stop(). Drop must clean up.
    }
    // Give the OS a moment to reap the killed child.
    for _ in 0..50 {
        if common::count_orchestrators() <= before {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!(
        "orchestrator survived the harness drop: before={before} after={}",
        common::count_orchestrators()
    );
}

/// Panic path: a panicking test unwinds, Drop runs, the child must die.
#[tokio::test]
async fn rt24_panicking_test_kills_the_orchestrator() {
    let dir = tempfile::tempdir().expect("tempdir");
    let devices = common::make_devices_named(dir.path(), 1, |i| format!("dev-{i}"));
    let before = common::count_orchestrators();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let harness = common::E2ETest::with_devices_env(&devices, vec![]).await;
            let _ = harness.port();
            panic!("simulated test failure");
        });
    }));
    assert!(result.is_err(), "the panic did not propagate");
    for _ in 0..50 {
        if common::count_orchestrators() <= before {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!(
        "orchestrator survived a panicking harness: before={before} after={}",
        common::count_orchestrators()
    );
}
