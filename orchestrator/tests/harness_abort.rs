//! RT-25: the Windows Job Object backstop kills a child when the harness
//! process dies abruptly (no clean Drop).
//!
//! RT-24 covers the Drop path. This covers what Drop cannot: the harness is
//! hard-killed, so its destructors never run. On Windows the Job Object with
//! JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE kills the child when the last job
//! handle closes, which the OS does even for an abrupt death.
//!
//! The test is written so it can never hang: the helper's idle is bounded,
//! the parent never waits on the helper's stdio, and on failure it kills the
//! grandchild explicitly before panicking.
//!
//! Unix has no equivalent kill-on-death primitive available here:
//! prctl(PR_SET_PDEATHSIG) needs a per-child syscall and still does not fire
//! when the parent is SIGKILLed. The Unix variant documents that gap.

mod common;

#[cfg(windows)]
use std::process::Command;
#[cfg(windows)]
use std::time::{Duration, Instant};

/// Helper: spawn a long-lived child through the harness `Child`, record its
/// pid, then idle. Run with HIMAN_ABORT_HELPER=1.
#[test]
fn harness_abort_helper() {
    if std::env::var("HIMAN_ABORT_HELPER").as_deref() != Ok("1") {
        return;
    }
    let bin = common::binary("himan-agent-pc").expect("agent binary");
    // A --ws URL with nothing listening keeps the agent alive (it retries).
    let mut child = common::Child::spawn(
        &bin,
        vec!["--ws".to_string(), "ws://127.0.0.1:1/ws".to_string()],
        vec![("HIMAN_DEVICE_ID".to_string(), "abort-helper".to_string())],
    );
    if let Ok(path) = std::env::var("HIMAN_ABORT_PID_FILE") {
        std::fs::write(path, child.id().to_string()).expect("write pid");
    }
    // Bounded idle: a failing parent assertion must not hang the suite.
    #[cfg(windows)]
    std::thread::sleep(Duration::from_secs(15));
    #[cfg(not(windows))]
    std::thread::sleep(std::time::Duration::from_secs(15));
    child.kill();
}

#[cfg(windows)]
#[test]
fn rt25_abrupt_harness_death_kills_the_child() {
    let pid_file = std::env::temp_dir().join(format!("himan-abort-{}.pid", std::process::id()));
    let _ = std::fs::remove_file(&pid_file);
    let mut helper = Command::new(std::env::current_exe().expect("test exe"))
        .arg("--exact")
        .arg("harness_abort_helper")
        .arg("--nocapture")
        .env("HIMAN_ABORT_HELPER", "1")
        .env("HIMAN_ABORT_PID_FILE", pid_file.display().to_string())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn helper");

    // Poll briefly for the helper to report the child pid.
    let mut child_pid: u32 = 0;
    for _ in 0..100 {
        if let Ok(text) = std::fs::read_to_string(&pid_file) {
            if let Ok(pid) = text.trim().parse::<u32>() {
                child_pid = pid;
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(child_pid != 0, "the helper did not report a child pid");

    // Hard-kill the helper: no unwinding, no Drop. Do not wait on it.
    let _ = kill_pid(helper.id());
    assert!(
        common::pid_is_alive(child_pid),
        "the child died before the helper was killed"
    );

    // The Job Object must take the child down within a bounded window.
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if !common::pid_is_alive(child_pid) {
            let _ = std::fs::remove_file(&pid_file);
            let _ = helper.wait();
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    // Clean up so the failure is not itself an orphan, then fail loudly.
    let _ = kill_pid(child_pid);
    let _ = std::fs::remove_file(&pid_file);
    let _ = helper.wait();
    panic!("child {child_pid} survived the abrupt harness death (Job Object backstop failed)");
}

#[cfg(windows)]
fn kill_pid(pid: u32) -> std::io::Result<()> {
    // Open with TERMINATE and call TerminateProcess: an abrupt death, so the
    // helper's destructors never run.
    unsafe {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::{
            OpenProcess, TerminateProcess, PROCESS_TERMINATE,
        };
        let handle = OpenProcess(PROCESS_TERMINATE, 0, pid);
        if handle.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        let ok = TerminateProcess(handle, 1) != 0;
        CloseHandle(handle);
        if ok {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
}

#[cfg(unix)]
#[test]
fn rt25_unix_has_no_kill_on_death_backstop() {
    // PR_SET_PDEATHSIG would need a per-child syscall and still does not fire
    // when the parent is SIGKILLed, so there is no backstop to test here.
    // Record the gap explicitly rather than asserting a vacuous truth.
    let backstop_available = cfg!(windows);
    assert!(
        !backstop_available,
        "if a Unix kill-on-death backstop is ever added, give it a real test"
    );
}
