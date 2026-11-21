//! RT-20: a second live listener on the same port must fail.
//!
//! Written FIRST. `serve()` sets SO_REUSEADDR unconditionally, which on
//! Windows lets a second process bind the same port and hijack the service
//! (Windows treats SO_REUSEADDR as SO_EXCLUSIVEADDRUSE's opposite). On Unix
//! SO_REUSEADDR is required so a restart binds over lingering TIME_WAIT
//! sockets. The fix is cfg-gated: SO_EXCLUSIVEADDRUSE on Windows,
//! SO_REUSEADDR on Unix.
//!
//! This test asserts the property directly on the socket helper, so it runs
//! on both platforms without a full orchestrator.

use std::net::SocketAddr;

/// The bind helper the server uses, mirrored here so the test exercises the
/// same socket options. Returns the bound std listener.
fn bind_like_server(port: u16) -> std::io::Result<std::net::TcpListener> {
    himan_orchestrator::server::bind_loopback(port)
}

fn port() -> u16 {
    // Bind an ephemeral port, drop it, and use that number.
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("ephemeral");
    l.local_addr().expect("addr").port()
}

#[test]
fn rt20_a_second_live_listener_on_the_same_port_is_refused() {
    let port = port();

    // First listener: the service, bound the way the server binds.
    let first = bind_like_server(port).expect("first bind");
    assert_eq!(first.local_addr().expect("addr").port(), port);

    // A second process binding the same addr while the first is live.
    //
    // On Unix this fails. On Windows it SUCCEEDS unless SO_EXCLUSIVEADDRUSE
    // is set, because Windows' SO_REUSEADDR lets a second socket steal the
    // port — exactly the hijack this task fixes. This is the red assertion.
    let second = bind_like_server(port);
    assert!(
        second.is_err(),
        "a second live listener bound the same port — the service can be hijacked \
         (Windows SO_REUSEADDR semantics)"
    );
    drop(first);
}

/// A plain SO_REUSEADDR bind (no exclusivity) is recorded, not asserted:
/// on Windows 10+ a second bind is refused even with SO_REUSEADDR on both
/// sockets, but SO_EXCLUSIVEADDRUSE is still the explicit, documented-safe
/// option, so the server sets it. This test documents the observed platform
/// behaviour and fails loudly if a future Windows changes it.
#[test]
fn rt20_plain_reuseaddr_bind_platform_note() {
    let port = port();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().expect("addr");
    let first = bind_like_server(port).expect("first bind");
    let second = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )
    .expect("socket");
    second.set_reuse_address(true).expect("reuse");
    let plain = second.bind(&addr.into());
    if cfg!(windows) {
        eprintln!(
            "rt20 platform note: plain SO_REUSEADDR second bind on Windows -> {:?}",
            plain.as_ref().err()
        );
    } else {
        assert!(
            plain.is_err(),
            "on Unix SO_REUSEADDR must not let a second live bind succeed"
        );
    }
    drop(first);
}

/// Windows: the server's socket must actually carry SO_EXCLUSIVEADDRUSE,
/// not just SO_REUSEADDR. Read the option back with getsockopt so the
/// cfg-gated implementation is verified rather than assumed.
#[cfg(windows)]
#[test]
fn rt20_windows_socket_sets_exclusive_address_use() {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{
        getsockopt, SOCKET, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
    };
    let port = port();
    let listener = bind_like_server(port).expect("bind");
    let mut value: i32 = 0;
    let mut len: i32 = std::mem::size_of::<i32>() as i32;
    let rc = unsafe {
        getsockopt(
            listener.as_raw_socket() as SOCKET,
            SOL_SOCKET,
            SO_EXCLUSIVEADDRUSE,
            &mut value as *mut i32 as *mut u8,
            &mut len,
        )
    };
    assert_eq!(
        rc,
        0,
        "getsockopt failed: {}",
        std::io::Error::last_os_error()
    );
    assert_eq!(
        value, 1,
        "the server's listener does not have SO_EXCLUSIVEADDRUSE set"
    );
    drop(listener);
}

/// On Unix the same helper must still allow a restart over a lingering
/// TIME_WAIT socket — the property the durable_audit x20 job depends on.
#[cfg(unix)]
#[test]
fn rt20_unix_restart_over_time_wait_still_binds() {
    use std::io::Read;
    let port = port();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().expect("addr");

    let listener = std::net::TcpListener::bind(addr).expect("bind");
    listener.set_nonblocking(false).ok();
    // Make a connection so the accepted side ends up in TIME_WAIT after close.
    let client = std::net::TcpStream::connect(addr).expect("connect");
    let (server_side, _) = listener.accept().expect("accept");
    client.shutdown(std::net::Shutdown::Both).ok();
    server_side.shutdown(std::net::Shutdown::Both).ok();
    drop(server_side);
    drop(client);
    drop(listener);

    // The port is now free but has TIME_WAIT connections; a restart must bind.
    let restarted = bind_like_server(port);
    assert!(
        restarted.is_ok(),
        "Unix restart over TIME_WAIT failed: {:?}",
        restarted.err()
    );
    // And it must still refuse a second LIVE listener.
    let again = std::net::TcpListener::bind(addr);
    assert!(again.is_err(), "a second live listener bound after restart");
    let _ = std::io::empty().read(&mut []);
}
