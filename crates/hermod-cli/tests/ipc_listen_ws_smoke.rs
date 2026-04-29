//! Hermetic smoke test for the `[daemon] ipc_listen_ws` plaintext path.
//!
//! Spawns a real `hermodd` configured with `HERMOD_DAEMON_IPC_LISTEN_WS`
//! and runs `hermod --remote ws://… --pin none` against it. Three
//! assertions cover the live edges of the path:
//!
//! 1. **Listener actually binds.** The daemon serves
//!    `serve_ws → handshake_and_serve` over a raw `TcpStream` — no TLS
//!    wrap. Boot must succeed without TLS material being touched on
//!    the IPC remote side (the daemon still self-generates TLS for
//!    federation, just not for IPC).
//! 2. **Bearer auth works on plaintext WS.** The `Authorization:
//!    Bearer …` header must reach the daemon's pre-handshake
//!    callback even when the WebSocket Upgrade arrived over plain
//!    TCP. A successful `hermod status` proves the round-trip.
//! 3. **Bearer rejection still works on plaintext WS.** A wrong
//!    token must surface the same HTTP 401 path the WSS listener
//!    produces — auth must not silently pass through just because
//!    the transport is plaintext.
//!
//! Defends the path against the regression class that broke twice
//! during the live deploy (TLS-at-daemon vs. Cloud Run plaintext;
//! HTTP/2 vs. HTTP/1.1 WebSocket Upgrade): both failures would have
//! been caught here without needing a Cloud Run round-trip.

#![cfg(unix)]

use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const RELEASE_DIR: &str = "../../target/release";

fn release_bin(name: &str) -> PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    PathBuf::from(manifest).join(RELEASE_DIR).join(name)
}

fn pick_free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    let p = l.local_addr().expect("local_addr").port();
    drop(l);
    p
}

fn wait_for_port(addr: SocketAddr, timeout: Duration) {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(100)).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("port {addr} unreachable after {timeout:?}");
}

fn wait_for_socket(socket: &std::path::Path, timeout: Duration) {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if socket.exists() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("ipc socket {} not created within {timeout:?}", socket.display());
}

struct PlainWsDaemon {
    child: Child,
    home: tempfile::TempDir,
    ws_addr: SocketAddr,
    bearer_path: PathBuf,
}

impl PlainWsDaemon {
    fn spawn() -> Self {
        let home = tempfile::tempdir().expect("tempdir");
        let bin_hermod = release_bin("hermod");
        let bin_hermodd = release_bin("hermodd");

        let init_status = Command::new(&bin_hermod)
            .env("HERMOD_HOME", home.path())
            .args(["init", "--alias", "ipc-listen-ws-test"])
            .status()
            .expect("hermod init");
        assert!(init_status.success());

        let bearer_path = home.path().join("identity").join("bearer_token");

        let ws_port = pick_free_port();
        let ws_addr: SocketAddr = format!("127.0.0.1:{ws_port}").parse().unwrap();
        let socket = home.path().join("sock");
        let stderr_file =
            std::fs::File::create(home.path().join("daemon.stderr")).expect("daemon stderr");
        let child = Command::new(&bin_hermodd)
            .env("HERMOD_HOME", home.path())
            .env("HERMOD_DAEMON_SOCKET_PATH", &socket)
            // Plaintext WS — the path under test. Mutually exclusive
            // with HERMOD_DAEMON_IPC_LISTEN_WSS; the daemon's config
            // validator rejects both being set, so leaving the WSS
            // env var unset is critical.
            .env("HERMOD_DAEMON_IPC_LISTEN_WS", ws_addr.to_string())
            .env("HERMOD_DAEMON_LOG", "warn")
            .stdout(Stdio::null())
            .stderr(stderr_file)
            .spawn()
            .expect("spawn hermodd");
        wait_for_port(ws_addr, Duration::from_secs(15));
        wait_for_socket(&socket, Duration::from_secs(5));
        Self {
            child,
            home,
            ws_addr,
            bearer_path,
        }
    }

    fn url(&self) -> String {
        // Plain ws:// — the URL scheme that lines up with
        // `serve_ws`. wss:// would route the client through its
        // rustls connector and hit the daemon as TLS bytes; the
        // daemon's plaintext listener would reject the handshake.
        format!("ws://{}/", self.ws_addr)
    }

    fn cli_status(&self, bearer_file: &std::path::Path) -> std::process::Output {
        let bin_hermod = release_bin("hermod");
        Command::new(bin_hermod)
            .env("HERMOD_HOME", self.home.path())
            .args([
                "--remote",
                &self.url(),
                "--bearer-file",
                bearer_file.to_str().expect("bearer-file utf-8"),
                // No TLS to validate — the URL is plain ws://. The
                // pin policy is a no-op on the plaintext branch
                // anyway, but `--pin none` makes the intent explicit
                // for any future reader of the failure.
                "--pin",
                "none",
                "status",
            ])
            .output()
            .expect("invoke hermod status")
    }
}

impl Drop for PlainWsDaemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn status_succeeds_over_plain_ws_with_real_bearer() {
    let daemon = PlainWsDaemon::spawn();
    let out = daemon.cli_status(&daemon.bearer_path);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "hermod status failed against plain ws:// listener\nstdout: {stdout}\nstderr: {stderr}",
    );
    // The status payload includes the agent_id line — pin a substring
    // a reader would recognise rather than the full output (which
    // includes uptime_secs and other moving values).
    assert!(
        stdout.contains("agent_id:"),
        "expected `agent_id:` line in status output; got:\n{stdout}",
    );
}

#[test]
fn wrong_bearer_is_rejected_on_plain_ws() {
    let daemon = PlainWsDaemon::spawn();
    let bad_bearer = daemon.home.path().join("bad_bearer");
    std::fs::write(&bad_bearer, "this-is-not-the-real-token").unwrap();

    let out = daemon.cli_status(&bad_bearer);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "wrong bearer must fail; got success\nstdout: {stdout}\nstderr: {stderr}",
    );
    // The CLI surfaces the upstream HTTP 401 in its post-refresh
    // diagnostic. We don't pin the exact phrasing (it can evolve)
    // but the failure must be auth-shaped, not transport-shaped.
    assert!(
        stderr.contains("401")
            || stderr.contains("rejected")
            || stderr.contains("unauthorized"),
        "expected an auth-rejection diagnostic in stderr; got:\n{stderr}",
    );
}
