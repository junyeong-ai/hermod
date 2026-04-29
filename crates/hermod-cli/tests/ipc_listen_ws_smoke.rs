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
    panic!(
        "ipc socket {} not created within {timeout:?}",
        socket.display()
    );
}

struct PlainWsDaemon {
    child: Child,
    home: tempfile::TempDir,
    ws_addr: SocketAddr,
    bearer_path: PathBuf,
}

impl PlainWsDaemon {
    fn spawn() -> Self {
        Self::spawn_with_env(&[])
    }

    /// Spawn with extra env vars layered on top of the standard
    /// IPC-listen-ws fixture. Used by tests that exercise additional
    /// daemon config knobs (e.g. `HERMOD_DAEMON_TRUSTED_PROXIES`).
    fn spawn_with_env(extra_env: &[(&str, &str)]) -> Self {
        let home = tempfile::tempdir().expect("tempdir");
        let bin_hermod = release_bin("hermod");
        let bin_hermodd = release_bin("hermodd");

        let init_status = Command::new(&bin_hermod)
            .env("HERMOD_HOME", home.path())
            .args(["init", "--alias", "ipc-listen-ws-test"])
            .status()
            .expect("hermod init");
        assert!(init_status.success());

        // Post-H2: per-agent bearer at agents/<bootstrap_id>/bearer_token.
        // The init above provisions exactly one bootstrap agent, so
        // its directory is the lone entry under agents/.
        let bearer_path = {
            let agents_dir = home.path().join("agents");
            let mut subdirs = std::fs::read_dir(&agents_dir)
                .expect("read agents dir")
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
                .collect::<Vec<_>>();
            assert_eq!(subdirs.len(), 1, "expected one bootstrap agent");
            subdirs.pop().expect("len == 1").path().join("bearer_token")
        };

        let ws_port = pick_free_port();
        let ws_addr: SocketAddr = format!("127.0.0.1:{ws_port}").parse().unwrap();
        let socket = home.path().join("sock");
        let stderr_file =
            std::fs::File::create(home.path().join("daemon.stderr")).expect("daemon stderr");
        let mut cmd = Command::new(&bin_hermodd);
        cmd.env("HERMOD_HOME", home.path())
            .env("HERMOD_DAEMON_SOCKET_PATH", &socket)
            // Plaintext WS — the path under test. Mutually exclusive
            // with HERMOD_DAEMON_IPC_LISTEN_WSS; the daemon's config
            // validator rejects both being set, so leaving the WSS
            // env var unset is critical.
            .env("HERMOD_DAEMON_IPC_LISTEN_WS", ws_addr.to_string())
            .env("HERMOD_DAEMON_LOG", "warn")
            .stdout(Stdio::null())
            .stderr(stderr_file);
        for (k, v) in extra_env {
            cmd.env(k, v);
        }
        let child = cmd.spawn().expect("spawn hermodd");
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

/// Open the daemon's SQLite audit_log directly and pull out the
/// `client_ip` of the most recent row matching `action`. Used to
/// verify end-to-end client-IP propagation: from the WebSocket
/// upgrade headers, through `audit_context::with_client_ip`, into
/// the `audit_or_warn` enrichment, into the persisted row.
async fn last_audit_client_ip(home: &std::path::Path, action: &str) -> Option<String> {
    use sqlx::Row;
    let dsn = format!("sqlite://{}/hermod.db", home.display());
    let pool = sqlx::SqlitePool::connect(&dsn)
        .await
        .expect("open audit db");
    let row =
        sqlx::query("SELECT client_ip FROM audit_log WHERE action = ? ORDER BY id DESC LIMIT 1")
            .bind(action)
            .fetch_one(&pool)
            .await
            .expect("audit row missing");
    pool.close().await;
    row.try_get::<Option<String>, _>("client_ip").unwrap()
}

/// Send one JSON-RPC request through a raw plaintext WebSocket
/// connection with a custom `X-Forwarded-For` header. Bypasses the
/// `hermod` CLI (which doesn't expose XFF) so the test can pin the
/// trusted-proxy resolution path against the actual handshake
/// callback, not a CLI wrapper.
async fn rpc_with_xff(
    url: &str,
    bearer: &str,
    xff: &str,
    method: &str,
    params: serde_json::Value,
) -> serde_json::Value {
    use futures::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;

    let mut req = url.into_client_request().expect("ws request");
    req.headers_mut()
        .insert("Authorization", format!("Bearer {bearer}").parse().unwrap());
    req.headers_mut()
        .insert("X-Forwarded-For", xff.parse().unwrap());
    let (mut ws, _) = tokio_tungstenite::connect_async(req)
        .await
        .expect("ws connect");
    let frame = serde_json::json!({
        "jsonrpc": "2.0",
        "id": "test-1",
        "method": method,
        "params": params,
    });
    ws.send(Message::Text(frame.to_string().into()))
        .await
        .expect("send");
    let resp = loop {
        match ws.next().await.expect("recv").expect("ws frame") {
            Message::Text(t) => break t,
            _ => continue,
        }
    };
    ws.close(None).await.ok();
    serde_json::from_str(resp.as_str()).expect("decode response")
}

/// XFF-resolved client IP from a trusted proxy must land in the
/// audit row's `client_ip`. Boots a daemon with
/// `HERMOD_DAEMON_TRUSTED_PROXIES` covering loopback, then sends a
/// raw WebSocket handshake whose `X-Forwarded-For` claims a public
/// IP. The auditable RPC (peer.add) records its row; the row's
/// `client_ip` must be the XFF-claimed IP, not the loopback peer.
///
/// Pins the full chain: WS upgrade header → handshake callback →
/// `xff_value` OnceLock → `client_ip::resolve_client_ip` →
/// `audit_context::CLIENT_IP` → `audit_or_warn` enrichment →
/// `AuditEntry.client_ip` → SQLite `audit_log.client_ip` column.
#[tokio::test(flavor = "multi_thread")]
async fn xff_resolved_client_ip_lands_in_audit_row() {
    let daemon = PlainWsDaemon::spawn_with_env(&[(
        "HERMOD_DAEMON_TRUSTED_PROXIES",
        // Loopback covers the test peer; the daemon trusts our XFF.
        "127.0.0.0/8",
    )]);
    let bearer = std::fs::read_to_string(&daemon.bearer_path)
        .expect("bearer")
        .trim()
        .to_string();

    // Use a different fake peer endpoint+pubkey for each invocation so
    // the test never collides with state left by an earlier run on a
    // shared tempdir (we don't have one, but cheap insurance).
    let host_pubkey_hex = "ab".repeat(32);
    let agent_pubkey_hex = "ac".repeat(32);
    let response = rpc_with_xff(
        &daemon.url(),
        &bearer,
        "203.0.113.42",
        "peer.add",
        serde_json::json!({
            "endpoint": {"scheme": "wss", "host": "fake-peer.example", "port": 7823},
            "host_pubkey_hex": host_pubkey_hex,
            "agent_pubkey_hex": agent_pubkey_hex,
        }),
    )
    .await;
    assert!(
        response.get("result").is_some(),
        "peer.add did not succeed: {response}"
    );

    let recorded = last_audit_client_ip(daemon.home.path(), "peer.add").await;
    assert_eq!(
        recorded.as_deref(),
        Some("203.0.113.42"),
        "audit row did not record the XFF-resolved client IP"
    );
}

/// Untrusted peer (no `trusted_proxies` set) must NOT believe the
/// XFF header — forgery defence. The daemon falls back to the TCP
/// peer IP (loopback in this test). Pins the security-critical
/// branch: an attacker who can hit the daemon directly cannot stamp
/// a fake originating IP into audit by sending a crafted XFF.
#[tokio::test(flavor = "multi_thread")]
async fn xff_from_untrusted_peer_is_ignored_in_audit() {
    // No HERMOD_DAEMON_TRUSTED_PROXIES — empty set means XFF is
    // ignored regardless of header content.
    let daemon = PlainWsDaemon::spawn();
    let bearer = std::fs::read_to_string(&daemon.bearer_path)
        .expect("bearer")
        .trim()
        .to_string();

    let host_pubkey_hex = "cd".repeat(32);
    let agent_pubkey_hex = "ce".repeat(32);
    let response = rpc_with_xff(
        &daemon.url(),
        &bearer,
        "198.51.100.13", // attacker-claimed IP — must be ignored
        "peer.add",
        serde_json::json!({
            "endpoint": {"scheme": "wss", "host": "fake-peer-2.example", "port": 7823},
            "host_pubkey_hex": host_pubkey_hex,
            "agent_pubkey_hex": agent_pubkey_hex,
        }),
    )
    .await;
    assert!(
        response.get("result").is_some(),
        "peer.add did not succeed: {response}"
    );

    let recorded = last_audit_client_ip(daemon.home.path(), "peer.add").await;
    // The XFF claim is ignored; client_ip falls back to the TCP peer,
    // which is loopback for this test fixture.
    assert!(
        matches!(recorded.as_deref(), Some(s) if s == "127.0.0.1" || s == "::1"),
        "audit row should record TCP peer (loopback), not XFF; got {recorded:?}"
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
        stderr.contains("401") || stderr.contains("rejected") || stderr.contains("unauthorized"),
        "expected an auth-rejection diagnostic in stderr; got:\n{stderr}",
    );
}
