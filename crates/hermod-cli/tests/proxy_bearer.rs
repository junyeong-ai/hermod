//! End-to-end tests for the dual-bearer (`--bearer*` + `--proxy-bearer*`)
//! connect path.
//!
//! The tests stand up a tiny in-process WebSocket server that plays the
//! daemon role behind an SSO reverse proxy: it inspects the upgrade
//! request's `Authorization` and `Proxy-Authorization` headers, accepts
//! only when both match the expected bearers, and otherwise returns
//! HTTP 401 (mirroring how Google Cloud IAP / oauth2-proxy / Cloudflare
//! Access actually behave — they emit 401 for an invalid OIDC token,
//! not 407).
//!
//! These tests are intentionally hermetic: no real `hermodd` is spawned.
//! The CLI's `connect_remote_with_refresh` is what we want to exercise,
//! and it's transport-agnostic — what matters is that the right bytes
//! land on the wire and the refresh-on-401 retry behaves.

#![cfg(unix)]
// `tungstenite::ErrorResponse` is a fixed shape from the upstream
// library — we can't shrink the `Err` variant our callback returns.
// The cold-path mock handler is the only place this triggers.
#![allow(clippy::result_large_err)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::http;

const RELEASE_DIR: &str = "../../target/release";

fn release_bin(name: &str) -> PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest).join(RELEASE_DIR).join(name)
}

fn pick_free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    let p = l.local_addr().expect("local_addr").port();
    drop(l);
    p
}

#[derive(Clone)]
struct MockState {
    expected_daemon: String,
    expected_proxy: String,
    /// Count of upgrade attempts that presented an `Authorization`
    /// header (whether or not it matched).
    daemon_seen: Arc<AtomicUsize>,
    /// Count of upgrade attempts that presented a `Proxy-Authorization`
    /// header (whether or not it matched).
    proxy_seen: Arc<AtomicUsize>,
    /// Count of upgrade attempts where both headers matched.
    accepted: Arc<AtomicUsize>,
}

impl MockState {
    fn new(daemon: &str, proxy: &str) -> Self {
        Self {
            expected_daemon: daemon.to_string(),
            expected_proxy: proxy.to_string(),
            daemon_seen: Arc::new(AtomicUsize::new(0)),
            proxy_seen: Arc::new(AtomicUsize::new(0)),
            accepted: Arc::new(AtomicUsize::new(0)),
        }
    }
}

/// Spawn the mock server on `addr` and return immediately. The server
/// runs until the test's tokio runtime is dropped.
async fn spawn_mock(addr: SocketAddr, state: MockState) {
    let listener = TcpListener::bind(addr).await.expect("bind mock");
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => return,
            };
            let state = state.clone();
            tokio::spawn(handle_conn(stream, state));
        }
    });
}

async fn handle_conn(stream: tokio::net::TcpStream, state: MockState) {
    let cb_state = state.clone();
    let cb = move |req: &Request, resp: Response| -> Result<Response, ErrorResponse> {
        let auth = req
            .headers()
            .get("Authorization")
            .and_then(|v| v.to_str().ok());
        let proxy_auth = req
            .headers()
            .get("Proxy-Authorization")
            .and_then(|v| v.to_str().ok());
        if auth.is_some() {
            cb_state.daemon_seen.fetch_add(1, Ordering::SeqCst);
        }
        if proxy_auth.is_some() {
            cb_state.proxy_seen.fetch_add(1, Ordering::SeqCst);
        }
        let expected_daemon = format!("Bearer {}", cb_state.expected_daemon);
        let expected_proxy = format!("Bearer {}", cb_state.expected_proxy);
        let daemon_match = auth == Some(expected_daemon.as_str());
        let proxy_match = proxy_auth == Some(expected_proxy.as_str());
        if daemon_match && proxy_match {
            cb_state.accepted.fetch_add(1, Ordering::SeqCst);
            return Ok(resp);
        }
        // Reject with HTTP 401 — matches how real reverse-proxy SSO
        // products (IAP, oauth2-proxy, Cloudflare Access) actually
        // signal a missing/invalid OIDC token. We stay 401 instead of
        // 407 because the CLI's 401 path refreshes BOTH families,
        // which is the more interesting code path to exercise.
        let body: Option<String> = None;
        let err: ErrorResponse = http::Response::builder()
            .status(401)
            .body(body)
            .expect("build 401 response");
        Err(err)
    };

    let mut ws = match tokio_tungstenite::accept_hdr_async(stream, cb).await {
        Ok(ws) => ws,
        Err(_) => return, // expected on rejected handshakes
    };

    // Echo back a canned StatusGetResult to the first request — every
    // test invokes `hermod status` and exits.
    if let Some(Ok(Message::Text(text))) = ws.next().await {
        let req: serde_json::Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(_) => return,
        };
        let id = req.get("id").cloned().unwrap_or(serde_json::Value::Null);
        let result = serde_json::json!({
            "version": "0.1.0-mock",
            "agent_id": "aaaaaaaaaaaaaaaaaaaaaaaaaa",
            "alias": null,
            "pending_messages": 0,
            "peer_count": 0,
            "uptime_secs": 0,
            "attached_sessions": 0,
            "schema_version": "1"
        });
        let resp = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": result
        });
        let _ = ws.send(Message::Text(resp.to_string().into())).await;
    }
}

/// Helper: build a `--proxy-bearer-command` shell stub that emits the
/// given sequence of values, one per invocation. The Nth invocation
/// emits `outputs[min(n-1, outputs.len()-1)]` — so a 2-item sequence
/// "stale", "real" gives "stale" on call 1 and "real" on calls 2+.
/// Returns `(script_path, counter_path)`.
fn write_command_stub(dir: &std::path::Path, outputs: &[&str]) -> (PathBuf, PathBuf) {
    let counter = dir.join("count");
    let script = dir.join("stub.sh");
    std::fs::write(&counter, "0").unwrap();
    let cases: String = outputs
        .iter()
        .enumerate()
        .map(|(i, val)| {
            format!(
                "if [ \"$n\" = \"{idx}\" ]; then\n    printf '%s' '{val}'\n    exit 0\nfi\n",
                idx = i + 1,
                val = val
            )
        })
        .collect();
    let last = outputs.last().copied().unwrap_or("");
    let body = format!(
        "#!/bin/sh\nn=$(cat '{c}')\nn=$((n+1))\nprintf '%s' \"$n\" > '{c}'\n{cases}printf '%s' '{last}'\n",
        c = counter.display(),
        cases = cases,
        last = last,
    );
    std::fs::write(&script, body).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
    (script, counter)
}

fn invocations(counter: &std::path::Path) -> usize {
    std::fs::read_to_string(counter)
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}

/// All four tests share the same setup: a `--bearer-file` for the
/// daemon-layer bearer, an ephemeral mock listening on a free port,
/// and `--pin none` to disable TLS pinning (we use plain `ws://`
/// since the dual-header behaviour is transport-agnostic).
struct Fixture {
    home: tempfile::TempDir,
    daemon_bearer_file: PathBuf,
    mock_state: MockState,
    url: String,
}

impl Fixture {
    async fn build(daemon_token: &str, proxy_token: &str) -> Self {
        let home = tempfile::tempdir().expect("tempdir");
        let daemon_bearer_file = home.path().join("daemon_bearer");
        std::fs::write(&daemon_bearer_file, daemon_token).unwrap();
        let port = pick_free_port();
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let state = MockState::new(daemon_token, proxy_token);
        spawn_mock(addr, state.clone()).await;
        // Give the listener a moment to bind. spawn_mock binds before
        // returning so this is conservative but cheap.
        tokio::time::sleep(Duration::from_millis(50)).await;
        Self {
            home,
            daemon_bearer_file,
            mock_state: state,
            url: format!("ws://127.0.0.1:{port}/"),
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dual_auth_success() {
    let fx = Fixture::build("daemon-real", "proxy-real").await;
    let proxy_dir = tempfile::tempdir().unwrap();
    let proxy_bearer_file = proxy_dir.path().join("proxy_bearer");
    std::fs::write(&proxy_bearer_file, "proxy-real").unwrap();

    let bin = release_bin("hermod");
    let out = tokio::task::spawn_blocking(move || {
        Command::new(&bin)
            .env("HERMOD_HOME", fx.home.path())
            .args([
                "--remote",
                &fx.url,
                "--pin",
                "none",
                "--bearer-file",
                fx.daemon_bearer_file.to_str().unwrap(),
                "--proxy-bearer-file",
                proxy_bearer_file.to_str().unwrap(),
                "status",
            ])
            .output()
            .expect("hermod status")
    })
    .await
    .unwrap();

    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        out.status.success(),
        "hermod status failed:\nstdout:{stdout}\nstderr:{stderr}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_token_refresh_after_401() {
    let fx = Fixture::build("daemon-real", "proxy-real").await;
    let proxy_dir = tempfile::tempdir().unwrap();
    let (proxy_script, proxy_counter) =
        write_command_stub(proxy_dir.path(), &["proxy-stale", "proxy-real"]);

    let bin = release_bin("hermod");
    let url = fx.url.clone();
    let home = fx.home.path().to_path_buf();
    let daemon_file = fx.daemon_bearer_file.clone();
    let proxy_script_str = proxy_script.display().to_string();
    let proxy_counter_clone = proxy_counter.clone();
    let mock_state = fx.mock_state.clone();
    let out = tokio::task::spawn_blocking(move || {
        Command::new(&bin)
            .env("HERMOD_HOME", &home)
            .args([
                "--remote",
                &url,
                "--pin",
                "none",
                "--bearer-file",
                daemon_file.to_str().unwrap(),
                "--proxy-bearer-command",
                &proxy_script_str,
                "status",
            ])
            .output()
            .expect("hermod status")
    })
    .await
    .unwrap();

    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        out.status.success(),
        "hermod status failed (expected 401-refresh recovery):\nstdout:{stdout}\nstderr:{stderr}"
    );
    let proxy_runs = invocations(&proxy_counter_clone);
    assert_eq!(
        proxy_runs, 2,
        "proxy-bearer command must be invoked exactly twice (got {proxy_runs}); \
         stdout:{stdout}\nstderr:{stderr}"
    );
    assert_eq!(
        mock_state.accepted.load(Ordering::SeqCst),
        1,
        "mock should have accepted exactly the second connect attempt"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_token_persistent_failure_is_fatal() {
    let fx = Fixture::build("daemon-real", "proxy-real").await;
    let proxy_dir = tempfile::tempdir().unwrap();
    let (proxy_script, proxy_counter) = write_command_stub(proxy_dir.path(), &["proxy-wrong"]);

    let bin = release_bin("hermod");
    let url = fx.url.clone();
    let home = fx.home.path().to_path_buf();
    let daemon_file = fx.daemon_bearer_file.clone();
    let proxy_script_str = proxy_script.display().to_string();
    let proxy_counter_clone = proxy_counter.clone();
    let out = tokio::task::spawn_blocking(move || {
        Command::new(&bin)
            .env("HERMOD_HOME", &home)
            .args([
                "--remote",
                &url,
                "--pin",
                "none",
                "--bearer-file",
                daemon_file.to_str().unwrap(),
                "--proxy-bearer-command",
                &proxy_script_str,
                "status",
            ])
            .output()
            .expect("hermod status")
    })
    .await
    .unwrap();

    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        !out.status.success(),
        "hermod status must fail when proxy bearer is persistently invalid"
    );
    assert!(
        stderr.contains("rejected after refresh") || stderr.contains("declined to renew"),
        "expected post-refresh failure message in stderr; got: {stderr}"
    );
    let proxy_runs = invocations(&proxy_counter_clone);
    assert_eq!(
        proxy_runs, 2,
        "proxy command must run twice (initial + 401-trigger refresh); got {proxy_runs}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn neither_token_appears_in_stderr() {
    let daemon_token = "DAEMON-SECRET-TOKEN-7K9X";
    let proxy_token = "PROXY-SECRET-TOKEN-Q3P2";
    let fx = Fixture::build(daemon_token, proxy_token).await;
    let proxy_dir = tempfile::tempdir().unwrap();
    let proxy_bearer_file = proxy_dir.path().join("proxy_bearer");
    std::fs::write(&proxy_bearer_file, proxy_token).unwrap();

    let bin = release_bin("hermod");
    let out = tokio::task::spawn_blocking(move || {
        Command::new(&bin)
            .env("HERMOD_HOME", fx.home.path())
            // Push the log filter to debug — if any debug-level log
            // accidentally formats a header value, it would leak here.
            .env("HERMOD_DAEMON_LOG", "debug")
            .args([
                "--remote",
                &fx.url,
                "--pin",
                "none",
                "--bearer-file",
                fx.daemon_bearer_file.to_str().unwrap(),
                "--proxy-bearer-file",
                proxy_bearer_file.to_str().unwrap(),
                "status",
            ])
            .output()
            .expect("hermod status")
    })
    .await
    .unwrap();

    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        out.status.success(),
        "hermod status failed:\nstdout:{stdout}\nstderr:{stderr}"
    );
    assert!(
        !stderr.contains(daemon_token),
        "daemon token leaked into stderr: {stderr}"
    );
    assert!(
        !stderr.contains(proxy_token),
        "proxy token leaked into stderr: {stderr}"
    );
}
