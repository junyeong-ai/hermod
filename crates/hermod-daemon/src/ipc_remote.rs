//! Remote IPC over WebSocket + Bearer auth.
//!
//! Same JSON-RPC dispatch the Unix socket serves, exposed over a
//! WebSocket channel. Auth: `Authorization: Bearer <bearer_token>` on
//! the handshake. The token is
//! `$HERMOD_HOME/agents/<bootstrap_id>/bearer_token` (mode 0600,
//! generated on `hermod init`).
//!
//! Two listener flavours, picked by config:
//!
//! - [`serve_wss`] — TLS terminated *at the daemon*. Reuses the
//!   daemon's TLS material (`host/tls.crt|key`); clients TOFU-pin
//!   the cert fingerprint just like federation peers do.
//!   `daemon.ipc_listen_wss = "0.0.0.0:7824"`.
//! - [`serve_ws`] — plaintext WebSocket, expects an upstream reverse
//!   proxy (Cloud Run, Google IAP, oauth2-proxy, Cloudflare Access,
//!   ALB+Cognito, k8s ingress) to terminate TLS in front of the
//!   daemon. The bearer token still gates auth — TLS termination at
//!   the proxy authenticates the *transport*, not the *client*.
//!   `daemon.ipc_listen_ws = "0.0.0.0:7824"`.
//!
//! The two are mutually exclusive; the config layer rejects both
//! being set (see [`crate::config::Config::validate`]).

use crate::client_ip::resolve_client_ip;
use crate::dispatcher::Dispatcher;
use anyhow::{Context, Result, anyhow};
use futures::{SinkExt, StreamExt};
use hermod_core::AgentId;
use hermod_crypto::TlsMaterial;
use hermod_daemon::local_agent::LocalAgentRegistry;
use hermod_protocol::ipc::{Request, Response, message::Id};
use ipnet::IpNet;
use rustls::ServerConfig;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::server::{
    ErrorResponse, Request as HsRequest, Response as HsResponse,
};
use tokio_tungstenite::tungstenite::http::StatusCode;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tracing::{debug, info, warn};

const EXPECTED_BEARER_PREFIX: &str = "Bearer ";

/// Hard cap on remote-IPC frame size. Generous for the largest legitimate
/// JSON-RPC reply (a paginated `message.list` page, ≤ 64 KiB) but small
/// enough that a misbehaving client can't pin the daemon's memory.
const MAX_REMOTE_IPC_BYTES: usize = 1024 * 1024;

/// Pause after a transient `accept` failure (FD exhaustion, RST
/// flood, ephemeral kernel resource pressure). Short enough that
/// recovery is prompt; long enough that a hard error doesn't pin a
/// CPU spinning on the same `accept` call.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(200);

/// Per-connection wrap chosen at listener-construction time. Adding a
/// new transport (mTLS, Unix-socket-bridge, …) is one new variant
/// here plus its arm in [`AcceptStrategy::wrap`].
enum AcceptStrategy {
    /// Plaintext WebSocket — the upstream reverse proxy terminates
    /// TLS and forwards plain HTTP to the daemon.
    Plain,
    /// TLS terminated at the daemon. Used by federation peers and
    /// LAN deployments that don't sit behind a fronting proxy.
    Tls(TlsAcceptor),
}

impl AcceptStrategy {
    /// Apply the per-connection wrap to a freshly-accepted TCP socket
    /// and run the WebSocket handshake + JSON-RPC dispatch on top.
    async fn wrap(
        &self,
        sock: tokio::net::TcpStream,
        peer: SocketAddr,
        registry: LocalAgentRegistry,
        trusted_proxies: Arc<Vec<IpNet>>,
        dispatcher: Dispatcher,
    ) -> Result<()> {
        match self {
            AcceptStrategy::Plain => {
                handshake_and_serve(sock, peer, registry, trusted_proxies, dispatcher).await
            }
            AcceptStrategy::Tls(acceptor) => {
                let stream = acceptor.accept(sock).await.context("TLS handshake")?;
                handshake_and_serve(stream, peer, registry, trusted_proxies, dispatcher).await
            }
        }
    }
}

/// TLS-at-the-daemon listener. Use when the daemon is reachable over
/// the network without a fronting reverse proxy (federation peers
/// connecting directly, internal LAN, …).
pub async fn serve_wss(
    addr: SocketAddr,
    tls: TlsMaterial,
    registry: LocalAgentRegistry,
    trusted_proxies: Arc<Vec<IpNet>>,
    dispatcher: Dispatcher,
) -> Result<()> {
    let acceptor = build_tls_acceptor(&tls)?;
    let listener = TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;
    info!(addr = %local, "remote IPC (WSS+Bearer) listener up");
    accept_loop(
        listener,
        AcceptStrategy::Tls(acceptor),
        registry,
        trusted_proxies,
        dispatcher,
    )
    .await
}

/// Plaintext-at-the-daemon listener. Use when an upstream L7 reverse
/// proxy (Cloud Run, Google IAP, oauth2-proxy, Cloudflare Access,
/// ALB+Cognito, k8s ingress) terminates TLS and forwards plain
/// HTTP/HTTP2 to the daemon. The bearer (and optional
/// proxy-bearer-via-`Proxy-Authorization`) carries the auth weight;
/// the proxy guarantees confidentiality.
pub async fn serve_ws(
    addr: SocketAddr,
    registry: LocalAgentRegistry,
    trusted_proxies: Arc<Vec<IpNet>>,
    dispatcher: Dispatcher,
) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;
    info!(addr = %local, "remote IPC (WS+Bearer, TLS-upstream) listener up");
    accept_loop(
        listener,
        AcceptStrategy::Plain,
        registry,
        trusted_proxies,
        dispatcher,
    )
    .await
}

/// Shared accept loop. One per listener. The `strategy` decides what
/// happens between TCP accept and WebSocket handshake — clone-free
/// for `Plain`, `acceptor.clone()` for `Tls` (cheap `Arc` clone).
async fn accept_loop(
    listener: TcpListener,
    strategy: AcceptStrategy,
    registry: LocalAgentRegistry,
    trusted_proxies: Arc<Vec<IpNet>>,
    dispatcher: Dispatcher,
) -> Result<()> {
    let strategy = Arc::new(strategy);
    loop {
        let (sock, peer) = match listener.accept().await {
            Ok(p) => p,
            Err(e) => {
                warn!(error = %e, "remote IPC accept failed");
                tokio::time::sleep(ACCEPT_BACKOFF).await;
                continue;
            }
        };
        let strategy = strategy.clone();
        let reg = registry.clone();
        let trusted = trusted_proxies.clone();
        let dispatcher = dispatcher.clone();
        tokio::spawn(async move {
            if let Err(e) = strategy.wrap(sock, peer, reg, trusted, dispatcher).await {
                debug!(peer = %peer, error = %e, "remote IPC connection ended");
            }
        });
    }
}

fn build_tls_acceptor(tls: &TlsMaterial) -> Result<TlsAcceptor> {
    let cert_chain: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(tls.cert_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .context("parse TLS cert PEM")?;
    let key = PrivateKeyDer::from_pem_slice(tls.key_pem.as_bytes()).context("parse TLS key PEM")?;

    let config =
        ServerConfig::builder_with_protocol_versions(hermod_transport::tls::PROTOCOL_VERSIONS)
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .context("build rustls ServerConfig")?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Stream-generic handshake + RPC loop. The stream is either a raw
/// `TcpStream` (plaintext mode) or a `TlsStream<TcpStream>` (TLS-at-
/// daemon mode) — the WebSocket handshake plus auth callback plus
/// per-frame JSON-RPC dispatch are identical in either case.
// `Result<HsResponse, ErrorResponse>` is the fixed signature
// `accept_hdr_async` requires from its callback — the Err variant carries an
// `http::Response`, which is heavyweight by design. Allowed locally.
#[allow(clippy::result_large_err)]
async fn handshake_and_serve<S>(
    stream: S,
    peer: SocketAddr,
    registry: LocalAgentRegistry,
    trusted_proxies: Arc<Vec<IpNet>>,
    dispatcher: Dispatcher,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Capture the resolved caller agent (with its session
    // registration), the shutdown receiver, and the X-Forwarded-For
    // header during the WS handshake. `accept_hdr_async` lets us
    // inspect the upgrade request before completing the handshake;
    // the auth callback hashes the presented bearer, atomically
    // resolves + registers the session under one registry write
    // lock (closes the rotate-vs-resolve race window), and stashes
    // the resulting `(agent_id, guard, rx)` triple for the
    // post-handshake reader. Returns 401 if the bearer doesn't
    // match any hosted agent.
    //
    // The `Mutex<Option<...>>` slot is what lets us move the guard
    // + receiver out of the sync handshake callback into the async
    // message loop without a clone (oneshot::Receiver isn't Clone).
    type Session = (
        AgentId,
        crate::local_agent::SessionGuard,
        tokio::sync::oneshot::Receiver<()>,
    );
    let session_slot: Arc<std::sync::Mutex<Option<Session>>> =
        Arc::new(std::sync::Mutex::new(None));
    let session_for_callback = session_slot.clone();
    let xff_value: std::sync::Arc<std::sync::OnceLock<String>> =
        std::sync::Arc::new(std::sync::OnceLock::new());
    let xff_for_callback = xff_value.clone();
    let auth_registry = registry.clone();

    let ws_config = WebSocketConfig::default()
        .max_message_size(Some(MAX_REMOTE_IPC_BYTES))
        .max_frame_size(Some(MAX_REMOTE_IPC_BYTES));

    let ws = tokio_tungstenite::accept_hdr_async_with_config(
        stream,
        move |req: &HsRequest, resp: HsResponse| -> Result<HsResponse, ErrorResponse> {
            if let Some(value) = req
                .headers()
                .get("X-Forwarded-For")
                .and_then(|v| v.to_str().ok())
            {
                let _ = xff_for_callback.set(value.to_string());
            }
            let header = req
                .headers()
                .get("Authorization")
                .and_then(|v| v.to_str().ok());
            let presented = header.and_then(|h| h.strip_prefix(EXPECTED_BEARER_PREFIX));
            if let Some(token) = presented
                && let Some(triple) = auth_registry.resolve_and_register_bearer(token)
            {
                if let Ok(mut g) = session_for_callback.lock() {
                    *g = Some(triple);
                }
                return Ok(resp);
            }
            let mut deny = ErrorResponse::new(Some("invalid or missing bearer token".into()));
            *deny.status_mut() = StatusCode::UNAUTHORIZED;
            Err(deny)
        },
        Some(ws_config),
    )
    .await?;

    let (caller_agent, _session_guard, mut shutdown_rx) = session_slot
        .lock()
        .ok()
        .and_then(|mut g| g.take())
        .ok_or_else(|| anyhow!("bearer auth failed for {peer}"))?;
    let xff_seen = xff_value.get().cloned();
    let client = resolve_client_ip(peer.ip(), xff_seen.as_deref(), &trusted_proxies);

    let span = tracing::info_span!(
        "ipc_conn",
        peer = %peer,
        client = %client,
        caller = %caller_agent,
    );
    let _enter = span.enter();
    debug!("remote IPC client authenticated");

    // `_session_guard` lives until this function exits — its `Drop`
    // impl removes the per-session entry from the registry's
    // `sessions` map, so a clean disconnect doesn't leak a sender.
    // A rotate / remove that fires while we're alive sends the
    // shutdown signal first, then the guard's drop is a harmless
    // no-op (the sessions map for this agent has already been
    // wholesale-removed).

    // Bind both ambient context values for every task-local read
    // inside the message loop. `audit_or_warn` overlays them onto
    // each emitted `AuditEntry`: client_ip onto the `client_ip`
    // field, caller_agent onto the `actor` field.
    let inner = crate::audit_context::with_client_ip(Some(client), async move {
        let (mut tx, mut rx) = ws.split();
        loop {
            tokio::select! {
                biased;
                _ = &mut shutdown_rx => {
                    // Bearer rotated or agent removed. Tear the
                    // connection down cleanly so the client gets a
                    // clean disconnect rather than a stale-bearer
                    // error on the next request.
                    let _ = tx.send(Message::Close(None)).await;
                    break;
                }
                frame = rx.next() => {
                    let Some(frame) = frame else { break };
                    let frame = frame?;
                    match frame {
                        Message::Text(body) => {
                            let resp = handle_rpc(&dispatcher, &body).await;
                            tx.send(Message::Text(resp.into())).await?;
                        }
                        Message::Binary(body) => {
                            let s = std::str::from_utf8(&body)
                                .map_err(|_| anyhow!("binary frame not utf-8"))?;
                            let resp = handle_rpc(&dispatcher, s).await;
                            tx.send(Message::Text(resp.into())).await?;
                        }
                        Message::Ping(p) => tx.send(Message::Pong(p)).await?,
                        Message::Close(_) => break,
                        _ => {}
                    }
                }
            }
        }
        Ok::<_, anyhow::Error>(())
    });
    crate::audit_context::with_caller_agent(Some(caller_agent), inner).await
}

async fn handle_rpc(dispatcher: &Dispatcher, body: &str) -> String {
    let req: Request = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(e) => {
            // The Response error wrapper itself is plain serde-derive types;
            // failure here would be an internal invariant breach worth surfacing.
            return serde_json::to_string(&Response::err(
                Id::Null,
                hermod_protocol::ipc::error::RpcError::new(
                    hermod_protocol::ipc::error::code::PARSE_ERROR,
                    format!("parse error: {e}"),
                ),
            ))
            .expect("error Response always serialises");
        }
    };
    let resp = dispatcher.handle(req).await;
    serde_json::to_string(&resp).expect("dispatcher Response always serialises")
}
