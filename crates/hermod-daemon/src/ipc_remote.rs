//! Remote IPC over WSS + Bearer auth.
//!
//! Same JSON-RPC dispatch the Unix socket serves, exposed over a WebSocket
//! channel inside TLS. Auth: `Authorization: Bearer <api_token>` on the
//! handshake. The token is `$HERMOD_HOME/identity/api_token` (mode 0600,
//! generated on `hermod init`).
//!
//! Reuses the daemon's existing TLS material (`identity/tls.crt|key`).
//! Clients TOFU-pin the cert fingerprint just like federation peers do.

use crate::dispatcher::Dispatcher;
use anyhow::{Context, Result, anyhow};
use futures::{SinkExt, StreamExt};
use hermod_crypto::TlsMaterial;
use hermod_protocol::ipc::{Request, Response, message::Id};
use rustls::ServerConfig;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::net::SocketAddr;
use std::sync::Arc;
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

pub async fn serve(
    addr: SocketAddr,
    tls: TlsMaterial,
    api_token: Arc<str>,
    dispatcher: Dispatcher,
) -> Result<()> {
    let acceptor = build_tls_acceptor(&tls)?;
    let listener = TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;
    info!(addr = %local, "remote IPC (WSS+Bearer) listener up");

    loop {
        let (sock, peer) = match listener.accept().await {
            Ok(p) => p,
            Err(e) => {
                warn!(error = %e, "remote IPC accept failed");
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let token = api_token.clone();
        let dispatcher = dispatcher.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(sock, peer, acceptor, token, dispatcher).await {
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
    let key = PrivateKeyDer::from_pem_slice(tls.key_pem.as_bytes())
        .context("parse TLS key PEM")?;

    let config =
        ServerConfig::builder_with_protocol_versions(hermod_transport::tls::PROTOCOL_VERSIONS)
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .context("build rustls ServerConfig")?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

// `Result<HsResponse, ErrorResponse>` is the fixed signature
// `accept_hdr_async` requires from its callback — the Err variant carries an
// `http::Response`, which is heavyweight by design. Allowed locally.
#[allow(clippy::result_large_err)]
async fn handle_connection(
    sock: tokio::net::TcpStream,
    peer: SocketAddr,
    acceptor: TlsAcceptor,
    expected_token: Arc<str>,
    dispatcher: Dispatcher,
) -> Result<()> {
    let tls = acceptor.accept(sock).await?;
    // Capture the auth header during the WS handshake. accept_hdr_async lets
    // us inspect the upgrade request before completing the handshake.
    let auth_ok = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let auth_ok_for_callback = auth_ok.clone();
    let token = expected_token.clone();

    let ws_config = WebSocketConfig::default()
        .max_message_size(Some(MAX_REMOTE_IPC_BYTES))
        .max_frame_size(Some(MAX_REMOTE_IPC_BYTES));

    let ws = tokio_tungstenite::accept_hdr_async_with_config(
        tls,
        move |req: &HsRequest, resp: HsResponse| -> Result<HsResponse, ErrorResponse> {
            let header = req
                .headers()
                .get("Authorization")
                .and_then(|v| v.to_str().ok());
            let presented = header.and_then(|h| h.strip_prefix(EXPECTED_BEARER_PREFIX));
            if let Some(t) = presented
                && constant_time_eq(t.as_bytes(), token.as_bytes())
            {
                auth_ok_for_callback.store(true, std::sync::atomic::Ordering::SeqCst);
                return Ok(resp);
            }
            let mut deny = ErrorResponse::new(Some("invalid or missing bearer token".into()));
            *deny.status_mut() = StatusCode::UNAUTHORIZED;
            Err(deny)
        },
        Some(ws_config),
    )
    .await?;

    if !auth_ok.load(std::sync::atomic::Ordering::SeqCst) {
        // The handshake error path above should have already returned 401;
        // this guard catches any logic regression.
        return Err(anyhow!("bearer auth failed for {peer}"));
    }

    debug!(peer = %peer, "remote IPC client authenticated");
    let (mut tx, mut rx) = ws.split();
    while let Some(frame) = rx.next().await {
        let frame = frame?;
        match frame {
            Message::Text(body) => {
                let resp = handle_rpc(&dispatcher, &body).await;
                tx.send(Message::Text(resp.into())).await?;
            }
            Message::Binary(body) => {
                // Tolerate clients that send JSON as binary frames.
                let s =
                    std::str::from_utf8(&body).map_err(|_| anyhow!("binary frame not utf-8"))?;
                let resp = handle_rpc(&dispatcher, s).await;
                tx.send(Message::Text(resp.into())).await?;
            }
            Message::Ping(p) => tx.send(Message::Pong(p)).await?,
            Message::Close(_) => break,
            _ => {}
        }
    }
    Ok(())
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

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for i in 0..a.len() {
        acc |= a[i] ^ b[i];
    }
    acc == 0
}
