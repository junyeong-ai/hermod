//! WebSocket transport for Hermod federation.
//!
//! Two flavours share one [`WsStream`] type via a tagged inner stream:
//! - **Plain WS** (testing / loopback only).
//! - **WSS** = TLS + WS (production federation).
//!
//! TLS is configured for *transport* security and middlebox compatibility.
//! Peer **authentication** happens at the Noise XX layer that runs inside
//! the WebSocket frames; the TLS verifier therefore accepts any cert and
//! exposes its SHA-256 fingerprint to the routing layer for TOFU pinning
//! against `agents.tls_fingerprint`.

use futures::{SinkExt, StreamExt};
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tokio_rustls::{
    TlsAcceptor, TlsConnector, client::TlsStream as ClientTlsStream,
    server::TlsStream as ServerTlsStream,
};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::client::generate_key;
use tokio_tungstenite::tungstenite::http::{Request, Uri};
use tokio_tungstenite::tungstenite::protocol::{
    CloseFrame, WebSocketConfig, frame::coding::CloseCode,
};
use tokio_tungstenite::{WebSocketStream, accept_async_with_config, client_async_with_config};
use tracing::trace;

use crate::error::TransportError;
use crate::tls::install_default_crypto_provider;

/// Hard cap on a single Hermod wire message.
///
/// Hermod's largest legitimate envelope is a brief / broadcast at 4 KiB body
/// plus envelope metadata, signatures, and capability tokens — well under
/// 16 KiB in practice. 256 KiB gives ~16× headroom for protocol evolution
/// and CBOR overhead while denying remote peers the ability to allocate
/// arbitrary memory just by sending a giant frame. Sized in bytes so it
/// matches `tungstenite::WebSocketConfig::max_message_size` directly.
const MAX_WS_MESSAGE_BYTES: usize = 256 * 1024;

fn ws_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(MAX_WS_MESSAGE_BYTES))
        .max_frame_size(Some(MAX_WS_MESSAGE_BYTES))
}

/// Hot-swappable handle to the listener's TLS acceptor. Holding it
/// behind `RwLock<Arc<…>>` lets `accept` take a cheap read-clone of
/// the current `Arc<TlsAcceptor>` while a parallel `reload` swaps the
/// inner Arc under a brief write lock. In-flight TLS handshakes
/// continue with the version they captured at handshake start; new
/// handshakes use the freshly-installed material.
pub type SharedTlsAcceptor = Arc<RwLock<Arc<TlsAcceptor>>>;

/// Build a `rustls::ServerConfig` and wrap it for shared, hot-swappable
/// access. Pulled out of `bind_tls` so `reload_tls` can reuse the same
/// PEM-parse + config-build path without duplicating the rustls plumbing.
fn build_acceptor(cert_pem: &str, key_pem: &str) -> Result<TlsAcceptor, TransportError> {
    install_default_crypto_provider();
    let cert_chain = crate::tls::parse_cert_chain(cert_pem)?;
    let key = crate::tls::parse_private_key(key_pem)?;
    let server_config =
        rustls::ServerConfig::builder_with_protocol_versions(crate::tls::PROTOCOL_VERSIONS)
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .map_err(|e| TransportError::WebSocket(format!("rustls server config: {e}")))?;
    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

/// Server-side accept loop. Plain TCP unless `bind_tls` was used.
pub struct WsListener {
    tcp: TcpListener,
    tls: Option<SharedTlsAcceptor>,
}

impl std::fmt::Debug for WsListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WsListener")
            .field("tls", &self.tls.is_some())
            .field("local_addr", &self.tcp.local_addr().ok())
            .finish_non_exhaustive()
    }
}

impl WsListener {
    pub async fn bind(addr: SocketAddr) -> Result<Self, TransportError> {
        let tcp = TcpListener::bind(addr).await?;
        Ok(Self { tcp, tls: None })
    }

    /// Bind a TLS-wrapped listener. `cert_pem` / `key_pem` are typically
    /// loaded from `$HERMOD_HOME/host/tls.{crt,key}` via
    /// `hermod_crypto::TlsMaterial`. The acceptor is held behind a
    /// shared handle so callers (e.g. `WssNoiseTransport::reload_tls`)
    /// can hot-swap the cert chain without rebinding the socket.
    pub async fn bind_tls(
        addr: SocketAddr,
        cert_pem: &str,
        key_pem: &str,
    ) -> Result<Self, TransportError> {
        let acceptor = build_acceptor(cert_pem, key_pem)?;
        let tcp = TcpListener::bind(addr).await?;
        Ok(Self {
            tcp,
            tls: Some(Arc::new(RwLock::new(Arc::new(acceptor)))),
        })
    }

    /// Bind a TLS-wrapped listener using a caller-provided
    /// [`SharedTlsAcceptor`] so multiple sites (typically the
    /// `WssNoiseTransport` and its listener) can share one rotation
    /// point. Calling [`Self::reload_tls`] on either end swaps the cert
    /// chain everywhere the same handle is referenced.
    pub async fn bind_tls_shared(
        addr: SocketAddr,
        acceptor: SharedTlsAcceptor,
    ) -> Result<Self, TransportError> {
        let tcp = TcpListener::bind(addr).await?;
        Ok(Self {
            tcp,
            tls: Some(acceptor),
        })
    }

    /// Hot-rotate the inbound TLS material. Parses + validates the new
    /// PEM and atomically swaps the acceptor; existing in-flight
    /// connections keep their handshake's pinned acceptor reference,
    /// new accepts use the swapped one.
    pub async fn reload_tls(&self, cert_pem: &str, key_pem: &str) -> Result<(), TransportError> {
        let Some(slot) = &self.tls else {
            return Err(TransportError::WebSocket(
                "listener is plain TCP — reload_tls has nothing to swap".into(),
            ));
        };
        let new_acceptor = Arc::new(build_acceptor(cert_pem, key_pem)?);
        let mut guard = slot.write().await;
        *guard = new_acceptor;
        Ok(())
    }

    /// Shared handle to the current acceptor — clone-cheap, used by
    /// callers that want to share the rotation point across multiple
    /// listener sites.
    pub fn shared_tls_acceptor(&self) -> Option<SharedTlsAcceptor> {
        self.tls.clone()
    }

    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        Ok(self.tcp.local_addr()?)
    }

    pub async fn accept(&self) -> Result<WsStream, TransportError> {
        let (tcp, addr) = self.accept_tcp().await?;
        self.handshake(tcp, addr).await
    }

    /// TCP-only accept. Returns the raw socket plus peer address so the
    /// caller can rate-limit / count permits *before* the (potentially
    /// slow) TLS + WS handshake runs. The caller must invoke
    /// [`Self::handshake`] to finish the connection.
    pub async fn accept_tcp(&self) -> Result<(TcpStream, SocketAddr), TransportError> {
        let (tcp, addr) = self.tcp.accept().await?;
        trace!(peer = %addr, tls = self.tls.is_some(), "ws accept (tcp)");
        Ok((tcp, addr))
    }

    /// Run the TLS (if configured) and WebSocket upgrade handshakes on a
    /// pre-accepted TCP socket. Splits the cost from `accept_tcp` so a
    /// slow peer can't tie up the accept loop — the handshake runs in
    /// whatever task context the caller picks (typically a spawned task
    /// holding a concurrency-limit permit).
    pub async fn handshake(
        &self,
        tcp: TcpStream,
        addr: SocketAddr,
    ) -> Result<WsStream, TransportError> {
        let _ = addr; // address already logged by accept_tcp; reserved for future tracing/metrics
        match &self.tls {
            None => {
                let ws = accept_async_with_config(InnerStream::Plain(tcp), Some(ws_config()))
                    .await
                    .map_err(|e| TransportError::WebSocket(e.to_string()))?;
                Ok(WsStream {
                    inner: ws,
                    peer_tls_fingerprint: None,
                })
            }
            Some(slot) => {
                // Capture a clone of the current acceptor under the
                // read lock, then drop the lock before the handshake
                // (which can take seconds with a slow client). A
                // concurrent `reload_tls` write-lock therefore
                // blocks at most one accept_tcp's worth of time, not
                // a full TLS round-trip.
                let acceptor = {
                    let guard = slot.read().await;
                    guard.clone()
                };
                let tls = acceptor
                    .accept(tcp)
                    .await
                    .map_err(|e| TransportError::WebSocket(format!("tls accept: {e}")))?;
                let ws = accept_async_with_config(
                    InnerStream::TlsServer(Box::new(tls)),
                    Some(ws_config()),
                )
                .await
                .map_err(|e| TransportError::WebSocket(e.to_string()))?;
                Ok(WsStream {
                    inner: ws,
                    // Server side does not request client certs; mutual auth runs at Noise.
                    peer_tls_fingerprint: None,
                })
            }
        }
    }
}

/// Plain (no-TLS) WebSocket connect — testing only.
pub async fn connect(host: &str, port: u16) -> Result<WsStream, TransportError> {
    let stream = TcpStream::connect((host, port)).await?;
    let request = build_ws_request(host, port)?;
    let (ws, _resp) =
        client_async_with_config(request, InnerStream::Plain(stream), Some(ws_config()))
            .await
            .map_err(|e| TransportError::WebSocket(e.to_string()))?;
    Ok(WsStream {
        inner: ws,
        peer_tls_fingerprint: None,
    })
}

/// TLS-wrapped WebSocket connect with the *insecure* policy: any cert
/// is accepted, the SHA-256 fingerprint is captured for routing-layer
/// pinning. Equivalent to `connect_tls_with_policy(host, port,
/// &TlsPinPolicy::Insecure)`. Kept for callers that want the lowest-
/// friction default; everyone else picks an explicit policy.
pub async fn connect_tls(host: &str, port: u16) -> Result<WsStream, TransportError> {
    connect_tls_with_policy(host, port, &crate::pin::TlsPinPolicy::Insecure).await
}

/// TLS-wrapped WebSocket connect with an explicit pin policy. The
/// rustls verifier is built from `policy`; `TlsPinPolicy::Tofu` writes
/// to its store on first contact and fails loud on subsequent
/// mismatch, `PublicCa` validates against the OS root store, etc.
pub async fn connect_tls_with_policy(
    host: &str,
    port: u16,
    policy: &crate::pin::TlsPinPolicy,
) -> Result<WsStream, TransportError> {
    install_default_crypto_provider();
    let stream = TcpStream::connect((host, port)).await?;
    let config = policy.build_client_config()?;
    let connector = TlsConnector::from(Arc::new(config));
    let server_name = rustls_pki_types::ServerName::try_from(host.to_string())
        .map_err(|e| TransportError::WebSocket(format!("invalid server name: {e}")))?;
    let tls = connector
        .connect(server_name, stream)
        .await
        .map_err(|e| TransportError::WebSocket(format!("tls handshake: {e}")))?;

    // Capture the cert fingerprint before consuming the TlsStream.
    // Surfaced even when the verifier is `Insecure` so callers (Noise
    // TOFU) can pin at their own layer.
    let peer_tls_fingerprint = tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certs| certs.first())
        .map(|c| hermod_crypto::sha256_fingerprint(c.as_ref()));

    let request = build_ws_request(host, port)?;
    let (ws, _resp) = client_async_with_config(
        request,
        InnerStream::TlsClient(Box::new(tls)),
        Some(ws_config()),
    )
    .await
    .map_err(|e| TransportError::WebSocket(e.to_string()))?;
    Ok(WsStream {
        inner: ws,
        peer_tls_fingerprint,
    })
}

fn build_ws_request(host: &str, port: u16) -> Result<Request<()>, TransportError> {
    let uri: Uri = format!("ws://{host}:{port}/hermod").parse().map_err(
        |e: tokio_tungstenite::tungstenite::http::uri::InvalidUri| {
            TransportError::WebSocket(e.to_string())
        },
    )?;
    let host_header = uri
        .host()
        .ok_or_else(|| TransportError::WebSocket("missing host".into()))?
        .to_string();
    Request::builder()
        .uri(uri)
        .header("Host", host_header)
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header("Sec-WebSocket-Key", generate_key())
        .body(())
        .map_err(|e| TransportError::WebSocket(e.to_string()))
}

/// Tagged inner stream — TcpStream / server-TLS / client-TLS. All three are
/// `Unpin`, so we project through `Pin::get_mut` without unsafe code.
#[derive(Debug)]
pub enum InnerStream {
    Plain(TcpStream),
    TlsServer(Box<ServerTlsStream<TcpStream>>),
    TlsClient(Box<ClientTlsStream<TcpStream>>),
}

impl AsyncRead for InnerStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this {
            InnerStream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            InnerStream::TlsServer(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
            InnerStream::TlsClient(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for InnerStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match this {
            InnerStream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            InnerStream::TlsServer(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
            InnerStream::TlsClient(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this {
            InnerStream::Plain(s) => Pin::new(s).poll_flush(cx),
            InnerStream::TlsServer(s) => Pin::new(s.as_mut()).poll_flush(cx),
            InnerStream::TlsClient(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this {
            InnerStream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            InnerStream::TlsServer(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
            InnerStream::TlsClient(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

pub struct WsStream {
    inner: WebSocketStream<InnerStream>,
    peer_tls_fingerprint: Option<String>,
}

impl std::fmt::Debug for WsStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WsStream")
            .field("peer_tls_fingerprint", &self.peer_tls_fingerprint)
            .finish_non_exhaustive()
    }
}

impl WsStream {
    /// SHA-256 fingerprint of the peer's TLS cert (only set on TLS clients).
    pub fn peer_tls_fingerprint(&self) -> Option<&str> {
        self.peer_tls_fingerprint.as_deref()
    }

    pub async fn send_binary(&mut self, bytes: Vec<u8>) -> Result<(), TransportError> {
        self.inner
            .send(Message::Binary(bytes.into()))
            .await
            .map_err(|e| TransportError::WebSocket(e.to_string()))
    }

    /// Read the next binary frame. Returns `Ok(None)` on clean close.
    pub async fn recv_binary(&mut self) -> Result<Option<Vec<u8>>, TransportError> {
        loop {
            let msg = match self.inner.next().await {
                Some(Ok(m)) => m,
                Some(Err(e)) => return Err(TransportError::WebSocket(e.to_string())),
                None => return Ok(None),
            };
            match msg {
                Message::Binary(b) => return Ok(Some(b.to_vec())),
                Message::Ping(p) => {
                    self.inner
                        .send(Message::Pong(p))
                        .await
                        .map_err(|e| TransportError::WebSocket(e.to_string()))?;
                    continue;
                }
                Message::Pong(_) => continue,
                Message::Close(_) => return Ok(None),
                Message::Text(_) => return Err(TransportError::NotBinary),
                Message::Frame(_) => continue,
            }
        }
    }

    pub async fn close(&mut self) -> Result<(), TransportError> {
        let frame = Some(CloseFrame {
            code: CloseCode::Normal,
            reason: "bye".into(),
        });
        self.inner
            .close(frame)
            .await
            .map_err(|e| TransportError::WebSocket(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ws_loopback_send_recv_binary() {
        let listener = WsListener::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let mut s = listener.accept().await.unwrap();
            let frame = s.recv_binary().await.unwrap().unwrap();
            assert_eq!(&frame, b"hello");
            s.send_binary(b"world".to_vec()).await.unwrap();
            s.close().await.ok();
        });

        let mut c = connect(&addr.ip().to_string(), addr.port()).await.unwrap();
        c.send_binary(b"hello".to_vec()).await.unwrap();
        let resp = c.recv_binary().await.unwrap().unwrap();
        assert_eq!(&resp, b"world");

        server.await.unwrap();
    }

    #[tokio::test]
    async fn wss_loopback_with_tls() {
        use hermod_crypto::{Keypair, TlsMaterial};
        let kp = Keypair::generate();
        let tls = TlsMaterial::generate(&kp.agent_id()).unwrap();

        let listener =
            WsListener::bind_tls("127.0.0.1:0".parse().unwrap(), &tls.cert_pem, &tls.key_pem)
                .await
                .unwrap();
        let addr = listener.local_addr().unwrap();
        let expected_fp = tls.fingerprint.clone();

        let server = tokio::spawn(async move {
            let mut s = listener.accept().await.unwrap();
            let frame = s.recv_binary().await.unwrap().unwrap();
            assert_eq!(&frame, b"hi over tls");
            s.send_binary(b"hi back".to_vec()).await.unwrap();
            s.close().await.ok();
        });

        let mut c = connect_tls("127.0.0.1", addr.port()).await.unwrap();
        assert_eq!(c.peer_tls_fingerprint(), Some(expected_fp.as_str()));
        c.send_binary(b"hi over tls".to_vec()).await.unwrap();
        let resp = c.recv_binary().await.unwrap().unwrap();
        assert_eq!(&resp, b"hi back");

        server.await.unwrap();
    }

    #[tokio::test]
    async fn reload_tls_swaps_acceptor_and_new_client_sees_new_fingerprint() {
        use hermod_crypto::{Keypair, TlsMaterial};
        let kp = Keypair::generate();
        let original = TlsMaterial::generate(&kp.agent_id()).unwrap();
        let rotated = TlsMaterial::generate(&kp.agent_id()).unwrap();
        // Self-signed certs from `TlsMaterial::generate` are nondeterministic
        // (random serial), so the fingerprints differ — that's what we
        // assert against.
        assert_ne!(original.fingerprint, rotated.fingerprint);

        let listener = WsListener::bind_tls(
            "127.0.0.1:0".parse().unwrap(),
            &original.cert_pem,
            &original.key_pem,
        )
        .await
        .unwrap();
        let addr = listener.local_addr().unwrap();
        let listener = Arc::new(listener);

        // Spawn a single accept loop that handles two connections —
        // before and after the rotate.
        let listener_for_accept = listener.clone();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let mut s = listener_for_accept.accept().await.unwrap();
                let frame = s.recv_binary().await.unwrap().unwrap();
                s.send_binary(frame).await.unwrap();
                s.close().await.ok();
            }
        });

        // First client sees the original cert.
        let mut c1 = connect_tls("127.0.0.1", addr.port()).await.unwrap();
        assert_eq!(
            c1.peer_tls_fingerprint(),
            Some(original.fingerprint.as_str())
        );
        c1.send_binary(b"first".to_vec()).await.unwrap();
        let _ = c1.recv_binary().await.unwrap();

        // Hot-rotate the cert.
        listener
            .reload_tls(&rotated.cert_pem, &rotated.key_pem)
            .await
            .expect("reload_tls succeeds with valid material");

        // Second client sees the rotated cert.
        let mut c2 = connect_tls("127.0.0.1", addr.port()).await.unwrap();
        assert_eq!(
            c2.peer_tls_fingerprint(),
            Some(rotated.fingerprint.as_str())
        );
        c2.send_binary(b"second".to_vec()).await.unwrap();
        let _ = c2.recv_binary().await.unwrap();

        server.await.unwrap();
    }

    #[tokio::test]
    async fn reload_tls_rejects_invalid_pem_and_keeps_previous() {
        use hermod_crypto::{Keypair, TlsMaterial};
        let kp = Keypair::generate();
        let original = TlsMaterial::generate(&kp.agent_id()).unwrap();

        let listener = WsListener::bind_tls(
            "127.0.0.1:0".parse().unwrap(),
            &original.cert_pem,
            &original.key_pem,
        )
        .await
        .unwrap();

        let err = listener
            .reload_tls("not a pem", "also not a pem")
            .await
            .expect_err("invalid PEM must reject");
        assert!(format!("{err}").to_lowercase().contains("pem"));

        // The original acceptor is still in place — a fresh client can
        // still connect and present the original fingerprint.
        let addr = listener.local_addr().unwrap();
        let listener = Arc::new(listener);
        let listener_for_accept = listener.clone();
        let server = tokio::spawn(async move {
            let mut s = listener_for_accept.accept().await.unwrap();
            let _ = s.recv_binary().await.unwrap();
            s.send_binary(b"ok".to_vec()).await.unwrap();
            s.close().await.ok();
        });
        let mut c = connect_tls("127.0.0.1", addr.port()).await.unwrap();
        assert_eq!(
            c.peer_tls_fingerprint(),
            Some(original.fingerprint.as_str())
        );
        c.send_binary(b"ping".to_vec()).await.unwrap();
        let _ = c.recv_binary().await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn reload_tls_on_plain_listener_returns_error() {
        let listener = WsListener::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let err = listener
            .reload_tls("ignored", "ignored")
            .await
            .expect_err("plain listener has no acceptor to swap");
        let msg = format!("{err}");
        assert!(
            msg.contains("plain TCP"),
            "expected 'plain TCP' in error, got: {msg}"
        );
    }
}
