//! WSS + Noise XX implementation of the federation [`Transport`] trait.
//!
//! Wraps the existing `PeerConnection` (WebSocket-over-TLS + Noise XX
//! handshake) behind the [`Transport`] / [`TransportListener`] /
//! [`TransportConnection`] traits so the daemon can construct
//! `Arc<dyn Transport>` and stay backend-agnostic.
//!
//! Future cousins (`GrpcMtlsTransport`, `QuicTransport`, etc.) implement
//! the same trio of traits and slot in without changing PeerPool or
//! FederationServer.

use async_trait::async_trait;
use hermod_core::{AgentAlias, Endpoint, MessageId, PubkeyBytes};
use hermod_crypto::Keypair;
use hermod_protocol::wire::{AckStatus, WireFrame};
use hermod_transport::ws::{SharedTlsAcceptor, WsListener, connect_tls};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::peer::PeerConnection;
use crate::transport::{
    PeerIdentity, PeerTransportError, Transport, TransportConnection, TransportListener,
};

/// WSS + Noise XX transport.
///
/// Holds the daemon's keypair (used for the Noise handshake's static
/// key derivation and for the post-handshake `Hello` frame the peer
/// uses to bind agent_id ↔ noise pubkey) plus the operator-set alias.
/// Optional TLS material is required for the listener side; outbound
/// dialing only consumes the keypair.
///
/// The listener's TLS acceptor lives behind a [`SharedTlsAcceptor`]
/// stored in `tls_state`, populated lazily on the first `listen`
/// call. `reload_tls` rebuilds the acceptor from new PEM and atomically
/// swaps the inner `Arc<TlsAcceptor>` — in-flight handshakes finish
/// with their pinned acceptor reference, new accepts use the rotated
/// material. Same handle is returned to every `listen` caller, so an
/// operator can hot-rotate certs without restarting the daemon.
///
/// Inbound handshake concurrency (`max_inflight_handshakes`) is
/// enforced one layer up by `FederationServer`'s semaphore — flow
/// control is the server's responsibility, not the transport's.
#[derive(Clone)]
pub struct WssNoiseTransport {
    keypair: Arc<Keypair>,
    alias: Option<AgentAlias>,
    /// Original TLS PEM kept around so we can rebuild the acceptor on
    /// the first `listen` call. None disables `listen` entirely
    /// (outbound-only mode).
    tls_material: Option<(Arc<str>, Arc<str>)>,
    /// Shared rotation point. Populated on first `listen()`; subsequent
    /// `listen()` calls reuse the same handle so `reload_tls` is a
    /// single point-of-truth swap for every active listener spawned
    /// from this transport.
    tls_state: Arc<Mutex<Option<SharedTlsAcceptor>>>,
}

impl std::fmt::Debug for WssNoiseTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WssNoiseTransport")
            .field("alias", &self.alias)
            .field("listen_capable", &self.tls_material.is_some())
            .finish_non_exhaustive()
    }
}

impl WssNoiseTransport {
    /// Outbound-only constructor — no TLS material, `listen` returns an
    /// error. Used by daemons running pure outbound federation
    /// (e.g. mobile clients that never accept inbound).
    pub fn outbound_only(keypair: Arc<Keypair>, alias: Option<AgentAlias>) -> Self {
        Self {
            keypair,
            alias,
            tls_material: None,
            tls_state: Arc::new(Mutex::new(None)),
        }
    }

    /// Full constructor: outbound + inbound. `cert_pem` / `key_pem` are
    /// the daemon's self-signed TLS material (see
    /// `hermod_crypto::TlsMaterial`).
    pub fn new(
        keypair: Arc<Keypair>,
        alias: Option<AgentAlias>,
        cert_pem: Arc<str>,
        key_pem: Arc<str>,
    ) -> Self {
        Self {
            keypair,
            alias,
            tls_material: Some((cert_pem, key_pem)),
            tls_state: Arc::new(Mutex::new(None)),
        }
    }
}

#[async_trait]
impl Transport for WssNoiseTransport {
    fn name(&self) -> &'static str {
        "wss-noise"
    }

    async fn listen(
        &self,
        addr: SocketAddr,
    ) -> Result<Box<dyn TransportListener>, PeerTransportError> {
        let (cert_pem, key_pem) = self.tls_material.clone().ok_or_else(|| {
            PeerTransportError::Backend(
                "WssNoiseTransport configured outbound-only — listen() unavailable".into(),
            )
        })?;

        // Reuse the rotation handle if `listen` ran before; otherwise
        // build a fresh one from the configured PEM and store it.
        // The mutex is held only across the bind, not across accepts
        // — accepts read the inner RwLock independently.
        let listener = {
            let mut guard = self.tls_state.lock().await;
            if let Some(shared) = guard.clone() {
                WsListener::bind_tls_shared(addr, shared)
                    .await
                    .map_err(|e| PeerTransportError::Io(e.to_string()))?
            } else {
                let listener = WsListener::bind_tls(addr, &cert_pem, &key_pem)
                    .await
                    .map_err(|e| PeerTransportError::Io(e.to_string()))?;
                if let Some(shared) = listener.shared_tls_acceptor() {
                    *guard = Some(shared);
                }
                listener
            }
        };

        Ok(Box::new(WssNoiseListener {
            inner: Arc::new(listener),
            keypair: self.keypair.clone(),
            alias: self.alias.clone(),
        }))
    }

    async fn reload_tls(
        &self,
        cert_pem: &str,
        key_pem: &str,
    ) -> Result<(), PeerTransportError> {
        if self.tls_material.is_none() {
            return Err(PeerTransportError::Backend(
                "WssNoiseTransport configured outbound-only — reload_tls has nothing to swap".into(),
            ));
        }
        // Validate the new material by building an acceptor against
        // it. If `listen` hasn't run yet we still want a clear
        // success/fail signal here (and the new material becomes the
        // baseline so the next `listen` picks it up). Build a fresh
        // listener-less swap point and stash it.
        let mut guard = self.tls_state.lock().await;
        if let Some(shared) = guard.as_ref() {
            // Reuse the existing handle — `WsListener` doesn't need to
            // mediate the swap; the same `Arc<RwLock<…>>` is held by
            // every active listener spawned from this transport.
            // Build the new acceptor via a throwaway listener so we
            // hit the same parse/validate path.
            let validator =
                hermod_transport::ws::WsListener::bind_tls_shared(
                    "127.0.0.1:0".parse().unwrap(),
                    shared.clone(),
                )
                .await
                .map_err(|e| PeerTransportError::Io(e.to_string()))?;
            validator
                .reload_tls(cert_pem, key_pem)
                .await
                .map_err(|e| PeerTransportError::Backend(e.to_string()))?;
        } else {
            // No active listener yet — just build a new shared handle
            // so the *next* `listen` picks up the rotated material.
            // We do this by binding a throwaway listener on
            // `127.0.0.1:0`, snapshotting its shared acceptor, then
            // dropping the listener (the TCP socket goes away with
            // it; only the `Arc<RwLock<…>>` survives).
            let throwaway =
                hermod_transport::ws::WsListener::bind_tls(
                    "127.0.0.1:0".parse().unwrap(),
                    cert_pem,
                    key_pem,
                )
                .await
                .map_err(|e| PeerTransportError::Io(e.to_string()))?;
            *guard = throwaway.shared_tls_acceptor();
        }
        Ok(())
    }

    async fn dial(
        &self,
        endpoint: &Endpoint,
    ) -> Result<Box<dyn TransportConnection>, PeerTransportError> {
        let (host, port) = match endpoint {
            Endpoint::Wss(w) => (w.host.clone(), w.port),
            Endpoint::Unix { path } => {
                return Err(PeerTransportError::Backend(format!(
                    "wss-noise transport cannot dial unix endpoint {}",
                    path.display()
                )));
            }
        };
        let ws = connect_tls(&host, port)
            .await
            .map_err(|e| PeerTransportError::Io(e.to_string()))?;
        let tls_fp = ws.peer_tls_fingerprint().map(|s| s.to_string());

        let noise = self.keypair.noise_static_key();
        let conn = PeerConnection::handshake_outbound(
            ws,
            noise.private_bytes(),
            self.keypair.to_pubkey_bytes(),
            PubkeyBytes(*noise.public_bytes()),
            self.alias.clone(),
        )
        .await
        .map_err(|e| PeerTransportError::Handshake(e.to_string()))?;

        Ok(Box::new(WssNoiseConnection::new(conn, tls_fp)))
    }
}

/// Inbound listener for [`WssNoiseTransport`]. Handshakes inbound peers
/// inside `accept` so the caller never sees pre-auth bytes.
#[derive(Clone)]
struct WssNoiseListener {
    inner: Arc<WsListener>,
    keypair: Arc<Keypair>,
    alias: Option<AgentAlias>,
}

impl std::fmt::Debug for WssNoiseListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WssNoiseListener").finish_non_exhaustive()
    }
}

#[async_trait]
impl TransportListener for WssNoiseListener {
    async fn accept(&self) -> Result<Box<dyn TransportConnection>, PeerTransportError> {
        let ws = self
            .inner
            .accept()
            .await
            .map_err(|e| PeerTransportError::Io(e.to_string()))?;
        let tls_fp = ws.peer_tls_fingerprint().map(|s| s.to_string());

        let noise = self.keypair.noise_static_key();
        let conn = PeerConnection::handshake_inbound(
            ws,
            noise.private_bytes(),
            self.keypair.to_pubkey_bytes(),
            PubkeyBytes(*noise.public_bytes()),
            self.alias.clone(),
        )
        .await
        .map_err(|e| PeerTransportError::Handshake(e.to_string()))?;

        Ok(Box::new(WssNoiseConnection::new(conn, tls_fp)))
    }

    fn local_addr(&self) -> Result<SocketAddr, PeerTransportError> {
        self.inner
            .local_addr()
            .map_err(|e| PeerTransportError::Io(e.to_string()))
    }
}

/// One authenticated WSS+Noise peer session. Wraps the existing
/// concrete `PeerConnection` and exposes its post-handshake identity
/// through [`PeerIdentity`].
#[derive(Debug)]
struct WssNoiseConnection {
    inner: PeerConnection,
    identity: PeerIdentity,
}

impl WssNoiseConnection {
    fn new(inner: PeerConnection, tls_fingerprint: Option<String>) -> Self {
        let identity = PeerIdentity {
            agent_id: inner.remote_agent_id.clone(),
            agent_pubkey: inner.remote_agent_pubkey,
            alias: inner.remote_alias.clone(),
            tls_fingerprint,
        };
        Self { inner, identity }
    }
}

#[async_trait]
impl TransportConnection for WssNoiseConnection {
    fn identity(&self) -> &PeerIdentity {
        &self.identity
    }

    async fn send_frame(&mut self, frame: &WireFrame) -> Result<(), PeerTransportError> {
        self.inner
            .send_frame(frame)
            .await
            .map_err(|e| PeerTransportError::Io(e.to_string()))
    }

    async fn recv_frame(&mut self) -> Result<Option<WireFrame>, PeerTransportError> {
        self.inner
            .recv_frame()
            .await
            .map_err(|e| PeerTransportError::Io(e.to_string()))
    }

    async fn send_ack(
        &mut self,
        message_id: MessageId,
        status: AckStatus,
        reason: Option<String>,
    ) -> Result<(), PeerTransportError> {
        self.inner
            .send_ack(message_id, status, reason)
            .await
            .map_err(|e| PeerTransportError::Io(e.to_string()))
    }

    async fn close(self: Box<Self>) {
        self.inner.close().await;
    }
}
