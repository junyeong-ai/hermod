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
use hermod_core::{Endpoint, MessageId};
use hermod_crypto::Keypair;
use hermod_protocol::wire::{AckStatus, WireFrame};
use hermod_transport::pin::{PinSpec, TlsPinStore};
use hermod_transport::ws::{SharedTlsAcceptor, WsListener, connect_tls_with_policy};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::peer::PeerConnection;
use crate::transport::{
    PeerIdentity, PeerTransportError, Transport, TransportConnection, TransportListener,
};

/// WSS + Noise XX transport.
///
/// Holds the daemon's *host* keypair: it derives the Noise XX static
/// key for the handshake and is the identity asserted in the
/// post-handshake `Hello` frame. Per-tenant agent keypairs live one
/// layer up (in `LocalAgentRegistry`); they sign envelopes but never
/// participate in the Noise handshake.
///
/// Optional TLS material is required for the listener side; outbound
/// dialing only consumes the keypair. The listener's TLS acceptor
/// lives behind a [`SharedTlsAcceptor`] stored in `tls_state`,
/// populated lazily on the first `listen` call. `reload_tls`
/// rebuilds the acceptor and atomically swaps the inner
/// `Arc<TlsAcceptor>` — in-flight handshakes finish with their
/// pinned acceptor reference, new accepts use the rotated material.
#[derive(Clone)]
pub struct WssNoiseTransport {
    host_keypair: Arc<Keypair>,
    tls_material: Option<(Arc<str>, Arc<str>)>,
    tls_state: Arc<Mutex<Option<SharedTlsAcceptor>>>,
    /// Outbound TLS verification spec. The `Tofu` arm needs the
    /// per-dial `host:port` to key its store, so the spec stays in
    /// its operator-string form here and is materialised to a
    /// `TlsPinPolicy` once per dial. Default: `Insecure` —
    /// federation relies on Noise XX for cryptographic peer auth
    /// regardless. Operators running through a public-CA-fronted
    /// broker (Cloud Run, IAP, Cloudflare Access) set `PublicCa`.
    dial_pin: Arc<PinSpec>,
    /// TOFU pin store, used only when `dial_pin == PinSpec::Tofu`.
    /// Each dial materialises a per-host_port `TlsPinPolicy::Tofu`
    /// so a single transport handles many peers.
    pin_store: TlsPinStore,
}

impl std::fmt::Debug for WssNoiseTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WssNoiseTransport")
            .field("listen_capable", &self.tls_material.is_some())
            .field("dial_pin", &spec_label(&self.dial_pin))
            .finish_non_exhaustive()
    }
}

fn spec_label(spec: &PinSpec) -> &'static str {
    match spec {
        PinSpec::Tofu => "tofu",
        PinSpec::PublicCa => "public-ca",
        PinSpec::Insecure => "insecure",
        PinSpec::Fingerprint(_) => "fingerprint",
    }
}

impl WssNoiseTransport {
    /// Outbound-only constructor — no TLS material, `listen` returns an
    /// error. Used by daemons running pure outbound federation
    /// (e.g. mobile clients that never accept inbound). `pin_store`
    /// is consulted only under TOFU policy; pass an unused store
    /// when running with `PublicCa` / `Insecure` / `Fingerprint`.
    pub fn outbound_only(host_keypair: Arc<Keypair>, pin_store: TlsPinStore) -> Self {
        Self {
            host_keypair,
            tls_material: None,
            tls_state: Arc::new(Mutex::new(None)),
            dial_pin: Arc::new(PinSpec::Insecure),
            pin_store,
        }
    }

    /// Full constructor: outbound + inbound. `cert_pem` / `key_pem` are
    /// the daemon's self-signed TLS material (see
    /// `hermod_crypto::TlsMaterial`). Outbound dial verification
    /// defaults to `Insecure`; override via [`Self::with_dial_pin`].
    pub fn new(
        host_keypair: Arc<Keypair>,
        cert_pem: Arc<str>,
        key_pem: Arc<str>,
        pin_store: TlsPinStore,
    ) -> Self {
        Self {
            host_keypair,
            tls_material: Some((cert_pem, key_pem)),
            tls_state: Arc::new(Mutex::new(None)),
            dial_pin: Arc::new(PinSpec::Insecure),
            pin_store,
        }
    }

    /// Replace the outbound dial pin spec. Server-side `accept` is
    /// unaffected (peers verify our cert at *their* layer).
    pub fn with_dial_pin(mut self, spec: PinSpec) -> Self {
        self.dial_pin = Arc::new(spec);
        self
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
            host_keypair: self.host_keypair.clone(),
        }))
    }

    async fn reload_tls(&self, cert_pem: &str, key_pem: &str) -> Result<(), PeerTransportError> {
        if self.tls_material.is_none() {
            return Err(PeerTransportError::Backend(
                "WssNoiseTransport configured outbound-only — reload_tls has nothing to swap"
                    .into(),
            ));
        }
        let mut guard = self.tls_state.lock().await;
        if let Some(shared) = guard.as_ref() {
            let validator = hermod_transport::ws::WsListener::bind_tls_shared(
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
            let throwaway = hermod_transport::ws::WsListener::bind_tls(
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
        let host_port = format!("{host}:{port}");
        let policy = (*self.dial_pin)
            .clone()
            .resolve(self.pin_store.clone(), host_port);
        let ws = connect_tls_with_policy(&host, port, &policy)
            .await
            .map_err(|e| PeerTransportError::Io(e.to_string()))?;
        let tls_fp = ws.peer_tls_fingerprint().map(|s| s.to_string());

        let noise = self.host_keypair.noise_static_key();
        let conn = PeerConnection::handshake_outbound(
            ws,
            noise.private_bytes(),
            self.host_keypair.to_pubkey_bytes(),
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
    host_keypair: Arc<Keypair>,
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

        let noise = self.host_keypair.noise_static_key();
        let conn = PeerConnection::handshake_inbound(
            ws,
            noise.private_bytes(),
            self.host_keypair.to_pubkey_bytes(),
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
/// concrete `PeerConnection` and exposes its post-handshake host
/// identity through [`PeerIdentity`].
#[derive(Debug)]
struct WssNoiseConnection {
    inner: PeerConnection,
    identity: PeerIdentity,
}

impl WssNoiseConnection {
    fn new(inner: PeerConnection, tls_fingerprint: Option<String>) -> Self {
        let identity = PeerIdentity {
            host_id: inner.remote_host_id.clone(),
            host_pubkey: inner.remote_host_pubkey,
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
