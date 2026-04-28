//! Federation transport abstraction.
//!
//! The daemon depends on three traits and lets each backend implement
//! whatever wire protocol is appropriate:
//!
//!   * [`Transport`] — factory. Knows how to listen on an address and
//!     dial an endpoint. Holds the long-lived material (signer, alias)
//!     a backend needs to perform handshakes.
//!
//!   * [`TransportListener`] — accept loop. Returns the next inbound
//!     [`TransportConnection`] whose mutual handshake has already completed,
//!     so the application layer never sees pre-auth bytes.
//!
//!   * [`TransportConnection`] — bidirectional [`WireFrame`] stream over an
//!     authenticated, encrypted channel. Exposes the post-handshake
//!     peer identity and (where applicable) the TLS fingerprint for
//!     TOFU pinning.
//!
//! Current production backend is `hermod_routing::wss_noise::WssNoiseTransport`
//! (WSS + Noise XX). Future backends — gRPC over mTLS, raw TCP for
//! in-cluster federation, QUIC — slot in by implementing these three
//! traits; the daemon picks one at startup and consumes
//! `Arc<dyn Transport>`.

use async_trait::async_trait;
use hermod_core::{AgentAlias, AgentId, Endpoint, MessageId, PubkeyBytes};
use hermod_protocol::wire::{AckStatus, WireFrame};
use std::net::SocketAddr;
use thiserror::Error;

/// Error type every transport backend reports.
///
/// Higher-level mapping (`TlsFingerprintMismatch`, etc.) lives in
/// `hermod_routing::RoutingError`, which converts from this. Backends
/// stay free of routing-specific semantics.
#[derive(Debug, Error)]
pub enum PeerTransportError {
    #[error("handshake: {0}")]
    Handshake(String),

    #[error("io: {0}")]
    Io(String),

    #[error("encoding: {0}")]
    Encoding(String),

    #[error("closed by peer")]
    Closed,

    #[error("backend: {0}")]
    Backend(String),
}

/// Identity + handshake metadata observed during the initial mutual
/// authentication. Returned alongside every freshly-established
/// connection so the caller can record peer state without
/// down-casting.
#[derive(Debug, Clone)]
pub struct PeerIdentity {
    pub agent_id: AgentId,
    pub agent_pubkey: PubkeyBytes,
    /// Self-asserted display name. Advisory only — operators use
    /// `peer add --alias` to set the routable `local_alias`.
    pub alias: Option<AgentAlias>,
    /// Optional TLS cert fingerprint for backends that wrap TLS
    /// (e.g. WSS+Noise, gRPC over mTLS). `None` for plaintext or
    /// non-TLS backends. Used by the routing layer for TOFU pinning.
    pub tls_fingerprint: Option<String>,
}

/// Bidirectional [`WireFrame`] stream over an authenticated channel.
///
/// Object-safe so the daemon can hold `Box<dyn TransportConnection>`
/// without depending on a backend type. All I/O is `&mut` to enforce
/// single-owner per direction; concurrent senders should serialise
/// through a per-peer mutex (see `hermod_routing::PeerPool`).
#[async_trait]
pub trait TransportConnection: Send + Sync + std::fmt::Debug {
    /// Identity of the remote peer as observed during the handshake.
    /// Stable for the lifetime of the connection.
    fn identity(&self) -> &PeerIdentity;

    /// Send one wire frame. Returns once the bytes are handed off to
    /// the underlying transport (no application-level ack here — those
    /// are explicit `WireFrame::DeliveryAck` payloads).
    async fn send_frame(&mut self, frame: &WireFrame) -> Result<(), PeerTransportError>;

    /// Receive the next wire frame. `Ok(None)` means the peer closed
    /// cleanly; `Err` is reserved for transport-level failure.
    async fn recv_frame(&mut self) -> Result<Option<WireFrame>, PeerTransportError>;

    /// Convenience for the common ack response. Backends may implement
    /// this directly if a fused send is cheaper, but the default
    /// implementation calls `send_frame` with the `DeliveryAck` variant.
    async fn send_ack(
        &mut self,
        message_id: MessageId,
        status: AckStatus,
        reason: Option<String>,
    ) -> Result<(), PeerTransportError> {
        self.send_frame(&WireFrame::DeliveryAck(
            hermod_protocol::wire::DeliveryAck {
                message_id,
                status,
                reason,
            },
        ))
        .await
    }

    /// Close the connection. Idempotent; double-close is a no-op.
    /// Consumes `self` because the connection is single-use after close.
    async fn close(self: Box<Self>);
}

/// Stream of inbound connections from a [`Transport::listen`] call.
/// One backend per listener; the daemon spawns the listener once at
/// startup and pulls connections off it via `accept`.
#[async_trait]
pub trait TransportListener: Send + Sync + std::fmt::Debug {
    /// Block until the next inbound peer completes its handshake.
    /// Returns the authenticated [`TransportConnection`]. Errors here are
    /// terminal for the listener — the caller should log and reattempt
    /// `listen` rather than calling `accept` again.
    async fn accept(&self) -> Result<Box<dyn TransportConnection>, PeerTransportError>;

    /// Local bound address. Mostly useful for tests that bind `:0`.
    fn local_addr(&self) -> Result<SocketAddr, PeerTransportError>;
}

/// Factory for the listener + dialer halves of a federation transport.
/// The daemon constructs one `Arc<dyn Transport>` at startup; both the
/// `FederationServer` (calls `listen`) and the `PeerPool` (calls `dial`)
/// share it.
#[async_trait]
pub trait Transport: Send + Sync + std::fmt::Debug + 'static {
    /// Backend name for logging / metrics labels.
    fn name(&self) -> &'static str;

    /// Open the inbound listener bound to `addr`. Returns once the
    /// socket is bound (handshakes happen lazily inside `accept`).
    async fn listen(
        &self,
        addr: SocketAddr,
    ) -> Result<Box<dyn TransportListener>, PeerTransportError>;

    /// Dial `endpoint`, run the mutual handshake, return the
    /// authenticated connection. Caller is responsible for any
    /// post-handshake policy (TLS fingerprint TOFU, peer state
    /// upsert, etc.) using the metadata exposed via `identity()`.
    async fn dial(
        &self,
        endpoint: &Endpoint,
    ) -> Result<Box<dyn TransportConnection>, PeerTransportError>;

    /// Hot-rotate the inbound TLS material without restarting the
    /// daemon or disrupting any in-flight connections.
    ///
    /// `cert_pem` and `key_pem` are PEM-encoded; backends parse +
    /// validate them and atomically swap the listener's acceptor.
    /// Outbound dialing is unaffected (each `dial` builds a fresh
    /// client side from the system trust store).
    ///
    /// Default impl returns `Backend("not supported")` — backends
    /// that don't terminate TLS (raw TCP, in-process test transport,
    /// gRPC delegating TLS to a sidecar) leave it unimplemented.
    async fn reload_tls(&self, _cert_pem: &str, _key_pem: &str) -> Result<(), PeerTransportError> {
        Err(PeerTransportError::Backend(
            "transport does not support TLS hot-rotate".into(),
        ))
    }
}
