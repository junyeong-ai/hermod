use thiserror::Error;

#[derive(Debug, Error)]
pub enum RoutingError {
    #[error(transparent)]
    Storage(#[from] hermod_storage::StorageError),

    #[error(transparent)]
    Core(#[from] hermod_core::HermodError),

    #[error("recipient not found: {0}")]
    RecipientNotFound(String),

    #[error("blocked by recipient")]
    Blocked,

    #[error("rate limit exceeded")]
    RateLimited,

    #[error("not authorized: {0}")]
    Unauthorized(String),

    #[error("federation: {0}")]
    Federation(String),

    #[error("transport: {0}")]
    Transport(#[from] hermod_transport::TransportError),

    #[error("handshake: {0}")]
    Handshake(#[from] hermod_protocol::handshake::HandshakeError),

    #[error("wire: {0}")]
    Wire(#[from] hermod_protocol::wire::WireError),

    #[error("crypto: {0}")]
    Crypto(#[from] hermod_crypto::CryptoError),

    #[error("peer pubkey mismatch (expected {expected}, got {actual})")]
    PeerPubkeyMismatch { expected: String, actual: String },

    #[error("tls fingerprint mismatch for peer {peer}: stored differs from observed {observed}")]
    TlsFingerprintMismatch { peer: String, observed: String },

    #[error("tls fingerprint TOFU lookup failed for peer {peer}: {detail}")]
    TofuLookupFailed { peer: String, detail: String },

    #[error("delivery rejected: {0}")]
    Rejected(String),

    #[error("timed out waiting for ack")]
    AckTimeout,

    #[error("peer link is dead (heartbeat timed out)")]
    DeadLink,
}

pub type Result<T, E = RoutingError> = std::result::Result<T, E>;
