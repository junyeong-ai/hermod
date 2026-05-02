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

    /// A `via_agent_id` chain looped back to an already-visited
    /// agent. The dispatch path refuses to forward — the operator's
    /// directory is misconfigured. `chain` lists the visit order
    /// (oldest first) ending at the cycle target so the audit row
    /// can replay the path.
    #[error("via-routing cycle detected: {chain:?}")]
    ViaCycle { chain: Vec<String> },

    /// Chain depth exceeded `MAX_RELAY_HOPS` before reaching a
    /// directly-dialable endpoint. Equivalent to a misconfigured
    /// directory (every broker hop should be at most a couple
    /// deep); fail-loud so the operator notices.
    #[error("via-routing chain exceeded MAX_RELAY_HOPS={limit} (target {target})")]
    ViaTooDeep { target: String, limit: u32 },
}

pub type Result<T, E = RoutingError> = std::result::Result<T, E>;
