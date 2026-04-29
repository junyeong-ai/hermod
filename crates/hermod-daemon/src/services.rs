//! Unified ServiceError type and module re-exports.

pub mod agent;
pub mod audit;
pub mod audit_remote;
pub mod beacon_audit;
pub mod brief;
pub mod broadcast;
pub mod broker;
pub mod capability;
pub mod channel;
pub mod confirmation;
pub mod fanout;
pub mod mcp;
pub mod message;
pub mod peer;
pub mod permission;
pub mod permission_relay;
pub mod presence;
pub mod status;
pub mod workspace;
pub mod workspace_observability;

use hermod_crypto::CryptoError;
use hermod_routing::RoutingError;
use hermod_storage::{AuditEntry, AuditSink, BlobError, StorageError};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error(transparent)]
    Storage(#[from] StorageError),

    #[error(transparent)]
    Blob(#[from] BlobError),

    #[error(transparent)]
    Routing(#[from] RoutingError),

    #[error(transparent)]
    Crypto(#[from] CryptoError),

    #[error("invalid param: {0}")]
    InvalidParam(String),

    #[error("not found")]
    NotFound,
}

/// Append an audit entry, overlaying the ambient client IP from
/// [`crate::audit_context`] when the call site left the field as
/// `None`. Every emission goes through this helper so the client-IP
/// resolution at the IPC entry point reaches every audit row inside
/// the connection's task tree without threading a parameter through
/// every service method.
///
/// Sites that already have a more specific IP (e.g. federation
/// inbound that records the cryptographically-verified peer) set
/// `client_ip: Some(_)` directly and the enrichment is a no-op.
/// Daemon-internal sites (outbox, janitor) leave `client_ip: None`;
/// running outside any connection scope, the lookup also returns
/// `None`, and the row records "no remote client".
///
/// Failure handling lives inside the sink impl (`StorageAuditSink`
/// converts append errors to a `tracing::warn`); this helper just
/// enriches and forwards.
pub async fn audit_or_warn(sink: &dyn AuditSink, mut entry: AuditEntry) {
    if entry.client_ip.is_none() {
        entry.client_ip = crate::audit_context::current_client_ip();
    }
    sink.record(entry).await;
}

pub use agent::AgentService;
pub use audit::AuditService;
pub use audit_remote::RemoteAuditSink;
pub use beacon_audit::AuditSinkBeaconAuditor;
pub use brief::BriefService;
pub use broadcast::BroadcastService;
pub use broker::{BrokerService, RelayOutcome};
pub use capability::CapabilityService;
pub use channel::ChannelService;
pub use confirmation::ConfirmationService;
pub use mcp::McpService;
pub use message::MessageService;
pub use peer::PeerService;
pub use permission::PermissionService;
pub use permission_relay::{CapabilityPromptForwarder, MessageRelayResponder};
pub use presence::PresenceService;
pub use status::{KeyRef, StatusService};
pub use workspace::WorkspaceService;
pub use workspace_observability::WorkspaceObservabilityService;

use hermod_crypto::Keypair;
use hermod_storage::{AgentRecord, Database};

/// Ensure the daemon's own identity is registered in the agents table with
/// `trust=self`. The operator-set alias from `[identity] alias` is stored as
/// `local_alias` (operator's own label for themselves); `peer_asserted_alias`
/// is left unset for self because we don't observe ourselves over federation.
pub async fn ensure_self_agent(
    db: &dyn Database,
    keypair: &Keypair,
    alias: Option<hermod_core::AgentAlias>,
) -> anyhow::Result<()> {
    let now = hermod_core::Timestamp::now();
    db.agents()
        .upsert(&AgentRecord {
            id: keypair.agent_id(),
            pubkey: keypair.to_pubkey_bytes(),
            host_pubkey: None,
            endpoint: None,
            local_alias: alias,
            peer_asserted_alias: None,
            trust_level: hermod_core::TrustLevel::Local,
            tls_fingerprint: None,
            reputation: 0,
            first_seen: now,
            last_seen: Some(now),
        })
        .await?;
    Ok(())
}
