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

use hermod_storage::{AgentRecord, Database};

/// Register every locally-hosted agent in the `agents` directory and
/// the `local_agents` sub-relation. Each agent's row carries
/// `host_pubkey = Some(host_pubkey)` so federation peers can resolve
/// "which daemon hosts this agent_id" without a separate lookup.
///
/// The operator-set `[identity] alias` is attached to the *bootstrap*
/// agent — identified by `agent.keypair.pubkey == host_pubkey`, which
/// is the H2 single-tenant invariant (the bootstrap re-uses the host
/// keypair). Selecting by that match instead of by registry index
/// keeps the assignment stable regardless of filesystem ordering;
/// when H5 introduces non-bootstrap agents whose keypairs diverge
/// from `host_pubkey`, those agents correctly receive `None` here
/// and rely on per-agent aliases from `hermod local add --alias`.
///
/// On return the registry's `workspace_root` / `created_at` fields
/// reflect the persisted `local_agents` rows (see
/// [`crate::local_agent::merge_with_db`]).
pub async fn ensure_local_agents(
    db: &dyn Database,
    host_pubkey: hermod_core::PubkeyBytes,
    registry: crate::local_agent::LocalAgentRegistry,
    primary_alias: Option<hermod_core::AgentAlias>,
) -> anyhow::Result<crate::local_agent::LocalAgentRegistry> {
    let now = hermod_core::Timestamp::now();
    for agent in registry.list().iter() {
        let agent_pubkey = agent.keypair.to_pubkey_bytes();
        let alias = if agent_pubkey == host_pubkey {
            primary_alias.clone()
        } else {
            None
        };
        db.agents()
            .upsert(&AgentRecord {
                id: agent.agent_id.clone(),
                pubkey: agent_pubkey,
                host_pubkey: Some(host_pubkey),
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
    }
    crate::local_agent::merge_with_db(db, registry).await
}
