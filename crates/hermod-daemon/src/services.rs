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
pub mod local_agent;
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

    /// A unique constraint or live-state invariant rejected the
    /// operation. Maps to JSON-RPC `code::CONFLICT` (-32005).
    #[error("conflict: {0}")]
    Conflict(String),
}

/// Append an audit entry, overlaying ambient context from
/// [`crate::audit_context`] onto fields the call site couldn't fill.
/// Every emission goes through this helper so context resolution at
/// the IPC entry point reaches every audit row inside the connection's
/// task tree without threading parameters through every service
/// method.
///
/// Two overlays apply:
///
/// 1. **Client IP** — sites set `client_ip: None` and the helper
///    overlays the ambient IP from the remote-IPC handshake's
///    XFF-resolved value. Sites that already have a more specific IP
///    (e.g. federation inbound that records the cryptographically-
///    verified peer) set `client_ip: Some(_)` directly and the
///    enrichment is a no-op.
/// 2. **Actor** — when an IPC scope's [`current_caller_agent`] is
///    `Some(agent)`, the helper overrides whatever `actor` the literal
///    carried (the host id, by convention) with the calling agent.
///    Daemon-internal sites (outbox, janitor, federation accept) run
///    outside any IPC scope, so `current_caller_agent` returns `None`
///    and the literal's `actor` (host_id) stays put.
///
/// Failure handling lives inside the sink impl (`StorageAuditSink`
/// converts append errors to a `tracing::warn`); this helper just
/// enriches and forwards.
pub async fn audit_or_warn(sink: &dyn AuditSink, mut entry: AuditEntry) {
    if entry.client_ip.is_none() {
        entry.client_ip = crate::audit_context::current_client_ip();
    }
    if let Some(caller) = crate::audit_context::current_caller_agent() {
        entry.actor = caller;
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
pub use local_agent::{LocalAgentService, LocalDiscoverHook};
pub use mcp::McpService;
pub use message::MessageService;
pub use peer::PeerService;
pub use permission::PermissionService;
pub use permission_relay::{CapabilityPromptForwarder, MessageRelayResponder};
pub use presence::PresenceService;
pub use status::StatusService;
pub use workspace::WorkspaceService;
pub use workspace_observability::WorkspaceObservabilityService;

use hermod_storage::{AgentRecord, Database};

/// Register every locally-hosted agent in the `agents` directory
/// and the `local_agents` sub-relation. Each agent's row carries
/// `host_pubkey = Some(host_pubkey)` so federation peers can
/// resolve "which daemon hosts this agent_id" without a separate
/// lookup, and `local_alias` mirrors the operator-set value from
/// the agent's on-disk `alias` file (read at scan time).
///
/// On return the registry's `workspace_root` / `created_at` fields
/// reflect the persisted `local_agents` rows. See
/// [`crate::local_agent::merge_with_db`] for the bearer-drift
/// reconciliation that runs alongside.
pub async fn ensure_local_agents(
    db: &dyn Database,
    host_pubkey: hermod_core::PubkeyBytes,
    registry: crate::local_agent::LocalAgentRegistry,
    audit_sink: &dyn AuditSink,
) -> anyhow::Result<crate::local_agent::LocalAgentRegistry> {
    let now = hermod_core::Timestamp::now();
    for agent in registry.list().iter() {
        db.agents()
            .upsert(&AgentRecord {
                id: agent.agent_id.clone(),
                pubkey: agent.keypair.to_pubkey_bytes(),
                host_pubkey: Some(host_pubkey),
                endpoint: None,
                via_agent: None,
                local_alias: agent.local_alias.clone(),
                peer_asserted_alias: None,
                trust_level: hermod_core::TrustLevel::Local,
                tls_fingerprint: None,
                reputation: 0,
                first_seen: now,
                last_seen: Some(now),
            })
            .await?;
    }
    crate::local_agent::merge_with_db(db, audit_sink, registry).await
}
