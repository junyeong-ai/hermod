//! MCP stdio session lifecycle.
//!
//! Each `hermod mcp` (the JSON-RPC server inside Claude Code) opens an IPC
//! connection to the daemon and registers via [`McpService::attach`]. While
//! attached it heartbeats every [`HEARTBEAT_INTERVAL_SECS`]; on stdin EOF it
//! [`McpService::detach`]es. The janitor prunes any session row whose
//! heartbeat is older than [`SESSION_TTL_SECS`] (a brutal client crash with
//! no clean detach decays to offline by itself).
//!
//! attach/detach are audited; heartbeats are not — they're noise.
//!
//! All transitions go through atomic primitives on
//! [`hermod_storage::McpSessionRepository`]. Two concurrent `attach` requests
//! can't both observe `was_live=false` and double-broadcast — SQLite WAL
//! serialises writers, so the second transaction sees the first attach's row
//! already committed.

use std::sync::Arc;
use hermod_core::{AgentId, Timestamp};
use hermod_protocol::ipc::methods::{
    McpAttachParams, McpAttachResult, McpDetachParams, McpDetachResult, McpHeartbeatParams,
    McpHeartbeatResult,
};
use hermod_storage::{AuditEntry, Database, HEARTBEAT_INTERVAL_SECS, McpSession, SESSION_TTL_SECS, AuditSink};
use ulid::Ulid;

use crate::services::{ServiceError, audit_or_warn, presence::PresenceService};

#[derive(Debug, Clone)]
pub struct McpService {
    db: Arc<dyn Database>,
    audit_sink: Arc<dyn AuditSink>,
    self_id: AgentId,
    presence: PresenceService,
}

impl McpService {
    pub fn new(db: Arc<dyn Database>, audit_sink: Arc<dyn AuditSink>,
        self_id: AgentId, presence: PresenceService) -> Self {
        Self {
            db,
            audit_sink,
            self_id,
            presence,
        }
    }

    /// Register a fresh MCP stdio session. The first attach flips
    /// self-liveness from offline to online and triggers a Presence fanout
    /// so collaborators see us back without waiting for their cache TTL.
    /// Atomic via `McpSessionRepository::attach_atomic` — concurrent
    /// attaches don't double-broadcast.
    #[tracing::instrument(
        name = "mcp.attach",
        skip(self, params),
        fields(client = ?params.client_name)
    )]
    pub async fn attach(&self, params: McpAttachParams) -> Result<McpAttachResult, ServiceError> {
        let now = Timestamp::now();
        let session_id = Ulid::new().to_string();
        let ttl_ms = (SESSION_TTL_SECS * 1_000) as i64;
        let was_live = self
            .db
            .mcp_sessions()
            .attach_atomic(
                &McpSession {
                    session_id: session_id.clone(),
                    attached_at: now,
                    last_heartbeat_at: now,
                    client_name: params.client_name.clone(),
                    client_version: params.client_version.clone(),
                },
                ttl_ms,
            )
            .await?;

        audit_or_warn(&*self.audit_sink,
            AuditEntry {
                id: None,
                ts: now,
                actor: self.self_id.clone(),
                action: "mcp.attach".into(),
                target: Some(session_id.clone()),
                details: Some(serde_json::json!({
                    "client_name": params.client_name,
                    "client_version": params.client_version,
                })),
                federation: hermod_storage::AuditFederationPolicy::Default,
            },
        )
        .await;

        // Offline → online transition only — subsequent attaches are
        // visibility no-ops to peers.
        if !was_live {
            let _ = self.presence.broadcast_self().await;
        }

        Ok(McpAttachResult {
            session_id,
            heartbeat_interval_secs: HEARTBEAT_INTERVAL_SECS as u32,
        })
    }

    pub async fn heartbeat(
        &self,
        params: McpHeartbeatParams,
    ) -> Result<McpHeartbeatResult, ServiceError> {
        let now = Timestamp::now();
        let recognised = self
            .db
            .mcp_sessions()
            .heartbeat(&params.session_id, now)
            .await?;
        Ok(McpHeartbeatResult {
            ack_at: now,
            recognised,
        })
    }

    pub async fn detach(&self, params: McpDetachParams) -> Result<McpDetachResult, ServiceError> {
        let now = Timestamp::now();
        let ttl_ms = (SESSION_TTL_SECS * 1_000) as i64;
        let outcome = self
            .db
            .mcp_sessions()
            .detach_atomic(&params.session_id, now, ttl_ms)
            .await?;

        audit_or_warn(&*self.audit_sink,
            AuditEntry {
                id: None,
                ts: now,
                actor: self.self_id.clone(),
                action: "mcp.detach".into(),
                target: Some(params.session_id.clone()),
                details: None,
                federation: hermod_storage::AuditFederationPolicy::Default,
            },
        )
        .await;

        // Online → offline transition only — broadcast Presence(live=false)
        // so peers age out our liveness immediately instead of waiting for
        // their cache TTL.
        if outcome.was_live && !outcome.is_live {
            let _ = self.presence.broadcast_self().await;
        }

        Ok(McpDetachResult {
            session_id: params.session_id,
        })
    }
}
