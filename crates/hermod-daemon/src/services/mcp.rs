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

use hermod_core::{AgentId, Timestamp};
use hermod_protocol::ipc::methods::{
    McpAttachParams, McpAttachResult, McpDetachParams, McpDetachResult, McpHeartbeatParams,
    McpHeartbeatResult,
};
use hermod_storage::{
    AuditEntry, AuditSink, Database, HEARTBEAT_INTERVAL_SECS, McpSession, SESSION_TTL_SECS,
};
use std::sync::Arc;
use ulid::Ulid;

use crate::audit_context::current_caller_agent;
use crate::services::{ServiceError, audit_or_warn, presence::PresenceService};

#[derive(Debug, Clone)]
pub struct McpService {
    db: Arc<dyn Database>,
    audit_sink: Arc<dyn AuditSink>,
    /// Audit fallback actor for emissions outside an IPC scope.
    host_actor: AgentId,
    presence: PresenceService,
}

impl McpService {
    pub fn new(
        db: Arc<dyn Database>,
        audit_sink: Arc<dyn AuditSink>,
        host_actor: AgentId,
        presence: PresenceService,
    ) -> Self {
        Self {
            db,
            audit_sink,
            host_actor,
            presence,
        }
    }

    fn caller(&self) -> Result<AgentId, ServiceError> {
        current_caller_agent().ok_or_else(|| {
            ServiceError::InvalidParam(
                "mcp.* requires an IPC caller scope (no caller_agent in context)".into(),
            )
        })
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
        let caller = self.caller()?;
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

        audit_or_warn(
            &*self.audit_sink,
            AuditEntry {
                id: None,
                ts: now,
                actor: self.host_actor.clone(),
                action: "mcp.attach".into(),
                target: Some(session_id.clone()),
                details: Some(serde_json::json!({
                    "client_name": params.client_name,
                    "client_version": params.client_version,
                })),
                client_ip: None,
                federation: hermod_storage::AuditFederationPolicy::Default,
            },
        )
        .await;

        // Offline → online transition only — subsequent attaches are
        // visibility no-ops to peers. The transition is host-wide
        // until `mcp_sessions` carries an `agent_id`; the broadcast
        // goes out on behalf of the caller agent (the one Claude
        // Code is binding this stdio for).
        if !was_live {
            let _ = self.presence.broadcast_for(&caller).await;
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
        let caller = self.caller()?;
        let now = Timestamp::now();
        let ttl_ms = (SESSION_TTL_SECS * 1_000) as i64;
        let outcome = self
            .db
            .mcp_sessions()
            .detach_atomic(&params.session_id, now, ttl_ms)
            .await?;

        audit_or_warn(
            &*self.audit_sink,
            AuditEntry {
                id: None,
                ts: now,
                actor: self.host_actor.clone(),
                action: "mcp.detach".into(),
                target: Some(params.session_id.clone()),
                details: None,
                client_ip: None,
                federation: hermod_storage::AuditFederationPolicy::Default,
            },
        )
        .await;

        // Online → offline transition only — broadcast Presence(live=false)
        // so peers age out our liveness immediately instead of waiting for
        // their cache TTL. Broadcasts on behalf of the caller agent.
        if outcome.was_live && !outcome.is_live {
            let _ = self.presence.broadcast_for(&caller).await;
        }

        Ok(McpDetachResult {
            session_id: params.session_id,
        })
    }
}
