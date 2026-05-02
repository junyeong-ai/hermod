//! MCP stdio session lifecycle.
//!
//! Each `hermod mcp` (the JSON-RPC server inside Claude Code) opens an IPC
//! connection to the daemon and registers via [`McpService::attach`]. While
//! attached it heartbeats every [`HEARTBEAT_INTERVAL_SECS`]; on stdin EOF it
//! [`McpService::detach`]es. The janitor prunes any session row whose
//! heartbeat is older than [`SESSION_TTL_SECS`] (a brutal client crash with
//! no clean detach decays to offline by itself).
//!
//! attach/detach are audited; heartbeats and cursor advances are not — the
//! former two are state transitions; the latter two are noise.
//!
//! All transitions go through atomic primitives on
//! [`hermod_storage::McpSessionRepository`]. Two concurrent `attach` requests
//! can't both observe `was_live=false` and double-broadcast — SQLite WAL
//! serialises writers, so the second transaction sees the first attach's row
//! already committed.
//!
//! ## Per-instance boundary
//!
//! Multiple Claude Code windows of the same agent are first-class.
//! `session_id` (daemon-minted) addresses one specific attach; the
//! optional `session_label` (operator-supplied via
//! `HERMOD_SESSION_LABEL`) names a *resumable* slot — re-attaching
//! with the same label after a process restart picks up the stored
//! cursors so messages aren't re-emitted from scratch. Two live
//! attaches with the same label are rejected (`Conflict`) so two
//! Claude Code windows can't silently share a single cursor stream.

use hermod_core::{AgentId, McpSessionId, Timestamp};
use hermod_protocol::ipc::methods::{
    LocalSessionsParams, LocalSessionsResult, McpAttachParams, McpAttachResult,
    McpCursorAdvanceParams, McpCursorAdvanceResult, McpDetachParams, McpDetachResult,
    McpHeartbeatParams, McpHeartbeatResult, McpSessionSummary,
};
use hermod_storage::{
    AttachOutcome, AttachParams, AuditEntry, AuditSink, CursorAdvance, Database,
    HEARTBEAT_INTERVAL_SECS, SESSION_TTL_SECS,
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
    /// When `session_label` is set and a stale labelled row exists for
    /// the same caller agent, the prior cursors are carried into the new
    /// row — restart resumes mid-stream.
    #[tracing::instrument(
        name = "mcp.attach",
        skip(self, params),
        fields(client = ?params.client_name, label = ?params.session_label)
    )]
    pub async fn attach(&self, params: McpAttachParams) -> Result<McpAttachResult, ServiceError> {
        let caller = self.caller()?;
        let now = Timestamp::now();
        let session_id = McpSessionId::from_raw(Ulid::new().to_string());
        let ttl_ms = (SESSION_TTL_SECS * 1_000) as i64;

        let outcome = self
            .db
            .mcp_sessions()
            .attach(AttachParams {
                session_id: session_id.clone(),
                agent_id: caller.clone(),
                session_label: params.session_label.clone(),
                attached_at: now,
                client_name: params.client_name.clone(),
                client_version: params.client_version.clone(),
                ttl_ms,
            })
            .await?;

        let (session, was_live, resumed) = match outcome {
            AttachOutcome::Inserted {
                session,
                was_live,
                resumed,
            } => (session, was_live, resumed),
            AttachOutcome::LabelInUse {
                live_session_id,
                last_heartbeat_at,
            } => {
                return Err(ServiceError::Conflict(format!(
                    "session label `{}` is already held by live session {} \
                     (last heartbeat {}); pick a different label or wait \
                     for its TTL to elapse",
                    params
                        .session_label
                        .as_ref()
                        .map(|l| l.as_str())
                        .unwrap_or("<none>"),
                    live_session_id,
                    last_heartbeat_at.unix_ms(),
                )));
            }
        };

        audit_or_warn(
            &*self.audit_sink,
            AuditEntry {
                id: None,
                ts: now,
                actor: self.host_actor.clone(),
                action: "mcp.attach".into(),
                target: Some(session.session_id.to_string()),
                details: Some(serde_json::json!({
                    "client_name": params.client_name,
                    "client_version": params.client_version,
                    "session_label": session.session_label.as_ref().map(|l| l.as_str()),
                    "resumed": resumed,
                })),
                client_ip: None,
                federation: hermod_storage::AuditFederationPolicy::Default,
            },
        )
        .await;

        // Offline → online transition only — subsequent attaches are
        // visibility no-ops to peers.
        if !was_live {
            let _ = self.presence.broadcast_for(&caller).await;
        }

        Ok(McpAttachResult {
            session_id: session.session_id,
            session_label: session.session_label,
            resumed,
            heartbeat_interval_secs: HEARTBEAT_INTERVAL_SECS as u32,
            last_message_id: session.last_message_id,
            last_confirmation_id: session.last_confirmation_id,
            last_resolved_seq: session.last_resolved_seq,
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

    /// Persist delivery cursors so a Claude Code restart resumes from
    /// the same position rather than re-emitting the agent's entire
    /// backlog. Idempotent partial advance — only `Some(_)` cursors
    /// are written; `None` leaves the column untouched.
    pub async fn cursor_advance(
        &self,
        params: McpCursorAdvanceParams,
    ) -> Result<McpCursorAdvanceResult, ServiceError> {
        let recognised = self
            .db
            .mcp_sessions()
            .cursor_advance(
                &params.session_id,
                &CursorAdvance {
                    last_message_id: params.last_message_id,
                    last_confirmation_id: params.last_confirmation_id,
                    last_resolved_seq: params.last_resolved_seq,
                },
            )
            .await?;
        Ok(McpCursorAdvanceResult { recognised })
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
                target: Some(params.session_id.to_string()),
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

    /// Live MCP sessions for the caller agent. The operator uses
    /// `hermod local sessions` to inspect which Claude Code windows
    /// are currently attached.
    pub async fn list_sessions(
        &self,
        _params: LocalSessionsParams,
    ) -> Result<LocalSessionsResult, ServiceError> {
        let caller = self.caller()?;
        let now = Timestamp::now();
        let ttl_ms = (SESSION_TTL_SECS * 1_000) as i64;
        let sessions = self
            .db
            .mcp_sessions()
            .list_for_agent(&caller, now, ttl_ms)
            .await?;
        Ok(LocalSessionsResult {
            sessions: sessions
                .into_iter()
                .map(|s| McpSessionSummary {
                    session_id: s.session_id,
                    session_label: s.session_label,
                    attached_at: s.attached_at,
                    last_heartbeat_at: s.last_heartbeat_at,
                    client_name: s.client_name,
                    client_version: s.client_version,
                    last_message_id: s.last_message_id,
                    last_confirmation_id: s.last_confirmation_id,
                    last_resolved_seq: s.last_resolved_seq,
                })
                .collect(),
        })
    }
}
