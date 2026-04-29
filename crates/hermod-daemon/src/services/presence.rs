//! Manual hint + derived liveness for this daemon's identity.
//!
//! The two facets are *combined* on read into the effective `PresenceStatus`.
//! Self liveness is derived from `Database::mcp_sessions()` on every call —
//! never cached in `agent_presence` — so a daemon restart with no attached
//! Claude Code session immediately reads as offline without storage cleanup.
//!
//! Whenever local state changes (manual hint set, MCP session attaches /
//! detaches / decays), the service publishes a Presence envelope to
//! workspace members via [`fanout::fanout_to_workspace_members`]. Peers
//! cache the advertised value in their own `agent_presence.peer_live`
//! columns; that's how cross-daemon liveness propagation works.

use hermod_core::{AgentAlias, AgentId, MessageBody, MessagePriority, Timestamp};
use hermod_protocol::ipc::methods::{
    PresenceClearManualParams, PresenceClearManualResult, PresenceGetParams, PresenceGetResult,
    PresenceSetManualParams, PresenceSetManualResult, PresenceView,
};
use hermod_storage::AuditSink;
use hermod_storage::{
    AuditEntry, Database, PEER_LIVE_TTL_SECS, SESSION_TTL_SECS, effective_status,
};
use std::str::FromStr;
use std::sync::Arc;

use crate::services::{ServiceError, audit_or_warn, fanout, message::MessageService};

/// Cadence at which we publish self-liveness to workspace members. Equal to
/// the peer-side cache TTL — receivers age out the entry exactly when our
/// next broadcast lands. Bound by [`PEER_LIVE_TTL_SECS`] but kept as a
/// distinct constant so we can change the publish cadence without churn on
/// the cache TTL.
pub const PRESENCE_FANOUT_TTL_SECS: u32 = PEER_LIVE_TTL_SECS as u32;

/// Priority of fanned-out Presence envelopes. Low because they're
/// background liveness signals; we never want them displacing direct
/// messages in a backed-up outbox.
const PRESENCE_PRIORITY: MessagePriority = MessagePriority::Low;

#[derive(Debug, Clone)]
pub struct PresenceService {
    db: Arc<dyn Database>,
    audit_sink: Arc<dyn AuditSink>,
    self_id: AgentId,
    messages: MessageService,
}

impl PresenceService {
    pub fn new(
        db: Arc<dyn Database>,
        audit_sink: Arc<dyn AuditSink>,
        self_id: AgentId,
        messages: MessageService,
    ) -> Self {
        Self {
            db,
            audit_sink,
            self_id,
            messages,
        }
    }

    pub async fn set_manual(
        &self,
        params: PresenceSetManualParams,
    ) -> Result<PresenceSetManualResult, ServiceError> {
        let now = Timestamp::now();
        let expires_at = params
            .ttl_secs
            .map(|s| Timestamp::from_unix_ms(now.unix_ms() + (s as i64) * 1_000))
            .transpose()
            .map_err(|e| ServiceError::InvalidParam(format!("ttl_secs out of range: {e}")))?;

        self.db
            .presences()
            .set_manual(&self.self_id, params.status, now, expires_at)
            .await?;

        let outcome = self.broadcast_self().await?;

        audit_or_warn(
            &*self.audit_sink,
            AuditEntry {
                id: None,
                ts: now,
                actor: self.self_id.clone(),
                action: "presence.set_manual".into(),
                target: None,
                details: Some(serde_json::json!({
                    "status": params.status.as_str(),
                    "ttl_secs": params.ttl_secs,
                    "fanout": outcome.delivered,
                    "skipped": outcome.skipped,
                    "truncated_at": outcome.truncated_at,
                })),
                client_ip: None,
                federation: hermod_storage::AuditFederationPolicy::Default,
            },
        )
        .await;

        Ok(PresenceSetManualResult {
            set_at: now,
            expires_at,
        })
    }

    pub async fn clear_manual(
        &self,
        _params: PresenceClearManualParams,
    ) -> Result<PresenceClearManualResult, ServiceError> {
        let now = Timestamp::now();
        self.db.presences().clear_manual(&self.self_id).await?;
        let outcome = self.broadcast_self().await?;
        audit_or_warn(
            &*self.audit_sink,
            AuditEntry {
                id: None,
                ts: now,
                actor: self.self_id.clone(),
                action: "presence.clear_manual".into(),
                target: None,
                details: Some(serde_json::json!({
                    "fanout": outcome.delivered,
                    "skipped": outcome.skipped,
                    "truncated_at": outcome.truncated_at,
                })),
                client_ip: None,
                federation: hermod_storage::AuditFederationPolicy::Default,
            },
        )
        .await;
        Ok(PresenceClearManualResult { cleared_at: now })
    }

    pub async fn get(&self, params: PresenceGetParams) -> Result<PresenceGetResult, ServiceError> {
        let agent_id = self.resolve_agent(&params.agent).await?;
        Ok(PresenceGetResult {
            presence: Some(self.view_for(&agent_id).await?),
        })
    }

    /// Build the public PresenceView. Self uses live `mcp_sessions` rows;
    /// peers use cached `peer_live`/manual hint with TTL gating.
    pub async fn view_for(&self, agent_id: &AgentId) -> Result<PresenceView, ServiceError> {
        let now = Timestamp::now();
        let rec = self.db.presences().get(agent_id).await?;
        let is_self = agent_id == &self.self_id;
        let live = if is_self {
            self.self_live(now).await?
        } else {
            rec.as_ref()
                .and_then(|r| r.active_peer_live(now))
                .unwrap_or(false)
        };
        let status = effective_status(rec.as_ref(), live, now);
        let manual_status = rec.as_ref().and_then(|r| r.active_manual_status(now));
        let manual_status_set_at = rec.as_ref().and_then(|r| r.manual_status_set_at);
        let manual_status_expires_at = rec.as_ref().and_then(|r| r.manual_status_expires_at);
        let last_seen_at = rec.as_ref().and_then(|r| {
            if is_self {
                None
            } else {
                r.peer_live_updated_at
            }
        });
        let agent_rec = self.db.agents().get(agent_id).await.ok().flatten();
        let agent_local_alias = agent_rec.as_ref().and_then(|a| a.local_alias.clone());
        let agent_peer_alias = agent_rec
            .as_ref()
            .and_then(|a| a.peer_asserted_alias.clone());
        let agent_alias = agent_rec
            .as_ref()
            .and_then(|a| a.effective_alias().cloned());
        Ok(PresenceView {
            agent: agent_id.clone(),
            agent_local_alias,
            agent_peer_alias,
            agent_alias,
            status,
            live,
            manual_status,
            manual_status_set_at,
            manual_status_expires_at,
            last_seen_at,
        })
    }

    /// Whether this daemon currently has at least one attached MCP session.
    pub async fn self_live(&self, now: Timestamp) -> Result<bool, ServiceError> {
        let ttl_ms = (SESSION_TTL_SECS * 1_000) as i64;
        Ok(self.db.mcp_sessions().count_live(now, ttl_ms).await? > 0)
    }

    /// Publish current self state to workspace members. Called whenever
    /// liveness or manual hint change — by `set_manual`, by `McpService`
    /// on attach/detach, and by the janitor when the last session decays.
    #[tracing::instrument(name = "presence.broadcast", skip(self))]
    pub async fn broadcast_self(&self) -> Result<fanout::FanoutOutcome, ServiceError> {
        let now = Timestamp::now();
        let rec = self.db.presences().get(&self.self_id).await?;
        let manual_status = rec.as_ref().and_then(|r| r.active_manual_status(now));
        let live = self.self_live(now).await?;
        let body = MessageBody::Presence {
            manual_status,
            live,
        };
        fanout::fanout_to_workspace_members(
            &*self.db,
            &self.messages,
            &self.self_id,
            body,
            PRESENCE_PRIORITY,
            PRESENCE_FANOUT_TTL_SECS,
        )
        .await
    }

    async fn resolve_agent(&self, reference: &str) -> Result<AgentId, ServiceError> {
        if let Some(alias_raw) = reference.strip_prefix('@') {
            let alias = AgentAlias::from_str(alias_raw)
                .map_err(|e| ServiceError::InvalidParam(format!("invalid alias: {e}")))?;
            let rec = self
                .db
                .agents()
                .get_by_local_alias(&alias)
                .await?
                .ok_or(ServiceError::NotFound)?;
            Ok(rec.id)
        } else {
            AgentId::from_str(reference)
                .map_err(|e| ServiceError::InvalidParam(format!("invalid agent id: {e}")))
        }
    }
}
