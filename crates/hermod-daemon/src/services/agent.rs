use hermod_core::{AgentAlias, AgentId, PubkeyBytes, Timestamp};
use hermod_crypto::{agent_id_from_pubkey, fingerprint_from_pubkey};
use hermod_protocol::ipc::methods::{
    AgentGetParams, AgentGetResult, AgentListParams, AgentListResult, AgentRegisterParams,
    AgentRegisterResult, AgentSummary,
};
use hermod_storage::{AgentRecord, AuditEntry, AuditSink, Database};
use std::str::FromStr;
use std::sync::Arc;

use crate::services::{ServiceError, audit_or_warn, presence::PresenceService};

#[derive(Debug, Clone)]
pub struct AgentService {
    db: Arc<dyn Database>,
    audit_sink: Arc<dyn AuditSink>,
    presence: PresenceService,
}

impl AgentService {
    pub fn new(
        db: Arc<dyn Database>,
        audit_sink: Arc<dyn AuditSink>,
        presence: PresenceService,
    ) -> Self {
        Self {
            db,
            audit_sink,
            presence,
        }
    }

    /// Return agents that are currently *live* (live=true). Listing offline
    /// agents has no operational value — you can't message them
    /// synchronously — so the live filter is the design, not a flag. Use
    /// [`AgentService::get`] to inspect a specific id regardless of state,
    /// and the audit log for forensic enumeration.
    pub async fn list(&self, params: AgentListParams) -> Result<AgentListResult, ServiceError> {
        let all = self.db.agents().list().await?;
        let mut agents = Vec::with_capacity(all.len());
        for a in all {
            let view = self.presence.view_for(&a.id).await?;
            if !view.live {
                continue;
            }
            // Effective tags = local (from `local_agents.tags` if
            // we host this agent) ∪ peer-asserted (from peer.advertise).
            // Single source of truth via `effective_tags()`.
            let local_tags = self.local_tags_for(&a.id).await;
            let effective: Vec<hermod_core::CapabilityTag> =
                hermod_core::effective_tags(&local_tags, &a.peer_asserted_tags);
            // Apply tag filters AFTER computing effective set so
            // operator-side filters match peer-asserted entries too.
            if !params.tags_all.is_empty() && !params.tags_all.iter().all(|t| effective.contains(t))
            {
                continue;
            }
            if !params.tags_any.is_empty() && !params.tags_any.iter().any(|t| effective.contains(t))
            {
                continue;
            }
            let effective_alias = a.effective_alias().cloned();
            let endpoint = self.host_endpoint(a.host_id.as_ref()).await;
            agents.push(AgentSummary {
                id: a.id,
                local_alias: a.local_alias,
                peer_asserted_alias: a.peer_asserted_alias,
                effective_alias,
                endpoint,
                trust_level: a.trust_level,
                last_seen: a.last_seen,
                status: view.status,
                manual_status: view.manual_status,
                tags: effective,
            });
        }
        Ok(AgentListResult { agents })
    }

    pub async fn get(&self, params: AgentGetParams) -> Result<AgentGetResult, ServiceError> {
        let record = self.resolve_ref(&params.agent).await?;
        let view = self.presence.view_for(&record.id).await?;
        let fingerprint = fingerprint_from_pubkey(&record.pubkey).to_human_prefix(8);
        let effective_alias = record.effective_alias().cloned();
        let local_tags = self.local_tags_for(&record.id).await;
        let effective_tags = hermod_core::effective_tags(&local_tags, &record.peer_asserted_tags);
        let endpoint = self.host_endpoint(record.host_id.as_ref()).await;
        Ok(AgentGetResult {
            id: record.id,
            local_alias: record.local_alias,
            peer_asserted_alias: record.peer_asserted_alias,
            effective_alias,
            endpoint,
            trust_level: record.trust_level,
            first_seen: record.first_seen,
            last_seen: record.last_seen,
            fingerprint,
            status: view.status,
            live: view.live,
            manual_status: view.manual_status,
            local_tags: local_tags.iter().cloned().collect(),
            peer_asserted_tags: record.peer_asserted_tags.iter().cloned().collect(),
            effective_tags,
        })
    }

    /// Read operator-set tags from `local_agents.tags` if we host
    /// this agent. Empty for peers — only locally-hosted agents
    /// have a `local_agents` row.
    async fn local_tags_for(&self, id: &hermod_core::AgentId) -> hermod_core::CapabilityTagSet {
        match self.db.local_agents().lookup_by_id(id).await {
            Ok(Some(rec)) => rec.tags,
            _ => hermod_core::CapabilityTagSet::empty(),
        }
    }

    /// Resolve an agent's `host_id` FK to its host's federation
    /// endpoint, or `None` if no host or endpoint is recorded.
    /// Surfaced into the `AgentSummary` / `AgentGetResult` views so
    /// CLI / API consumers see "where this agent lives" without
    /// having to call `peer list` separately.
    async fn host_endpoint(
        &self,
        host_id: Option<&hermod_core::AgentId>,
    ) -> Option<hermod_core::Endpoint> {
        let id = host_id?;
        self.db
            .hosts()
            .get(id)
            .await
            .ok()
            .flatten()
            .and_then(|h| h.endpoint)
    }

    pub async fn register(
        &self,
        params: AgentRegisterParams,
    ) -> Result<AgentRegisterResult, ServiceError> {
        let raw = hex::decode(&params.pubkey_hex)
            .map_err(|e| ServiceError::InvalidParam(format!("pubkey_hex invalid: {e}")))?;
        if raw.len() != PubkeyBytes::LEN {
            return Err(ServiceError::InvalidParam(format!(
                "pubkey must be {} bytes, got {}",
                PubkeyBytes::LEN,
                raw.len()
            )));
        }
        let mut arr = [0u8; PubkeyBytes::LEN];
        arr.copy_from_slice(&raw);
        let pubkey = PubkeyBytes(arr);
        let id = agent_id_from_pubkey(&pubkey);
        let now = Timestamp::now();

        let record = AgentRecord {
            id: id.clone(),
            pubkey,
            // `agent register` is a directory-only IPC — operator
            // hands us identity + alias + trust level. Routing
            // info (host_id / via_agent) belongs to `peer add`,
            // which has the host pubkey context to build the FK.
            host_id: None,
            via_agent: None,
            local_alias: params.local_alias.clone(),
            peer_asserted_alias: None,
            trust_level: params.trust_level,
            reputation: 0,
            first_seen: now,
            last_seen: Some(now),
            peer_asserted_tags: hermod_core::CapabilityTagSet::empty(),
        };
        // `agent register` is operator-driven; goes through `upsert`
        // so a re-register on an existing agent_id preserves any
        // peer-asserted columns the row has accumulated. Alias
        // collision against a different agent_id surfaces as a
        // UNIQUE storage error — operator input must resolve cleanly.
        self.db.agents().upsert(&record).await?;

        audit_or_warn(
            &*self.audit_sink,
            AuditEntry {
                id: None,
                ts: now,
                actor: id.clone(),
                action: "agent.register".into(),
                target: Some(id.to_string()),
                details: Some(serde_json::json!({
                    "trust_level": params.trust_level.as_str(),
                    "local_alias": params.local_alias.as_ref().map(|a| a.as_str()),
                })),
                client_ip: None,
                federation: hermod_storage::AuditFederationPolicy::Default,
            },
        )
        .await;

        Ok(AgentRegisterResult { id })
    }

    async fn resolve_ref(&self, reference: &str) -> Result<AgentRecord, ServiceError> {
        if let Some(alias_raw) = reference.strip_prefix('@') {
            let alias = AgentAlias::from_str(alias_raw).map_err(|e| {
                ServiceError::InvalidParam(format!("invalid alias {reference:?}: {e}"))
            })?;
            return self
                .db
                .agents()
                .get_by_local_alias(&alias)
                .await?
                .ok_or(ServiceError::NotFound);
        }
        let id = AgentId::from_str(reference).map_err(|e| {
            ServiceError::InvalidParam(format!("invalid agent id {reference:?}: {e}"))
        })?;
        self.db
            .agents()
            .get(&id)
            .await?
            .ok_or(ServiceError::NotFound)
    }
}
