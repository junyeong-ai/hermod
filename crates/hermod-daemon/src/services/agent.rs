use hermod_core::{AgentAlias, AgentId, PubkeyBytes, Timestamp};
use hermod_crypto::{agent_id_from_pubkey, fingerprint_from_pubkey};
use hermod_protocol::ipc::methods::{
    AgentGetParams, AgentGetResult, AgentListParams, AgentListResult, AgentRegisterParams,
    AgentRegisterResult, AgentSummary, AliasOutcomeView,
};
use hermod_storage::{AgentRecord, AliasOutcome, AuditEntry, AuditSink, Database};
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
    pub async fn list(&self, _params: AgentListParams) -> Result<AgentListResult, ServiceError> {
        let all = self.db.agents().list().await?;
        let mut agents = Vec::with_capacity(all.len());
        for a in all {
            let view = self.presence.view_for(&a.id).await?;
            if !view.live {
                continue;
            }
            let effective_alias = a.effective_alias().cloned();
            agents.push(AgentSummary {
                id: a.id,
                local_alias: a.local_alias,
                peer_asserted_alias: a.peer_asserted_alias,
                effective_alias,
                endpoint: a.endpoint,
                trust_level: a.trust_level,
                last_seen: a.last_seen,
                status: view.status,
                manual_status: view.manual_status,
            });
        }
        Ok(AgentListResult { agents })
    }

    pub async fn get(&self, params: AgentGetParams) -> Result<AgentGetResult, ServiceError> {
        let record = self.resolve_ref(&params.agent).await?;
        let view = self.presence.view_for(&record.id).await?;
        let fingerprint = fingerprint_from_pubkey(&record.pubkey).to_human_prefix(8);
        let effective_alias = record.effective_alias().cloned();
        Ok(AgentGetResult {
            id: record.id,
            local_alias: record.local_alias,
            peer_asserted_alias: record.peer_asserted_alias,
            effective_alias,
            endpoint: record.endpoint,
            trust_level: record.trust_level,
            first_seen: record.first_seen,
            last_seen: record.last_seen,
            fingerprint,
            status: view.status,
            live: view.live,
            manual_status: view.manual_status,
        })
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
            host_pubkey: None,
            endpoint: params.endpoint.clone(),
            via_agent_id: None,
            local_alias: params.local_alias.clone(),
            peer_asserted_alias: None,
            trust_level: params.trust_level,
            tls_fingerprint: None,
            reputation: 0,
            first_seen: now,
            last_seen: Some(now),
        };
        // `upsert_observed` is the receiver-sovereignty path — if the
        // proposed `local_alias` collides with an existing different agent's
        // sacred label, it's silently dropped (the rest of the record is
        // still stored). This keeps the contract symmetric with `peer.add`.
        let outcome = self.db.agents().upsert_observed(&record).await?;

        if let AliasOutcome::LocalDropped {
            proposed,
            conflicting_id,
        } = &outcome
        {
            audit_or_warn(
                &*self.audit_sink,
                AuditEntry {
                    id: None,
                    ts: now,
                    actor: id.clone(),
                    action: "agent.alias_collision".into(),
                    target: Some(conflicting_id.to_string()),
                    details: Some(serde_json::json!({
                        "proposed": proposed.as_str(),
                        "for_id": id.to_string(),
                    })),
                    client_ip: None,
                    federation: hermod_storage::AuditFederationPolicy::Default,
                },
            )
            .await;
        }

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
                    "endpoint": params.endpoint.as_ref().map(|e| e.to_string()),
                    "alias_outcome": match &outcome {
                        AliasOutcome::Accepted => "accepted",
                        AliasOutcome::LocalDropped { .. } => "local_dropped",
                    },
                })),
                client_ip: None,
                federation: hermod_storage::AuditFederationPolicy::Default,
            },
        )
        .await;

        Ok(AgentRegisterResult {
            id,
            alias_outcome: match outcome {
                AliasOutcome::Accepted => AliasOutcomeView::Accepted,
                AliasOutcome::LocalDropped { .. } => AliasOutcomeView::LocalDropped,
            },
        })
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
