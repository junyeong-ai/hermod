use hermod_core::{
    AdvertisedAgent, AgentAddress, AgentAlias, AgentId, Endpoint, MessageBody, MessagePriority,
    PubkeyBytes, Timestamp, TrustLevel,
};
use hermod_protocol::ipc::methods::{
    AliasOutcomeView, MessageSendParams, PeerAddParams, PeerAddResult, PeerAdvertiseParams,
    PeerAdvertiseResult, PeerListResult, PeerRemoveParams, PeerRemoveResult, PeerRepinParams,
    PeerRepinResult, PeerSummary, PeerTrustParams,
};
use hermod_routing::PeerPool;
use hermod_storage::{AuditEntry, AuditSink, Database};
use std::collections::HashSet;
use std::str::FromStr;
use std::sync::Arc;

use crate::federation::record_agent_peer;
use crate::local_agent::LocalAgentRegistry;
use crate::services::{
    ServiceError, audit_or_warn, message::MessageService, presence::PresenceService,
};

#[derive(Debug, Clone)]
pub struct PeerService {
    db: Arc<dyn Database>,
    audit_sink: Arc<dyn AuditSink>,
    self_id: AgentId,
    presence: PresenceService,
    pool: Arc<PeerPool>,
    /// Locally-hosted agents enumerated by `peer.advertise`.
    registry: LocalAgentRegistry,
    /// Daemon's host pubkey — body.host_pubkey of every emitted
    /// `PeerAdvertise`.
    host_pubkey: PubkeyBytes,
    /// Outbound envelope path for the advertise fan-out.
    messages: MessageService,
}

impl PeerService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        db: Arc<dyn Database>,
        audit_sink: Arc<dyn AuditSink>,
        self_id: AgentId,
        presence: PresenceService,
        pool: Arc<PeerPool>,
        registry: LocalAgentRegistry,
        host_pubkey: PubkeyBytes,
        messages: MessageService,
    ) -> Self {
        Self {
            db,
            audit_sink,
            self_id,
            presence,
            pool,
            registry,
            host_pubkey,
            messages,
        }
    }

    pub async fn add(&self, params: PeerAddParams) -> Result<PeerAddResult, ServiceError> {
        let endpoint = match params.endpoint {
            Endpoint::Wss(w) => w,
            Endpoint::Unix { .. } => {
                return Err(ServiceError::InvalidParam(
                    "peer.add only accepts wss:// endpoints".into(),
                ));
            }
        };
        let host_pubkey = parse_pubkey(&params.host_pubkey_hex)?;
        let agent_pubkey = parse_pubkey(&params.agent_pubkey_hex)?;
        let (rec, outcome) = record_agent_peer(
            &*self.db,
            endpoint,
            host_pubkey,
            agent_pubkey,
            params.local_alias,
        )
        .await
        .map_err(|e| ServiceError::InvalidParam(e.to_string()))?;
        let fingerprint = hermod_crypto::fingerprint_from_pubkey(&rec.pubkey).to_human_prefix(8);

        // Audit a collision *before* the peer.add row so the chain shows
        // the operator was warned (the alias they asked for was already
        // taken; the new peer is registered without it).
        if let hermod_storage::AliasOutcome::LocalDropped {
            proposed,
            conflicting_id,
        } = &outcome
        {
            audit_or_warn(
                &*self.audit_sink,
                AuditEntry {
                    id: None,
                    ts: Timestamp::now(),
                    actor: self.self_id.clone(),
                    action: "peer.alias_collision".into(),
                    target: Some(conflicting_id.to_string()),
                    details: Some(serde_json::json!({
                        "proposed": proposed.as_str(),
                        "for_id": rec.id.to_string(),
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
                ts: Timestamp::now(),
                actor: self.self_id.clone(),
                action: "peer.add".into(),
                target: Some(rec.id.to_string()),
                details: Some(serde_json::json!({
                    "fingerprint": fingerprint,
                    "endpoint": rec.endpoint.as_ref().map(|e| e.to_string()),
                    "alias_outcome": match &outcome {
                        hermod_storage::AliasOutcome::Accepted => "accepted",
                        hermod_storage::AliasOutcome::LocalDropped { .. } => "local_dropped",
                    },
                })),
                client_ip: None,
                federation: hermod_storage::AuditFederationPolicy::Default,
            },
        )
        .await;

        // Auto-advertise our local agents back to the freshly-added
        // peer so the operator doesn't have to think about a second
        // step. Best-effort — if the envelope can't be enqueued
        // (broker down, transport unavailable), the explicit
        // `peer.advertise` IPC method or the next outbound dial covers
        // the gap.
        let target_id = rec.id.clone();
        if let Err(e) = self.advertise_to_agent(&target_id).await {
            tracing::warn!(
                target = %target_id,
                error = %e,
                "auto-advertise on peer.add failed (operator can retry via `hermod peer advertise`)",
            );
        }

        Ok(PeerAddResult {
            id: rec.id,
            fingerprint,
            trust_level: rec.trust_level,
            alias_outcome: match outcome {
                hermod_storage::AliasOutcome::Accepted => AliasOutcomeView::Accepted,
                hermod_storage::AliasOutcome::LocalDropped { .. } => AliasOutcomeView::LocalDropped,
            },
        })
    }

    /// Enumerate this daemon's hosted agents and ship a `PeerAdvertise`
    /// envelope to one peer (or every peer with a known endpoint).
    /// Body carries `host_pubkey` + the agents' `(id, pubkey, alias)`
    /// triples. Receiver upserts into its directory; subsequent
    /// envelopes from those agents land without further out-of-band
    /// exchange.
    pub async fn advertise(
        &self,
        params: PeerAdvertiseParams,
    ) -> Result<PeerAdvertiseResult, ServiceError> {
        let agents = self.advertised_agents();
        let agent_count = agents.len() as u32;
        let mut fanout: u32 = 0;
        match params.target {
            Some(reference) => {
                let target = self.resolve_target(&reference).await?;
                if self.send_advertise(&target, agents.clone()).await.is_ok() {
                    fanout = 1;
                }
            }
            None => {
                // Walk federated peers; pick one canonical local-agent
                // recipient per distinct host_pubkey so a peer running N
                // hosted agents receives the advertise once, not N
                // times.
                let rows = self.db.agents().list_federated().await?;
                let mut seen_hosts: HashSet<PubkeyBytes> = HashSet::new();
                for r in rows {
                    let host = match r.host_pubkey {
                        Some(h) => h,
                        // No host pubkey known yet — can't dedup safely;
                        // skip rather than risk a duplicate advertise. The
                        // first inbound envelope from this peer will
                        // populate host_pubkey via TOFU.
                        None => continue,
                    };
                    if !seen_hosts.insert(host) {
                        continue;
                    }
                    if self.send_advertise(&r.id, agents.clone()).await.is_ok() {
                        fanout = fanout.saturating_add(1);
                    }
                }
            }
        }

        audit_or_warn(
            &*self.audit_sink,
            AuditEntry {
                id: None,
                ts: Timestamp::now(),
                actor: self.self_id.clone(),
                action: "peer.advertise".into(),
                target: None,
                details: Some(serde_json::json!({
                    "fanout": fanout,
                    "agents": agent_count,
                })),
                client_ip: None,
                federation: hermod_storage::AuditFederationPolicy::Default,
            },
        )
        .await;

        Ok(PeerAdvertiseResult {
            fanout,
            agents: agent_count,
        })
    }

    /// Internal: advertise to a specific peer agent_id. Used by the
    /// `peer.add` auto-trigger.
    async fn advertise_to_agent(&self, target: &AgentId) -> Result<(), ServiceError> {
        let agents = self.advertised_agents();
        self.send_advertise(target, agents).await
    }

    fn advertised_agents(&self) -> Vec<AdvertisedAgent> {
        self.registry
            .list()
            .iter()
            .map(|a| AdvertisedAgent {
                id: a.agent_id.clone(),
                pubkey: a.keypair.to_pubkey_bytes(),
                alias: a.local_alias.clone(),
            })
            .collect()
    }

    async fn send_advertise(
        &self,
        target: &AgentId,
        agents: Vec<AdvertisedAgent>,
    ) -> Result<(), ServiceError> {
        // Resolve recipient endpoint so the router knows whether to
        // dial direct or via a broker.
        let rec = self.db.agents().get(target).await?.ok_or_else(|| {
            ServiceError::InvalidParam(format!("peer.advertise target {target} not in directory"))
        })?;
        let to = match rec.endpoint {
            Some(ep) if !ep.is_local() => AgentAddress::with_endpoint(rec.id, ep),
            _ => AgentAddress::local(rec.id),
        };
        let body = MessageBody::PeerAdvertise {
            host_pubkey: self.host_pubkey,
            agents,
        };
        // Self-inclusion proof: the caller (resolved by
        // `MessageService::send` from the IPC scope) must be one of
        // the listed agents — it already is, since `advertised_agents`
        // walks our own registry.
        self.messages
            .send(MessageSendParams {
                to,
                body,
                priority: Some(MessagePriority::Low),
                thread: None,
                ttl_secs: Some(300),
                caps: None,
            })
            .await?;
        Ok(())
    }

    async fn resolve_target(&self, reference: &str) -> Result<AgentId, ServiceError> {
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

    pub async fn list(&self) -> Result<PeerListResult, ServiceError> {
        let rows = self.db.agents().list_federated().await?;
        let mut peers = Vec::with_capacity(rows.len());
        for r in rows {
            // list_federated guarantees endpoint IS NOT NULL via the WHERE clause.
            let endpoint = r.endpoint.clone().ok_or_else(|| {
                ServiceError::InvalidParam(format!(
                    "federated agent {} missing endpoint after select",
                    r.id
                ))
            })?;
            let view = self.presence.view_for(&r.id).await?;
            let effective_alias = r.effective_alias().cloned();
            peers.push(PeerSummary {
                id: r.id,
                local_alias: r.local_alias,
                peer_asserted_alias: r.peer_asserted_alias,
                effective_alias,
                endpoint,
                trust_level: r.trust_level,
                fingerprint: hermod_crypto::fingerprint_from_pubkey(&r.pubkey).to_human_prefix(8),
                reputation: r.reputation,
                status: view.status,
                live: view.live,
            });
        }
        Ok(PeerListResult { peers })
    }

    pub async fn remove(&self, params: PeerRemoveParams) -> Result<PeerRemoveResult, ServiceError> {
        let agent_id = AgentId::from_str(&params.peer).map_err(|e| {
            ServiceError::InvalidParam(format!("peer.remove requires an agent_id: {e}"))
        })?;
        // Order matters: fail in-flight messages first, then clear the
        // endpoint. Once endpoint is NULL the outbox skips them by query
        // filter — failing them after that point would leave them
        // invisible-but-pending in the operator's inbox.
        let failed = self.db.messages().fail_pending_to(&agent_id).await?;
        // `forget_peer` reads-and-clears atomically, so there's no race
        // against a concurrent `peer.add` that could leave a pool entry
        // pointed at a stale endpoint.
        let outcome = self.db.agents().forget_peer(&agent_id).await?;
        if let Some(ep) = &outcome.prior_endpoint {
            self.pool.evict_endpoint(ep).await;
        }
        if outcome.existed {
            audit_or_warn(
                &*self.audit_sink,
                AuditEntry {
                    id: None,
                    ts: Timestamp::now(),
                    actor: self.self_id.clone(),
                    action: "peer.remove".into(),
                    target: Some(agent_id.to_string()),
                    details: Some(serde_json::json!({
                        "messages_failed": failed,
                    })),
                    client_ip: None,
                    federation: hermod_storage::AuditFederationPolicy::Default,
                },
            )
            .await;
        }
        Ok(PeerRemoveResult {
            removed: outcome.existed,
        })
    }

    pub async fn repin(&self, params: PeerRepinParams) -> Result<PeerRepinResult, ServiceError> {
        let agent_id = AgentId::from_str(&params.peer).map_err(|e| {
            ServiceError::InvalidParam(format!("peer.repin requires an agent_id: {e}"))
        })?;
        // Atomic: trust check + read of endpoint + fp swap all in one
        // SQL transaction. The endpoint snapshot lets us evict the right
        // pool entry without a follow-up SELECT — without that snapshot,
        // a concurrent `peer.add` could change endpoint between the swap
        // and our evict, leaving a stale-context entry alive while we
        // tear down the wrong one.
        let outcome = self
            .db
            .agents()
            .replace_tls_fingerprint(&agent_id, &params.fingerprint, TrustLevel::Verified)
            .await?;
        let (previous, endpoint) = match outcome {
            hermod_storage::RepinOutcome::Replaced { previous, endpoint } => (previous, endpoint),
            hermod_storage::RepinOutcome::TrustMismatch { actual } => {
                return Err(ServiceError::InvalidParam(format!(
                    "peer.repin only applies to Verified peers (current: {})",
                    actual.as_str()
                )));
            }
            hermod_storage::RepinOutcome::NotFound => return Err(ServiceError::NotFound),
        };
        // Tear down the pooled connection that was bound to the old fp
        // so the next dial re-handshakes against the new pin immediately
        // rather than riding the existing TLS session for up to `idle_ttl`.
        if let Some(ep) = &endpoint {
            self.pool.evict_endpoint(ep).await;
        }
        audit_or_warn(
            &*self.audit_sink,
            AuditEntry {
                id: None,
                ts: Timestamp::now(),
                actor: self.self_id.clone(),
                action: "peer.repin".into(),
                target: Some(agent_id.to_string()),
                details: Some(serde_json::json!({
                    "previous": previous,
                    "new": params.fingerprint,
                })),
                client_ip: None,
                federation: hermod_storage::AuditFederationPolicy::Default,
            },
        )
        .await;
        Ok(PeerRepinResult {
            previous,
            new: params.fingerprint,
        })
    }

    pub async fn trust(&self, params: PeerTrustParams) -> Result<PeerSummary, ServiceError> {
        let agent_id = AgentId::from_str(&params.peer).map_err(|e| {
            ServiceError::InvalidParam(format!("peer.trust requires an agent_id: {e}"))
        })?;
        self.db.agents().set_trust(&agent_id, params.level).await?;
        let rec = self
            .db
            .agents()
            .get(&agent_id)
            .await?
            .ok_or(ServiceError::NotFound)?;
        let endpoint = rec.endpoint.clone().ok_or_else(|| {
            ServiceError::InvalidParam(
                "agent has no federation endpoint registered — \
                 peer.trust applies only to federated peers"
                    .into(),
            )
        })?;

        audit_or_warn(
            &*self.audit_sink,
            AuditEntry {
                id: None,
                ts: Timestamp::now(),
                actor: self.self_id.clone(),
                action: "peer.trust".into(),
                target: Some(agent_id.to_string()),
                details: Some(serde_json::json!({
                    "level": params.level.as_str(),
                })),
                client_ip: None,
                federation: hermod_storage::AuditFederationPolicy::Default,
            },
        )
        .await;

        let view = self.presence.view_for(&rec.id).await?;
        let effective_alias = rec.effective_alias().cloned();
        Ok(PeerSummary {
            id: rec.id,
            local_alias: rec.local_alias,
            peer_asserted_alias: rec.peer_asserted_alias,
            effective_alias,
            endpoint,
            trust_level: params.level,
            fingerprint: hermod_crypto::fingerprint_from_pubkey(&rec.pubkey).to_human_prefix(8),
            reputation: rec.reputation,
            status: view.status,
            live: view.live,
        })
    }
}

fn parse_pubkey(hex: &str) -> Result<PubkeyBytes, ServiceError> {
    let bytes = hex::decode(hex)
        .map_err(|e| ServiceError::InvalidParam(format!("pubkey_hex invalid: {e}")))?;
    if bytes.len() != PubkeyBytes::LEN {
        return Err(ServiceError::InvalidParam(format!(
            "pubkey must be {} bytes, got {}",
            PubkeyBytes::LEN,
            bytes.len()
        )));
    }
    let mut arr = [0u8; PubkeyBytes::LEN];
    arr.copy_from_slice(&bytes);
    Ok(PubkeyBytes(arr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_pubkey_round_trip() {
        let pk = parse_pubkey(&hex::encode([7u8; 32])).unwrap();
        assert_eq!(pk.0[0], 7);
    }

    #[test]
    fn parse_pubkey_rejects_short() {
        assert!(parse_pubkey(&hex::encode([1u8; 8])).is_err());
    }
}
