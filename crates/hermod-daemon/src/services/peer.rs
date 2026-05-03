use hermod_core::{
    AdvertisedAgent, AgentAddress, AgentAlias, AgentId, Endpoint, MessageBody, MessagePriority,
    MessageStatus, PubkeyBytes, Timestamp, TrustLevel,
};
use hermod_protocol::ipc::methods::{
    MessageSendParams, MessageSendResult, PeerAddParams, PeerAddResult, PeerAdvertiseOutcome,
    PeerAdvertiseParams, PeerAdvertiseResult, PeerListResult, PeerRemoveParams, PeerRemoveResult,
    PeerRepinParams, PeerRepinResult, PeerSummary, PeerTrustParams,
};
use hermod_routing::PeerPool;
use hermod_storage::{AuditEntry, AuditSink, Database};
use std::collections::HashSet;
use std::str::FromStr;
use std::sync::Arc;

use crate::federation::{record_agent_peer, record_brokered_peer};
use crate::local_agent::LocalAgentRegistry;
use crate::services::{
    ServiceError, audit_or_warn, message::MessageService, presence::PresenceService,
    resolve_host_endpoint,
};

#[derive(Debug, Clone)]
pub struct PeerService {
    db: Arc<dyn Database>,
    audit_sink: Arc<dyn AuditSink>,
    host_actor: AgentId,
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
        host_actor: AgentId,
        presence: PresenceService,
        pool: Arc<PeerPool>,
        registry: LocalAgentRegistry,
        host_pubkey: PubkeyBytes,
        messages: MessageService,
    ) -> Self {
        Self {
            db,
            audit_sink,
            host_actor,
            presence,
            pool,
            registry,
            host_pubkey,
            messages,
        }
    }

    pub async fn add(&self, params: PeerAddParams) -> Result<PeerAddResult, ServiceError> {
        let agent_pubkey = parse_pubkey(&params.agent_pubkey_hex)?;
        let rec = match params.reach {
            hermod_protocol::ipc::methods::PeerReach::Direct {
                endpoint,
                host_pubkey_hex,
            } => {
                let host_pubkey = parse_pubkey(&host_pubkey_hex)?;
                let wss = match endpoint {
                    Endpoint::Wss(w) => w,
                    Endpoint::Unix { .. } => {
                        return Err(ServiceError::InvalidParam(
                            "peer.add only accepts wss:// endpoints".into(),
                        ));
                    }
                };
                record_agent_peer(
                    &*self.db,
                    wss,
                    host_pubkey,
                    agent_pubkey,
                    params.local_alias.clone(),
                )
                .await
                .map_err(|e| ServiceError::InvalidParam(e.to_string()))?
            }
            hermod_protocol::ipc::methods::PeerReach::Via { via } => {
                let via_id = self.resolve_target(&via).await?;
                record_brokered_peer(&*self.db, via_id, agent_pubkey, params.local_alias.clone())
                    .await
                    .map_err(|e| ServiceError::InvalidParam(e.to_string()))?
            }
        };
        let fingerprint = hermod_crypto::fingerprint_from_pubkey(&rec.pubkey).to_human_prefix(8);

        audit_or_warn(
            &*self.audit_sink,
            AuditEntry {
                id: None,
                ts: Timestamp::now(),
                actor: self.host_actor.clone(),
                action: "peer.add".into(),
                target: Some(rec.id.to_string()),
                details: Some(serde_json::json!({
                    "fingerprint": fingerprint,
                    "host_id": rec.host_id.as_ref().map(|h| h.to_string()),
                    "via_agent": rec.via_agent.as_ref().map(|a| a.to_string()),
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
        let agents = self.advertised_agents().await;
        let agent_count = agents.len() as u32;
        // One row per resolved target; status mirrors what
        // `MessageService::send` actually saw on the wire (not just
        // the queue ack), so the operator/script can tell apart
        // "delivered" from "looks delivered, was actually queued
        // against a dead pool entry". Mirrors the honesty contract
        // of `MessageSendResult`.
        let mut outcomes: Vec<PeerAdvertiseOutcome> = Vec::new();
        match params.target {
            Some(reference) => {
                let target = self.resolve_target(&reference).await?;
                outcomes.push(self.dispatch_one(target, agents.clone()).await);
            }
            None => {
                // Walk federated peers; pick one canonical recipient
                // per distinct `host_id` so a peer running N hosted
                // agents receives the advertise once, not N times.
                // Brokered agents (host_id NULL, via_agent set) get
                // their own dispatch — the broker will fan out the
                // second hop.
                let rows = self.db.agents().list_federated().await?;
                let mut seen_hosts: HashSet<AgentId> = HashSet::new();
                for r in rows {
                    if let Some(host) = &r.host_id
                        && !seen_hosts.insert(host.clone())
                    {
                        continue;
                    }
                    outcomes.push(self.dispatch_one(r.id, agents.clone()).await);
                }
            }
        }

        let delivered = outcomes
            .iter()
            .filter(|o| o.status == MessageStatus::Delivered)
            .count() as u32;
        let failed = outcomes
            .iter()
            .filter(|o| o.status == MessageStatus::Failed)
            .count() as u32;

        audit_or_warn(
            &*self.audit_sink,
            AuditEntry {
                id: None,
                ts: Timestamp::now(),
                actor: self.host_actor.clone(),
                action: "peer.advertise".into(),
                target: None,
                details: Some(serde_json::json!({
                    "delivered": delivered,
                    "failed": failed,
                    "agents": agent_count,
                })),
                client_ip: None,
                federation: hermod_storage::AuditFederationPolicy::Default,
            },
        )
        .await;

        Ok(PeerAdvertiseResult {
            outcomes,
            agents: agent_count,
        })
    }

    /// Dispatch one advertise envelope and synthesise the per-target
    /// row. Wire failures land in `error: Some(...)` rather than
    /// bubbling — the caller wants a populated row per attempted
    /// target, even on failure (that's the whole point of the honest
    /// response). `Pending` from the underlying `send` (transient
    /// failure, queued for retry) is reported as `Failed` here: from
    /// the advertise CLI's perspective the wire didn't ack, so the
    /// operator should retry or investigate, not assume success.
    async fn dispatch_one(
        &self,
        target: AgentId,
        agents: Vec<AdvertisedAgent>,
    ) -> PeerAdvertiseOutcome {
        match self.send_advertise(&target, agents).await {
            Ok(res) if res.status == MessageStatus::Delivered => PeerAdvertiseOutcome {
                target,
                status: MessageStatus::Delivered,
                error: None,
            },
            Ok(res) => PeerAdvertiseOutcome {
                target,
                status: MessageStatus::Failed,
                error: Some(format!(
                    "advertise dispatch did not deliver (status={:?})",
                    res.status
                )),
            },
            Err(e) => PeerAdvertiseOutcome {
                target,
                status: MessageStatus::Failed,
                error: Some(e.to_string()),
            },
        }
    }

    /// Internal: advertise to a specific peer agent_id. Used by the
    /// `peer.add` auto-trigger. Returns `Ok(())` only if the
    /// underlying wire delivery succeeded — best-effort site, so a
    /// `Pending` result (queued for retry) and outright errors both
    /// surface as `Err` so the caller logs a warning the operator
    /// can act on.
    async fn advertise_to_agent(&self, target: &AgentId) -> Result<(), ServiceError> {
        let agents = self.advertised_agents().await;
        let res = self.send_advertise(target, agents).await?;
        if res.status != MessageStatus::Delivered {
            return Err(ServiceError::InvalidParam(format!(
                "advertise to {target} did not deliver (status={:?})",
                res.status
            )));
        }
        Ok(())
    }

    /// Build the `AdvertisedAgent` list for an outbound
    /// `peer.advertise` envelope. Reads operator-set tags from
    /// `local_agents.tags` so peers receive the discovery
    /// metadata alongside the identity. Failures during the tag
    /// read fall through to empty — the directory entry still
    /// propagates, which is the existing pre-PR-4 behaviour.
    async fn advertised_agents(&self) -> Vec<AdvertisedAgent> {
        let mut out = Vec::with_capacity(self.registry.list().len());
        for a in self.registry.list().iter() {
            let tags = match self.db.local_agents().lookup_by_id(&a.agent_id).await {
                Ok(Some(rec)) => rec.tags.into_strings(),
                _ => Vec::new(),
            };
            out.push(AdvertisedAgent {
                id: a.agent_id.clone(),
                pubkey: a.keypair.to_pubkey_bytes(),
                alias: a.local_alias.clone(),
                tags,
            });
        }
        out
    }

    async fn send_advertise(
        &self,
        target: &AgentId,
        agents: Vec<AdvertisedAgent>,
    ) -> Result<MessageSendResult, ServiceError> {
        // Resolve recipient endpoint via the host record so the
        // router knows whether to dial direct or via a broker.
        let rec = self.db.agents().get(target).await?.ok_or_else(|| {
            ServiceError::InvalidParam(format!("peer.advertise target {target} not in directory"))
        })?;
        let to = match resolve_host_endpoint(&*self.db, &rec).await {
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
        // walks our own registry. Returns the inner send result so
        // the dispatcher can map `(Ok, status)` cleanly to a
        // `PeerAdvertiseOutcome` without shoehorning wire status
        // into the error variants.
        self.messages
            .send(MessageSendParams {
                to,
                body,
                priority: Some(MessagePriority::Low),
                thread: None,
                ttl_secs: Some(300),
                caps: None,
            })
            .await
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
            // Federated agents either route via host (host_id) or via
            // a broker (via_agent). For the operator-facing peer list
            // we surface the host endpoint when present; brokered
            // agents render with no endpoint (their dial target is
            // the broker, which has its own row).
            let endpoint = resolve_host_endpoint(&*self.db, &r).await;
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
        // Order matters: fail in-flight messages first, then clear
        // the host endpoint. The outbox skips host-less rows by
        // query filter — failing them after that point would leave
        // them invisible-but-pending in the operator's inbox.
        let failed = self.db.messages().fail_pending_to(&agent_id).await?;
        let agent = self.db.agents().get(&agent_id).await?;
        // `hosts().forget` reads-and-clears atomically; we evict the
        // pool entry inside the same atomic snapshot so a concurrent
        // `peer.add` can't leave a stale-endpoint connection alive.
        let mut existed = false;
        if let Some(host_id) = agent.as_ref().and_then(|a| a.host_id.clone()) {
            let outcome = self.db.hosts().forget(&host_id).await?;
            existed = outcome.existed;
            if let Some(ep) = &outcome.prior_endpoint {
                self.pool.evict_endpoint(ep).await;
            }
        }
        // The agent row stays for audit / capability lineage, but it
        // is no longer routable — clear both routing pointers so a
        // subsequent envelope addressed `--to @alias` fails fast
        // rather than hanging on the dead host.
        self.db.agents().clear_routing(&agent_id).await?;
        if existed {
            audit_or_warn(
                &*self.audit_sink,
                AuditEntry {
                    id: None,
                    ts: Timestamp::now(),
                    actor: self.host_actor.clone(),
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
        Ok(PeerRemoveResult { removed: existed })
    }

    pub async fn repin(&self, params: PeerRepinParams) -> Result<PeerRepinResult, ServiceError> {
        let agent_id = AgentId::from_str(&params.peer).map_err(|e| {
            ServiceError::InvalidParam(format!("peer.repin requires an agent_id: {e}"))
        })?;
        // Operator gate: only Verified peers can rotate cert pins —
        // a malicious advertise-only path can't trigger TOFU
        // re-acceptance.
        let agent = self
            .db
            .agents()
            .get(&agent_id)
            .await?
            .ok_or(ServiceError::NotFound)?;
        if agent.trust_level != TrustLevel::Verified {
            return Err(ServiceError::InvalidParam(format!(
                "peer.repin only applies to Verified peers (current: {})",
                agent.trust_level.as_str()
            )));
        }
        let host_id = agent.host_id.ok_or_else(|| {
            ServiceError::InvalidParam(
                "agent has no host record — peer.repin requires a federated peer".into(),
            )
        })?;
        // Atomic: read of endpoint + fp swap in one SQL transaction.
        // The endpoint snapshot lets us evict the right pool entry
        // without a follow-up SELECT — without that snapshot, a
        // concurrent `peer.add` could change endpoint between the
        // swap and our evict, leaving a stale-context entry alive.
        let outcome = self
            .db
            .hosts()
            .replace_tls_fingerprint(&host_id, &params.fingerprint)
            .await?;
        let (previous, endpoint) = match outcome {
            hermod_storage::RepinOutcome::Replaced { previous, endpoint } => (previous, endpoint),
            hermod_storage::RepinOutcome::NotFound => return Err(ServiceError::NotFound),
        };
        // Tear down the pooled connection bound to the old fp so the
        // next dial re-handshakes against the new pin immediately
        // rather than riding the existing TLS session for up to
        // `idle_ttl`.
        if let Some(ep) = &endpoint {
            self.pool.evict_endpoint(ep).await;
        }
        audit_or_warn(
            &*self.audit_sink,
            AuditEntry {
                id: None,
                ts: Timestamp::now(),
                actor: self.host_actor.clone(),
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
        let endpoint = resolve_host_endpoint(&*self.db, &rec).await;

        audit_or_warn(
            &*self.audit_sink,
            AuditEntry {
                id: None,
                ts: Timestamp::now(),
                actor: self.host_actor.clone(),
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
