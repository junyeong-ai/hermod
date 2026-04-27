use hermod_core::{AgentId, Endpoint, PubkeyBytes, Timestamp, TrustLevel};
use hermod_protocol::ipc::methods::{
    AliasOutcomeView, PeerAddParams, PeerAddResult, PeerListResult, PeerRemoveParams,
    PeerRemoveResult, PeerRepinParams, PeerRepinResult, PeerSummary, PeerTrustParams,
};
use hermod_routing::PeerPool;
use hermod_storage::{AuditEntry, Database, AuditSink};
use std::str::FromStr;
use std::sync::Arc;

use crate::federation::record_peer;
use crate::services::{ServiceError, audit_or_warn, presence::PresenceService};

#[derive(Debug, Clone)]
pub struct PeerService {
    db: Arc<dyn Database>,
    audit_sink: Arc<dyn AuditSink>,
    self_id: AgentId,
    presence: PresenceService,
    pool: Arc<PeerPool>,
}

impl PeerService {
    pub fn new(
        db: Arc<dyn Database>,
        audit_sink: Arc<dyn AuditSink>,
        self_id: AgentId,
        presence: PresenceService,
        pool: Arc<PeerPool>,
    ) -> Self {
        Self {
            db,
            audit_sink,
            self_id,
            presence,
            pool,
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
        let pubkey_hex = params.pubkey_hex.ok_or_else(|| {
            ServiceError::InvalidParam(
                "peer.add requires --pubkey-hex; an endpoint without a known \
                 pubkey can't authenticate via Noise"
                    .into(),
            )
        })?;
        let pubkey = parse_pubkey(&pubkey_hex)?;
        // local_alias arrived already validated thanks to AgentAlias's
        // `try_from` Deserialize impl — no extra parse step here.
        let (rec, outcome) = record_peer(&*self.db, endpoint, pubkey, None, params.local_alias)
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
            audit_or_warn(&*self.audit_sink,
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
                    federation: hermod_storage::AuditFederationPolicy::Default,
                },
            )
            .await;
        }

        audit_or_warn(&*self.audit_sink,
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
                federation: hermod_storage::AuditFederationPolicy::Default,
            },
        )
        .await;

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
            audit_or_warn(&*self.audit_sink,
                AuditEntry {
                    id: None,
                    ts: Timestamp::now(),
                    actor: self.self_id.clone(),
                    action: "peer.remove".into(),
                    target: Some(agent_id.to_string()),
                    details: Some(serde_json::json!({
                        "messages_failed": failed,
                    })),
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
        audit_or_warn(&*self.audit_sink,
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

        audit_or_warn(&*self.audit_sink,
            AuditEntry {
                id: None,
                ts: Timestamp::now(),
                actor: self.self_id.clone(),
                action: "peer.trust".into(),
                target: Some(agent_id.to_string()),
                details: Some(serde_json::json!({
                    "level": params.level.as_str(),
                })),
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
