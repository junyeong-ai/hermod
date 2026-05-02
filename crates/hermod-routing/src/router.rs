use hermod_core::{AgentAddress, AgentId, Endpoint};
use hermod_storage::Database;
use std::collections::HashSet;
use std::sync::Arc;

use crate::error::{Result, RoutingError};

/// Cap on how many `via_agent_id` indirections the resolver will
/// walk before giving up. Mirrors `wire::MAX_RELAY_HOPS` — a
/// brokered envelope must reach a dialable endpoint within the
/// same hop budget the inbound side will accept on the wire, or
/// the broker chain will reject it anyway.
pub const MAX_VIA_DEPTH: u32 = hermod_protocol::wire::MAX_RELAY_HOPS as u32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RouteDecision {
    /// Target is one of this daemon's hosted local agents — the
    /// envelope short-circuits the federation transport and applies
    /// to that agent's inbox directly.
    Loopback,
    /// Target is registered in the local `agents` table but has no
    /// remote endpoint and no via chain, and no upstream broker is
    /// configured. Delivery is local-only — the daemon stores the
    /// envelope and any attached side-effects run, but no network
    /// I/O happens.
    LocalKnown,
    /// Target has a remote endpoint; delivery goes over WSS+Noise.
    Remote(Endpoint),
    /// Target reached via a broker. The broker's endpoint is the
    /// dial target; `via` is the broker's `agent_id`, surfaced so
    /// audit can record the full hop. The broker's `BrokerMode`
    /// fall-through forwards `to.id` to the actual recipient.
    /// Two paths produce this:
    ///   * Per-peer `agents.via_agent_id` — operator pinned this
    ///     specific recipient to a specific broker.
    ///   * Daemon-wide `upstream_broker` — fallback for any
    ///     directory entry without an endpoint or `via_agent_id`.
    Brokered { endpoint: Endpoint, via: AgentId },
}

/// Daemon-wide fallback broker — used for any directory entry that
/// has neither a direct `endpoint` nor a per-peer `via_agent_id`.
/// Both fields are needed: `endpoint` to dial, `agent_id` to record
/// in audit (and so the resulting `RouteDecision::Brokered` carries
/// the broker's identity uniformly with the per-peer case).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpstreamBrokerHint {
    pub agent_id: AgentId,
    pub endpoint: Endpoint,
}

#[derive(Clone)]
pub struct Router {
    /// Agents this daemon hosts. `Loopback` fires when an envelope's
    /// `to.id` matches any of them; in single-tenant deployments
    /// there's exactly one entry, in multi-tenant there are N.
    local_ids: Arc<HashSet<AgentId>>,
    db: Arc<dyn Database>,
    upstream_broker: Option<UpstreamBrokerHint>,
}

impl std::fmt::Debug for Router {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Router")
            .field("local_id_count", &self.local_ids.len())
            .field("upstream_broker", &self.upstream_broker)
            .finish_non_exhaustive()
    }
}

impl Router {
    pub fn new<I: IntoIterator<Item = AgentId>>(local_ids: I, db: Arc<dyn Database>) -> Self {
        Self {
            local_ids: Arc::new(local_ids.into_iter().collect()),
            db,
            upstream_broker: None,
        }
    }

    /// Configure a daemon-wide fallback broker. Recipients registered
    /// without a remote endpoint of their own AND without a per-peer
    /// `via_agent_id` route via this broker — the daemon does not need
    /// to know peer endpoints itself (Matrix homeserver / SMTP
    /// smarthost / IMAP relay pattern). For per-recipient brokering,
    /// set `agents.via_agent_id` instead.
    pub fn with_upstream_broker(mut self, broker: UpstreamBrokerHint) -> Self {
        self.upstream_broker = Some(broker);
        self
    }

    /// True iff `id` is one of this daemon's hosted local agents.
    pub fn is_local(&self, id: &AgentId) -> bool {
        self.local_ids.contains(id)
    }

    /// Classify where a message to `target` should go.
    ///
    /// Resolution order:
    ///   1. Loopback (target is a hosted local agent).
    ///   2. Direct endpoint hint on the address itself.
    ///   3. Walk `agents.via_agent_id` chain — each hop must have
    ///      either an endpoint (terminal: dial it as broker) or
    ///      another `via_agent_id` (recurse). Cap at
    ///      [`MAX_VIA_DEPTH`]; cycles fail with [`RoutingError::ViaCycle`].
    ///   4. Fall back to the daemon-wide upstream broker.
    ///   5. `LocalKnown` (directory entry exists but has no path —
    ///      messages sit in the outbox).
    ///
    /// Recipients absent from the directory error out: signature
    /// verification on replies requires the peer's pubkey, which
    /// must be ingested first (`agent register` or the workspace
    /// invite flow).
    pub async fn resolve(&self, target: &AgentAddress) -> Result<RouteDecision> {
        if self.is_local(&target.id) {
            return Ok(RouteDecision::Loopback);
        }
        if let Some(ep) = &target.endpoint
            && !ep.is_local()
        {
            return Ok(RouteDecision::Remote(ep.clone()));
        }
        let record = match self.db.agents().get(&target.id).await? {
            Some(r) => r,
            None => return Err(RoutingError::RecipientNotFound(target.id.to_string())),
        };
        if let Some(ep) = record.endpoint
            && !ep.is_local()
        {
            return Ok(RouteDecision::Remote(ep));
        }
        // Walk the via chain. We carry the IMMEDIATE next hop's
        // agent_id ("via") — that's what audit + the outbox will
        // record as the broker. Each iteration moves one step
        // along the chain; the broker that finally surfaces a
        // dialable endpoint is the dial target, but `via` stays
        // pinned to the FIRST hop so the audit trail names the
        // broker the operator configured (not the deepest leaf).
        if let Some(first_via) = record.via_agent_id {
            let resolved = self.resolve_via_chain(&target.id, first_via).await?;
            return Ok(resolved);
        }
        // No per-peer broker — fall back to the daemon-wide hint.
        if let Some(broker) = &self.upstream_broker {
            return Ok(RouteDecision::Brokered {
                endpoint: broker.endpoint.clone(),
                via: broker.agent_id.clone(),
            });
        }
        Ok(RouteDecision::LocalKnown)
    }

    /// Walk `via_agent_id` indirections from `first_via` until a
    /// directly-dialable endpoint surfaces, or fail with
    /// `ViaCycle` / `ViaTooDeep`. The returned decision's `via`
    /// is `first_via` itself — the broker the operator pinned for
    /// the original target — even when resolution traversed
    /// deeper hops.
    async fn resolve_via_chain(
        &self,
        target: &AgentId,
        first_via: AgentId,
    ) -> Result<RouteDecision> {
        let mut visited: HashSet<AgentId> = HashSet::new();
        visited.insert(target.clone());
        let mut chain: Vec<String> = vec![target.to_string()];
        let mut current = first_via.clone();
        for _ in 0..MAX_VIA_DEPTH {
            if !visited.insert(current.clone()) {
                chain.push(current.to_string());
                return Err(RoutingError::ViaCycle { chain });
            }
            chain.push(current.to_string());
            let hop = self
                .db
                .agents()
                .get(&current)
                .await?
                .ok_or_else(|| RoutingError::RecipientNotFound(current.to_string()))?;
            if let Some(ep) = hop.endpoint
                && !ep.is_local()
            {
                return Ok(RouteDecision::Brokered {
                    endpoint: ep,
                    via: first_via,
                });
            }
            current = match hop.via_agent_id {
                Some(next) => next,
                None => {
                    return Err(RoutingError::Rejected(format!(
                        "via chain dead end at {current}: no endpoint, no further via",
                    )));
                }
            };
        }
        Err(RoutingError::ViaTooDeep {
            target: target.to_string(),
            limit: MAX_VIA_DEPTH,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hermod_core::{PubkeyBytes, Timestamp, TrustLevel, WssEndpoint};
    use hermod_crypto::{Keypair, LocalKeySigner, Signer};
    use hermod_storage::AgentRecord;

    async fn fresh_router(self_id: AgentId) -> (Router, Arc<dyn Database>) {
        let signer: Arc<dyn Signer> = Arc::new(LocalKeySigner::new(Arc::new(Keypair::generate())));
        let mut path = std::env::temp_dir();
        path.push(format!("hermod-router-{}.sqlite", ulid::Ulid::new()));
        let blobs = Arc::new(hermod_storage::MemoryBlobStore::new());
        let db = hermod_storage::backends::sqlite::SqliteDatabase::connect(&path, signer, blobs)
            .await
            .unwrap();
        let db: Arc<dyn Database> = Arc::new(db);
        let router = Router::new([self_id], db.clone());
        (router, db)
    }

    fn agent_id(seed: u8) -> AgentId {
        hermod_crypto::agent_id_from_pubkey(&PubkeyBytes([seed; 32]))
    }

    fn wss(host: &str, port: u16) -> Endpoint {
        Endpoint::Wss(WssEndpoint {
            host: host.into(),
            port,
        })
    }

    async fn upsert(db: &Arc<dyn Database>, id: AgentId, endpoint: Option<Endpoint>) {
        let pk = PubkeyBytes([0x42; 32]);
        db.agents()
            .upsert(&AgentRecord {
                id,
                pubkey: pk,
                host_pubkey: None,
                endpoint,
                via_agent_id: None,
                local_alias: None,
                peer_asserted_alias: None,
                trust_level: TrustLevel::Tofu,
                tls_fingerprint: None,
                reputation: 0,
                first_seen: Timestamp::now(),
                last_seen: None,
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn loopback_for_self() {
        let me = agent_id(1);
        let (router, _) = fresh_router(me.clone()).await;
        let dec = router.resolve(&AgentAddress::local(me)).await.unwrap();
        assert_eq!(dec, RouteDecision::Loopback);
    }

    #[tokio::test]
    async fn remote_via_explicit_endpoint() {
        let (router, _) = fresh_router(agent_id(1)).await;
        let target = AgentAddress::with_endpoint(agent_id(2), wss("peer", 7823));
        let dec = router.resolve(&target).await.unwrap();
        assert_eq!(dec, RouteDecision::Remote(wss("peer", 7823)));
    }

    #[tokio::test]
    async fn remote_via_directory_endpoint() {
        let (router, db) = fresh_router(agent_id(1)).await;
        upsert(&db, agent_id(2), Some(wss("peer", 7823))).await;
        let dec = router
            .resolve(&AgentAddress::local(agent_id(2)))
            .await
            .unwrap();
        assert_eq!(dec, RouteDecision::Remote(wss("peer", 7823)));
    }

    #[tokio::test]
    async fn local_known_when_no_endpoint_and_no_broker() {
        let (router, db) = fresh_router(agent_id(1)).await;
        upsert(&db, agent_id(2), None).await;
        let dec = router
            .resolve(&AgentAddress::local(agent_id(2)))
            .await
            .unwrap();
        assert_eq!(dec, RouteDecision::LocalKnown);
    }

    fn upstream_hint(seed: u8, ep: Endpoint) -> UpstreamBrokerHint {
        UpstreamBrokerHint {
            agent_id: agent_id(seed),
            endpoint: ep,
        }
    }

    #[tokio::test]
    async fn brokered_when_no_endpoint_and_broker_set() {
        let (router, db) = fresh_router(agent_id(1)).await;
        let router = router.with_upstream_broker(upstream_hint(99, wss("broker", 7823)));
        upsert(&db, agent_id(2), None).await;
        let dec = router
            .resolve(&AgentAddress::local(agent_id(2)))
            .await
            .unwrap();
        assert_eq!(
            dec,
            RouteDecision::Brokered {
                endpoint: wss("broker", 7823),
                via: agent_id(99),
            }
        );
    }

    #[tokio::test]
    async fn direct_endpoint_beats_broker() {
        // Recipient with a known endpoint goes direct, even with broker
        // configured — broker is the *fallback*, not a forced relay.
        let (router, db) = fresh_router(agent_id(1)).await;
        let router = router.with_upstream_broker(upstream_hint(99, wss("broker", 7823)));
        upsert(&db, agent_id(2), Some(wss("peer", 9000))).await;
        let dec = router
            .resolve(&AgentAddress::local(agent_id(2)))
            .await
            .unwrap();
        assert_eq!(dec, RouteDecision::Remote(wss("peer", 9000)));
    }

    #[tokio::test]
    async fn unknown_recipient_errors_even_with_broker() {
        // The agents row has to exist for signature verification on
        // replies — we don't auto-register on send.
        let (router, _) = fresh_router(agent_id(1)).await;
        let router = router.with_upstream_broker(upstream_hint(99, wss("broker", 7823)));
        let dec = router.resolve(&AgentAddress::local(agent_id(2))).await;
        assert!(matches!(dec, Err(RoutingError::RecipientNotFound(_))));
    }

    /// Per-peer `via_agent_id` overrides the daemon-wide upstream
    /// fallback. Operator pinning a specific recipient to a specific
    /// broker beats the global default.
    #[tokio::test]
    async fn via_agent_id_overrides_upstream_broker() {
        let (router, db) = fresh_router(agent_id(1)).await;
        let router = router.with_upstream_broker(upstream_hint(99, wss("upstream", 1)));
        // broker has its own endpoint — insert FIRST so the FK target
        // exists when we then upsert the target row pointing at it.
        upsert(&db, agent_id(50), Some(wss("specific-broker", 7823))).await;
        upsert(&db, agent_id(2), None).await;
        upsert_via(&db, agent_id(2), agent_id(50)).await;
        let dec = router
            .resolve(&AgentAddress::local(agent_id(2)))
            .await
            .unwrap();
        assert_eq!(
            dec,
            RouteDecision::Brokered {
                endpoint: wss("specific-broker", 7823),
                via: agent_id(50),
            }
        );
    }

    /// Two-hop via chain: target → broker A → broker B (with endpoint).
    /// The `via` reported in the decision is the FIRST hop the
    /// operator pinned (broker A), even though the dial actually
    /// hits broker B's endpoint.
    #[tokio::test]
    async fn via_chain_two_hops_resolves_to_first_via() {
        let (router, db) = fresh_router(agent_id(1)).await;
        upsert(&db, agent_id(60), Some(wss("broker-b", 7823))).await;
        upsert(&db, agent_id(50), None).await;
        upsert(&db, agent_id(2), None).await;
        upsert_via(&db, agent_id(50), agent_id(60)).await; // A → B
        upsert_via(&db, agent_id(2), agent_id(50)).await; // target → A
        let dec = router
            .resolve(&AgentAddress::local(agent_id(2)))
            .await
            .unwrap();
        assert_eq!(
            dec,
            RouteDecision::Brokered {
                endpoint: wss("broker-b", 7823),
                via: agent_id(50),
            }
        );
    }

    /// A → B → A self-cycle is detected at dispatch and surfaces as
    /// a `ViaCycle` error so the operator's misconfiguration fails
    /// loud rather than spinning the resolver.
    #[tokio::test]
    async fn via_cycle_detected() {
        let (router, db) = fresh_router(agent_id(1)).await;
        // FK ordering: insert empty rows first so each via target
        // exists before the via reference is set. Then upsert the
        // via fields, which `COALESCE(excluded.via_agent_id, …)`
        // will fill in (NULL → Some, no-op for already-set).
        upsert(&db, agent_id(50), None).await;
        upsert(&db, agent_id(60), None).await;
        upsert(&db, agent_id(2), None).await;
        upsert_via(&db, agent_id(50), agent_id(60)).await;
        upsert_via(&db, agent_id(60), agent_id(50)).await;
        upsert_via(&db, agent_id(2), agent_id(50)).await;
        let err = router
            .resolve(&AgentAddress::local(agent_id(2)))
            .await
            .unwrap_err();
        assert!(matches!(err, RoutingError::ViaCycle { .. }), "got {err:?}");
    }

    /// Chain depth exceeded — no endpoint reached within
    /// `MAX_VIA_DEPTH` hops, even without a cycle.
    #[tokio::test]
    async fn via_too_deep() {
        let (router, db) = fresh_router(agent_id(1)).await;
        let depth = MAX_VIA_DEPTH + 2;
        // Phase 1: pre-create every node row so FK targets exist.
        for i in 0..=depth {
            upsert(&db, agent_id(50 + i as u8), None).await;
        }
        upsert(&db, agent_id(2), None).await;
        // Phase 2: link them into a chain.
        for i in 0..depth {
            let cur = agent_id(50 + i as u8);
            let next = agent_id(50 + i as u8 + 1);
            upsert_via(&db, cur, next).await;
        }
        upsert_via(&db, agent_id(2), agent_id(50)).await;
        let err = router
            .resolve(&AgentAddress::local(agent_id(2)))
            .await
            .unwrap_err();
        assert!(
            matches!(err, RoutingError::ViaTooDeep { .. }),
            "got {err:?}",
        );
    }

    async fn upsert_via(db: &Arc<dyn Database>, id: AgentId, via: AgentId) {
        let pk = PubkeyBytes([0x42; 32]);
        db.agents()
            .upsert(&AgentRecord {
                id,
                pubkey: pk,
                host_pubkey: None,
                endpoint: None,
                via_agent_id: Some(via),
                local_alias: None,
                peer_asserted_alias: None,
                trust_level: TrustLevel::Tofu,
                tls_fingerprint: None,
                reputation: 0,
                first_seen: Timestamp::now(),
                last_seen: None,
            })
            .await
            .unwrap();
    }
}
