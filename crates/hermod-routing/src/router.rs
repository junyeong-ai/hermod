use hermod_core::{AgentAddress, AgentId, Endpoint};
use hermod_storage::Database;
use std::sync::Arc;

use crate::error::{Result, RoutingError};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RouteDecision {
    /// Target is this daemon's own identity.
    Loopback,
    /// Target is registered in the local `agents` table but has no
    /// remote endpoint, and no upstream broker is configured.
    /// Delivery is local-only — the daemon stores the envelope and
    /// any attached side-effects run, but no network I/O happens.
    LocalKnown,
    /// Target has a remote endpoint; delivery goes over WSS+Noise.
    Remote(Endpoint),
    /// Target lives behind an upstream broker. Delivery goes to the
    /// broker over WSS+Noise; the broker forwards to the recipient.
    /// Audit distinguishes this from `Remote` so operators can spot
    /// which envelopes traversed the broker.
    Brokered(Endpoint),
}

#[derive(Clone)]
pub struct Router {
    self_id: AgentId,
    db: Arc<dyn Database>,
    upstream_broker: Option<Endpoint>,
}

impl std::fmt::Debug for Router {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Router")
            .field("self_id", &self.self_id)
            .field("upstream_broker", &self.upstream_broker)
            .finish_non_exhaustive()
    }
}

impl Router {
    pub fn new(self_id: AgentId, db: Arc<dyn Database>) -> Self {
        Self {
            self_id,
            db,
            upstream_broker: None,
        }
    }

    /// Configure an upstream broker. Recipients registered without
    /// a remote endpoint of their own route via this endpoint — the
    /// daemon does not need to know peer endpoints itself (Matrix
    /// homeserver / SMTP smarthost / IMAP relay pattern).
    pub fn with_upstream_broker(mut self, endpoint: Endpoint) -> Self {
        self.upstream_broker = Some(endpoint);
        self
    }

    pub fn self_id(&self) -> &AgentId {
        &self.self_id
    }

    /// Classify where a message to `target` should go.
    ///
    /// Recipients absent from the directory error out:
    /// signature verification on replies requires the peer's
    /// pubkey, which must be ingested first (`agent register` or the
    /// workspace invite flow).
    pub async fn resolve(&self, target: &AgentAddress) -> Result<RouteDecision> {
        if target.id.as_str() == self.self_id.as_str() {
            return Ok(RouteDecision::Loopback);
        }
        // Prefer explicit endpoint on the address.
        if let Some(ep) = &target.endpoint
            && !ep.is_local()
        {
            return Ok(RouteDecision::Remote(ep.clone()));
        }
        // Otherwise consult the directory.
        match self.db.agents().get(&target.id).await? {
            Some(record) => match record.endpoint {
                Some(ep) if !ep.is_local() => Ok(RouteDecision::Remote(ep)),
                _ => match &self.upstream_broker {
                    Some(broker) => Ok(RouteDecision::Brokered(broker.clone())),
                    None => Ok(RouteDecision::LocalKnown),
                },
            },
            None => Err(RoutingError::RecipientNotFound(target.id.to_string())),
        }
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
        let router = Router::new(self_id, db.clone());
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

    #[tokio::test]
    async fn brokered_when_no_endpoint_and_broker_set() {
        let (router, db) = fresh_router(agent_id(1)).await;
        let router = router.with_upstream_broker(wss("broker", 7823));
        upsert(&db, agent_id(2), None).await;
        let dec = router
            .resolve(&AgentAddress::local(agent_id(2)))
            .await
            .unwrap();
        assert_eq!(dec, RouteDecision::Brokered(wss("broker", 7823)));
    }

    #[tokio::test]
    async fn direct_endpoint_beats_broker() {
        // Recipient with a known endpoint goes direct, even with broker
        // configured — broker is the *fallback*, not a forced relay.
        let (router, db) = fresh_router(agent_id(1)).await;
        let router = router.with_upstream_broker(wss("broker", 7823));
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
        let router = router.with_upstream_broker(wss("broker", 7823));
        let dec = router.resolve(&AgentAddress::local(agent_id(2))).await;
        assert!(matches!(dec, Err(RoutingError::RecipientNotFound(_))));
    }
}
