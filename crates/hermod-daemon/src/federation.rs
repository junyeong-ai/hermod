//! Federation server: binds the inbound listener via the configured
//! [`Transport`], runs the mutual handshake per connection, and feeds
//! verified frames to [`InboundProcessor`].
//!
//! ## Transport boundary
//!
//! The handshake (TLS + Noise XX for the WSS+Noise backend; mTLS for a
//! future gRPC backend; etc.) is the [`Transport`]'s responsibility —
//! [`hermod_routing::TransportListener::accept`] returns a
//! fully-authenticated [`TransportConnection`]. This file only sees
//! the post-handshake identity and the bidirectional frame stream.
//!
//! ## Slow-loris and flood protection
//!
//! Two layers cap how many partial / abusive connections can stack up:
//!
//!   * An `Arc<Semaphore>` sized by `[policy] max_inflight_handshakes`
//!     gates the spawn of any handshake task. New connections beyond
//!     the cap park at `acquire_owned()`.
//!   * Per-source-IP token bucket (one-second refill, future addition)
//!     for transports that expose source-IP at accept time. The
//!     current `Transport` trait abstracts that detail away;
//!     reintroduce per-IP gating when transport adds an
//!     `accept_with_metadata` method.

use hermod_core::{Endpoint, PubkeyBytes, Timestamp, TrustLevel, WssEndpoint};
use hermod_protocol::wire::{AckStatus, Pong, WireFrame};
use hermod_routing::{Transport, TransportConnection};
use hermod_storage::{AgentRecord, Database, HostRecord};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

use crate::inbound::InboundProcessor;

/// Compile-time floor on the inflight-handshake cap. The runtime value
/// comes from `[policy] max_inflight_handshakes`; this is the smallest
/// the operator can set it to so a misconfiguration can't reduce the
/// listener to a single-connection bottleneck.
const MIN_INFLIGHT_HANDSHAKES: usize = 4;

#[derive(Clone)]
pub struct FederationServer {
    transport: Arc<dyn Transport>,
    processor: InboundProcessor,
    max_inflight_handshakes: usize,
}

impl std::fmt::Debug for FederationServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FederationServer")
            .field("transport", &self.transport.name())
            .field("processor", &self.processor)
            .finish_non_exhaustive()
    }
}

impl FederationServer {
    pub fn new(
        transport: Arc<dyn Transport>,
        processor: InboundProcessor,
        max_inflight_handshakes: u32,
    ) -> Self {
        let max = std::cmp::max(max_inflight_handshakes as usize, MIN_INFLIGHT_HANDSHAKES);
        Self {
            transport,
            processor,
            max_inflight_handshakes: max,
        }
    }

    /// Bind to `addr` via the configured transport and serve inbound
    /// peer connections forever (until the runtime shuts down).
    pub async fn run(self, addr: SocketAddr) -> anyhow::Result<()> {
        let listener = self.transport.listen(addr).await?;
        let local = listener.local_addr()?;
        info!(
            backend = self.transport.name(),
            addr = %local,
            "federation listener up"
        );

        let semaphore = Arc::new(Semaphore::new(self.max_inflight_handshakes));

        loop {
            // Acquire a global handshake slot. Caller waits if the cap is
            // reached — backpressure on accept; new flooders sit in the
            // kernel queue rather than burning daemon memory.
            let permit = match semaphore.clone().acquire_owned().await {
                Ok(p) => p,
                Err(_) => {
                    warn!("federation semaphore closed; aborting accept loop");
                    break Ok(());
                }
            };

            let conn = match listener.accept().await {
                Ok(c) => c,
                Err(e) => {
                    debug!(error = %e, "federation accept failed");
                    drop(permit);
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    continue;
                }
            };

            let me = self.clone();
            tokio::spawn(async move {
                let _permit = permit; // released when this task ends
                let host_id = conn.identity().host_id.clone();
                if let Err(e) = me.handle_peer(conn).await {
                    warn!(peer = %host_id, error = %e, "inbound peer task ended");
                }
            });
        }
    }

    async fn handle_peer(&self, mut conn: Box<dyn TransportConnection>) -> anyhow::Result<()> {
        let identity = conn.identity().clone();
        info!(
            host = %identity.host_id,
            tls_fp = ?identity.tls_fingerprint,
            "inbound peer authenticated"
        );

        // TOFU register/update on first contact. The handshake
        // authenticates the *host* (Noise XX static is host_pubkey),
        // so the agents row created here is the host's. Per-tenant
        // agents on the remote daemon are learned later, when their
        // envelopes arrive (`InboundProcessor::upsert_sender_observed`).
        record_host_peer(
            self.processor.db(),
            None,
            identity.host_pubkey,
            None,
            identity.tls_fingerprint.clone(),
        )
        .await?;

        loop {
            let frame = match conn.recv_frame().await? {
                Some(f) => f,
                None => {
                    debug!("peer closed");
                    break;
                }
            };
            match frame {
                WireFrame::Envelope(envelope_frame) => {
                    let id = envelope_frame.envelope.id;
                    let hops = envelope_frame.hops;
                    match self
                        .processor
                        .accept_envelope(&identity.host_id, &envelope_frame.envelope, hops)
                        .await
                    {
                        Ok(()) => conn.send_ack(id, AckStatus::Delivered, None).await?,
                        Err(e) => {
                            warn!(error = %e, "rejecting envelope");
                            conn.send_ack(id, AckStatus::Rejected, Some(e.to_string()))
                                .await?
                        }
                    }
                }
                WireFrame::Ping(p) => {
                    // Universal echo — pong back with the same nonce so the
                    // initiator can correlate. Half-open detection on either
                    // side relies on this being prompt and reflexive.
                    if let Err(e) = conn
                        .send_frame(&WireFrame::Pong(Pong { nonce: p.nonce }))
                        .await
                    {
                        warn!(error = %e, "failed to pong; dropping connection");
                        break;
                    }
                }
                WireFrame::Pong(_) => {
                    // We never initiate Pings on the inbound listener — the
                    // outbound `PeerPool` is the prober. A Pong here is
                    // either lag from a previous role or a misbehaving peer;
                    // either way, no correlator to satisfy, so ignore.
                    continue;
                }
                WireFrame::Close(c) => {
                    info!(code = c.code, reason = %c.reason, "peer requested close");
                    break;
                }
                WireFrame::Hello(_) => {
                    warn!("unexpected duplicate Hello after handshake");
                    break;
                }
                WireFrame::DeliveryAck(_) => continue,
            }
        }
        Ok(())
    }
}

/// Register a federation host (a remote daemon).
///
/// A host is the entity authenticated by the federation Noise XX
/// handshake. Used by:
///
///   * Inbound handshake TOFU (`endpoint = None`, alias = None,
///     `tls_fingerprint = Some(observed)`)
///   * Broker config seed (`endpoint = Some(broker_endpoint)`)
///   * Discovery ingestion (mDNS, static-config peers — alias from beacon)
///
/// Hosts live in the dedicated `hosts` table. Agents reference them
/// via `agents.host_id` FK. Re-observation COALESCEs missing fields
/// so a partial update never blanks a known endpoint / TLS pin /
/// alias.
pub async fn record_host_peer(
    db: &dyn Database,
    endpoint: Option<WssEndpoint>,
    host_pubkey: PubkeyBytes,
    peer_asserted_alias: Option<hermod_core::AgentAlias>,
    tls_fingerprint: Option<String>,
) -> anyhow::Result<HostRecord> {
    use hermod_crypto::agent_id_from_pubkey;
    let now = Timestamp::now();
    let host_id = agent_id_from_pubkey(&host_pubkey);
    db.hosts()
        .upsert(&HostRecord {
            id: host_id.clone(),
            pubkey: host_pubkey,
            endpoint: endpoint.map(Endpoint::Wss),
            tls_fingerprint,
            peer_asserted_alias,
            first_seen: now,
            last_seen: Some(now),
        })
        .await?;
    db.hosts()
        .get(&host_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("host vanished after upsert: {host_id}"))
}

/// Register a federation peer agent — `peer add --endpoint`. Inserts
/// the host record (so the dial pool can resolve endpoint + TLS pin)
/// and the agent record (so envelope addressing by `to.id` resolves).
/// Both rows go through `upsert`, not `upsert_observed`, so a re-run
/// of `peer add` on an agent the operator has already seen does not
/// clobber peer-asserted columns the row has accumulated. A
/// `local_alias` collision against a different agent_id surfaces as
/// a UNIQUE-constraint storage error — operator input must resolve
/// cleanly; the silent-drop sovereignty path is reserved for inbound.
pub async fn record_agent_peer(
    db: &dyn Database,
    endpoint: WssEndpoint,
    host_pubkey: PubkeyBytes,
    agent_pubkey: PubkeyBytes,
    local_alias: Option<hermod_core::AgentAlias>,
) -> anyhow::Result<AgentRecord> {
    use hermod_crypto::agent_id_from_pubkey;
    let host = record_host_peer(db, Some(endpoint), host_pubkey, None, None).await?;

    let now = Timestamp::now();
    let agent_id = agent_id_from_pubkey(&agent_pubkey);
    db.agents()
        .upsert(&AgentRecord {
            id: agent_id.clone(),
            pubkey: agent_pubkey,
            host_id: Some(host.id.clone()),
            via_agent: None,
            local_alias,
            peer_asserted_alias: None,
            trust_level: TrustLevel::Tofu,
            reputation: 0,
            first_seen: now,
            last_seen: None,
            peer_asserted_tags: hermod_core::CapabilityTagSet::empty(),
        })
        .await?;
    // Pin direct routing explicitly. `upsert` doesn't touch routing
    // fields; this call carries the operator's intent and atomically
    // satisfies the `host_id XOR via_agent` CHECK against any prior
    // brokered configuration.
    db.agents().set_routing_direct(&agent_id, &host.id).await?;
    db.agents()
        .get(&agent_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("agent peer vanished after upsert: {agent_id}"))
}

/// Register a peer agent reachable only through a broker.
///
/// Mirror of [`record_agent_peer`] for the brokered case: instead of
/// `host_id`, the new agent's row points at `via_agent`. The
/// broker's host record must already exist (the broker itself is
/// added first via `peer add --endpoint`, or learned via inbound
/// federation handshake — both go through `record_host_peer`).
///
/// The peer's own host record is NOT inserted here. The dial path
/// goes through the broker's host; the peer's `host_pubkey` is
/// captured implicitly inside `agent_pubkey`'s self-certifying
/// derivation when its envelopes start arriving and inbound TOFU
/// runs `record_host_peer` to back the cert pin then.
pub async fn record_brokered_peer(
    db: &dyn Database,
    via_agent: hermod_core::AgentId,
    agent_pubkey: PubkeyBytes,
    local_alias: Option<hermod_core::AgentAlias>,
) -> anyhow::Result<AgentRecord> {
    use hermod_crypto::agent_id_from_pubkey;
    // Verify the broker exists in the directory — FK will reject
    // otherwise, but a friendly error here saves the operator a
    // round-trip to the SQL log.
    if db.agents().get(&via_agent).await?.is_none() {
        anyhow::bail!(
            "via target {via_agent} not in directory; add the broker first \
             (`peer add --endpoint <broker_url> --host-pubkey-hex … --agent-pubkey-hex …`)"
        );
    }

    let now = Timestamp::now();
    let agent_id = agent_id_from_pubkey(&agent_pubkey);
    db.agents()
        .upsert(&AgentRecord {
            id: agent_id.clone(),
            pubkey: agent_pubkey,
            host_id: None,
            via_agent: Some(via_agent.clone()),
            local_alias,
            peer_asserted_alias: None,
            trust_level: TrustLevel::Tofu,
            reputation: 0,
            first_seen: now,
            last_seen: None,
            peer_asserted_tags: hermod_core::CapabilityTagSet::empty(),
        })
        .await?;
    // Pin brokered routing explicitly (atomic with `host_id` clear).
    db.agents()
        .set_routing_brokered(&agent_id, &via_agent)
        .await?;
    db.agents()
        .get(&agent_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("brokered peer vanished after upsert: {agent_id}"))
}
