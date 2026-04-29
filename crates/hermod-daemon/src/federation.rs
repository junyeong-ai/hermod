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
use hermod_storage::{AgentRecord, Database};
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
                let agent_id = conn.identity().agent_id.clone();
                if let Err(e) = me.handle_peer(conn).await {
                    warn!(peer = %agent_id, error = %e, "inbound peer task ended");
                }
            });
        }
    }

    async fn handle_peer(&self, mut conn: Box<dyn TransportConnection>) -> anyhow::Result<()> {
        let identity = conn.identity().clone();
        info!(
            agent = %identity.agent_id,
            tls_fp = ?identity.tls_fingerprint,
            alias = ?identity.alias,
            "inbound peer authenticated"
        );

        // TOFU register/update on first contact. Peer's self-claimed alias
        // (from the signed Hello frame) goes into `peer_asserted_alias`; we
        // never set `local_alias` here — that's reserved for explicit
        // operator action via `peer add --alias`. `upsert_observed` is
        // collision-safe so a peer self-claiming an existing local label
        // is silently downgraded (and audited below) rather than rejecting
        // the connection.
        let now = Timestamp::now();
        let alias_outcome = self
            .processor
            .db()
            .agents()
            .upsert_observed(&AgentRecord {
                id: identity.agent_id.clone(),
                pubkey: identity.agent_pubkey,
                endpoint: None,
                local_alias: None,
                peer_asserted_alias: identity.alias.clone(),
                trust_level: TrustLevel::Tofu,
                tls_fingerprint: None,
                reputation: 0,
                first_seen: now,
                last_seen: Some(now),
            })
            .await?;
        if let hermod_storage::AliasOutcome::LocalDropped {
            proposed,
            conflicting_id,
        } = &alias_outcome
        {
            // Belt and braces: record the collision in audit so operators
            // can investigate impersonation attempts. (Never reachable on
            // this path today since we don't propose a local_alias here,
            // but kept symmetric with the operator-driven `peer.add`
            // path.)
            crate::services::audit_or_warn(
                &**self.processor.audit_sink(),
                hermod_storage::AuditEntry {
                    id: None,
                    ts: now,
                    actor: identity.agent_id.clone(),
                    action: "peer.alias_collision".into(),
                    target: Some(conflicting_id.to_string()),
                    details: Some(serde_json::json!({
                        "proposed": proposed.as_str(),
                    })),
                    client_ip: None,
                    federation: hermod_storage::AuditFederationPolicy::Default,
                },
            )
            .await;
        }

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
                        .accept_envelope(&identity.agent_id, &envelope_frame.envelope, hops)
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

/// Register a federated agent (called by `peer.add` RPC and discovery
/// ingestion). Requires a pubkey — without it Noise XX (or whatever
/// authenticated handshake the transport runs) can't authenticate the
/// peer, so an endpoint-only entry would never accept any traffic.
///
/// The agent_id is derived deterministically from the pubkey, so existing
/// directory entries (e.g. ones we've previously DM'd over loopback) get
/// their `endpoint` populated here without losing operator-set trust.
/// Atomic peer record. Splits the alias claim into two slots:
///   * `peer_asserted_alias` — what the peer claimed in their signed Hello /
///     Presence / mDNS TXT. Stored verbatim, no UNIQUE constraint.
///   * `local_alias` — operator-set override (only set by `peer.add` paths,
///     never by inbound discovery). Sacred — collisions with an existing
///     local label are dropped via [`hermod_storage::AgentRepository::upsert_observed`]
///     so a malicious / unlucky peer can't take a name the operator already
///     bound. The returned [`hermod_storage::AliasOutcome`] reports any drop
///     so the caller can audit.
pub async fn record_peer(
    db: &dyn Database,
    endpoint: WssEndpoint,
    pubkey: PubkeyBytes,
    peer_asserted_alias: Option<hermod_core::AgentAlias>,
    local_alias: Option<hermod_core::AgentAlias>,
) -> anyhow::Result<(AgentRecord, hermod_storage::AliasOutcome)> {
    use hermod_crypto::agent_id_from_pubkey;
    let now = Timestamp::now();
    let agent_id = agent_id_from_pubkey(&pubkey);
    let outcome = db
        .agents()
        .upsert_observed(&AgentRecord {
            id: agent_id.clone(),
            pubkey,
            endpoint: Some(Endpoint::Wss(endpoint)),
            local_alias,
            peer_asserted_alias,
            trust_level: TrustLevel::Tofu,
            tls_fingerprint: None,
            reputation: 0,
            first_seen: now,
            last_seen: None,
        })
        .await?;
    let rec = db
        .agents()
        .get(&agent_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("agent vanished after upsert: {agent_id}"))?;
    Ok((rec, outcome))
}
