//! Inbound acceptor for [`MessageBody::PeerAdvertise`].
//!
//! Accepts a sender daemon's enumeration of the agents it hosts and
//! upserts each into the local directory keyed on `host_pubkey`.
//! Authentication chain (after the standard envelope guards have
//! already cleared this envelope through the `accept_envelope`
//! pipeline):
//!
//! 1. `envelope.from.id` is the sender's signing agent (already
//!    bound to `from_pubkey` by self-cert + signature verify).
//! 2. The body's `host_pubkey` must match the sender's already-known
//!    `agents.host_id` (cross-check) — or, if the sender row has
//!    no host yet (first contact), we adopt the body's value via
//!    TOFU, also recording the host in the `hosts` table.
//! 3. `envelope.from.id` must appear in `body.agents` (self-inclusion
//!    proof: the sender wouldn't put itself in the list under a host
//!    it doesn't belong to without also presenting that agent's own
//!    keypair, which the envelope-signing path already validated).
//! 4. Each advertised agent self-certifies via
//!    `id == blake3(pubkey)[:26]`.
//!
//! Existing rows whose `host_id` is already pinned to a *different*
//! value are NOT downgraded — the sender's claim that agent X moved
//! to a new host is rejected for that one entry, the rest of the
//! advertise still applies.

use hermod_core::{AdvertisedAgent, Envelope, PubkeyBytes, Timestamp, TrustLevel};
use hermod_crypto::agent_id_from_pubkey;
use hermod_storage::{AgentRecord, AuditEntry, HostRecord};

use super::InboundProcessor;
use super::scope::FederationRejection;
use crate::services::audit_or_warn;

impl InboundProcessor {
    pub(super) async fn accept_peer_advertise(
        &self,
        envelope: &Envelope,
        host_pubkey: &PubkeyBytes,
        agents: &[AdvertisedAgent],
    ) -> Result<(), FederationRejection> {
        // Self-inclusion proof — the sender must be among the agents it
        // claims as roster-mates. Otherwise an agent on host X could
        // forge a roster claim about host Y.
        if !agents.iter().any(|a| a.id == envelope.from.id) {
            return Err(FederationRejection::Unauthorized(
                "PeerAdvertise sender is not in body.agents (self-inclusion proof missing)",
            ));
        }

        // Cross-check (or TOFU-adopt) the sender's host. If we
        // already know `from.id` is on a *different* host, the
        // advertise is suspicious — reject. First contact (no
        // stored host_id) accepts the body's value.
        let body_host_id = agent_id_from_pubkey(host_pubkey);
        let now = Timestamp::now();
        if let Some(rec) = self
            .db
            .agents()
            .get(&envelope.from.id)
            .await
            .map_err(|e| FederationRejection::Storage(e.to_string()))?
            && let Some(known) = rec.host_id
            && known != body_host_id
        {
            return Err(FederationRejection::Unauthorized(
                "PeerAdvertise body.host_pubkey conflicts with sender's pinned host",
            ));
        }

        // TOFU-record the host so the FK on `agents.host_id` resolves
        // and downstream agent rows can point at it. Endpoint /
        // tls_fingerprint stay None until the operator runs `peer
        // add --endpoint` or the inbound handshake observes a cert.
        self.db
            .hosts()
            .upsert(&HostRecord {
                id: body_host_id.clone(),
                pubkey: *host_pubkey,
                endpoint: None,
                tls_fingerprint: None,
                peer_asserted_alias: None,
                first_seen: now,
                last_seen: Some(now),
            })
            .await
            .map_err(|e| FederationRejection::Storage(e.to_string()))?;

        // Upsert each advertised agent.
        let mut upserted: u32 = 0;
        let mut rejected_self_cert: u32 = 0;
        let mut rejected_host_conflict: u32 = 0;
        // Cumulative count of tag entries dropped during
        // per-entry `CapabilityTag::parse` filter-map. Folded
        // into the `peer.advertise.received` audit row so a peer
        // shipping malformed tag strings is observable.
        let mut total_invalid_tags: u32 = 0;
        for advertised in agents {
            // Self-cert: id == blake3(pubkey)[:26].
            let expected = agent_id_from_pubkey(&advertised.pubkey);
            if expected != advertised.id {
                rejected_self_cert += 1;
                continue;
            }
            // Host-conflict guard for existing rows. If we already
            // know agent X is on host Z != body_host_id, don't
            // downgrade.
            let existing = self
                .db
                .agents()
                .get(&advertised.id)
                .await
                .map_err(|e| FederationRejection::Storage(e.to_string()))?;
            if let Some(rec) = &existing
                && let Some(known) = &rec.host_id
                && known != &body_host_id
            {
                rejected_host_conflict += 1;
                continue;
            }
            // Skip rows that already exist in our own registry — an
            // operator-managed local agent is authoritative; an
            // advertise from a peer must not clobber its
            // operator-set fields.
            if self.local_agents.lookup(&advertised.id).is_some() {
                continue;
            }

            // Identity / peer-asserted facets first. Routing is
            // pinned separately below so the `host_id XOR via_agent`
            // CHECK is satisfied atomically against any prior
            // brokered configuration the row may have carried.
            self.db
                .agents()
                .upsert_observed(&AgentRecord {
                    id: advertised.id.clone(),
                    pubkey: advertised.pubkey,
                    host_id: None,
                    via_agent: None,
                    local_alias: existing.as_ref().and_then(|r| r.local_alias.clone()),
                    peer_asserted_alias: advertised.alias.clone().or_else(|| {
                        existing
                            .as_ref()
                            .and_then(|r| r.peer_asserted_alias.clone())
                    }),
                    trust_level: existing
                        .as_ref()
                        .map(|r| r.trust_level)
                        .unwrap_or(TrustLevel::Tofu),
                    reputation: existing.as_ref().map(|r| r.reputation).unwrap_or(0),
                    first_seen: existing.as_ref().map(|r| r.first_seen).unwrap_or(now),
                    last_seen: Some(now),
                    // Per-entry parse drop so a single bad string
                    // doesn't reject the whole row; dropped count
                    // is folded into the `peer.advertise.received`
                    // audit detail. `upsert_observed` is
                    // latest-wins for peer-asserted columns
                    // (alias + tags), so an advertise that clears
                    // labels propagates the empty set verbatim.
                    peer_asserted_tags: parsed_tags_for(advertised, &mut total_invalid_tags),
                })
                .await
                .map_err(|e| FederationRejection::Storage(e.to_string()))?;
            // Routing is operator-owned: `peer add --endpoint` /
            // `peer add --via` set it explicitly. `peer.advertise`
            // teaches us the sender's host record (above) and the
            // peer-asserted facets (alias + tags) of each agent,
            // but it never silently flips a brokered route to
            // direct or vice-versa — the operator's network policy
            // (e.g. an inbound-only NAT topology that requires the
            // broker hop) must not be overruled by a peer's
            // self-claim. First-contact rows that have no routing
            // yet stay directory-only until the operator runs
            // `peer add`; subsequent envelopes from those agents
            // arrive via inbound TOFU, where direct hops auto-link
            // `host_id` (see `upsert_sender_observed`).
            upserted += 1;
        }

        audit_or_warn(
            &*self.audit_sink,
            AuditEntry {
                id: None,
                ts: now,
                actor: envelope.from.id.clone(),
                action: "peer.advertise.received".into(),
                target: Some(hex::encode(host_pubkey.as_slice())),
                details: Some(serde_json::json!({
                    "agents_advertised": agents.len(),
                    "agents_upserted": upserted,
                    "rejected_self_cert": rejected_self_cert,
                    "rejected_host_conflict": rejected_host_conflict,
                    "dropped_invalid_tags": total_invalid_tags,
                })),
                client_ip: None,
                federation: hermod_storage::AuditFederationPolicy::Default,
            },
        )
        .await;

        Ok(())
    }
}

/// Per-advertised-agent tag parse with cumulative-drop counter.
/// Splitting this out keeps the upsert site readable and gives a
/// single place future variants of `AdvertisedAgent.tags` (e.g. a
/// stricter validator in v2) plug in.
fn parsed_tags_for(
    advertised: &AdvertisedAgent,
    total_dropped: &mut u32,
) -> hermod_core::CapabilityTagSet {
    let (set, dropped) = hermod_core::CapabilityTagSet::parse_lossy(advertised.tags.clone());
    *total_dropped = total_dropped.saturating_add(dropped);
    set
}
