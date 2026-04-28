//! Broker daemon role — relay + witness for envelopes destined to
//! other peers.
//!
//! When `[broker] mode = "relay_only"` or `"relay_and_witness"`, this
//! service is wired into [`InboundProcessor`] via the
//! `with_broker_service` builder method. The inbound pipeline's
//! standard `to.id == self_id` check is relaxed: envelopes addressed
//! to other peers are handed to this service instead of being
//! rejected as `NotForUs`.
//!
//! ## Forwarding model
//!
//! The broker is **untrusted for content**. Envelopes are forwarded
//! verbatim — `envelope.from_pubkey` carries the original sender's
//! key, so the eventual recipient verifies the binding +
//! signature without consulting any directory. Same security model
//! as Matrix homeserver relaying or XMPP S2S forwarding.
//!
//! Lookup: the broker treats its own `agents` directory as its
//! routing table. Envelope `to.id = B` → lookup B in directory →
//! deliver via [`RemoteDeliverer`] (the daemon's outbound peer
//! pool). Unknown recipients are rejected (the broker doesn't
//! source-route).
//!
//! ## Witness
//!
//! When `[broker] mode = "relay_and_witness"`, every relay attempt
//! emits a `broker.relay.forwarded` (success) or
//! `broker.relay.rejected` (failure) audit row. The audit row goes
//! through the same hash-chained `AuditSink` the daemon uses for its
//! own actions, so an operator querying the broker has a complete
//! ground-truth log of every envelope that traversed it.
//!
//! ## Loop / fanout caps
//!
//! Two layered guards bound forwarding:
//!   * The wire frame's [`hermod_protocol::wire::EnvelopeFrame`]
//!     carries a `hops: u8` counter. Each broker increments it before
//!     forwarding and refuses past
//!     [`hermod_protocol::wire::MAX_RELAY_HOPS`] — finite-cycle
//!     guarantee independent of clock drift.
//!   * Identity-level recursion check: the broker refuses to forward
//!     an envelope whose `from.id` matches its own identity (a
//!     single-hop echo from an upstream broker).
//!
//! TTL on the envelope (`expires_at`) is a third complementary
//! guard evaluated by the eventual recipient — but cycles must abort
//! on hop count alone, since wall-clock TTL admits arbitrary per-hop
//! delay manipulation.

use hermod_core::Timestamp;
use hermod_core::{AgentId, Envelope};
use hermod_protocol::envelope::serialize_envelope;
use hermod_routing::{RemoteDeliverer, remote::DeliveryOutcome};
use hermod_storage::{AuditEntry, AuditSink, Database};
use std::sync::Arc;
use tracing::{debug, warn};

use hermod_daemon::config::BrokerMode;

use crate::services::audit_or_warn;

/// Outcome of one relay attempt — surfaces the success/failure mode
/// to the inbound caller so it can ack the source peer correctly.
#[derive(Debug, Clone)]
pub enum RelayOutcome {
    /// Envelope was handed to the outbound pool. The destination
    /// peer's ack is asynchronous; the broker treats handoff as
    /// success at the wire level.
    Forwarded,
    /// Recipient is not in the broker's routing table. Source peer
    /// gets a `NoRoute` rejection on the inbound channel.
    NoRoute,
    /// Outbound transport rejected the forward (peer offline, TLS
    /// pin mismatch, …). Source peer gets a `Deferred` rejection.
    Deferred(String),
    /// Recipient is the broker's own identity — caller should fall
    /// through to the normal `accept_envelope` path.
    LocalDestination,
    /// Loop guard tripped: envelope `from.id` is the broker's own
    /// identity (a forwarded envelope echoed back to us).
    LoopDetected,
}

/// The verb suffix on `broker.relay.<verb>` audit rows. Adding a new
/// witnessable outcome requires extending this enum AND adding a
/// catalogue entry to `docs/audit_actions.md`; the mismatch fails CI
/// via `audit_doc_lists_every_relay_witness_verb` in the routing
/// crate's `docs_coverage` test.
#[derive(Clone, Copy, Debug, PartialEq, Eq, strum::EnumIter)]
pub enum RelayWitnessVerb {
    Forwarded,
    Rejected,
}

impl RelayWitnessVerb {
    pub fn as_str(self) -> &'static str {
        match self {
            RelayWitnessVerb::Forwarded => "forwarded",
            RelayWitnessVerb::Rejected => "rejected",
        }
    }

    /// Full audit-log action string (`broker.relay.<verb>`) — the
    /// shape `docs/audit_actions.md` documents.
    pub fn audit_action(self) -> String {
        format!("broker.relay.{}", self.as_str())
    }
}

#[cfg(test)]
mod doc_coverage {
    use super::RelayWitnessVerb;
    use strum::IntoEnumIterator;

    const AUDIT_DOC: &str = include_str!("../../../../docs/audit_actions.md");

    /// Every `RelayWitnessVerb` variant must have its audit action
    /// catalogued in `docs/audit_actions.md`. Adding a new verb
    /// without doc'ing it fails this test.
    #[test]
    fn audit_doc_lists_every_relay_witness_verb() {
        for v in RelayWitnessVerb::iter() {
            let action = v.audit_action();
            assert!(
                AUDIT_DOC.contains(&format!("`{action}`")),
                "docs/audit_actions.md is missing `{action}` — \
                 every RelayWitnessVerb variant must be catalogued."
            );
        }
    }
}

#[derive(Clone)]
pub struct BrokerService {
    db: Arc<dyn Database>,
    audit_sink: Arc<dyn AuditSink>,
    self_id: AgentId,
    remote: RemoteDeliverer,
    mode: BrokerMode,
}

impl std::fmt::Debug for BrokerService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrokerService")
            .field("self_id", &self.self_id)
            .field("mode", &self.mode)
            .finish()
    }
}

impl BrokerService {
    pub fn new(
        db: Arc<dyn Database>,
        audit_sink: Arc<dyn AuditSink>,
        self_id: AgentId,
        remote: RemoteDeliverer,
        mode: BrokerMode,
    ) -> Self {
        Self {
            db,
            audit_sink,
            self_id,
            remote,
            mode,
        }
    }

    /// Try to relay `envelope` (whose `to.id` is NOT the broker's
    /// own identity). `inbound_hops` is the hop counter as observed on
    /// the incoming wire frame; the broker increments it before
    /// forwarding and refuses if the post-increment count would exceed
    /// [`hermod_protocol::wire::MAX_RELAY_HOPS`].
    pub async fn relay(
        &self,
        source_hop: &AgentId,
        envelope: &Envelope,
        inbound_hops: u8,
    ) -> RelayOutcome {
        // Defensive: caller should have checked, but be safe.
        if envelope.to.id.as_str() == self.self_id.as_str() {
            return RelayOutcome::LocalDestination;
        }
        // Identity-level loop guard: an envelope this daemon originated
        // and that has come back to us must not re-enter the relay
        // pipeline. The hops bound below catches mesh cycles between
        // distinct peers; this catches single-step echoes.
        if envelope.from.id.as_str() == self.self_id.as_str() {
            return RelayOutcome::LoopDetected;
        }
        // Hop-count loop bound. Receivers also enforce this defensively
        // on the inbound side (see `InboundProcessor::accept_envelope`),
        // so a peer running an old / hostile broker can't bypass the
        // termination guarantee by lying about the count.
        let outbound_hops = match inbound_hops.checked_add(1) {
            Some(n) if n <= hermod_protocol::wire::MAX_RELAY_HOPS => n,
            _ => {
                self.witness(
                    source_hop,
                    envelope,
                    RelayWitnessVerb::Rejected,
                    Some("hops_exceeded"),
                )
                .await;
                return RelayOutcome::LoopDetected;
            }
        };
        if !self.mode.relays() {
            // Disabled mode — service is wired but operator hasn't
            // opted into forwarding. The caller maps NoRoute to
            // `Unroutable`, so peers see "no path" rather than a
            // permission error.
            return RelayOutcome::NoRoute;
        }

        // Resolve the target's endpoint from our routing table.
        let recipient_record = match self.db.agents().get(&envelope.to.id).await {
            Ok(Some(rec)) => rec,
            Ok(None) => {
                self.witness(
                    source_hop,
                    envelope,
                    RelayWitnessVerb::Rejected,
                    Some("no_route"),
                )
                .await;
                return RelayOutcome::NoRoute;
            }
            Err(e) => {
                warn!(error = %e, "broker: directory lookup failed");
                return RelayOutcome::Deferred(e.to_string());
            }
        };
        let endpoint = match recipient_record.endpoint {
            Some(ep) if !ep.is_local() => ep,
            _ => {
                self.witness(
                    source_hop,
                    envelope,
                    RelayWitnessVerb::Rejected,
                    Some("no_endpoint"),
                )
                .await;
                return RelayOutcome::NoRoute;
            }
        };

        // Re-serialise the canonical envelope bytes so the outbound
        // pool can frame them. The signature is preserved by
        // construction — we never mutate `envelope` between deserialise
        // and re-serialise.
        if serialize_envelope(envelope).is_err() {
            self.witness(
                source_hop,
                envelope,
                RelayWitnessVerb::Rejected,
                Some("serialize"),
            )
            .await;
            return RelayOutcome::Deferred("serialize".into());
        }

        match self
            .remote
            .forward(envelope, &endpoint, outbound_hops)
            .await
        {
            Ok(DeliveryOutcome::Delivered) => {
                self.witness(source_hop, envelope, RelayWitnessVerb::Forwarded, None)
                    .await;
                RelayOutcome::Forwarded
            }
            Ok(DeliveryOutcome::Deferred) => {
                self.witness(
                    source_hop,
                    envelope,
                    RelayWitnessVerb::Rejected,
                    Some("deferred"),
                )
                .await;
                RelayOutcome::Deferred("upstream deferred".into())
            }
            Ok(DeliveryOutcome::Rejected) => {
                self.witness(
                    source_hop,
                    envelope,
                    RelayWitnessVerb::Rejected,
                    Some("upstream_reject"),
                )
                .await;
                RelayOutcome::Deferred("upstream rejected".into())
            }
            Err(e) => {
                self.witness(
                    source_hop,
                    envelope,
                    RelayWitnessVerb::Rejected,
                    Some(&e.to_string()),
                )
                .await;
                RelayOutcome::Deferred(e.to_string())
            }
        }
    }

    async fn witness(
        &self,
        source_hop: &AgentId,
        envelope: &Envelope,
        verb: RelayWitnessVerb,
        reason: Option<&str>,
    ) {
        if !self.mode.witnesses() {
            return;
        }
        debug!(
            source = %source_hop,
            destination = %envelope.to.id,
            kind = envelope.kind.as_str(),
            verb = verb.as_str(),
            "broker witness"
        );
        let action = verb.audit_action();
        let mut details = serde_json::json!({
            "envelope_id": envelope.id.to_string(),
            "kind": envelope.kind.as_str(),
            "from": envelope.from.id.to_string(),
            "to": envelope.to.id.to_string(),
            "source_hop": source_hop.to_string(),
        });
        if let Some(r) = reason {
            details["reason"] = serde_json::Value::String(r.to_string());
        }
        audit_or_warn(
            &*self.audit_sink,
            AuditEntry {
                id: None,
                ts: Timestamp::now(),
                actor: source_hop.clone(),
                action,
                target: Some(envelope.to.id.to_string()),
                details: Some(details),
                federation: hermod_storage::AuditFederationPolicy::Default,
            },
        )
        .await;
    }
}
