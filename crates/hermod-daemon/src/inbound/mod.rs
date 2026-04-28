//! Inbound envelope processor.
//!
//! The pure-logic counterpart to [`crate::federation::FederationServer`]. Owns
//! the policy pipeline (sender binding, replay window, signature, capability,
//! confirmation gate) and the per-kind apply paths. Free of network I/O — it
//! only touches storage and routing — which lets the confirmation service
//! replay held envelopes through the same code path the live federation
//! handshake takes.

mod capability_audit;
mod channel;
mod file_brief_presence;
mod permission;
mod scope;
mod workspace_observability;

pub use scope::FederationRejection;
use scope::{PermissionPromptFields, intent_for, validate_inbound_body_size};
pub(crate) use scope::{always_requires_capability, scope_for};

use hermod_core::{AgentId, Envelope, MessageStatus, PubkeyBytes, Timestamp, TrustLevel};
use hermod_crypto::PublicKey;
use hermod_protocol::envelope::{deserialize_envelope, serialize_envelope};
use hermod_routing::confirmation::{Verdict, classify, decide, summarize};
use hermod_routing::{AccessController, AccessVerdict, RateLimiter};
use hermod_storage::{AuditEntry, AuditSink, Database, MessageRecord};
use std::sync::Arc;
use tracing::debug;

use crate::services::audit_or_warn;

#[derive(Clone)]
pub struct InboundProcessor {
    pub(super) db: Arc<dyn Database>,
    pub(super) audit_sink: Arc<dyn AuditSink>,
    pub(super) self_id: AgentId,
    access: AccessController,
    rate_limit: RateLimiter,
    replay_window_secs: u32,
    /// Held envelopes older than this are refused on accept (Phase 3 —
    /// closes the "operator parks for days, then accepts a stale
    /// envelope as if fresh" gap). 0 disables the check.
    held_envelope_max_age_secs: u64,
    /// Inbound `MessageBody::File` payload cap. Operators tune this to
    /// trade off inbox RAM/disk vs. legitimate AI-agent file shares.
    /// Cannot exceed the compile-time ceiling
    /// [`hermod_core::MAX_FILE_PAYLOAD_BYTES`] (1 MiB).
    max_file_payload_bytes: usize,
    /// Operator opt-in to act as an audit-federation aggregator. When
    /// `true`, inbound `AuditFederate` envelopes from authenticated
    /// peers are written into the local hash-chained log under
    /// `audit.federate.<original_action>`. When `false` (default),
    /// `AuditFederate` envelopes are rejected with `Unauthorized` —
    /// stops a peer from polluting our audit log without operator
    /// consent.
    pub(super) accept_audit_federation: bool,
    /// Permission relay state — receives `PermissionPrompt`
    /// envelopes (origin = Relayed) and dispatches verdicts
    /// (`PermissionResponse`) back to the originator. `None` only in
    /// the test harness; production always wires this up.
    pub(super) permission: Option<crate::services::PermissionService>,
    /// Workspace observability — answers roster / channel-list
    /// requests and routes responses back to in-flight queries.
    /// `None` only in the test harness.
    pub(super) observability: Option<crate::services::WorkspaceObservabilityService>,
    /// Broker role — when wired, envelopes whose `to.id` is not us
    /// are handed here for relay/witness instead of rejected as
    /// `NotForUs`. `None` for non-broker daemons (the common case).
    broker: Option<crate::services::BrokerService>,
}

impl std::fmt::Debug for InboundProcessor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InboundProcessor")
            .field("self_id", &self.self_id)
            .field("replay_window_secs", &self.replay_window_secs)
            .field(
                "held_envelope_max_age_secs",
                &self.held_envelope_max_age_secs,
            )
            .finish_non_exhaustive()
    }
}

impl InboundProcessor {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        db: Arc<dyn Database>,
        audit_sink: Arc<dyn AuditSink>,
        self_id: AgentId,
        access: AccessController,
        rate_limit: RateLimiter,
        replay_window_secs: u32,
        held_envelope_max_age_secs: u64,
        max_file_payload_bytes: usize,
        accept_audit_federation: bool,
    ) -> Self {
        // Cap the runtime knob at the compile-time ceiling so a
        // misconfigured operator can't relax the wire-level invariant.
        let max_file_payload_bytes =
            max_file_payload_bytes.min(hermod_core::MAX_FILE_PAYLOAD_BYTES);
        Self {
            db,
            audit_sink,
            self_id,
            access,
            rate_limit,
            replay_window_secs,
            held_envelope_max_age_secs,
            max_file_payload_bytes,
            accept_audit_federation,
            permission: None,
            observability: None,
            broker: None,
        }
    }

    /// Wire the permission service. Returns `Self` so the caller
    /// chains the wiring before any clone — `Clone` on a half-wired
    /// instance would silently lose the service. Consuming `self`
    /// makes that misuse a compile error.
    pub fn with_permission_service(mut self, svc: crate::services::PermissionService) -> Self {
        self.permission = Some(svc);
        self
    }

    /// Wire the workspace observability service. Same consume-on-set
    /// invariant as [`Self::with_permission_service`].
    pub fn with_workspace_observability(
        mut self,
        svc: crate::services::WorkspaceObservabilityService,
    ) -> Self {
        self.observability = Some(svc);
        self
    }

    /// Wire the broker service. When wired, the inbound dispatch's
    /// `to.id != self_id` check becomes a relay hand-off instead of
    /// an immediate `NotForUs` rejection.
    pub fn with_broker_service(mut self, svc: crate::services::BrokerService) -> Self {
        self.broker = Some(svc);
        self
    }

    pub fn db(&self) -> &dyn Database {
        &*self.db
    }

    pub fn audit_sink(&self) -> &Arc<dyn AuditSink> {
        &self.audit_sink
    }

    /// Run the full inbound pipeline: recipient → hops → replay window →
    /// signature (via envelope's self-introduced pubkey) → cap →
    /// confirmation gate → apply.
    ///
    /// `inbound_hops` is the hop counter from the wire frame the
    /// federation listener received. Receivers reject anything past
    /// [`hermod_protocol::wire::MAX_RELAY_HOPS`] as a defensive guard
    /// — even an originator-direct frame should arrive with hops=0,
    /// so a high count is always anomalous.
    #[tracing::instrument(
        name = "inbound.accept",
        skip(self, envelope),
        fields(
            peer = %source_hop,
            envelope = %envelope.id,
            kind = %envelope.kind.as_str(),
            hops = inbound_hops,
        )
    )]
    pub async fn accept_envelope(
        &self,
        source_hop: &AgentId,
        envelope: &Envelope,
        inbound_hops: u8,
    ) -> Result<(), FederationRejection> {
        if inbound_hops > hermod_protocol::wire::MAX_RELAY_HOPS {
            return Err(FederationRejection::Invalid(format!(
                "relay hops {inbound_hops} exceeds MAX_RELAY_HOPS={}",
                hermod_protocol::wire::MAX_RELAY_HOPS
            )));
        }
        if envelope.to.id.as_str() != self.self_id.as_str() {
            // Broker mode: hand off to relay before rejecting. The
            // broker forwards verbatim — recipient's daemon does the
            // signature check from the envelope's self-introducing
            // pubkey, no directory dependency.
            if let Some(broker) = &self.broker {
                use crate::services::RelayOutcome;
                match broker.relay(source_hop, envelope, inbound_hops).await {
                    RelayOutcome::Forwarded => return Ok(()),
                    RelayOutcome::LocalDestination => {} // fall through
                    RelayOutcome::LoopDetected => {
                        return Err(FederationRejection::Invalid("relay loop".into()));
                    }
                    RelayOutcome::NoRoute => {
                        return Err(FederationRejection::Unroutable("broker: no route"));
                    }
                    RelayOutcome::Deferred(reason) => {
                        return Err(FederationRejection::Storage(format!(
                            "broker forward deferred: {reason}"
                        )));
                    }
                }
            } else {
                return Err(FederationRejection::NotForUs);
            }
        }
        // Cap-count guard. Every cap is an ed25519 verify; an
        // unbounded Vec would let a peer amplify CPU cost. The
        // outbound side (`MessageService::send`) enforces the same
        // bound — this is defense-in-depth against a non-cooperating
        // sender.
        if envelope.caps.len() > hermod_core::MAX_CAPS_PER_ENVELOPE {
            return Err(FederationRejection::Invalid(format!(
                "envelope.caps has {} entries (cap {})",
                envelope.caps.len(),
                hermod_core::MAX_CAPS_PER_ENVELOPE
            )));
        }
        if self.replay_window_secs > 0 {
            let now_ms = Timestamp::now().unix_ms();
            let env_ms = envelope.ts.unix_ms();
            let window_ms = (self.replay_window_secs as i64) * 1000;
            if (now_ms - env_ms).abs() > window_ms {
                return Err(FederationRejection::ReplayWindow {
                    skew_ms: now_ms - env_ms,
                });
            }
        }
        // Self-verifying envelope: the sender's pubkey is embedded in
        // `envelope.from_pubkey`, bound to `envelope.from.id` by
        // `agent_id = blake3(pubkey)[:26]`. Receivers authenticate
        // from the bytes alone — no directory lookup, identical
        // verification logic for direct and broker-relayed paths.
        let claimed_pubkey = envelope.from_pubkey;
        let derived_id = hermod_crypto::agent_id_from_pubkey(&claimed_pubkey);
        if derived_id.as_str() != envelope.from.id.as_str() {
            return Err(FederationRejection::Unauthorized(
                "envelope.from_pubkey does not bind to envelope.from.id",
            ));
        }
        let pk = PublicKey::from_bytes(&claimed_pubkey)
            .map_err(|e| FederationRejection::Invalid(format!("pubkey: {e}")))?;
        pk.verify_envelope(envelope)
            .map_err(|e| FederationRejection::Invalid(format!("signature: {e}")))?;
        // Auto-upsert sender into the directory on Tofu trust. The
        // pubkey-id binding above is cryptographic, so a sender
        // can only ever introduce themselves — never impersonate
        // another identity.
        self.upsert_sender_observed(&envelope.from.id, &claimed_pubkey)
            .await?;

        // Token-bucket per (sender → us) pair. Keyed on the
        // *envelope-authenticated* sender, not the immediate
        // transport peer — alice can't bypass her bucket by routing
        // through a broker. Bucket consumption sits after signature
        // verification so an unauthenticated source can't burn down
        // a real peer's allowance by spoofing their `from`.
        if let Err(e) = self
            .rate_limit
            .consume_one(&envelope.from.id, &self.self_id)
            .await
        {
            return Err(FederationRejection::RateLimited(e.to_string()));
        }

        let scope_for_kind = scope_for(envelope.kind);
        let decision = if always_requires_capability(envelope.kind) {
            // Forces the cap check even when
            // `policy.require_capability = false` — these kinds carry
            // delegated authority and must be explicitly granted.
            self.access
                .check_caps_strict(
                    &envelope.from.id,
                    scope_for_kind,
                    Some(&self.self_id),
                    &envelope.caps,
                )
                .await
                .map_err(|e| FederationRejection::Invalid(format!("access: {e}")))?
        } else {
            self.access
                .check_caps(
                    &envelope.from.id,
                    scope_for_kind,
                    Some(&self.self_id),
                    &envelope.caps,
                )
                .await
                .map_err(|e| FederationRejection::Invalid(format!("access: {e}")))?
        };
        if let AccessVerdict::Reject(reason) = decision {
            return Err(FederationRejection::Unauthorized(reason));
        }

        // Confirmation gate. Trust is the *sender's* trust level —
        // a Verified broker forwarding a Tofu sender's invite does
        // not promote the invite to Verified.
        let trust = self
            .db
            .agents()
            .get(&envelope.from.id)
            .await
            .map_err(|e| FederationRejection::Storage(e.to_string()))?
            .map(|r| r.trust_level)
            .unwrap_or(TrustLevel::Tofu);
        let sensitivity = classify(envelope);
        match decide(trust, sensitivity) {
            Verdict::Accept => {}
            Verdict::Reject => {
                debug!(
                    sender = %envelope.from.id,
                    sensitivity = sensitivity.as_str(),
                    "confirmation gate rejected envelope"
                );
                return Err(FederationRejection::Unauthorized("trust matrix"));
            }
            Verdict::Confirm => {
                let cbor = serialize_envelope(envelope)
                    .map_err(|e| FederationRejection::Invalid(format!("serialize: {e}")))?;
                let summary = summarize(envelope);
                let held = self
                    .db
                    .confirmations()
                    .enqueue(hermod_storage::HoldRequest {
                        envelope_id: &envelope.id,
                        actor: &envelope.from.id,
                        intent: intent_for(envelope),
                        sensitivity: sensitivity.as_str(),
                        trust_level: trust,
                        summary: &summary,
                        envelope_cbor: &cbor,
                    })
                    .await
                    .map_err(|e| FederationRejection::Storage(e.to_string()))?;
                if let Some(id) = held {
                    audit_or_warn(
                        &*self.audit_sink,
                        AuditEntry {
                            id: None,
                            ts: Timestamp::now(),
                            actor: envelope.from.id.clone(),
                            action: "confirmation.held".into(),
                            target: Some(id),
                            details: Some(serde_json::json!({
                                "envelope_id": envelope.id.to_string(),
                                "sensitivity": sensitivity.as_str(),
                                "trust_level": trust.as_str(),
                            })),
                            federation: hermod_storage::AuditFederationPolicy::Default,
                        },
                    )
                    .await;
                }
                return Ok(());
            }
        }

        self.apply_envelope(envelope).await
    }

    /// Add a freshly-verified sender to the agents directory on Tofu
    /// trust. Called from the envelope-authentication path right after
    /// `blake3(from_pubkey)[:26] == from.id` and signature pass — at
    /// which point the sender's identity is cryptographically fixed
    /// and can be persisted without spoofing risk. Idempotent for
    /// known senders (the storage layer's upsert merges fields and
    /// preserves operator-set trust).
    async fn upsert_sender_observed(
        &self,
        sender: &AgentId,
        pubkey: &PubkeyBytes,
    ) -> Result<(), FederationRejection> {
        if sender.as_str() == self.self_id.as_str() {
            return Ok(());
        }
        let now = Timestamp::now();
        self.db
            .agents()
            .upsert_observed(&hermod_storage::AgentRecord {
                id: sender.clone(),
                pubkey: *pubkey,
                endpoint: None,
                local_alias: None,
                peer_asserted_alias: None,
                trust_level: TrustLevel::Tofu,
                tls_fingerprint: None,
                reputation: 0,
                first_seen: now,
                last_seen: Some(now),
            })
            .await
            .map_err(|e| FederationRejection::Storage(e.to_string()))?;
        Ok(())
    }

    /// Apply an envelope that has already cleared every gate. The confirmation
    /// service re-enters here when the operator accepts a held envelope.
    pub async fn apply_envelope(&self, envelope: &Envelope) -> Result<(), FederationRejection> {
        // Body-size guard. Outbound `MessageService::send` /
        // `BriefService::publish` / `BroadcastService::send` already cap
        // these on the originator side; we re-validate on the receiver
        // path so a peer running a non-cooperating daemon can't bypass
        // the limit and force us to persist huge rows. WS frame cap
        // (256 KiB at the transport layer) is the outermost guard;
        // these per-kind caps are tight defense-in-depth.
        validate_inbound_body_size(&envelope.body, self.max_file_payload_bytes)?;

        match &envelope.body {
            hermod_core::MessageBody::ChannelBroadcast {
                workspace_id,
                channel_id,
                text,
                hmac,
            } => {
                return self
                    .accept_channel_broadcast(
                        envelope,
                        workspace_id,
                        channel_id,
                        text,
                        hmac.as_ref().map(|b| b.as_ref()),
                    )
                    .await;
            }
            hermod_core::MessageBody::WorkspaceInvite {
                workspace_id,
                name,
                secret,
            } => {
                return self
                    .accept_workspace_invite(envelope, workspace_id, name, secret)
                    .await;
            }
            hermod_core::MessageBody::ChannelAdvertise {
                workspace_id,
                channel_id,
                channel_name,
            } => {
                return self
                    .accept_channel_advertise(envelope, workspace_id, channel_id, channel_name)
                    .await;
            }
            hermod_core::MessageBody::Brief { summary, topic } => {
                return self.accept_brief(envelope, summary, topic.as_deref()).await;
            }
            hermod_core::MessageBody::Presence {
                manual_status,
                live,
            } => {
                return self.accept_presence(envelope, *manual_status, *live).await;
            }
            hermod_core::MessageBody::File {
                name,
                mime,
                hash,
                data,
            } => {
                return self.accept_file(envelope, name, mime, hash, data).await;
            }
            hermod_core::MessageBody::PermissionPrompt {
                request_id,
                tool_name,
                description,
                input_preview,
                expires_at,
            } => {
                return self
                    .accept_permission_prompt(
                        envelope,
                        PermissionPromptFields {
                            request_id,
                            tool_name,
                            description,
                            input_preview,
                            expires_at: *expires_at,
                        },
                    )
                    .await;
            }
            hermod_core::MessageBody::PermissionResponse {
                request_id,
                behavior,
            } => {
                return self
                    .accept_permission_response(envelope, request_id, behavior)
                    .await;
            }
            hermod_core::MessageBody::CapabilityGrant { token, scope } => {
                return self.accept_capability_grant(envelope, token, scope).await;
            }
            hermod_core::MessageBody::AuditFederate {
                action,
                target,
                details,
                original_ts_ms,
            } => {
                return self
                    .accept_audit_federate(
                        envelope,
                        action,
                        target.as_deref(),
                        details.as_ref(),
                        *original_ts_ms,
                    )
                    .await;
            }
            hermod_core::MessageBody::WorkspaceRosterRequest { workspace_id, hmac } => {
                return self
                    .accept_workspace_roster_request(
                        envelope,
                        workspace_id,
                        hmac.as_ref().map(|b| b.as_ref()),
                    )
                    .await;
            }
            hermod_core::MessageBody::WorkspaceRosterResponse {
                request_id,
                workspace_id,
                members,
                hmac,
            } => {
                return self
                    .accept_workspace_roster_response(
                        envelope,
                        request_id,
                        workspace_id,
                        members,
                        hmac.as_ref().map(|b| b.as_ref()),
                    )
                    .await;
            }
            hermod_core::MessageBody::WorkspaceChannelsRequest { workspace_id, hmac } => {
                return self
                    .accept_workspace_channels_request(
                        envelope,
                        workspace_id,
                        hmac.as_ref().map(|b| b.as_ref()),
                    )
                    .await;
            }
            hermod_core::MessageBody::WorkspaceChannelsResponse {
                request_id,
                workspace_id,
                channels,
                hmac,
            } => {
                return self
                    .accept_workspace_channels_response(
                        envelope,
                        request_id,
                        workspace_id,
                        channels,
                        hmac.as_ref().map(|b| b.as_ref()),
                    )
                    .await;
            }
            // Direct DMs land in the inbox via the `messages` table below.
            hermod_core::MessageBody::Direct { .. } => {}
        }

        let cbor = serialize_envelope(envelope)
            .map_err(|e| FederationRejection::Invalid(format!("serialize: {e}")))?;
        let mut record = MessageRecord::from_envelope(envelope, cbor, MessageStatus::Delivered);
        record.delivered_at = Some(Timestamp::now());
        self.db
            .messages()
            .enqueue(&record)
            .await
            .map_err(|e| FederationRejection::Storage(e.to_string()))?;

        audit_or_warn(
            &*self.audit_sink,
            AuditEntry {
                id: None,
                ts: Timestamp::now(),
                actor: envelope.from.id.clone(),
                action: "message.delivered".into(),
                target: Some(self.self_id.to_string()),
                details: Some(serde_json::json!({
                    "id": envelope.id.to_string(),
                    "kind": envelope.kind.as_str(),
                })),
                federation: hermod_storage::AuditFederationPolicy::Default,
            },
        )
        .await;
        Ok(())
    }

    /// Replay a previously held envelope after the operator accepts the
    /// confirmation.
    ///
    /// Signature and capability checks already cleared at hold time —
    /// the stored CBOR is byte-identical to what we verified — so we
    /// don't repeat them here.
    ///
    /// Timestamp freshness IS re-checked: an envelope held for days
    /// then accepted is no longer "this peer is asking right now", and
    /// a downstream apply that treats it as fresh would be wrong. The
    /// staleness window is independent of the inbound replay window
    /// because the operator-decision context allows for longer review
    /// periods than wire transit.
    pub async fn apply_held(&self, envelope_cbor: &[u8]) -> Result<(), FederationRejection> {
        let envelope = deserialize_envelope(envelope_cbor)
            .map_err(|e| FederationRejection::Invalid(format!("deserialize: {e}")))?;

        if self.held_envelope_max_age_secs > 0 {
            let age_ms = Timestamp::now()
                .unix_ms()
                .saturating_sub(envelope.ts.unix_ms());
            let max_ms = (self.held_envelope_max_age_secs as i64) * 1000;
            if age_ms > max_ms {
                return Err(FederationRejection::StaleHeldEnvelope { age_ms });
            }
        }

        self.apply_envelope(&envelope).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hermod_core::{AgentAddress, MessageBody, MessagePriority};
    use hermod_protocol::envelope::serialize_envelope;
    use hermod_routing::access::AccessController;
    use hermod_routing::rate_limit::RateLimiter;
    use std::sync::Arc;

    async fn fresh_processor(held_max_age_secs: u64) -> InboundProcessor {
        let mut p = std::env::temp_dir();
        p.push(format!("hermod-inbound-{}.sqlite", ulid::Ulid::new()));
        let keypair = Arc::new(hermod_crypto::Keypair::generate());
        let self_id = keypair.agent_id();
        let self_public_key = keypair.public_key();
        let signer: Arc<dyn hermod_crypto::Signer> =
            Arc::new(hermod_crypto::LocalKeySigner::new(keypair));
        let dsn = format!("sqlite://{}", p.display());
        let db = hermod_storage::open_database(
            &dsn,
            signer,
            std::sync::Arc::new(hermod_storage::MemoryBlobStore::new()),
        )
        .await
        .unwrap();
        crate::services::ensure_self_agent(&*db, &hermod_crypto::Keypair::generate(), None)
            .await
            .ok();
        let access = AccessController::new(
            db.clone(),
            self_id.clone(),
            self_public_key,
            hermod_routing::access::AccessPolicy::default(),
        );
        let rate_limit = RateLimiter::new(db.clone(), 60);
        let audit_sink: Arc<dyn AuditSink> =
            Arc::new(hermod_storage::StorageAuditSink::new(db.clone()));
        InboundProcessor::new(
            db,
            audit_sink,
            self_id,
            access,
            rate_limit,
            300,
            held_max_age_secs,
            hermod_core::MAX_FILE_PAYLOAD_BYTES,
            false,
        )
    }

    fn fake_envelope(self_id: &AgentId, ts_ms_offset: i64) -> Envelope {
        let from = AgentAddress::local(self_id.clone());
        let to = AgentAddress::local(self_id.clone());
        let mut env = Envelope::draft(
            from,
            to,
            MessageBody::Direct {
                text: "stale test".into(),
            },
            MessagePriority::Normal,
            60,
        );
        env.ts = Timestamp::now().offset_by_ms(ts_ms_offset);
        env
    }

    #[tokio::test]
    async fn apply_held_rejects_envelope_older_than_max_age() {
        let p = fresh_processor(60).await;
        // 5 minutes old vs 60-second cap → reject.
        let env = fake_envelope(&p.self_id, -5 * 60 * 1000);
        let cbor = serialize_envelope(&env).unwrap();
        let err = p.apply_held(&cbor).await.unwrap_err();
        match err {
            FederationRejection::StaleHeldEnvelope { age_ms } => {
                assert!(age_ms > 60_000, "age must be reported: {age_ms}");
            }
            other => panic!("expected StaleHeldEnvelope, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn apply_held_accepts_recent_envelope_within_window() {
        let p = fresh_processor(3600).await;
        // 30 seconds old vs 1-hour cap → accept (downstream apply may
        // still error on missing cert / etc., but freshness gate passes).
        let env = fake_envelope(&p.self_id, -30 * 1000);
        let cbor = serialize_envelope(&env).unwrap();
        let res = p.apply_held(&cbor).await;
        assert!(
            !matches!(res, Err(FederationRejection::StaleHeldEnvelope { .. })),
            "freshness gate must pass: {res:?}"
        );
    }

    #[tokio::test]
    async fn apply_held_freshness_gate_disabled_when_max_age_zero() {
        let p = fresh_processor(0).await;
        // Years old, but the gate is disabled.
        let env = fake_envelope(&p.self_id, -10 * 365 * 24 * 3600 * 1000);
        let cbor = serialize_envelope(&env).unwrap();
        let res = p.apply_held(&cbor).await;
        assert!(
            !matches!(res, Err(FederationRejection::StaleHeldEnvelope { .. })),
            "max_age=0 must skip the gate: {res:?}"
        );
    }

    #[tokio::test]
    async fn accept_envelope_rejects_overlong_hop_count() {
        // Receiver-side defensive check: a buggy or hostile broker
        // could ship a frame with `hops > MAX`. The pipeline must
        // refuse before signature verification — there's no
        // legitimate originator-direct frame past the bound, and
        // accepting one would just feed the cycle the bound is meant
        // to break.
        let p = fresh_processor(0).await;
        let env = fake_envelope(&p.self_id, 0);
        // Use a different agent_id to bypass the LocalDestination
        // short-circuit and exercise the hop bound; the call must
        // fail with `Invalid` before any storage / cap check.
        let stranger = hermod_crypto::Keypair::generate().agent_id();
        let mut env = env;
        env.to = AgentAddress::local(stranger);
        let res = p
            .accept_envelope(
                &p.self_id.clone(),
                &env,
                hermod_protocol::wire::MAX_RELAY_HOPS + 1,
            )
            .await;
        match res {
            Err(FederationRejection::Invalid(reason)) => {
                assert!(
                    reason.contains("relay hops"),
                    "expected hop-count rejection, got: {reason}"
                );
            }
            other => panic!("expected Invalid(relay hops…), got {other:?}"),
        }
    }
}
