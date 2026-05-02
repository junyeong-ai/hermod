use hermod_core::{
    AgentAddress, AgentId, Envelope, MessageBody, MessagePriority, MessageStatus, Timestamp,
};
use hermod_crypto::{LocalKeySigner, Signer};
use hermod_daemon::local_agent::LocalAgentRegistry;
use hermod_protocol::envelope::serialize_envelope;
use hermod_protocol::ipc::methods::{
    MessageAckParams, MessageAckResult, MessageListParams, MessageListResult, MessageSendParams,
    MessageSendResult, MessageView,
};
use hermod_routing::remote::DeliveryOutcome;
use hermod_routing::{AccessController, RateLimiter, RemoteDeliverer, RouteOutcome, Router};
use hermod_storage::{AuditEntry, AuditSink, Database, InboxFilter, MessageRecord};
use std::sync::Arc;

use crate::audit_context::current_caller_agent;
use crate::outbox::OutboxNotifier;
use crate::services::{ServiceError, audit_or_warn};

/// Hard cap on DM (`MessageBody::Direct`) text. Briefs / broadcasts are
/// also 4 KiB; one limit across all human-text bodies keeps the rules
/// memorable. Also bounds memory use on the inbound path before any
/// DB / fanout work.
pub const MAX_DIRECT_TEXT_BYTES: usize = 4096;

/// Hard cap on `message.list` page size. Caps both the SQL query result
/// and the IPC reply size (stays comfortably under the 1 MiB remote-IPC
/// frame cap even with full `MessageView` serialisation). Operators
/// paginate via `after_id` for larger sweeps.
pub const MAX_LIST_LIMIT: u32 = 500;
pub const DEFAULT_LIST_LIMIT: u32 = 100;

/// Hard cap on `message.ack` batch size. Bounds the SQL fan-out and the
/// returned `acked` vector even on the local socket (which has no IPC
/// frame cap). Operators acking a larger backlog can paginate through
/// `message.list` and call `ack` per page.
pub const MAX_ACK_BATCH: usize = 500;

#[derive(Debug, Clone)]
pub struct MessageService {
    db: Arc<dyn Database>,
    audit_sink: Arc<dyn AuditSink>,
    router: Router,
    access: AccessController,
    rate_limit: RateLimiter,
    /// Lookup table from `caller_agent_id` (resolved at the IPC
    /// handshake; see `crate::audit_context::CALLER_AGENT`) to the
    /// keypair that signs the outbound envelope. Per-call signer
    /// derivation replaces the H2.5-era static `Arc<dyn Signer>`.
    registry: LocalAgentRegistry,
    remote: RemoteDeliverer,
    outbox_notifier: OutboxNotifier,
}

impl MessageService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        db: Arc<dyn Database>,
        audit_sink: Arc<dyn AuditSink>,
        router: Router,
        access: AccessController,
        rate_limit: RateLimiter,
        registry: LocalAgentRegistry,
        remote: RemoteDeliverer,
        outbox_notifier: OutboxNotifier,
    ) -> Self {
        Self {
            db,
            audit_sink,
            router,
            access,
            rate_limit,
            registry,
            remote,
            outbox_notifier,
        }
    }

    /// Resolve the caller agent + a signer wrapping its keypair.
    /// Errors when either no IPC scope is active (daemon-internal
    /// call site that should provide its own signer) or the caller
    /// agent isn't in this daemon's hosted-agent registry (auth-time
    /// race: the caller's row was removed between handshake and now).
    fn caller_signer(&self) -> Result<(AgentId, Arc<dyn Signer>), ServiceError> {
        let caller = current_caller_agent().ok_or_else(|| {
            ServiceError::InvalidParam(
                "message.send requires an IPC caller scope (no caller_agent in context)".into(),
            )
        })?;
        let agent = self.registry.lookup(&caller).ok_or_else(|| {
            ServiceError::InvalidParam(format!(
                "caller {caller} is not in this daemon's local-agent registry"
            ))
        })?;
        let signer: Arc<dyn Signer> = Arc::new(LocalKeySigner::new(agent.keypair.clone()));
        Ok((caller, signer))
    }

    #[tracing::instrument(
        name = "message.send",
        skip(self, params),
        fields(to = %params.to.id, kind = ?params.body.kind(), priority = ?params.priority)
    )]
    pub async fn send(&self, params: MessageSendParams) -> Result<MessageSendResult, ServiceError> {
        if let MessageBody::Direct { text } = &params.body
            && text.len() > MAX_DIRECT_TEXT_BYTES
        {
            return Err(ServiceError::InvalidParam(format!(
                "DM body exceeds {MAX_DIRECT_TEXT_BYTES} bytes"
            )));
        }
        if let MessageBody::File {
            name, hash, data, ..
        } = &params.body
        {
            if data.len() > hermod_core::MAX_FILE_PAYLOAD_BYTES {
                return Err(ServiceError::InvalidParam(format!(
                    "file `{name}` is {} bytes (cap {})",
                    data.len(),
                    hermod_core::MAX_FILE_PAYLOAD_BYTES
                )));
            }
            // Sender-side hash invariant: the same blake3 the receiver
            // verifies. Catches caller bugs at send time rather than as
            // a confusing rejection from the remote.
            let computed = blake3::hash(data.as_ref());
            if hash.as_ref() != computed.as_bytes() {
                return Err(ServiceError::InvalidParam(format!(
                    "file `{name}` hash does not match payload"
                )));
            }
        }

        let (caller, signer) = self.caller_signer()?;
        let from = AgentAddress::local(caller.clone());
        let priority = params.priority.unwrap_or(MessagePriority::Normal);
        let ttl = params.ttl_secs.unwrap_or(3600);

        let mut envelope = Envelope::draft(from, params.to.clone(), params.body, priority, ttl);
        if let Some(thread) = params.thread {
            envelope = envelope.with_thread(thread);
        }
        if let Some(caps) = params.caps {
            if caps.len() > hermod_core::MAX_CAPS_PER_ENVELOPE {
                return Err(ServiceError::InvalidParam(format!(
                    "params.caps has {} entries (cap {})",
                    caps.len(),
                    hermod_core::MAX_CAPS_PER_ENVELOPE
                )));
            }
            for cap in caps {
                envelope = envelope.with_capability(cap);
            }
        }

        let decision = match self.router.resolve(&params.to).await {
            Ok(d) => d,
            Err(hermod_routing::RoutingError::ViaCycle { chain }) => {
                // Operator misconfigured the directory's via chain.
                // Per-send audit row so forensic queries can answer
                // "from when did messages to X stop routing?". The
                // condition persists until the operator repairs, so
                // every send to the affected target re-emits — same
                // pattern as wire-level rejections.
                audit_or_warn(
                    &*self.audit_sink,
                    AuditEntry {
                        id: None,
                        ts: Timestamp::now(),
                        actor: caller.clone(),
                        action: "routing.cycle_detected".into(),
                        target: Some(params.to.id.to_string()),
                        details: Some(serde_json::json!({ "chain": chain.clone() })),
                        client_ip: None,
                        federation: hermod_storage::AuditFederationPolicy::Default,
                    },
                )
                .await;
                return Err(hermod_routing::RoutingError::ViaCycle { chain }.into());
            }
            Err(hermod_routing::RoutingError::ViaTooDeep { target, limit }) => {
                audit_or_warn(
                    &*self.audit_sink,
                    AuditEntry {
                        id: None,
                        ts: Timestamp::now(),
                        actor: caller.clone(),
                        action: "routing.via_too_deep".into(),
                        target: Some(target.clone()),
                        details: Some(serde_json::json!({ "limit": limit })),
                        client_ip: None,
                        federation: hermod_storage::AuditFederationPolicy::Default,
                    },
                )
                .await;
                return Err(hermod_routing::RoutingError::ViaTooDeep { target, limit }.into());
            }
            Err(e) => return Err(e.into()),
        };

        // Outbound: sender is the calling agent, AccessController
        // short-circuits for self. Caps are only required at inbound
        // (federation listener side).
        self.access.check_send(&caller, &params.to.id, &[]).await?;
        self.rate_limit.consume_one(&caller, &params.to.id).await?;

        signer
            .sign_envelope(&mut envelope)
            .await
            .map_err(ServiceError::Crypto)?;
        let cbor = serialize_envelope(&envelope)
            .map_err(|e| ServiceError::InvalidParam(format!("serialize envelope: {e}")))?;

        let (status, schedule_retry) = match &decision {
            RouteOutcome::Loopback | RouteOutcome::LocalKnown => (MessageStatus::Delivered, false),
            RouteOutcome::Remote(endpoint) | RouteOutcome::Brokered { endpoint, .. } => {
                // First attempt is synchronous; on transient failure, leave Pending
                // and let the outbox worker retry with exponential backoff. The
                // broker case uses the same outbound deliverer — the broker is just
                // another peer carrying authenticated WSS+Noise, the envelope
                // signature is preserved verbatim, and the broker's
                // `relay` path handles the second hop on its side.
                match self.remote.deliver(&envelope, endpoint).await {
                    Ok(DeliveryOutcome::Delivered) => (MessageStatus::Delivered, false),
                    Ok(DeliveryOutcome::Deferred) => (MessageStatus::Pending, true),
                    Ok(DeliveryOutcome::Rejected) => (MessageStatus::Failed, false),
                    Err(hermod_routing::RoutingError::Rejected(reason)) => {
                        tracing::warn!(reason = %reason, "remote rejected; not retrying");
                        (MessageStatus::Failed, false)
                    }
                    Err(hermod_routing::RoutingError::TlsFingerprintMismatch {
                        peer,
                        observed,
                    }) => {
                        tracing::warn!(
                            peer = %peer,
                            observed = %observed,
                            "tls fingerprint mismatch; not retrying — operator must re-pin via `hermod peer trust`"
                        );
                        (MessageStatus::Failed, false)
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "first attempt failed; queued for retry");
                        (MessageStatus::Pending, true)
                    }
                }
            }
        };
        let mut record = MessageRecord::from_envelope(&envelope, cbor, status);
        // Stamp the resolved endpoint so the outbox replays straight to
        // it without re-resolving — covers brokered envelopes whose
        // recipient has no `agents.endpoint` of their own.
        record.delivery_endpoint = match &decision {
            RouteOutcome::Remote(ep) | RouteOutcome::Brokered { endpoint: ep, .. } => {
                Some(ep.to_string())
            }
            _ => None,
        };
        if status == MessageStatus::Delivered {
            record.delivered_at = Some(Timestamp::now());
        }
        if schedule_retry {
            record.attempts = 1;
            record.next_attempt_at = Some(
                Timestamp::from_unix_ms(Timestamp::now().unix_ms() + 1_000)
                    .expect("now+1s cannot overflow Timestamp"),
            );
        }

        // Loopback / local-known File payloads bypass the federation
        // inbound path that normally writes the blob, so persist
        // directly to the BlobStore here. Without this, a self-sent
        // file would land in `messages` with no `file_blob_location`
        // — operators / Claude Code couldn't read it back. Mirrors
        // the inbound `accept_file` rollback discipline: blob put
        // first, then enqueue; on enqueue failure, delete the blob to
        // prevent orphans (storage row gone but bytes still on disk).
        let blob_location = if matches!(decision, RouteOutcome::Loopback | RouteOutcome::LocalKnown)
            && let MessageBody::File { name, data, .. } = &envelope.body
        {
            let key = format!("{}-{}", envelope.id, name);
            let loc = self
                .db
                .blobs()
                .put(hermod_storage::bucket::FILES, &key, data.as_ref())
                .await?;
            record.file_blob_location = Some(loc.clone());
            Some(loc)
        } else {
            None
        };

        if let Err(e) = self.db.messages().enqueue(&record).await {
            if let Some(loc) = blob_location {
                let _ = self.db.blobs().delete(&loc).await;
            }
            return Err(e.into());
        }
        self.audit_send(caller.clone(), &envelope, status, &decision)
            .await;

        // Nudge the outbox worker so the retry runs as soon as the backoff
        // timer expires, not on the next backstop tick.
        if schedule_retry {
            self.outbox_notifier.wake();
        }

        let recipient_live = self.is_recipient_live(&params.to.id).await;

        Ok(MessageSendResult {
            id: envelope.id,
            status,
            recipient_live,
        })
    }

    /// Best-effort liveness lookup for the recipient. For loopback —
    /// the recipient is one of our hosted agents — we consult
    /// `mcp_sessions` (any active local Claude Code session counts).
    /// For federated peers we consult the cached `peer_live`
    /// populated by inbound Presence envelopes. On error, degrades
    /// to `false` — never blocks the send.
    async fn is_recipient_live(&self, recipient: &hermod_core::AgentId) -> bool {
        let now = Timestamp::now();
        if self.router.is_local(recipient) {
            return self
                .db
                .mcp_sessions()
                .count_live(now, (hermod_storage::SESSION_TTL_SECS * 1_000) as i64)
                .await
                .map(|n| n > 0)
                .unwrap_or(false);
        }
        match self.db.presences().get(recipient).await {
            Ok(Some(rec)) => rec.active_peer_live(now).unwrap_or(false),
            _ => false,
        }
    }

    pub async fn list(&self, params: MessageListParams) -> Result<MessageListResult, ServiceError> {
        let caller = current_caller_agent().ok_or_else(|| {
            ServiceError::InvalidParam(
                "message.list requires an IPC caller scope (no caller_agent in context)".into(),
            )
        })?;
        let limit = params
            .limit
            .unwrap_or(DEFAULT_LIST_LIMIT)
            .min(MAX_LIST_LIMIT);
        let filter = InboxFilter {
            statuses: params.statuses,
            priority_min: params.priority_min,
            limit: Some(limit),
            after_id: params.after_id,
        };
        let records = self.db.messages().list_inbox(&caller, &filter).await?;
        let total = self.db.messages().count_pending_to(&caller).await?;
        // Per-batch alias cache. Multiple messages from the same sender
        // share one directory lookup; the directory is small + indexed so
        // this is O(distinct senders) sqlite SELECTs.
        let mut sender_cache: std::collections::HashMap<hermod_core::AgentId, SenderProjection> =
            std::collections::HashMap::new();
        let mut messages = Vec::with_capacity(records.len());
        for r in records {
            let proj = match sender_cache.get(&r.from_agent) {
                Some(v) => v.clone(),
                None => {
                    let t = SenderProjection::lookup(&self.db, &r.from_agent).await;
                    sender_cache.insert(r.from_agent.clone(), t.clone());
                    t
                }
            };
            messages.push(MessageView {
                id: r.id,
                from: r.from_agent,
                from_local_alias: proj.local,
                from_peer_alias: proj.peer,
                from_alias: proj.effective,
                from_alias_ambiguous: proj.effective_ambiguous,
                from_host_pubkey: proj.host_pubkey_hex,
                to: r.to_agent,
                kind: r.kind,
                priority: r.priority,
                status: r.status,
                created_at: r.created_at,
                body: r.body,
                thread: r.thread_id,
                file_blob_location: r.file_blob_location,
                file_size: r.file_size,
            });
        }
        Ok(MessageListResult { messages, total })
    }

    pub async fn ack(&self, params: MessageAckParams) -> Result<MessageAckResult, ServiceError> {
        if params.message_ids.len() > MAX_ACK_BATCH {
            return Err(ServiceError::InvalidParam(format!(
                "ack batch size {} exceeds max {MAX_ACK_BATCH}; paginate",
                params.message_ids.len()
            )));
        }
        let caller = current_caller_agent().ok_or_else(|| {
            ServiceError::InvalidParam(
                "message.ack requires an IPC caller scope (no caller_agent in context)".into(),
            )
        })?;
        let now = Timestamp::now();
        let mut acked = Vec::with_capacity(params.message_ids.len());
        for id in params.message_ids {
            let ok = self.db.messages().ack(&id, &caller, now).await?;
            if ok {
                acked.push(id);
            }
        }
        self.audit_ack(caller, &acked).await;
        Ok(MessageAckResult { acked })
    }

    async fn audit_send(
        &self,
        actor: AgentId,
        envelope: &Envelope,
        status: MessageStatus,
        decision: &RouteOutcome,
    ) {
        let route = match decision {
            RouteOutcome::Loopback => "loopback",
            RouteOutcome::LocalKnown => "local",
            RouteOutcome::Remote(_) => "remote",
            RouteOutcome::Brokered { .. } => "brokered",
        };
        // For brokered routes, surface the broker's agent_id so
        // operators tracing a misrouted envelope can see WHICH broker
        // it traversed. Omitted for non-brokered routes to keep the
        // audit row lean.
        let via = match decision {
            RouteOutcome::Brokered { via, .. } => Some(via.to_string()),
            _ => None,
        };
        audit_or_warn(
            &*self.audit_sink,
            AuditEntry {
                id: None,
                ts: Timestamp::now(),
                actor,
                action: "message.sent".into(),
                target: Some(envelope.to.id.to_string()),
                details: Some(serde_json::json!({
                    "id": envelope.id.to_string(),
                    "kind": envelope.kind.as_str(),
                    "priority": envelope.priority.as_str(),
                    "status": status.as_str(),
                    "route": route,
                    "via": via,
                })),
                // Federation audit shipping itself emits `message.sent`
                // for every aggregator-bound envelope. Skipping breaks
                // the recursion at the source — without this, every
                // federated row would re-trigger N more federations.
                client_ip: None,
                federation: hermod_storage::AuditFederationPolicy::Skip,
            },
        )
        .await;
    }

    async fn audit_ack(&self, actor: AgentId, ids: &[hermod_core::MessageId]) {
        if ids.is_empty() {
            return;
        }
        audit_or_warn(
            &*self.audit_sink,
            AuditEntry {
                id: None,
                ts: Timestamp::now(),
                actor,
                action: "message.read".into(),
                target: None,
                details: Some(serde_json::json!({
                    "ids": ids.iter().map(|i| i.to_string()).collect::<Vec<_>>(),
                })),
                client_ip: None,
                federation: hermod_storage::AuditFederationPolicy::Default,
            },
        )
        .await;
    }
}

/// Three-tier alias snapshot used by views that surface a sender's display
/// name. `local` is the operator-set nickname, `peer` is the sender's own
/// self-claim, `effective` is what UIs render. `host_pubkey_hex` is the
/// hex-encoded ed25519 host pubkey of the daemon hosting the sender —
/// surfaced for cross-host disambiguation when local aliases collide.
/// `effective_ambiguous` is true iff *another* agent in the receiver's
/// directory shares the same effective alias — UI / channel meta lift
/// `from_host` to disambiguate.
///
/// Looked up once per distinct sender per batch (see callers in
/// `message::list` / `confirmation::list`).
#[derive(Debug, Clone, Default)]
pub(crate) struct SenderProjection {
    pub local: Option<hermod_core::AgentAlias>,
    pub peer: Option<hermod_core::AgentAlias>,
    pub effective: Option<hermod_core::AgentAlias>,
    pub effective_ambiguous: bool,
    pub host_pubkey_hex: Option<String>,
}

impl SenderProjection {
    pub async fn lookup(db: &Arc<dyn Database>, id: &hermod_core::AgentId) -> Self {
        match db.agents().get(id).await.ok().flatten() {
            Some(rec) => {
                let effective = rec.effective_alias().cloned();
                // Ambiguity is computed via an indexed COUNT(*) per
                // distinct sender per batch — same cache scope as
                // the directory lookup itself, so cost is O(distinct
                // senders) regardless of batch size.
                let effective_ambiguous = match effective.as_ref() {
                    Some(alias) => {
                        db.agents()
                            .count_with_effective_alias(alias, id)
                            .await
                            .unwrap_or(0)
                            > 0
                    }
                    None => false,
                };
                Self {
                    effective,
                    effective_ambiguous,
                    local: rec.local_alias,
                    peer: rec.peer_asserted_alias,
                    host_pubkey_hex: rec.host_pubkey.map(|h| hex::encode(h.as_slice())),
                }
            }
            None => Self::default(),
        }
    }
}
