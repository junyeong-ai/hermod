//! Outbound audit federation sink.
//!
//! Composes inside the global [`AuditSink`] stack via
//! [`hermod_storage::TeeAuditSink`].
//! Every audit row that flows through the daemon is wrapped into an
//! `AuditFederate` envelope and shipped to **every** operator-designated
//! aggregator in parallel. Each aggregator must have opted in to
//! ingestion (`[audit] accept_federation = true`) — otherwise it
//! rejects the envelope with `unauthorized`, which we observe as a
//! `warn` log line and discard (best-effort by `AuditSink` contract).
//!
//! ## HA fan-out
//!
//! Multiple aggregators are first-class: operators name as many as they
//! want in `[audit] aggregators`, and each row is shipped to all of
//! them concurrently. This is the standard "primary + secondaries"
//! pattern for audit aggregation — a primary down/restarting does not
//! black-hole the audit stream because every row landed at the
//! secondary too. Audit rows are small (typically <1 KiB), so the
//! bandwidth cost of replication is dominated by the WS frame
//! overhead; one fan-out is cheap relative to the operational value
//! of HA.
//!
//! ## Loop prevention
//!
//! The act of federating an audit row itself emits a downstream audit
//! row (`message.sent`). If the sink shipped that row too, we'd loop
//! forever. The boundary is decided at *emission* time via
//! [`AuditFederationPolicy`] on every [`AuditEntry`]: emitters that
//! produce federation feedback (`MessageService::send` for the
//! federation envelope itself, `accept_audit_federate` for the
//! aggregator-side echo) tag the row with `Skip`. This sink simply
//! honours the tag — no string matching, no prefix heuristic.
//!
//! ## Best-effort
//!
//! `AuditSink::record` cannot return an error. A send failure here
//! (peer offline, signature broken, transport down) is logged as a
//! `tracing::warn` and dropped — the row stays in our local
//! hash-chained log regardless, so the aggregator's view is "best
//! effort recent state", not "the source of truth".

use async_trait::async_trait;
use futures::future::join_all;
use hermod_core::{AgentAddress, AgentId, MessageBody, MessagePriority};
use hermod_protocol::ipc::methods::MessageSendParams;
use hermod_storage::{AuditEntry, AuditFederationPolicy, AuditSink};
use std::sync::{Arc, OnceLock};
use tracing::{debug, warn};

use crate::services::message::MessageService;

/// `RemoteAuditSink` lives inside the global audit `Tee` that
/// `MessageService` itself consumes — so we can't pass `MessageService`
/// to its constructor without a cycle. Instead, the sink starts with
/// an empty [`OnceLock`] and `server.rs` calls
/// [`RemoteAuditSink::set_messages`] *after* `MessageService::new`
/// returns. Audit rows emitted during the small startup window before
/// that call are silently skipped — they're construction-time
/// bookkeeping, not operator-meaningful state.
#[derive(Clone)]
pub struct RemoteAuditSink {
    aggregators: Arc<[AgentId]>,
    messages: Arc<OnceLock<MessageService>>,
}

impl std::fmt::Debug for RemoteAuditSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteAuditSink")
            .field("aggregators", &self.aggregators)
            .field("wired", &self.messages.get().is_some())
            .finish()
    }
}

impl RemoteAuditSink {
    /// Construct with one or more aggregator destinations. Empty
    /// `aggregators` is a programming error (the constructor in
    /// `server.rs` only calls this when at least one aggregator is
    /// configured); we accept it gracefully (record becomes a no-op)
    /// rather than panic so a misconfiguration is observable as
    /// "nothing federates" rather than a daemon crash.
    pub fn new(aggregators: Vec<AgentId>) -> Self {
        Self {
            aggregators: aggregators.into(),
            messages: Arc::new(OnceLock::new()),
        }
    }

    /// Populate the post-construction `MessageService` reference.
    /// Idempotent: a second call is a silent no-op (OnceLock semantics).
    pub fn set_messages(&self, messages: MessageService) {
        let _ = self.messages.set(messages);
    }

    #[cfg(test)]
    pub fn aggregators(&self) -> &[AgentId] {
        &self.aggregators
    }
}

#[async_trait]
impl AuditSink for RemoteAuditSink {
    async fn record(&self, entry: AuditEntry) {
        if entry.federation == AuditFederationPolicy::Skip {
            return;
        }
        let Some(messages) = self.messages.get() else {
            // Pre-wire window during daemon startup. Skipping these
            // rows is intentional — they're construction noise.
            return;
        };
        if self.aggregators.is_empty() {
            return;
        }

        // Fan out to every aggregator concurrently. `join_all` keeps
        // the call latency at max(per-aggregator latency) rather than
        // sum-of-latencies — important once an operator has 3+
        // aggregators on different links.
        let action = entry.action.clone();
        let original_ts_ms = entry.ts.unix_ms();
        let target = entry.target.clone();
        let details = entry.details.clone();
        let sends = self.aggregators.iter().map(|aggregator| {
            let body = MessageBody::AuditFederate {
                action: action.clone(),
                target: target.clone(),
                details: details.clone(),
                original_ts_ms,
            };
            let to = AgentAddress::local(aggregator.clone());
            let messages = messages.clone();
            let aggregator_id = aggregator.clone();
            let action_for_log = action.clone();
            async move {
                match messages
                    .send(MessageSendParams {
                        to,
                        body,
                        priority: Some(MessagePriority::Low),
                        thread: None,
                        // 1h is well past the aggregator's typical
                        // reconnect window. Past that, the row is
                        // stale enough that re-emitting it on the
                        // next federation cycle is the honest
                        // behaviour.
                        ttl_secs: Some(3600),
                        caps: None,
                    })
                    .await
                {
                    Ok(_) => debug!(
                        action = %action_for_log,
                        aggregator = %aggregator_id,
                        "audit row federated"
                    ),
                    Err(e) => warn!(
                        action = %action_for_log,
                        aggregator = %aggregator_id,
                        error = %e,
                        "audit federation send failed (best-effort)"
                    ),
                }
            }
        });
        join_all(sends).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hermod_core::Timestamp;
    use hermod_crypto::Keypair;

    fn fresh_id() -> AgentId {
        Keypair::generate().agent_id()
    }

    fn entry(actor: AgentId, action: &str, federation: AuditFederationPolicy) -> AuditEntry {
        AuditEntry {
            id: None,
            ts: Timestamp::now(),
            actor,
            action: action.to_string(),
            target: None,
            details: None,
            federation,
        }
    }

    #[tokio::test]
    async fn skip_policy_short_circuits_record() {
        // Sink without a wired MessageService — record() must return
        // early on Skip before reaching the OnceLock check.
        let sink = RemoteAuditSink::new(vec![fresh_id()]);
        let actor = fresh_id();
        sink.record(entry(
            actor.clone(),
            "audit.federate.workspace.create",
            AuditFederationPolicy::Skip,
        ))
        .await;
        sink.record(entry(actor, "message.sent", AuditFederationPolicy::Skip))
            .await;
    }

    #[tokio::test]
    async fn default_policy_without_messages_is_quiet_noop() {
        // Pre-wire window during daemon startup: `set_messages` not
        // called yet. Default-policy rows are quietly dropped with no
        // crash; once wiring completes, subsequent rows fan out.
        let sink = RemoteAuditSink::new(vec![fresh_id()]);
        sink.record(entry(
            fresh_id(),
            "workspace.create",
            AuditFederationPolicy::Default,
        ))
        .await;
    }

    #[tokio::test]
    async fn empty_aggregators_is_construction_noop() {
        // Operators who clear `[audit] aggregators` should observe
        // federation pause without a crash.
        let sink = RemoteAuditSink::new(Vec::new());
        sink.record(entry(
            fresh_id(),
            "workspace.create",
            AuditFederationPolicy::Default,
        ))
        .await;
        assert_eq!(sink.aggregators(), &[] as &[AgentId]);
    }
}
