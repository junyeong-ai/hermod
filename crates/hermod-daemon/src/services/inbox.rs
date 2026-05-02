//! Inbox service — recipient-side delivery surface.
//!
//! ## Why a separate service
//!
//! The `messages` table is the underlying store, but two distinct
//! viewers consume it:
//!
//!  * Operator CLI (`hermod inbox list`) wants every row regardless
//!    of disposition. The view is operator-facing — silent rows
//!    coexist with push rows in one human-readable listing.
//!  * MCP channel poller wants `Push` rows only — silent rows must
//!    never enter AI-agent context.
//!
//! Both go through this service and through one repository call
//! (`MessageRepository::list_inbox` with an `InboxFilter`). Sender
//! enrichment (`SenderProjection` — local alias + peer alias +
//! effective + ambiguity flag + host pubkey) lives here so both
//! viewers see the same projection.
//!
//! `inbox.promote` flips a silent row to push so the channel
//! emitter surfaces it on its next poll. The audit row records
//! who promoted what.

use hermod_core::{AgentId, Timestamp};
use hermod_protocol::ipc::methods::{
    InboxListParams, InboxListResult, InboxPromoteParams, InboxPromoteResult, MessageView,
};
use hermod_storage::{AuditEntry, AuditSink, Database, InboxFilter, TransitionOutcome};
use std::sync::Arc;

use crate::audit_context::current_caller_agent;
use crate::services::{ServiceError, audit_or_warn, message::SenderProjection};

/// Default `inbox.list` limit when the caller doesn't pass one.
/// Matches the prior `message.list` default so existing operator
/// muscle memory is preserved (the rename is the only behaviour
/// change for the unfiltered path).
const DEFAULT_LIST_LIMIT: u32 = 100;
const MAX_LIST_LIMIT: u32 = 500;

#[derive(Clone)]
pub struct InboxService {
    db: Arc<dyn Database>,
    audit_sink: Arc<dyn AuditSink>,
    /// Audit fallback actor for emissions outside an IPC scope —
    /// used by `audit_or_warn` only when `current_caller_agent`
    /// returns `None`. Set to the daemon's host id at construction.
    host_actor: AgentId,
}

impl std::fmt::Debug for InboxService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InboxService")
            .field("host_actor", &self.host_actor)
            .finish()
    }
}

impl InboxService {
    pub fn new(db: Arc<dyn Database>, audit_sink: Arc<dyn AuditSink>, host_actor: AgentId) -> Self {
        Self {
            db,
            audit_sink,
            host_actor,
        }
    }

    fn caller(&self) -> Result<AgentId, ServiceError> {
        current_caller_agent().ok_or_else(|| {
            ServiceError::InvalidParam(
                "inbox.* requires an IPC caller scope (no caller_agent in context)".into(),
            )
        })
    }

    pub async fn list(&self, params: InboxListParams) -> Result<InboxListResult, ServiceError> {
        let caller = self.caller()?;
        let limit = params
            .limit
            .unwrap_or(DEFAULT_LIST_LIMIT)
            .min(MAX_LIST_LIMIT);
        let filter = InboxFilter {
            statuses: params.statuses,
            priority_min: params.priority_min,
            limit: Some(limit),
            after_id: params.after_id,
            dispositions: params.dispositions,
        };
        let records = self.db.messages().list_inbox(&caller, &filter).await?;
        let total = self.db.messages().count_pending_to(&caller).await?;

        // Per-batch alias cache. Multiple messages from the same sender
        // share one directory lookup; the directory is small + indexed so
        // this is O(distinct senders) sqlite SELECTs.
        let mut sender_cache: std::collections::HashMap<AgentId, SenderProjection> =
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
                disposition: r.disposition,
                created_at: r.created_at,
                body: r.body,
                thread: r.thread_id,
                file_blob_location: r.file_blob_location,
                file_size: r.file_size,
            });
        }
        Ok(InboxListResult { messages, total })
    }

    /// Flip a silent row to push. Audit row records the promotion
    /// so an operator review trail is preserved.
    pub async fn promote(
        &self,
        params: InboxPromoteParams,
    ) -> Result<InboxPromoteResult, ServiceError> {
        let caller = self.caller()?;
        let outcome = self
            .db
            .messages()
            .promote_to_push(&params.id, &caller)
            .await?;
        let promoted = matches!(outcome, TransitionOutcome::Applied);
        if promoted {
            audit_or_warn(
                &*self.audit_sink,
                AuditEntry {
                    id: None,
                    ts: Timestamp::now(),
                    actor: self.host_actor.clone(),
                    action: "inbox.promote".into(),
                    target: Some(params.id.to_string()),
                    details: None,
                    client_ip: None,
                    federation: hermod_storage::AuditFederationPolicy::Default,
                },
            )
            .await;
        }
        Ok(InboxPromoteResult { promoted })
    }
}
