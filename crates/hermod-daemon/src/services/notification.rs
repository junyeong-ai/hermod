//! OS-notification queue service.
//!
//! Bridge between the daemon's `notifications` table and the
//! MCP-side `NotificationDispatcher`. Each method is per-tenant
//! scoped: every call resolves the IPC caller via
//! `audit_context::current_caller_agent()` and the underlying repo
//! filters by that agent_id, so sibling local agents can never
//! enumerate or claim each other's queues.
//!
//! ## Method semantics
//!
//! * **`list`** — operator inspection (`hermod notification list`).
//!   Newest first; status filter optional.
//! * **`claim`** — atomic worker pull. Mirrors `messages.outbox`
//!   semantics: claim_token + claimed_at; stale claims past TTL
//!   reclaimable. Caller (the dispatcher) gets every row needed
//!   to invoke the platform notifier — `message_id`, `sound`,
//!   `claim_token`.
//! * **`complete`** / **`fail`** — terminal transitions. Both echo
//!   the worker's `claim_token`; rows owned by another worker
//!   (claim raced) return `matched=false` so a late completer
//!   discovers it lost the race without overwriting state.
//! * **`dismiss`** — operator-driven (`hermod notification dismiss`).
//! * **`purge`** — terminal-row reaping. The janitor invokes this on
//!   a fixed cadence; operators can also fire it ad hoc.
//!
//! Audit emissions:
//!   `notification.queued`     — emitted by `InboundProcessor` after a
//!                               successful enqueue (NOT here — this
//!                               module only handles the live path).
//!   `notification.suppressed` — same source, on `BackPressure` from
//!                               the storage layer's atomic enqueue.
//!   `notification.dispatched` — `complete` success.
//!   `notification.failed`     — `fail` success.
//!   `notification.dismissed`  — `dismiss` success.

use hermod_core::{AgentId, Timestamp};
use hermod_protocol::ipc::methods::{
    NotificationClaimParams, NotificationClaimResult, NotificationClaimView,
    NotificationCompleteParams, NotificationCompleteResult, NotificationDismissParams,
    NotificationDismissResult, NotificationFailParams, NotificationFailResult,
    NotificationListParams, NotificationListResult, NotificationPurgeParams,
    NotificationPurgeResult, NotificationView,
};
use hermod_storage::{AuditEntry, AuditSink, Database, NotificationRecord, TransitionOutcome};
use std::sync::Arc;

use crate::audit_context::current_caller_agent;
use crate::services::{ServiceError, audit_or_warn};

/// Default `notification.list` limit. Operators rarely need more
/// than a screenful; large historical sweeps go through `audit query`.
const DEFAULT_LIST_LIMIT: u32 = 50;
const MAX_LIST_LIMIT: u32 = 500;

/// Default `notification.claim` batch. Higher values let one
/// dispatcher poll absorb a burst; lower values smooth latency on
/// a slow notifier.
const DEFAULT_CLAIM_LIMIT: u32 = 16;
const MAX_CLAIM_LIMIT: u32 = 64;

/// Claim TTL — a worker that holds a claim past this without
/// completing or failing is assumed crashed. Two minutes covers
/// pathological osascript / notify-send latency without burying
/// genuine stalls.
const CLAIM_TTL_MS: i64 = 120_000;

#[derive(Clone)]
pub struct NotificationService {
    db: Arc<dyn Database>,
    audit_sink: Arc<dyn AuditSink>,
    host_actor: AgentId,
    /// Operator-configured retention. Used by `purge` when the
    /// caller doesn't override via `older_than_secs`. Captured at
    /// boot from `[routing.notification] retention_days` and never
    /// mutated — the routing-config validator guarantees a sane
    /// value.
    retention_days: u32,
}

impl std::fmt::Debug for NotificationService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NotificationService")
            .field("host_actor", &self.host_actor)
            .field("retention_days", &self.retention_days)
            .finish()
    }
}

impl NotificationService {
    pub fn new(
        db: Arc<dyn Database>,
        audit_sink: Arc<dyn AuditSink>,
        host_actor: AgentId,
        retention_days: u32,
    ) -> Self {
        Self {
            db,
            audit_sink,
            host_actor,
            retention_days,
        }
    }

    fn caller(&self) -> Result<AgentId, ServiceError> {
        current_caller_agent().ok_or_else(|| {
            ServiceError::InvalidParam(
                "notification.* requires an IPC caller scope (no caller_agent in context)".into(),
            )
        })
    }

    pub async fn list(
        &self,
        params: NotificationListParams,
    ) -> Result<NotificationListResult, ServiceError> {
        let caller = self.caller()?;
        let limit = params
            .limit
            .unwrap_or(DEFAULT_LIST_LIMIT)
            .min(MAX_LIST_LIMIT);
        let rows = self
            .db
            .notifications()
            .list(&caller, params.statuses.as_deref(), limit)
            .await?;
        Ok(NotificationListResult {
            notifications: rows.into_iter().map(record_to_view).collect(),
        })
    }

    pub async fn claim(
        &self,
        params: NotificationClaimParams,
    ) -> Result<NotificationClaimResult, ServiceError> {
        let caller = self.caller()?;
        let limit = params
            .limit
            .unwrap_or(DEFAULT_CLAIM_LIMIT)
            .min(MAX_CLAIM_LIMIT);
        let now = Timestamp::now();
        let rows = self
            .db
            .notifications()
            .claim_pending(&params.worker_id, &caller, now, CLAIM_TTL_MS, limit)
            .await?;
        Ok(NotificationClaimResult {
            notifications: rows
                .into_iter()
                .map(|r| NotificationClaimView {
                    id: r.id,
                    message_id: r.message_id,
                    recipient_agent_id: r.recipient_agent_id,
                    sound: r.sound,
                    claim_token: r.claim_token.unwrap_or_default(),
                    created_at: r.created_at,
                })
                .collect(),
        })
    }

    pub async fn complete(
        &self,
        params: NotificationCompleteParams,
    ) -> Result<NotificationCompleteResult, ServiceError> {
        let _ = self.caller()?;
        let now = Timestamp::now();
        let outcome = self
            .db
            .notifications()
            .mark_dispatched(&params.id, &params.claim_token, now)
            .await?;
        let matched = matches!(outcome, TransitionOutcome::Applied);
        if matched {
            audit_or_warn(
                &*self.audit_sink,
                AuditEntry {
                    id: None,
                    ts: now,
                    actor: self.host_actor.clone(),
                    action: "notification.dispatched".into(),
                    target: Some(params.id.clone()),
                    details: None,
                    client_ip: None,
                    federation: hermod_storage::AuditFederationPolicy::Default,
                },
            )
            .await;
        }
        Ok(NotificationCompleteResult { matched })
    }

    pub async fn fail(
        &self,
        params: NotificationFailParams,
    ) -> Result<NotificationFailResult, ServiceError> {
        let _ = self.caller()?;
        let outcome = self
            .db
            .notifications()
            .mark_failed(&params.id, &params.claim_token, &params.reason)
            .await?;
        let matched = matches!(outcome, TransitionOutcome::Applied);
        if matched {
            audit_or_warn(
                &*self.audit_sink,
                AuditEntry {
                    id: None,
                    ts: Timestamp::now(),
                    actor: self.host_actor.clone(),
                    action: "notification.failed".into(),
                    target: Some(params.id.clone()),
                    details: Some(serde_json::json!({ "reason": params.reason })),
                    client_ip: None,
                    federation: hermod_storage::AuditFederationPolicy::Default,
                },
            )
            .await;
        }
        Ok(NotificationFailResult { matched })
    }

    pub async fn dismiss(
        &self,
        params: NotificationDismissParams,
    ) -> Result<NotificationDismissResult, ServiceError> {
        let caller = self.caller()?;
        let outcome = self.db.notifications().dismiss(&params.id, &caller).await?;
        let matched = matches!(outcome, TransitionOutcome::Applied);
        if matched {
            audit_or_warn(
                &*self.audit_sink,
                AuditEntry {
                    id: None,
                    ts: Timestamp::now(),
                    actor: self.host_actor.clone(),
                    action: "notification.dismissed".into(),
                    target: Some(params.id.clone()),
                    details: None,
                    client_ip: None,
                    federation: hermod_storage::AuditFederationPolicy::Default,
                },
            )
            .await;
        }
        Ok(NotificationDismissResult { matched })
    }

    pub async fn purge(
        &self,
        params: NotificationPurgeParams,
    ) -> Result<NotificationPurgeResult, ServiceError> {
        let _ = self.caller()?;
        let now = Timestamp::now();
        let secs = params
            .older_than_secs
            .unwrap_or(self.retention_days.saturating_mul(86_400));
        let cutoff_ms = now.unix_ms() - (secs as i64) * 1_000;
        let purged = self
            .db
            .notifications()
            .purge_terminal_older_than(cutoff_ms)
            .await?;
        if purged > 0 {
            audit_or_warn(
                &*self.audit_sink,
                AuditEntry {
                    id: None,
                    ts: now,
                    actor: self.host_actor.clone(),
                    action: "notification.purged".into(),
                    target: None,
                    details: Some(serde_json::json!({ "rows": purged })),
                    client_ip: None,
                    federation: hermod_storage::AuditFederationPolicy::Default,
                },
            )
            .await;
        }
        Ok(NotificationPurgeResult { purged })
    }
}

fn record_to_view(r: NotificationRecord) -> NotificationView {
    NotificationView {
        id: r.id,
        recipient_agent_id: r.recipient_agent_id,
        message_id: r.message_id,
        status: r.status,
        sound: r.sound,
        attempts: r.attempts,
        dispatched_at: r.dispatched_at,
        failed_reason: r.failed_reason,
        created_at: r.created_at,
    }
}
