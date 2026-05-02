//! OS-notification queue contract.
//!
//! Recipient-side: when the routing engine assigns
//! `NotifyPreference::Os { sound }` to an inbound, the daemon writes
//! one row here. The MCP-side `NotificationDispatcher` claims rows
//! atomically (claim_token + claimed_at, mirrors the messages outbox
//! semantics), invokes the platform notifier, and transitions via
//! `complete` / `fail`.
//!
//! Atomic enqueue with cap (Q4 fix): the cap check + INSERT live in
//! one statement so a sustained inbound burst can't punch through
//! `notification.max_pending` between SELECT and INSERT.
//!
//! Per-tenant scope: every method that returns rows or lets the
//! caller decide on rows takes a `recipient_agent_id` argument and
//! filters on it. Sibling local agents can never enumerate or claim
//! each other's queues — the IPC dispatcher's caller-agent overlay
//! plus this argument together enforce isolation.

use async_trait::async_trait;
use hermod_core::{AgentId, MessageId, NotificationStatus, Timestamp};

use crate::error::Result;
use crate::repositories::messages::TransitionOutcome;

/// One notification-queue row, materialised for inspection /
/// dispatch. Internal — the wire-side projection is
/// `hermod_protocol::NotificationView`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotificationRecord {
    pub id: String,
    pub recipient_agent_id: AgentId,
    pub message_id: MessageId,
    pub status: NotificationStatus,
    pub sound: Option<String>,
    pub attempts: u32,
    pub claim_token: Option<String>,
    pub claimed_at: Option<Timestamp>,
    pub dispatched_at: Option<Timestamp>,
    pub failed_reason: Option<String>,
    pub created_at: Timestamp,
}

/// Outcome of [`NotificationRepository::enqueue`]. `BackPressure`
/// means the per-recipient cap was at or above `max_pending` when
/// the INSERT ran — the row was *not* written and the caller emits
/// `notification.suppressed` audit instead of `notification.queued`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnqueueOutcome {
    Inserted,
    BackPressure,
}

/// What a fresh enqueue carries. The dispatch decision lives in
/// `hermod-routing`; the storage layer just persists.
#[derive(Debug, Clone)]
pub struct EnqueueRequest {
    pub id: String,
    pub recipient_agent_id: AgentId,
    pub message_id: MessageId,
    pub sound: Option<String>,
    pub created_at: Timestamp,
}

#[async_trait]
pub trait NotificationRepository: Send + Sync + std::fmt::Debug {
    /// Atomically insert one notification IFF the recipient's
    /// `pending` + `failed` count is strictly below `max_pending`.
    /// The cap check + INSERT live in one statement so a burst can't
    /// punch through the cap between SELECT and INSERT.
    async fn enqueue(&self, req: &EnqueueRequest, max_pending: u32) -> Result<EnqueueOutcome>;

    /// Atomically claim a batch of `pending` rows for `worker_id`,
    /// mirroring the messages outbox claim. Returns rows whose
    /// `claim_token` is now `worker_id` and `claimed_at = now`. A
    /// claim older than `claim_ttl_ms` is reclaimable as if the
    /// prior worker had crashed.
    async fn claim_pending(
        &self,
        worker_id: &str,
        recipient: &AgentId,
        now: Timestamp,
        claim_ttl_ms: i64,
        limit: u32,
    ) -> Result<Vec<NotificationRecord>>;

    /// Transition a claimed row to `dispatched`. `Applied` iff the
    /// row exists, is owned by `claim_token`, and is currently
    /// `pending` (after-claim it stays `pending` until this method
    /// runs). `NoOp` for any mismatch — caller treats it as "another
    /// worker beat us" and moves on.
    async fn mark_dispatched(
        &self,
        id: &str,
        claim_token: &str,
        at: Timestamp,
    ) -> Result<TransitionOutcome>;

    /// Transition a claimed row to `failed` with a free-form reason
    /// the operator surfaces in `hermod doctor`. Same ownership
    /// rules as [`mark_dispatched`].
    async fn mark_failed(
        &self,
        id: &str,
        claim_token: &str,
        reason: &str,
    ) -> Result<TransitionOutcome>;

    /// Operator-driven dismissal: move any non-terminal row owned
    /// by `recipient` to `dismissed`. Returns `Applied` iff the row
    /// was live for that recipient, `NoOp` otherwise (so the IPC
    /// surface can return a clear "no such notification" error).
    async fn dismiss(&self, id: &str, recipient: &AgentId) -> Result<TransitionOutcome>;

    /// List notifications for `recipient`. Unfiltered by status when
    /// `statuses` is `None`. Newest first.
    async fn list(
        &self,
        recipient: &AgentId,
        statuses: Option<&[NotificationStatus]>,
        limit: u32,
    ) -> Result<Vec<NotificationRecord>>;

    /// Drop terminal-state rows (`dispatched`, `failed`, `dismissed`)
    /// whose `created_at` is older than `cutoff_ms`. Returns the row
    /// count for the operator's purge audit row.
    async fn purge_terminal_older_than(&self, cutoff_ms: i64) -> Result<u64>;

    /// Count rows in `pending` or `failed` state for `recipient` —
    /// the back-pressure metric `/metrics` exposes.
    async fn count_open_for(&self, recipient: &AgentId) -> Result<u64>;
}
