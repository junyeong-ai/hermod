//! Message store contract — inbox, outbox, and File-blob metadata.

use async_trait::async_trait;
use hermod_core::{
    AgentId, Envelope, MessageBody, MessageId, MessageKind, MessagePriority, MessageStatus,
    Timestamp,
};

use crate::error::Result;

/// Result of a state-machine transition. `Applied` means the row was in
/// the expected starting state and the new state has been persisted.
/// `NoOp` means the row was either missing or already past the starting
/// state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionOutcome {
    Applied,
    NoOp,
}

impl TransitionOutcome {
    pub fn applied(self) -> bool {
        matches!(self, TransitionOutcome::Applied)
    }
}

#[derive(Debug, Clone)]
pub struct MessageRecord {
    pub id: MessageId,
    pub thread_id: Option<MessageId>,
    pub from_agent: AgentId,
    pub to_agent: AgentId,
    pub kind: MessageKind,
    pub priority: MessagePriority,
    pub body: MessageBody,
    /// Full signed envelope as canonical CBOR — used for outbox replay
    /// and peer forwarding without re-signing.
    pub envelope_cbor: Vec<u8>,
    pub status: MessageStatus,
    pub created_at: Timestamp,
    pub delivered_at: Option<Timestamp>,
    pub read_at: Option<Timestamp>,
    pub expires_at: Option<Timestamp>,
    pub attempts: u32,
    pub next_attempt_at: Option<Timestamp>,
    /// BlobStore opaque location for `MessageBody::File` payloads.
    pub file_blob_location: Option<String>,
    /// File payload size in bytes, decoded from the body_json metadata
    /// projection. `None` for non-File rows.
    pub file_size: Option<u64>,
    /// Resolved delivery endpoint string (e.g. `wss://host:port`)
    /// captured by the router at send time. The outbox replays
    /// straight to this endpoint, so a recipient with no
    /// `agents.endpoint` of their own (brokered case) and a recipient
    /// with one (standard remote case) share one retry mechanism.
    /// `None` for loopback / local-known destinations.
    pub delivery_endpoint: Option<String>,
}

impl MessageRecord {
    /// Build a record from a signed envelope.
    pub fn from_envelope(env: &Envelope, envelope_cbor: Vec<u8>, status: MessageStatus) -> Self {
        let expires_at =
            Timestamp::from_unix_ms(env.ts.unix_ms() + (env.ttl_secs as i64) * 1000).ok();
        Self {
            id: env.id,
            thread_id: env.thread,
            from_agent: env.from.id.clone(),
            to_agent: env.to.id.clone(),
            kind: env.kind,
            priority: env.priority,
            body: env.body.clone(),
            envelope_cbor,
            status,
            created_at: env.ts,
            delivered_at: None,
            read_at: None,
            expires_at,
            attempts: 0,
            next_attempt_at: None,
            file_blob_location: None,
            file_size: if let MessageBody::File { data, .. } = &env.body {
                Some(data.len() as u64)
            } else {
                None
            },
            delivery_endpoint: None,
        }
    }

    /// Attach a BlobStore location for File-kind records.
    pub fn with_file_blob_location(mut self, location: String) -> Self {
        self.file_blob_location = Some(location);
        self
    }
}

#[derive(Debug, Clone, Default)]
pub struct InboxFilter {
    pub statuses: Option<Vec<MessageStatus>>,
    pub priority_min: Option<MessagePriority>,
    pub limit: Option<u32>,
    pub after_id: Option<MessageId>,
}

/// Side-effect summary of a `messages` prune call. `rows` is how many
/// rows the statement deleted; `blob_locations` is the subset of
/// deleted rows that referenced a `BlobStore` payload.
#[derive(Debug, Default, Clone)]
pub struct MessagePruneOutcome {
    pub rows: u64,
    pub blob_locations: Vec<String>,
}

#[async_trait]
pub trait MessageRepository: Send + Sync + std::fmt::Debug {
    async fn enqueue(&self, record: &MessageRecord) -> Result<()>;

    /// Atomically claim a batch of pending remote-recipient messages for
    /// `worker_id`. Concurrent workers serialize through the backend
    /// without corruption. Every returned record has
    /// `delivery_endpoint = Some(_)` — the SELECT filter guarantees it.
    async fn claim_pending_remote(
        &self,
        worker_id: &str,
        now: Timestamp,
        claim_ttl_ms: i64,
        limit: u32,
    ) -> Result<Vec<MessageRecord>>;

    /// Drop the claim ownership without touching status. Used after a
    /// failed delivery attempt so another worker can pick the row up.
    async fn release_claim(&self, id: &MessageId) -> Result<()>;

    async fn record_send_attempt(
        &self,
        id: &MessageId,
        attempts: u32,
        next_attempt_at: Option<Timestamp>,
    ) -> Result<()>;

    /// Move a `pending` or `delivered` row to `failed`. Refuses to overwrite
    /// terminal rows (`read`, `failed`).
    async fn try_fail_pending_or_delivered(&self, id: &MessageId) -> Result<TransitionOutcome>;

    /// Mark every pending / delivered row addressed to `recipient` as `failed`.
    /// Used when the operator forgets a peer.
    async fn fail_pending_to(&self, recipient: &AgentId) -> Result<u64>;

    /// Drop messages whose `expires_at` has elapsed regardless of status.
    async fn prune_expired(&self, now_ms: i64) -> Result<MessagePruneOutcome>;

    /// Drop terminal-state messages older than `cutoff_ms`.
    async fn prune_terminal_older_than(&self, cutoff_ms: i64) -> Result<MessagePruneOutcome>;

    /// Stamp `delivered_at` and flip a `pending` row to `delivered`.
    /// Refuses to overwrite later states.
    async fn try_deliver_pending(
        &self,
        id: &MessageId,
        at: Timestamp,
    ) -> Result<TransitionOutcome>;

    async fn get(&self, id: &MessageId) -> Result<Option<MessageRecord>>;

    async fn list_inbox(
        &self,
        to: &AgentId,
        filter: &InboxFilter,
    ) -> Result<Vec<MessageRecord>>;

    /// Mark as read. Returns true if a row was affected.
    async fn ack(&self, id: &MessageId, recipient: &AgentId, at: Timestamp) -> Result<bool>;

    async fn count_pending_to(&self, to: &AgentId) -> Result<i64>;
}
