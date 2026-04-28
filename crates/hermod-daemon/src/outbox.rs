//! Outbox retry worker.
//!
//! Polls `messages` for pending remotely-addressed envelopes and re-attempts
//! delivery via `RemoteDeliverer`. Backs off exponentially on failure and gives up
//! at `MAX_ATTEMPTS`, marking the message `failed`.
//!
//! ## Concurrent workers
//!
//! Each worker generates a unique `worker_id` (ULID) at startup and uses
//! [`hermod_storage::MessageRepository::claim_pending_remote`] to
//! atomically grab a batch of rows. SQLite's IMMEDIATE transaction
//! inside that call serialises the SELECT-then-UPDATE so two workers
//! never deliver the same row. [`CLAIM_TTL`] caps how long a claim is
//! honoured: a worker that crashed mid-batch leaves rows owned for at
//! most that long before another worker picks them back up.

use hermod_core::{Endpoint, Timestamp};
use hermod_protocol::envelope::deserialize_envelope;
use hermod_routing::RemoteDeliverer;
use hermod_routing::remote::DeliveryOutcome;
use hermod_storage::{AuditEntry, AuditSink, Database};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Notify, oneshot};
use tracing::{debug, error, info, warn};
use ulid::Ulid;

/// Maximum delivery attempts before marking failed.
pub const MAX_ATTEMPTS: u32 = 5;

/// Maximum staleness of an outbox claim before it's reclaimable. Bounded
/// above the longest single-attempt cost (TLS+Noise dial timeout +
/// ack timeout + handler scheduling) so a healthy worker never has its
/// own claims stolen mid-batch.
const CLAIM_TTL: Duration = Duration::from_secs(120);

/// Backoff schedule (seconds) by attempt count: 1s, 5s, 15s, 60s, 300s.
fn backoff_secs(attempt: u32) -> u64 {
    match attempt {
        0 | 1 => 1,
        2 => 5,
        3 => 15,
        4 => 60,
        _ => 300,
    }
}

/// Wakeup signal handed to the outbox worker. `MessageService::send` fires it
/// after enqueueing a Pending envelope so the worker drains immediately
/// instead of waiting for the safety-backstop tick.
#[derive(Clone, Debug, Default)]
pub struct OutboxNotifier(Arc<Notify>);

impl OutboxNotifier {
    pub fn new() -> Self {
        Self(Arc::new(Notify::new()))
    }

    /// Wake the worker. If no worker is parked, the signal is held (Notify
    /// permits coalesce: one notify wakes one waiter, multiple notifies
    /// before a wait still wake at most once).
    pub fn wake(&self) {
        self.0.notify_one();
    }

    /// Wait for the next wake. Held by the worker in its select arm.
    pub async fn wait(&self) {
        self.0.notified().await;
    }
}

#[derive(Clone)]
pub struct OutboxWorker {
    db: Arc<dyn Database>,
    audit_sink: Arc<dyn AuditSink>,
    remote: RemoteDeliverer,
    /// Safety backstop: drain even if no notify came in. 30s — long enough that
    /// it doesn't dominate CPU on idle daemons, short enough that a missed
    /// notify can't strand a Pending message for long.
    backstop_interval: Duration,
    batch_size: u32,
    notifier: OutboxNotifier,
    /// Per-process worker identifier. Persisted on each claimed row so
    /// the row's `claim_token` column tells operators which daemon /
    /// process is currently responsible for the delivery attempt.
    worker_id: String,
}

impl std::fmt::Debug for OutboxWorker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboxWorker")
            .field("backstop_interval_ms", &self.backstop_interval.as_millis())
            .field("batch_size", &self.batch_size)
            .field("worker_id", &self.worker_id)
            .finish_non_exhaustive()
    }
}

impl OutboxWorker {
    pub fn new(
        db: Arc<dyn Database>,
        audit_sink: Arc<dyn AuditSink>,
        remote: RemoteDeliverer,
        notifier: OutboxNotifier,
    ) -> Self {
        Self {
            db,
            audit_sink,
            remote,
            backstop_interval: Duration::from_secs(30),
            batch_size: 32,
            notifier,
            worker_id: Ulid::new().to_string(),
        }
    }

    pub async fn run(self, mut shutdown: oneshot::Receiver<()>) {
        let mut ticker = tokio::time::interval(self.backstop_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        info!(?self, "outbox worker started (event-driven + backstop)");
        loop {
            tokio::select! {
                _ = &mut shutdown => {
                    info!("outbox worker shutting down");
                    break;
                }
                _ = self.notifier.wait() => {
                    if let Err(e) = self.process_batch().await {
                        warn!(error = %e, "outbox batch error (notify)");
                    }
                }
                _ = ticker.tick() => {
                    if let Err(e) = self.process_batch().await {
                        warn!(error = %e, "outbox batch error (backstop)");
                    }
                }
            }
        }
    }

    /// Mark a message permanently failed and audit the transition. Audit
    /// row carries the reason so an operator querying `audit query --action
    /// message.failed` gets actionable signal: which message, who it was
    /// for, and why we gave up.
    ///
    /// Only audits when the status row actually transitioned. A NoOp means
    /// the row was already terminal — re-auditing would fork the operator's
    /// view of "what failed".
    async fn fail(&self, msg: &hermod_storage::MessageRecord, reason: &str, detail: &str) {
        let transitioned = match self
            .db
            .messages()
            .try_fail_pending_or_delivered(&msg.id)
            .await
        {
            Ok(o) if o.applied() => true,
            Ok(_) => {
                debug!(id = %msg.id, "fail() no-op: row already terminal");
                false
            }
            Err(e) => {
                warn!(id = %msg.id, error = %e, "fail() try_fail error");
                false
            }
        };
        if !transitioned {
            return;
        }
        crate::services::audit_or_warn(
            &*self.audit_sink,
            AuditEntry {
                id: None,
                ts: Timestamp::now(),
                actor: msg.from_agent.clone(),
                action: "message.failed".into(),
                target: Some(msg.to_agent.to_string()),
                details: Some(serde_json::json!({
                    "id": msg.id.to_string(),
                    "reason": reason,
                    "detail": detail,
                    "attempts": msg.attempts,
                })),
                federation: hermod_storage::AuditFederationPolicy::Default,
            },
        )
        .await;
    }

    #[tracing::instrument(name = "outbox.batch", skip(self))]
    async fn process_batch(&self) -> anyhow::Result<()> {
        let now = Timestamp::now();
        let candidates = self
            .db
            .messages()
            .claim_pending_remote(
                &self.worker_id,
                now,
                CLAIM_TTL.as_millis() as i64,
                self.batch_size,
            )
            .await?;
        if candidates.is_empty() {
            return Ok(());
        }
        debug!(n = candidates.len(), worker = %self.worker_id, "outbox batch claimed");

        // Backpressure / fan-out: deliveries to *different* peers run
        // concurrently, so a slow peer can no longer stall the whole
        // batch. Deliveries to the *same* peer naturally serialise on
        // the per-peer mutex inside `RemoteDeliverer`, preserving wire
        // ordering. We `join_all` to wait for the batch to drain before
        // claiming the next batch — this caps in-flight work per worker
        // at `batch_size` and avoids unbounded task accumulation.
        let mut tasks = Vec::with_capacity(candidates.len());
        for msg in candidates {
            let me = self.clone();
            tasks.push(tokio::spawn(async move {
                me.process_one(msg).await;
            }));
        }
        for t in tasks {
            // Task panics are logged but don't propagate — the message
            // stays claimed and the CLAIM_TTL janitor reclaims it.
            if let Err(e) = t.await
                && !e.is_cancelled()
            {
                warn!(error = %e, "outbox per-message task panicked");
            }
        }
        Ok(())
    }

    /// Single-message delivery + bookkeeping. Lifted out of `process_batch`
    /// so per-peer fan-out can run multiple of these in parallel — peers
    /// that don't share an endpoint don't share a per-peer mutex inside
    /// `RemoteDeliverer` either, so the only point of contention is the
    /// SQLite write path (already serialised by the WAL).
    async fn process_one(&self, msg: hermod_storage::MessageRecord) {
        // `claim_pending_remote` filters `delivery_endpoint IS NOT NULL`,
        // so this `expect` is structurally guaranteed — a None here
        // means the storage backend lied about its filter, which is a
        // bug we want loud, not a silent skip.
        let endpoint_str = msg
            .delivery_endpoint
            .as_deref()
            .expect("claim_pending_remote returns rows with delivery_endpoint Some");
        let endpoint = match Endpoint::from_str(endpoint_str) {
            Ok(ep) => ep,
            Err(e) => {
                error!(id = %msg.id, error = %e, "invalid endpoint; marking failed");
                self.fail(&msg, "invalid_endpoint", &e.to_string()).await;
                return;
            }
        };

        let envelope = match deserialize_envelope(&msg.envelope_cbor) {
            Ok(e) => e,
            Err(err) => {
                error!(id = %msg.id, error = %err, "envelope CBOR corrupt; marking failed");
                self.fail(&msg, "cbor_corrupt", &err.to_string()).await;
                return;
            }
        };

        let attempt_n = msg.attempts.saturating_add(1);
        match self.remote.deliver(&envelope, &endpoint).await {
            Ok(DeliveryOutcome::Delivered) => {
                debug!(id = %msg.id, attempt = attempt_n, "outbox delivered");
                if let Err(e) = self
                    .db
                    .messages()
                    .try_deliver_pending(&msg.id, Timestamp::now())
                    .await
                {
                    warn!(id = %msg.id, error = %e, "try_deliver_pending failed");
                }
            }
            Ok(DeliveryOutcome::Rejected) => {
                error!(id = %msg.id, "remote rejected; marking failed");
                self.fail(&msg, "remote_rejected", "remote refused delivery")
                    .await;
            }
            Ok(DeliveryOutcome::Deferred) | Err(_) if attempt_n >= MAX_ATTEMPTS => {
                error!(
                    id = %msg.id,
                    attempts = attempt_n,
                    "exhausted retries; marking failed — message lost"
                );
                self.fail(
                    &msg,
                    "exhausted_retries",
                    &format!("after {attempt_n} attempts"),
                )
                .await;
            }
            Ok(DeliveryOutcome::Deferred) => {
                let next = next_attempt(attempt_n);
                debug!(id = %msg.id, attempt = attempt_n, "deferred, retrying later");
                if let Err(e) = self
                    .db
                    .messages()
                    .record_send_attempt(&msg.id, attempt_n, Some(next))
                    .await
                {
                    warn!(id = %msg.id, error = %e, "record_send_attempt failed");
                }
                self.release(&msg.id).await;
            }
            Err(e) => {
                let next = next_attempt(attempt_n);
                debug!(id = %msg.id, attempt = attempt_n, error = %e, "transient error");
                if let Err(e) = self
                    .db
                    .messages()
                    .record_send_attempt(&msg.id, attempt_n, Some(next))
                    .await
                {
                    warn!(id = %msg.id, error = %e, "record_send_attempt failed");
                }
                self.release(&msg.id).await;
            }
        }
    }

    /// Release the claim on a row that's heading back into the pending
    /// pool. Failure is logged and ignored — the claim TTL guarantees
    /// another worker can pick the row up regardless.
    async fn release(&self, id: &hermod_core::MessageId) {
        if let Err(e) = self.db.messages().release_claim(id).await {
            debug!(id = %id, error = %e, "release_claim failed");
        }
    }
}

fn next_attempt(attempt: u32) -> Timestamp {
    let secs = backoff_secs(attempt);
    Timestamp::now().offset_by_ms((secs as i64) * 1000)
}
