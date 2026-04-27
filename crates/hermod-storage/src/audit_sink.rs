//! Audit emission abstraction.
//!
//! Services emit audit rows through a [`AuditSink`] rather than calling
//! the [`AuditRepository`] directly. The default `StorageAuditSink`
//! writes to the local hash-chained log; composable backends like
//! `TeeAuditSink` mirror to additional destinations (Kafka, OpenTelemetry,
//! a remote Hermod's `audit.federate.ingest` RPC) without touching every
//! service callsite.
//!
//! `record` is best-effort by design — a sink failure must not break the
//! action being audited (we don't want a Kafka outage to refuse a
//! legitimate `peer.add`). Failed sinks log a warning under the audit
//! action's name and keep going.

use async_trait::async_trait;
use std::sync::Arc;
use tracing::warn;

use crate::Database;
use crate::repositories::audit::AuditEntry;

/// Best-effort audit sink. Implementations MUST NOT propagate errors —
/// an audit emission failure is a side-effect of the action being
/// audited, not a precondition. Persistent failures are surfaced via
/// `tracing::warn` so an SRE can detect them in logs.
#[async_trait]
pub trait AuditSink: Send + Sync + std::fmt::Debug + 'static {
    /// Record an audit entry. Best-effort. Always returns; never errors.
    async fn record(&self, entry: AuditEntry);
}

/// Default sink: persists into the local hash-chained `audit_log` via
/// the storage backend. Failures are logged as warnings under the
/// action name so a recurring drop is visible without forcing every
/// service to know about audit transport.
#[derive(Clone)]
pub struct StorageAuditSink {
    db: Arc<dyn Database>,
}

impl std::fmt::Debug for StorageAuditSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StorageAuditSink").finish_non_exhaustive()
    }
}

impl StorageAuditSink {
    pub fn new(db: Arc<dyn Database>) -> Self {
        Self { db }
    }
}

#[async_trait]
impl AuditSink for StorageAuditSink {
    async fn record(&self, entry: AuditEntry) {
        let action = entry.action.clone();
        // The single legitimate `AuditRepository::append` call site —
        // every service goes through this seam (enforced by clippy.toml).
        #[allow(clippy::disallowed_methods)]
        if let Err(e) = self.db.audit().append(&entry).await {
            warn!(action = %action, error = %e, "audit append failed (best-effort)");
        }
    }
}

/// Composite sink that fans out every record to multiple downstream
/// sinks. Used when an operator wants the local hash-chained log AND
/// a Kafka mirror (or OTel span, or remote ingest). Each sink runs
/// sequentially in order — switch to a parallel join in the impl if
/// any sink ever blocks long enough that it matters.
pub struct TeeAuditSink {
    sinks: Vec<Arc<dyn AuditSink>>,
}

impl std::fmt::Debug for TeeAuditSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TeeAuditSink")
            .field("sinks", &self.sinks.len())
            .finish()
    }
}

impl TeeAuditSink {
    pub fn new(sinks: Vec<Arc<dyn AuditSink>>) -> Self {
        Self { sinks }
    }
}

#[async_trait]
impl AuditSink for TeeAuditSink {
    async fn record(&self, entry: AuditEntry) {
        for sink in &self.sinks {
            sink.record(entry.clone()).await;
        }
    }
}
