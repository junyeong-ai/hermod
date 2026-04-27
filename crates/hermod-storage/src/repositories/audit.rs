//! Hash-chained, signed audit log contract.

use async_trait::async_trait;
use hermod_core::{AgentId, Timestamp};
use serde_json::Value as JsonValue;

use crate::blobs::BlobStore;
use crate::error::Result;

/// Whether this audit row is eligible for outbound federation
/// (`RemoteAuditSink`). Decided by the emitter; downstream sinks honour
/// it without re-deriving from the action string. `Default` is the
/// common case — emit through every sink. `Skip` marks rows that would
/// trigger federation feedback loops (the federation envelope's own
/// `message.sent`, the aggregator-side `audit.federate.*` echo) or
/// rows whose semantics are local-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditFederationPolicy {
    Default,
    Skip,
}

#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub id: Option<i64>,
    pub ts: Timestamp,
    pub actor: AgentId,
    pub action: String,
    pub target: Option<String>,
    pub details: Option<JsonValue>,
    pub federation: AuditFederationPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainVerification {
    Ok { rows: u64 },
    BrokenLink { row_id: i64 },
    HashMismatch { row_id: i64 },
    BadSignature { row_id: i64 },
}

#[derive(Debug, Clone)]
pub struct ArchiveSummary {
    pub epoch_start_ms: i64,
    pub epoch_end_ms: i64,
    pub blob_location: String,
    pub row_count: u64,
    pub file_size: u64,
    pub deleted_rows: u64,
}

#[derive(Debug, Clone)]
pub struct ArchiveIndexEntry {
    pub epoch_start_ms: i64,
    pub epoch_end_ms: i64,
    pub row_count: u64,
    pub file_size: u64,
    pub blob_location: String,
    pub archived_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArchiveVerification {
    Ok { rows: u64 },
    IndexMissing,
    BlobMissing { blob_location: String },
    ParseError,
    SigInvalid,
    ManifestMismatch,
    BrokenLink { row_id: i64 },
    HashMismatch { row_id: i64 },
}

#[async_trait]
pub trait AuditRepository: Send + Sync + std::fmt::Debug {
    /// Append a new entry. Hash-chains under the daemon keypair and
    /// returns the new row id. Concurrent appends serialize through the
    /// backend's strongest isolation; the chain link is always taken
    /// against the most recent row.
    async fn append(&self, entry: &AuditEntry) -> Result<i64>;

    async fn query(
        &self,
        actor: Option<&AgentId>,
        action: Option<&str>,
        since: Option<Timestamp>,
        limit: u32,
    ) -> Result<Vec<AuditEntry>>;

    /// Walk every row in id order and verify each chained link, hash, and
    /// signature.
    async fn verify_chain(&self) -> Result<ChainVerification>;

    /// Archive every row in `[epoch_start_ms, epoch_end_ms)` into a
    /// gzip-compressed JSONL blob, index the archive, then DELETE the
    /// archived rows. Whole sequence is atomic — a crash mid-archive
    /// either leaves all rows live or all archived.
    async fn archive_day(
        &self,
        blobs: &dyn BlobStore,
        epoch_start_ms: i64,
        epoch_end_ms: i64,
    ) -> Result<Option<ArchiveSummary>>;

    async fn list_archives(&self, limit: u32) -> Result<Vec<ArchiveIndexEntry>>;

    /// Verify a previously-archived day: fetch blob, parse manifest,
    /// re-verify manifest signature, walk inner row chain, confirm
    /// manifest's first/last hashes match file content.
    async fn verify_archive(
        &self,
        blobs: &dyn BlobStore,
        epoch_start_ms: i64,
    ) -> Result<ArchiveVerification>;

    /// Earliest `ts` in the live audit_log, or `None` if empty.
    /// Used by services that need to know whether a retention window is
    /// already enforced without the daemon depending on raw SQL.
    async fn earliest_ts(&self) -> Result<Option<i64>>;
}
