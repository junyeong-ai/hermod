//! Persistent storage for Hermod.
//!
//! Two trait families, each with a DSN-dispatched factory at the
//! crate root — same shape on both sides so operators see one
//! consistent mental model:
//!
//! | Layer       | Trait        | Factory               | Config field    |
//! | ----------- | ------------ | --------------------- | --------------- |
//! | Relational  | [`Database`] | [`open_database`]     | `[storage] dsn` |
//! | Blob        | [`BlobStore`]| [`open_blob_store`]   | `[blob] dsn`    |
//!
//! The crate exposes:
//!   * [`Database`] — backend-agnostic trait that the daemon depends
//!     on. Concrete backends in [`backends`]: `sqlite` (always) and
//!     `postgres` (`--features postgres`).
//!   * [`BlobStore`] — backend-agnostic trait for opaque binary
//!     payloads. Concrete backends in [`blobs`]: `local_fs` and
//!     `memory` always; `gcs` (`--features gcs`) and `s3`
//!     (`--features s3`) for cloud object stores.
//!   * Per-collection repository traits in [`repositories`] —
//!     `AgentRepository`, `MessageRepository`, `AuditRepository`, etc.
//!   * Records and value types alongside their trait (e.g.
//!     [`AgentRecord`] ships with [`AgentRepository`]).
//!
//! Daemon code consumes `Arc<dyn Database>` and `Arc<dyn BlobStore>`
//! — never the concrete backend types. Backend selection is the
//! operator's job, encoded in the two `dsn` fields.

use std::path::PathBuf;
use std::sync::Arc;

use hermod_crypto::Signer;

pub mod audit_archive;
pub mod audit_sink;
pub mod backends;
pub mod blobs;
pub mod database;
pub mod error;
pub mod file_audit_sink;
pub mod repositories;
pub mod webhook_audit_sink;

// ── Public surface ──────────────────────────────────────────────────────

pub use audit_sink::{AuditSink, StorageAuditSink, TeeAuditSink};
#[cfg(feature = "gcs")]
pub use blobs::GcsBlobStore;
#[cfg(feature = "s3")]
pub use blobs::S3BlobStore;
pub use blobs::{
    BlobError, BlobStore, LocalFsBlobStore, MemoryBlobStore, bucket, open as open_blob_store,
};
pub use database::{Database, MetricsSnapshot};
pub use error::{Result, StorageError};
pub use file_audit_sink::FileAuditSink;
pub use hermod_core::CapabilityDirection;
pub use webhook_audit_sink::{WebhookAuditSink, WebhookAuditSinkConfig};

// Repository traits and their value types — re-exported flat for ergonomic
// single-import callers (`use hermod_storage::AgentRecord`).
pub use repositories::agents::{
    AgentRecord, AgentRepository, AliasOutcome, ForgetOutcome, RepinOutcome,
};
pub use repositories::audit::{
    ArchiveIndexEntry, ArchiveSummary, ArchiveVerification, AuditEntry, AuditFederationPolicy,
    AuditRepository, ChainVerification,
};
pub use repositories::briefs::{BriefRecord, BriefRepository};
pub use repositories::capabilities::{CapabilityFilter, CapabilityRecord, CapabilityRepository};
pub use repositories::confirmations::{
    ConfirmationRepository, ConfirmationStatus, HoldRequest, HoldedIntent, MAX_PENDING_PER_ACTOR,
    PendingConfirmation,
};
pub use repositories::messages::{
    InboxFilter, MessagePruneOutcome, MessageRecord, MessageRepository, TransitionOutcome,
};
pub use repositories::presence::{
    AgentPresenceRecord, AgentPresenceRepository, DetachOutcome, HEARTBEAT_INTERVAL_SECS,
    McpSession, McpSessionRepository, ObservedPresence, PEER_LIVE_TTL_SECS, PruneOutcome,
    SESSION_TTL_SECS, effective_status,
};
pub use repositories::rate_limit::RateLimitRepository;
pub use repositories::workspaces::{
    ChannelMessage, ChannelRecord, ChannelRepository, DiscoveredChannel,
    DiscoveredChannelRepository, WorkspaceMemberRepository, WorkspaceRecord, WorkspaceRepository,
};

/// Open the backend named by `dsn` and return it as the daemon's
/// single trait object. Dispatch is by DSN scheme; adding a new
/// backend is one new arm in this `match` plus one new module under
/// [`backends`]. Mirrors [`blobs::open`] for the blob layer — both
/// follow the same DSN-dispatch convention so operators see one
/// consistent shape across `[storage] dsn` and `[blob] dsn`.
///
/// Supported schemes:
///
/// | scheme       | form                                              | enabled by             |
/// | ------------ | ------------------------------------------------- | ---------------------- |
/// | `sqlite`     | `sqlite:///abs/path/hermod.db`                    | always                 |
/// | `postgresql` | `postgresql://user:pass@host:5432/db?sslmode=...` | `--features postgres`  |
///
/// `signer` is consumed by audit-row signing on the SQLite backend
/// (and by any future backend that hash-chains audit rows). `blobs`
/// is the file-payload / audit-archive blob store, kept separate
/// because operators frequently want a different backend for blobs
/// (S3 / GCS) than for relational data.
pub async fn open_database(
    dsn: &str,
    signer: Arc<dyn Signer>,
    blobs: Arc<dyn BlobStore>,
) -> Result<Arc<dyn Database>> {
    let parsed = url::Url::parse(dsn)
        .map_err(|e| StorageError::Backend(format!("parse storage dsn {dsn:?}: {e}")))?;
    match parsed.scheme() {
        "sqlite" => {
            // `sqlite:///abs/path` — empty host, absolute path.
            // Reject ambiguous forms early so a misconfigured DSN
            // surfaces as a clear error rather than a silently-wrong
            // file location.
            if parsed.host_str().is_some_and(|h| !h.is_empty()) {
                return Err(StorageError::Backend(format!(
                    "sqlite dsn has a host component {dsn:?} — use `sqlite:///abs/path` (three slashes)"
                )));
            }
            let path_str = parsed.path();
            if path_str.is_empty() || path_str == "/" {
                return Err(StorageError::Backend(format!(
                    "sqlite dsn missing path: {dsn:?}"
                )));
            }
            let path = PathBuf::from(path_str);
            let db = backends::sqlite::SqliteDatabase::connect(&path, signer, blobs).await?;
            Ok(Arc::new(db))
        }
        #[cfg(feature = "postgres")]
        "postgres" | "postgresql" => {
            // Full Database trait implemented — see
            // `crate::backends::postgres` for dialect-parity notes.
            // Pass the original DSN through so sqlx parses
            // `?options=…&user=…&password=…&sslmode=…` natively.
            let db = backends::postgres::PostgresDatabase::connect(dsn, signer, blobs).await?;
            Ok(Arc::new(db))
        }
        other => Err(StorageError::Backend(format!(
            "unsupported storage scheme {other:?} (supported: sqlite{})",
            if cfg!(feature = "postgres") {
                ", postgres"
            } else {
                ""
            }
        ))),
    }
}

#[cfg(test)]
mod open_database_tests {
    use super::*;
    use hermod_crypto::{Keypair, LocalKeySigner};

    fn fake_signer() -> Arc<dyn Signer> {
        Arc::new(LocalKeySigner::new(Arc::new(Keypair::generate())))
    }

    fn fake_blobs() -> Arc<dyn BlobStore> {
        Arc::new(MemoryBlobStore::new())
    }

    #[tokio::test]
    async fn rejects_unparseable_dsn() {
        let err = open_database("not a dsn", fake_signer(), fake_blobs())
            .await
            .unwrap_err();
        assert!(
            matches!(err, StorageError::Backend(ref s) if s.contains("parse storage dsn")),
            "want Backend('parse storage dsn …'), got {err:?}"
        );
    }

    #[tokio::test]
    async fn rejects_unsupported_scheme() {
        let err = open_database("mysql://localhost/hermod", fake_signer(), fake_blobs())
            .await
            .unwrap_err();
        assert!(
            matches!(err, StorageError::Backend(ref s) if s.contains("unsupported storage scheme")),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn rejects_sqlite_with_host_component() {
        // `sqlite://relative/path` — `relative` parses as a host;
        // such a DSN would silently drop it. We reject so the
        // operator's mistake surfaces immediately.
        let err = open_database("sqlite://relative/path", fake_signer(), fake_blobs())
            .await
            .unwrap_err();
        assert!(
            matches!(err, StorageError::Backend(ref s) if s.contains("host component")),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn rejects_sqlite_with_no_path() {
        let err = open_database("sqlite://", fake_signer(), fake_blobs())
            .await
            .unwrap_err();
        assert!(
            matches!(err, StorageError::Backend(ref s) if s.contains("missing path")),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn opens_sqlite_with_absolute_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hermod.db");
        let dsn = format!("sqlite://{}", path.display());
        let db = open_database(&dsn, fake_signer(), fake_blobs())
            .await
            .expect("open succeeds for valid sqlite dsn");
        // Trait method works → connection is real.
        db.ping().await.expect("ping succeeds");
        db.shutdown().await;
    }
}
