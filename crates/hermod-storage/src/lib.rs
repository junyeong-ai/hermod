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

use std::path::{Path, PathBuf};
use std::sync::Arc;

use hermod_crypto::Signer;

pub mod audit_archive;
pub mod audit_sink;
pub mod backends;
pub mod blobs;
pub mod database;
pub mod error;
pub mod file_audit_sink;
pub mod local_file;
pub mod repositories;
pub mod webhook_audit_sink;

// ── Public surface ──────────────────────────────────────────────────────

pub use audit_sink::{AuditSink, StorageAuditSink, TeeAuditSink};
#[cfg(feature = "gcs")]
pub use blobs::GcsBlobStore;
#[cfg(feature = "s3")]
pub use blobs::S3BlobStore;
pub use blobs::{
    BlobError, BlobStore, BlobStoreBackend, LocalFsBlobStore, MemoryBlobStore, bucket,
    classify_blob_dsn, local_files as blob_store_local_files, open as open_blob_store,
};
pub use database::{Database, DatabaseBackend, MetricsSnapshot};
pub use error::{Result, StorageError};
pub use file_audit_sink::FileAuditSink;
pub use hermod_core::CapabilityDirection;
pub use local_file::{LocalFile, LocalFileKind, LocalFilePresence};
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
pub use repositories::local_agents::{
    LocalAgentInsertOutcome, LocalAgentRecord, LocalAgentRemoveOutcome, LocalAgentRepository,
};
pub use repositories::messages::{
    InboxFilter, MessagePruneOutcome, MessageRecord, MessageRepository, TransitionOutcome,
};
pub use repositories::notifications::{
    EnqueueOutcome, EnqueueRequest, NotificationRecord, NotificationRepository,
};
pub use repositories::presence::{
    AgentPresenceRecord, AgentPresenceRepository, AttachOutcome, AttachParams, CursorAdvance,
    DetachOutcome, HEARTBEAT_INTERVAL_SECS, McpSession, McpSessionRepository, ObservedPresence,
    PEER_LIVE_TTL_SECS, PruneOutcome, SESSION_TTL_SECS, effective_status,
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
    match classify_database_dsn(dsn)? {
        DatabaseBackend::Sqlite => {
            let path = parse_sqlite_dsn_path(dsn)?;
            let db = backends::sqlite::SqliteDatabase::connect(&path, signer, blobs).await?;
            Ok(Arc::new(db))
        }
        DatabaseBackend::Postgres => {
            #[cfg(feature = "postgres")]
            {
                // Pass the original DSN through so sqlx parses
                // `?options=…&user=…&password=…&sslmode=…` natively.
                let db = backends::postgres::PostgresDatabase::connect(dsn, signer, blobs).await?;
                Ok(Arc::new(db))
            }
            #[cfg(not(feature = "postgres"))]
            {
                let _ = (signer, blobs);
                Err(StorageError::Backend(format!(
                    "postgres dsn {dsn:?} requires `--features postgres` at build time"
                )))
            }
        }
    }
}

/// Identify which relational backend a DSN selects without opening
/// it. Valid for any DSN that [`open_database`] would accept; returns
/// [`DatabaseBackend`] independent of which backend is compiled in.
///
/// Used by callers that need to branch on the backend before
/// construction (e.g. `home_layout` deciding which on-disk files
/// belong in the boot enforcement spec).
pub fn classify_database_dsn(dsn: &str) -> Result<DatabaseBackend> {
    let parsed = url::Url::parse(dsn)
        .map_err(|e| StorageError::Backend(format!("parse storage dsn {dsn:?}: {e}")))?;
    match parsed.scheme() {
        "sqlite" => Ok(DatabaseBackend::Sqlite),
        "postgres" | "postgresql" => Ok(DatabaseBackend::Postgres),
        other => Err(StorageError::Backend(format!(
            "unsupported storage scheme {other:?} (supported: sqlite, postgres, postgresql)"
        ))),
    }
}

/// Enumerate the on-disk files this DSN's backend writes under the
/// daemon's filesystem root. Resolved purely from the DSN — no
/// connection is opened. Returns the canonical paths and their
/// presence/kind so the daemon's `home_layout` can derive boot-time
/// enforcement and `hermod doctor` audit from one source.
///
/// Backend declarations:
///
/// - `sqlite`: `<db>` (Required) + `<db>-wal` + `<db>-shm` (both Optional).
///   The WAL/SHM companions are produced by appending the suffix to
///   the *full* db path (SQLite invariant — `path.with_extension`
///   would replace, not append).
/// - `postgres` / `postgresql`: empty Vec — Postgres holds no local
///   state under `$HERMOD_HOME`.
///
/// Errors only on a malformed or unsupported DSN; the daemon's
/// `open_database` will report the same error a moment later, so
/// callers that want to defer the failure can `unwrap_or_default()`
/// here without losing the diagnostic.
pub fn database_local_files(dsn: &str) -> Result<Vec<LocalFile>> {
    match classify_database_dsn(dsn)? {
        DatabaseBackend::Sqlite => {
            let db_path = parse_sqlite_dsn_path(dsn)?;
            let wal = append_path_suffix(&db_path, "-wal");
            let shm = append_path_suffix(&db_path, "-shm");
            Ok(vec![
                LocalFile::secret_required("hermod database", db_path),
                LocalFile::secret_optional("hermod database WAL", wal),
                LocalFile::secret_optional("hermod database SHM", shm),
            ])
        }
        DatabaseBackend::Postgres => Ok(Vec::new()),
    }
}

/// Extract the on-disk filesystem path from a `sqlite:` DSN.
/// Accepts the canonical `sqlite:///abs/path` form and
/// `sqlite:///abs/path?mode=rwc` (sqlx tolerates a query suffix).
/// Rejects relative-via-host (`sqlite://relative/path`) and missing
/// path forms — symmetric with [`open_database`]'s validation.
fn parse_sqlite_dsn_path(dsn: &str) -> Result<PathBuf> {
    let parsed = url::Url::parse(dsn)
        .map_err(|e| StorageError::Backend(format!("parse storage dsn {dsn:?}: {e}")))?;
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
    Ok(PathBuf::from(path_str))
}

/// Append a literal suffix to a path's full string form. Used for
/// SQLite's `-wal` / `-shm` companions, where the suffix attaches to
/// the *complete* db path (e.g. `hermod.db` → `hermod.db-wal`).
/// `Path::with_extension` would replace the extension instead.
fn append_path_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(suffix);
    PathBuf::from(s)
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
        // Instance-level backend identification matches the DSN-static
        // classification — the two answer the same question, one
        // before construction and one after.
        assert_eq!(db.backend(), DatabaseBackend::Sqlite);
        db.shutdown().await;
    }

    #[tokio::test]
    async fn blob_store_backend_methods_self_identify() {
        let mem = open_blob_store("memory://").await.unwrap();
        assert_eq!(mem.backend(), BlobStoreBackend::Memory);
        let dir = tempfile::tempdir().unwrap();
        let dsn = format!("file://{}", dir.path().display());
        let local = open_blob_store(&dsn).await.unwrap();
        assert_eq!(local.backend(), BlobStoreBackend::LocalFs);
    }
}

#[cfg(test)]
mod local_files_tests {
    use super::*;

    #[test]
    fn classifies_sqlite() {
        assert_eq!(
            classify_database_dsn("sqlite:////var/lib/hermod/hermod.db").unwrap(),
            DatabaseBackend::Sqlite
        );
    }

    #[test]
    fn classifies_postgres_both_schemes() {
        assert_eq!(
            classify_database_dsn("postgres://user@host/db").unwrap(),
            DatabaseBackend::Postgres
        );
        assert_eq!(
            classify_database_dsn("postgresql://user@host/db?sslmode=require").unwrap(),
            DatabaseBackend::Postgres
        );
    }

    #[test]
    fn classify_rejects_unknown_scheme() {
        let err = classify_database_dsn("mysql://host/db").unwrap_err();
        assert!(
            matches!(err, StorageError::Backend(ref s) if s.contains("unsupported storage scheme")),
            "got {err:?}"
        );
    }

    #[test]
    fn classify_blob_dsn_recognises_every_scheme() {
        assert_eq!(
            classify_blob_dsn("file:///var/lib/hermod/blob-store").unwrap(),
            BlobStoreBackend::LocalFs
        );
        assert_eq!(
            classify_blob_dsn("memory://").unwrap(),
            BlobStoreBackend::Memory
        );
        assert_eq!(
            classify_blob_dsn("gcs://bucket/prefix").unwrap(),
            BlobStoreBackend::Gcs
        );
        assert_eq!(
            classify_blob_dsn("s3://bucket/prefix").unwrap(),
            BlobStoreBackend::S3
        );
    }

    #[test]
    fn classify_blob_dsn_rejects_unknown_scheme() {
        let err = classify_blob_dsn("ftp://host/path").unwrap_err();
        assert!(matches!(err, BlobError::Backend(_)), "got {err:?}");
    }

    #[test]
    fn classify_rejects_unparseable() {
        assert!(classify_database_dsn("not a dsn").is_err());
    }

    #[test]
    fn database_local_files_sqlite_returns_triplet() {
        let files = database_local_files("sqlite:////var/lib/hermod/hermod.db").unwrap();
        let labels: Vec<&str> = files.iter().map(|f| f.label).collect();
        assert_eq!(
            labels,
            vec![
                "hermod database",
                "hermod database WAL",
                "hermod database SHM"
            ]
        );
        assert_eq!(files[0].path, PathBuf::from("/var/lib/hermod/hermod.db"));
        assert_eq!(
            files[1].path,
            PathBuf::from("/var/lib/hermod/hermod.db-wal")
        );
        assert_eq!(
            files[2].path,
            PathBuf::from("/var/lib/hermod/hermod.db-shm")
        );
        assert_eq!(files[0].kind, LocalFileKind::Secret);
        assert_eq!(files[0].presence, LocalFilePresence::Required);
        assert_eq!(files[1].presence, LocalFilePresence::Optional);
        assert_eq!(files[2].presence, LocalFilePresence::Optional);
    }

    #[test]
    fn database_local_files_postgres_is_empty() {
        assert!(
            database_local_files("postgres://user@host/db")
                .unwrap()
                .is_empty()
        );
        assert!(
            database_local_files("postgresql://user@host/db?sslmode=require")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn database_local_files_propagates_dsn_errors() {
        assert!(database_local_files("not a dsn").is_err());
        assert!(database_local_files("sqlite://").is_err());
        assert!(database_local_files("sqlite://relative/path").is_err());
        assert!(database_local_files("mysql://host/db").is_err());
    }

    #[test]
    fn database_local_files_accepts_query_suffix() {
        let files = database_local_files("sqlite:////tmp/x.db?mode=rwc").unwrap();
        assert_eq!(files[0].path, PathBuf::from("/tmp/x.db"));
        assert_eq!(files[1].path, PathBuf::from("/tmp/x.db-wal"));
    }

    #[test]
    fn blob_store_local_files_file_returns_root_dir() {
        let files = blob_store_local_files("file:///var/lib/hermod/blob-store").unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].label, "blob store directory");
        assert_eq!(files[0].kind, LocalFileKind::Directory);
        assert_eq!(files[0].presence, LocalFilePresence::Optional);
        assert_eq!(files[0].path, PathBuf::from("/var/lib/hermod/blob-store"));
    }

    #[test]
    fn blob_store_local_files_memory_is_empty() {
        assert!(blob_store_local_files("memory://").unwrap().is_empty());
    }

    #[cfg(feature = "gcs")]
    #[test]
    fn blob_store_local_files_gcs_is_empty() {
        assert!(
            blob_store_local_files("gcs://bucket/prefix")
                .unwrap()
                .is_empty()
        );
    }

    #[cfg(feature = "s3")]
    #[test]
    fn blob_store_local_files_s3_is_empty() {
        assert!(
            blob_store_local_files("s3://bucket/prefix")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn blob_store_local_files_rejects_unknown_scheme() {
        let err = blob_store_local_files("ftp://host/path").unwrap_err();
        assert!(matches!(err, BlobError::Backend(_)), "got {err:?}");
    }

    #[test]
    fn append_path_suffix_appends_not_replaces() {
        // Critical SQLite invariant: WAL/SHM are <db>-wal / <db>-shm,
        // NOT <db-without-extension>-wal.
        assert_eq!(
            append_path_suffix(Path::new("/var/lib/hermod/hermod.db"), "-wal"),
            PathBuf::from("/var/lib/hermod/hermod.db-wal")
        );
        assert_eq!(
            append_path_suffix(Path::new("/tmp/no-extension"), "-wal"),
            PathBuf::from("/tmp/no-extension-wal")
        );
    }
}
