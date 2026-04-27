//! Persistent storage for Hermod.
//!
//! The crate exposes:
//!   * [`Database`] — backend-agnostic trait that the daemon depends on.
//!   * Per-collection repository traits in [`repositories`] —
//!     `AgentRepository`, `MessageRepository`, `AuditRepository`, etc.
//!   * Concrete backends in [`backends`] — `sqlite` (always) and
//!     `postgres` (behind the `postgres` cargo feature). Each
//!     implements the same `Database` trait surface; switching
//!     backends is one config-field change.
//!   * [`connect`] — URL-dispatched factory that returns
//!     `Arc<dyn Database>`; this is the daemon's only construction
//!     entrypoint. The backend is selected by URL scheme.
//!   * Records and value types alongside their trait (e.g.
//!     [`AgentRecord`] ships with [`AgentRepository`]).
//!
//! Daemon code consumes `Arc<dyn Database>` and never names a concrete
//! backend type. Backend selection is the operator's job, encoded in a
//! single config field (`[storage] url`).

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
pub use file_audit_sink::FileAuditSink;
pub use webhook_audit_sink::{WebhookAuditSink, WebhookAuditSinkConfig};
pub use blobs::{BlobError, BlobStore, LocalFsBlobStore, MemoryBlobStore, bucket};
pub use database::{Database, MetricsSnapshot};
pub use error::{Result, StorageError};
pub use hermod_core::CapabilityDirection;

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

/// Open the backend named by `url` and return it as the daemon's
/// single trait object. Dispatch is by URL scheme; adding a new
/// backend is one new arm in this `match` plus one new module under
/// [`backends`].
///
/// Supported schemes:
///
/// | scheme    | form                                                   |
/// | --------- | ------------------------------------------------------ |
/// | `sqlite`  | `sqlite:///abs/path/hermod.db`                         |
///
/// `signer` is consumed by audit-row signing on the SQLite backend
/// (and by any future backend that hash-chains audit rows). `blobs`
/// is the file-payload / audit-archive blob store, kept separate
/// because operators frequently want a different backend for blobs
/// (S3 / GCS) than for relational data.
pub async fn connect(
    url: &str,
    signer: Arc<dyn Signer>,
    blobs: Arc<dyn BlobStore>,
) -> Result<Arc<dyn Database>> {
    let parsed = url::Url::parse(url)
        .map_err(|e| StorageError::Backend(format!("parse storage url {url:?}: {e}")))?;
    match parsed.scheme() {
        "sqlite" => {
            // `sqlite:///abs/path` — empty host, absolute path.
            // Reject ambiguous forms early so a misconfigured DSN
            // surfaces as a clear error rather than a silently-wrong
            // file location.
            if parsed.host_str().is_some_and(|h| !h.is_empty()) {
                return Err(StorageError::Backend(format!(
                    "sqlite url has a host component {url:?} — use `sqlite:///abs/path` (three slashes)"
                )));
            }
            let path_str = parsed.path();
            if path_str.is_empty() || path_str == "/" {
                return Err(StorageError::Backend(format!(
                    "sqlite url missing path: {url:?}"
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
            // Pass the original URL through so sqlx parses
            // `?options=…&user=…&password=…&sslmode=…` natively.
            let db =
                backends::postgres::PostgresDatabase::connect(url, signer, blobs).await?;
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
mod connect_tests {
    use super::*;
    use hermod_crypto::{Keypair, LocalKeySigner};

    fn fake_signer() -> Arc<dyn Signer> {
        Arc::new(LocalKeySigner::new(Arc::new(Keypair::generate())))
    }

    fn fake_blobs() -> Arc<dyn BlobStore> {
        Arc::new(MemoryBlobStore::default())
    }

    #[tokio::test]
    async fn rejects_unparseable_url() {
        let err = connect("not a url", fake_signer(), fake_blobs())
            .await
            .unwrap_err();
        assert!(
            matches!(err, StorageError::Backend(ref s) if s.contains("parse storage url")),
            "want Backend('parse storage url …'), got {err:?}"
        );
    }

    #[tokio::test]
    async fn rejects_unsupported_scheme() {
        let err = connect(
            "mysql://localhost/hermod",
            fake_signer(),
            fake_blobs(),
        )
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
        // such a URL would silently drop it. We reject so the
        // operator's mistake surfaces immediately.
        let err = connect("sqlite://relative/path", fake_signer(), fake_blobs())
            .await
            .unwrap_err();
        assert!(
            matches!(err, StorageError::Backend(ref s) if s.contains("host component")),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn rejects_sqlite_with_no_path() {
        let err = connect("sqlite://", fake_signer(), fake_blobs())
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
        let url = format!("sqlite://{}", path.display());
        let db = connect(&url, fake_signer(), fake_blobs())
            .await
            .expect("open succeeds for valid sqlite url");
        // Trait method works → connection is real.
        db.ping().await.expect("ping succeeds");
        db.shutdown().await;
    }
}

