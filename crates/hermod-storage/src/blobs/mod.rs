//! Pluggable content storage for binary payloads.
//!
//! Hermod stores two kinds of opaque binary content outside the SQLite
//! metadata tables: file-message payloads (1 MiB cap, surfaced to the
//! operator's MCP host) and audit-log archive files (gzip-compressed
//! JSONL day-buckets). Both are append-only, content-addressed, and
//! large enough that interleaving them with metadata rows would bloat
//! the messages / audit_log tables.
//!
//! The [`BlobStore`] trait is shaped to S3-style semantics so any
//! cloud object store (S3, GCS, Azure Blob, MinIO, R2, …) plugs in by
//! implementing three methods. The default backend is
//! [`LocalFsBlobStore`] (mode-0700 directory under `$HERMOD_HOME`); a
//! [`MemoryBlobStore`] is provided for tests.
//!
//! ## Locations are opaque
//!
//! `put` returns a backend-chosen string; `get` and `delete` accept
//! the same string back. Metadata tables persist these strings
//! verbatim. The trait NEVER exposes "this is a path" vs "this is an
//! s3:// url" upward — adding a new backend requires no change in
//! callers.
//!
//! ## Buckets
//!
//! A `bucket` is a logical namespace inside the store
//! ([`bucket::FILES`], [`bucket::AUDIT_ARCHIVE`]). Backends translate
//! it to whatever they prefer: a subdirectory for LocalFs, a literal
//! S3 bucket prefix, a column value for SqliteBlob.
//!
//! ## Construction
//!
//! [`open`] is the daemon's single construction entrypoint. Backend
//! is selected by the DSN scheme; adding a new backend is one new
//! arm in [`open`] plus one new module under this directory.
//!
//! Supported schemes:
//!
//! | scheme    | form                                | enabled by             |
//! | --------- | ----------------------------------- | ---------------------- |
//! | `file`    | `file:///abs/path/blob-store`       | always                 |
//! | `memory`  | `memory://`                         | always                 |
//! | `gcs`     | `gcs://bucket/prefix`               | `--features gcs`       |
//! | `s3`      | `s3://bucket/prefix`                | `--features s3`        |
//!
//! ## Conformance
//!
//! Backends are expected to satisfy
//! [`testing::blob_store_conformance`] — a parameterised test suite
//! that pins the put/get/delete/atomicity invariants. Adding a new
//! backend = implement the trait + run conformance.

use std::sync::Arc;

use async_trait::async_trait;
use thiserror::Error;

pub mod local_fs;
pub mod memory;

#[cfg(any(feature = "gcs", feature = "s3"))]
mod object_store_adapter;

#[cfg(feature = "gcs")]
pub mod gcs;
#[cfg(feature = "s3")]
pub mod s3;

pub use local_fs::LocalFsBlobStore;
pub use memory::MemoryBlobStore;

#[cfg(feature = "gcs")]
pub use gcs::GcsBlobStore;
#[cfg(feature = "s3")]
pub use s3::S3BlobStore;

/// Logical namespaces inside a [`BlobStore`].
pub mod bucket {
    /// File-message payloads delivered to the operator's inbox.
    pub const FILES: &str = "files";
    /// Audit-log day-bucket archives (gzip-compressed JSONL).
    pub const AUDIT_ARCHIVE: &str = "audit-archive";
}

#[async_trait]
pub trait BlobStore: Send + Sync + std::fmt::Debug + 'static {
    /// Persist `data` under `bucket` keyed by `key`. Returns the
    /// opaque location string the caller persists in its metadata
    /// table. Implementations MUST be atomic — a partially-written
    /// blob must not be readable. LocalFs achieves this with write-to-
    /// tmp + rename; S3 with a single PUT.
    ///
    /// Two `put` calls with the same `(bucket, key)` overwrite the
    /// previous content. Callers should choose unique keys (envelope
    /// id is the natural choice for files) when overwrite is
    /// undesirable.
    async fn put(&self, bucket: &str, key: &str, data: &[u8]) -> Result<String, BlobError>;

    /// Read back the blob at `location`. `location` MUST be a value
    /// previously returned by [`Self::put`] on the same backend
    /// instance.
    async fn get(&self, location: &str) -> Result<Vec<u8>, BlobError>;

    /// Best-effort delete. `BlobError::NotFound` is NOT returned —
    /// callers may legitimately retry deletion or run cleanup against
    /// a partially-cleaned state, and a missing blob means the
    /// invariant is already satisfied.
    async fn delete(&self, location: &str) -> Result<(), BlobError>;
}

#[derive(Debug, Error)]
pub enum BlobError {
    #[error("blob not found at {0}")]
    NotFound(String),
    #[error("invalid location: {0}")]
    InvalidLocation(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("backend: {0}")]
    Backend(String),
}

/// Open the blob store named by `dsn` and return it as the daemon's
/// single trait object. Dispatch is by URL scheme; adding a new
/// backend is one new arm in this `match` plus one new module under
/// [`crate::blobs`].
///
/// Mirrors [`crate::open_database`]: this function owns DSN parsing,
/// each backend constructor takes natural primitives. See
/// module-level docs for the supported scheme list. Auth and region
/// for cloud backends come from the SDK's standard env-var chain
/// (ADC for GCS, AWS credential chain for S3) — the DSN carries only
/// "where" (bucket + prefix), never secrets.
pub async fn open(dsn: &str) -> Result<Arc<dyn BlobStore>, BlobError> {
    let parsed = url::Url::parse(dsn)
        .map_err(|e| BlobError::Backend(format!("parse blob dsn {dsn:?}: {e}")))?;
    match parsed.scheme() {
        "file" => {
            let path = parse_file_path(&parsed)?;
            let store = LocalFsBlobStore::new(path)
                .map_err(|e| BlobError::Backend(format!("open local_fs blob store: {e}")))?;
            Ok(Arc::new(store))
        }
        "memory" => Ok(Arc::new(MemoryBlobStore::new())),
        #[cfg(feature = "gcs")]
        "gcs" => {
            let (bucket, prefix) = parse_bucket_prefix("gcs", &parsed)?;
            Ok(Arc::new(GcsBlobStore::new(&bucket, prefix)?))
        }
        #[cfg(feature = "s3")]
        "s3" => {
            let (bucket, prefix) = parse_bucket_prefix("s3", &parsed)?;
            Ok(Arc::new(S3BlobStore::new(&bucket, prefix)?))
        }
        other => Err(BlobError::Backend(format!(
            "unsupported blob scheme {other:?} (supported: file, memory{}{})",
            if cfg!(feature = "gcs") { ", gcs" } else { "" },
            if cfg!(feature = "s3") { ", s3" } else { "" },
        ))),
    }
}

/// Extract an absolute filesystem path from a `file:///abs/path` DSN.
/// Rejects the two-slash form (`file://relative/path`) early so a
/// misconfigured DSN surfaces as a clear error rather than silently
/// writing blobs to an unintended location.
fn parse_file_path(url: &url::Url) -> Result<std::path::PathBuf, BlobError> {
    if url.host_str().is_some_and(|h| !h.is_empty()) {
        return Err(BlobError::Backend(format!(
            "file blob dsn has a host component {url:?} \
             — use `file:///abs/path` (three slashes)"
        )));
    }
    let path_str = url.path();
    if path_str.is_empty() || path_str == "/" {
        return Err(BlobError::Backend(format!(
            "file blob dsn missing path: {url:?}"
        )));
    }
    Ok(std::path::PathBuf::from(path_str))
}

/// Extract `(bucket, prefix)` from a `<scheme>://<bucket>/<prefix>` DSN.
/// `prefix` is whatever follows the bucket, with leading and trailing
/// slashes stripped — empty means "bucket root".
#[cfg(any(feature = "gcs", feature = "s3"))]
fn parse_bucket_prefix(scheme: &str, url: &url::Url) -> Result<(String, String), BlobError> {
    let bucket = url
        .host_str()
        .filter(|h| !h.is_empty())
        .ok_or_else(|| BlobError::Backend(format!("{scheme} dsn missing bucket: {url:?}")))?
        .to_string();
    let prefix = url
        .path()
        .trim_start_matches('/')
        .trim_end_matches('/')
        .to_string();
    Ok((bucket, prefix))
}

/// Filename-safe sanitisation: alphanumeric + `_`, `-`, `.` are
/// preserved; everything else is replaced with `_`. Path separators
/// (`/`, `\`), control chars, and unicode oddities all collapse to
/// `_`. Empty input maps to `_` (one char) so callers always get a
/// non-empty filename.
pub(crate) fn sanitize_segment(s: &str) -> String {
    if s.is_empty() {
        return "_".into();
    }
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Cross-backend test helpers. `pub` so the workspace's own
/// integration tests in `tests/blob_conformance.rs` and any
/// out-of-tree [`BlobStore`] impls drive the same fixture.
///
/// The body is unconditionally compiled — `BlobStore` is part of the
/// crate's public API, so the conformance contract is too. The fn is
/// trait-generic so it adds nothing to a build that doesn't call it.
pub mod testing {
    use super::{BlobError, BlobStore, bucket};

    /// Conformance suite — every [`BlobStore`] backend must pass this.
    /// Backends call it from their own test module:
    ///
    /// ```ignore
    /// #[tokio::test]
    /// async fn conforms() {
    ///     let store = MyBackend::new(...);
    ///     blob_store_conformance(&store).await;
    /// }
    /// ```
    pub async fn blob_store_conformance<S: BlobStore + ?Sized>(store: &S) {
        // 1. put + get roundtrip
        let loc = store
            .put(bucket::FILES, "roundtrip.bin", b"hello, blob")
            .await
            .expect("put roundtrip");
        let got = store.get(&loc).await.expect("get roundtrip");
        assert_eq!(got, b"hello, blob", "roundtrip data mismatch");

        // 2. delete then get returns NotFound
        store.delete(&loc).await.expect("delete after roundtrip");
        match store.get(&loc).await {
            Err(BlobError::NotFound(_)) => {}
            other => panic!("expected NotFound after delete, got {other:?}"),
        }

        // 3. delete on missing is a no-op (NOT NotFound)
        store
            .delete(&loc)
            .await
            .expect("delete on missing must be a no-op");

        // 4. overwrite semantics
        let loc1 = store
            .put(bucket::FILES, "overwrite.bin", b"first")
            .await
            .unwrap();
        let loc2 = store
            .put(bucket::FILES, "overwrite.bin", b"second")
            .await
            .unwrap();
        assert_eq!(loc1, loc2, "same (bucket,key) must yield same location");
        assert_eq!(store.get(&loc1).await.unwrap(), b"second");

        // 5. distinct buckets isolated
        let a = store
            .put(bucket::FILES, "iso.bin", b"in-files")
            .await
            .unwrap();
        let b = store
            .put(bucket::AUDIT_ARCHIVE, "iso.bin", b"in-archive")
            .await
            .unwrap();
        assert_ne!(a, b, "distinct buckets must produce distinct locations");
        assert_eq!(store.get(&a).await.unwrap(), b"in-files");
        assert_eq!(store.get(&b).await.unwrap(), b"in-archive");

        // 6. invalid location handled cleanly
        match store.get("not-a-real-location-format-anywhere").await {
            Err(BlobError::NotFound(_)) | Err(BlobError::InvalidLocation(_)) => {}
            other => panic!("expected NotFound/InvalidLocation, got {other:?}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_strips_path_separators() {
        // `.` is allowed (filenames legitimately have it). `..` alone is
        // not a traversal — `/` is. Sanitisation drops every separator.
        assert_eq!(sanitize_segment("../../etc/passwd"), ".._.._etc_passwd");
        assert_eq!(sanitize_segment("a/b\\c"), "a_b_c");
        assert_eq!(sanitize_segment("file.tar.gz"), "file.tar.gz");
        assert_eq!(sanitize_segment(""), "_");
        assert_eq!(
            sanitize_segment("name with spaces.txt"),
            "name_with_spaces.txt"
        );
        assert_eq!(sanitize_segment("nul\0byte"), "nul_byte");
    }

    #[tokio::test]
    async fn open_rejects_unparseable_dsn() {
        let err = open("not a dsn").await.unwrap_err();
        assert!(
            matches!(err, BlobError::Backend(ref s) if s.contains("parse blob dsn")),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn open_rejects_unsupported_scheme() {
        let err = open("ftp://example.com/blobs").await.unwrap_err();
        assert!(
            matches!(err, BlobError::Backend(ref s) if s.contains("unsupported blob scheme")),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn open_rejects_file_with_host_component() {
        // `file://relative/path` parses `relative` as a host; we reject
        // so the operator's mistake doesn't silently land blobs in an
        // unintended location.
        let err = open("file://relative/path").await.unwrap_err();
        assert!(
            matches!(err, BlobError::Backend(ref s) if s.contains("host component")),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn open_rejects_file_without_path() {
        let err = open("file://").await.unwrap_err();
        assert!(
            matches!(err, BlobError::Backend(ref s) if s.contains("missing path")),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn open_memory_dsn() {
        let store = open("memory://").await.expect("memory dsn opens");
        // Conformance over the trait object proves dispatch lands on
        // a real backend (not a stub).
        let loc = store
            .put(bucket::FILES, "x", b"y")
            .await
            .expect("put on opened memory store");
        assert_eq!(store.get(&loc).await.unwrap(), b"y");
    }

    #[tokio::test]
    async fn open_file_dsn() {
        let dir = tempfile::tempdir().unwrap();
        let dsn = format!("file://{}", dir.path().display());
        let store = open(&dsn).await.expect("file dsn opens");
        let loc = store.put(bucket::FILES, "x", b"y").await.unwrap();
        assert_eq!(store.get(&loc).await.unwrap(), b"y");
    }
}
