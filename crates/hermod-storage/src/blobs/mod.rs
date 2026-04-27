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
//! ## Conformance
//!
//! Backends are expected to satisfy
//! [`tests::blob_store_conformance`] — a parameterised test suite
//! that pins the put/get/delete/atomicity invariants. Adding a new
//! backend = implement the trait + run conformance.

use async_trait::async_trait;
use thiserror::Error;

pub mod local_fs;
pub mod memory;

pub use local_fs::LocalFsBlobStore;
pub use memory::MemoryBlobStore;

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
        assert_eq!(sanitize_segment("name with spaces.txt"), "name_with_spaces.txt");
        assert_eq!(sanitize_segment("nul\0byte"), "nul_byte");
    }

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
    pub async fn blob_store_conformance<S: BlobStore>(store: &S) {
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
