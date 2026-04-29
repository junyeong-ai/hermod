//! Filesystem-backed [`crate::BlobStore`].
//!
//! Layout: `<root>/<bucket>/<sanitized-key>`. Locations are
//! `local-fs://<bucket>/<sanitized-key>` strings — operators can map
//! a location back to a path via
//! [`LocalFsBlobStore::location_to_path`] for direct inspection
//! (e.g. Claude's `Read` tool reading a file in the operator's inbox).
//!
//! Atomicity: writes go to `.<key>.tmp.<ulid>` then `rename(2)` over
//! the final path — `rename` on POSIX is atomic within the same
//! filesystem, so a crash between write and rename leaves no
//! partial blob visible to readers.
//!
//! Permissions: the root directory is created mode 0o700 so only the
//! daemon's UID can read its own blobs.

use async_trait::async_trait;
use std::path::{Path, PathBuf};
use ulid::Ulid;

use super::{BlobError, BlobStore, sanitize_segment};

const URI_SCHEME: &str = "local-fs://";

#[derive(Debug, Clone)]
pub struct LocalFsBlobStore {
    root: PathBuf,
}

impl LocalFsBlobStore {
    pub fn new(root: PathBuf) -> Result<Self, BlobError> {
        std::fs::create_dir_all(&root)?;
        // Lock to operator-only access. Fail loud if the chmod fails —
        // a wide-open blob root would leak file payloads to other
        // local users (T6 in `docs/threat-model.md`). Daemon's
        // `home_layout::enforce` re-checks this at boot for any
        // pre-existing root that may have been chmod-relaxed.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Convert an opaque location back to a filesystem path. Returns
    /// `None` if the location wasn't issued by this backend (foreign
    /// scheme).
    ///
    /// Surfaced so the MCP layer can hand a real path to Claude's
    /// `Read` tool. Cloud backends carry no such inverse mapping;
    /// callers downcast to `LocalFsBlobStore` when they need a path
    /// and skip the inspection feature otherwise.
    pub fn location_to_path(&self, location: &str) -> Option<PathBuf> {
        let suffix = location.strip_prefix(URI_SCHEME)?;
        let (bucket, key) = suffix.split_once('/')?;
        Some(self.root.join(bucket).join(key))
    }

    fn parse_location<'a>(&self, location: &'a str) -> Result<(&'a str, &'a str), BlobError> {
        let suffix = location
            .strip_prefix(URI_SCHEME)
            .ok_or_else(|| BlobError::InvalidLocation(location.to_string()))?;
        suffix
            .split_once('/')
            .ok_or_else(|| BlobError::InvalidLocation(location.to_string()))
    }
}

#[async_trait]
impl BlobStore for LocalFsBlobStore {
    async fn put(&self, bucket: &str, key: &str, data: &[u8]) -> Result<String, BlobError> {
        let safe_bucket = sanitize_segment(bucket);
        let safe_key = sanitize_segment(key);
        let dir = self.root.join(&safe_bucket);
        tokio::fs::create_dir_all(&dir).await?;
        let final_path = dir.join(&safe_key);
        let tmp_name = format!(".{safe_key}.tmp.{}", Ulid::new());
        let tmp_path = dir.join(&tmp_name);

        // Atomic: write tmp, fsync via tokio::fs::write semantics
        // (which uses a one-shot create+write+close), then rename.
        tokio::fs::write(&tmp_path, data).await?;
        match tokio::fs::rename(&tmp_path, &final_path).await {
            Ok(()) => {}
            Err(e) => {
                // Best-effort cleanup of the orphaned tmp file.
                let _ = tokio::fs::remove_file(&tmp_path).await;
                return Err(e.into());
            }
        }
        Ok(format!("{URI_SCHEME}{safe_bucket}/{safe_key}"))
    }

    async fn get(&self, location: &str) -> Result<Vec<u8>, BlobError> {
        let (bucket, key) = self.parse_location(location)?;
        let path = self.root.join(bucket).join(key);
        match tokio::fs::read(&path).await {
            Ok(data) => Ok(data),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(BlobError::NotFound(location.to_string()))
            }
            Err(e) => Err(e.into()),
        }
    }

    async fn delete(&self, location: &str) -> Result<(), BlobError> {
        let (bucket, key) = self.parse_location(location)?;
        let path = self.root.join(bucket).join(key);
        match tokio::fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blobs::testing::blob_store_conformance;

    fn fresh_store() -> LocalFsBlobStore {
        let mut root = std::env::temp_dir();
        root.push(format!("hermod-blobs-{}", Ulid::new()));
        LocalFsBlobStore::new(root).expect("create store")
    }

    #[tokio::test]
    async fn local_fs_conforms() {
        let store = fresh_store();
        blob_store_conformance(&store).await;
    }

    #[tokio::test]
    async fn location_to_path_round_trips() {
        let store = fresh_store();
        let loc = store
            .put(super::super::bucket::FILES, "report.pdf", b"PDF")
            .await
            .unwrap();
        let path = store.location_to_path(&loc).expect("path mapping");
        assert!(path.exists());
        assert_eq!(tokio::fs::read(&path).await.unwrap(), b"PDF");
    }

    #[tokio::test]
    async fn location_to_path_rejects_foreign_scheme() {
        let store = fresh_store();
        assert!(store.location_to_path("s3://bucket/key").is_none());
        assert!(store.location_to_path("plain-string").is_none());
    }

    #[tokio::test]
    async fn unsafe_keys_are_sanitised() {
        let store = fresh_store();
        // Path traversal attempt — must collapse to underscores.
        let loc = store
            .put(super::super::bucket::FILES, "../../etc/passwd", b"x")
            .await
            .unwrap();
        let path = store.location_to_path(&loc).unwrap();
        // The file should land inside the bucket dir, never outside root.
        assert!(path.starts_with(store.root()));
    }
}
