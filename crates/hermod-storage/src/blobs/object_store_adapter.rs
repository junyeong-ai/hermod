//! Internal adapter that turns any [`object_store::ObjectStore`] into
//! a Hermod [`BlobStore`]. Used by `gcs.rs` and `s3.rs` so the wiring
//! lives in exactly one place — adding a new cloud backend
//! (Azure Blob, Cloudflare R2, MinIO, …) is a 30-line newtype.
//!
//! The adapter prepends an optional DSN-supplied path prefix to every
//! `(bucket, key)` pair, then writes through the configured
//! `ObjectStore`. Returned location strings carry a scheme tag
//! (`gcs://…`, `s3://…`) so a daemon configured with multiple stores
//! could in principle be migrated by walking metadata; the prefix is
//! the canonical "where in the bucket" address.
//!
//! This module is `pub(super)`-scoped — the daemon and external
//! callers never see it. The naming-taxonomy contract says concrete
//! impls are `<Provider>BlobStore`; this is glue.

use std::fmt;

use async_trait::async_trait;
use object_store::{ObjectStore, ObjectStoreExt, PutPayload, path::Path as ObjectPath};

use super::{BlobError, BlobStore};

pub(super) struct ObjectStoreAdapter<S: ObjectStore> {
    inner: S,
    /// Path prefix prepended inside the bucket — empty means "no
    /// prefix". DSN `gcs://my-bucket/audit` ⇒ `prefix = "audit"`.
    prefix: String,
    /// `"gcs"` or `"s3"` — used as the location-string scheme so a
    /// stored location is round-trippable.
    location_scheme: &'static str,
}

impl<S: ObjectStore> ObjectStoreAdapter<S> {
    pub(super) fn new(inner: S, prefix: String, location_scheme: &'static str) -> Self {
        Self {
            inner,
            prefix,
            location_scheme,
        }
    }

    fn object_path(&self, bucket: &str, key: &str) -> Result<(ObjectPath, String), BlobError> {
        let mut segments: Vec<&str> = Vec::with_capacity(3);
        if !self.prefix.is_empty() {
            segments.push(&self.prefix);
        }
        segments.push(bucket);
        segments.push(key);
        let joined = segments.join("/");
        let path = ObjectPath::parse(&joined)
            .map_err(|e| BlobError::Backend(format!("invalid object path {joined:?}: {e}")))?;
        Ok((path, joined))
    }

    fn parse_location<'a>(&self, location: &'a str) -> Option<&'a str> {
        let want = format!("{}://", self.location_scheme);
        location.strip_prefix(&want)
    }
}

impl<S: ObjectStore> fmt::Debug for ObjectStoreAdapter<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObjectStoreAdapter")
            .field("scheme", &self.location_scheme)
            .field("prefix", &self.prefix)
            .finish()
    }
}

#[async_trait]
impl<S: ObjectStore> BlobStore for ObjectStoreAdapter<S> {
    async fn put(&self, bucket: &str, key: &str, data: &[u8]) -> Result<String, BlobError> {
        let (path, joined) = self.object_path(bucket, key)?;
        let payload = PutPayload::from(data.to_vec());
        self.inner.put(&path, payload).await.map_err(|e| {
            BlobError::Backend(format!("{}: put {joined:?}: {e}", self.location_scheme))
        })?;
        Ok(format!("{}://{}", self.location_scheme, joined))
    }

    async fn get(&self, location: &str) -> Result<Vec<u8>, BlobError> {
        let path_str = self.parse_location(location).ok_or_else(|| {
            BlobError::InvalidLocation(format!(
                "expected {}:// prefix, got {location:?}",
                self.location_scheme
            ))
        })?;
        let path = ObjectPath::parse(path_str).map_err(|e| {
            BlobError::InvalidLocation(format!("invalid object path {path_str:?}: {e}"))
        })?;
        match self.inner.get(&path).await {
            Ok(result) => {
                let bytes = result.bytes().await.map_err(|e| {
                    BlobError::Backend(format!("{}: read {location}: {e}", self.location_scheme))
                })?;
                Ok(bytes.to_vec())
            }
            Err(object_store::Error::NotFound { .. }) => Err(BlobError::NotFound(location.into())),
            Err(e) => Err(BlobError::Backend(format!(
                "{}: get {location}: {e}",
                self.location_scheme
            ))),
        }
    }

    async fn delete(&self, location: &str) -> Result<(), BlobError> {
        // Scheme-mismatch surfaces as `InvalidLocation` rather than a
        // silent Ok. A `gcs://…` location passed to an S3-backed
        // store — or vice versa — almost certainly indicates a
        // backend swap left stale rows in metadata; silently
        // succeeding would orphan the actual blob in the *other*
        // store. Within-scheme "blob already gone" stays Ok per the
        // [`BlobStore::delete`] best-effort contract.
        let path_str = self.parse_location(location).ok_or_else(|| {
            BlobError::InvalidLocation(format!(
                "expected {}:// prefix, got {location:?}",
                self.location_scheme
            ))
        })?;
        let path = ObjectPath::parse(path_str).map_err(|e| {
            BlobError::InvalidLocation(format!("invalid object path {path_str:?}: {e}"))
        })?;
        match self.inner.delete(&path).await {
            Ok(()) | Err(object_store::Error::NotFound { .. }) => Ok(()),
            Err(e) => Err(BlobError::Backend(format!(
                "{}: delete {location}: {e}",
                self.location_scheme
            ))),
        }
    }
}
