//! Google Cloud Storage backend for [`BlobStore`].
//!
//! Auth comes from the standard ADC (Application Default Credentials)
//! chain — `GOOGLE_APPLICATION_CREDENTIALS`, gcloud user creds, or the
//! GCE / Cloud Run / GKE metadata server. To override individual bits
//! set the env vars `object_store` honours: `GOOGLE_SERVICE_ACCOUNT`,
//! `GOOGLE_BUCKET_NAME` (overrides the constructor bucket), etc.
//!
//! Project ID is implicit — GCS object operations don't need it once
//! a bucket is named, so we don't carry it.

use async_trait::async_trait;
use object_store::gcp::{GoogleCloudStorage, GoogleCloudStorageBuilder};

use super::{BlobError, BlobStore, object_store_adapter::ObjectStoreAdapter};

#[derive(Debug)]
pub struct GcsBlobStore {
    inner: ObjectStoreAdapter<GoogleCloudStorage>,
}

impl GcsBlobStore {
    /// Construct a GCS-backed [`BlobStore`] for `bucket`, with all
    /// objects prefixed by `prefix` (empty string = bucket root).
    /// `bucket` and `prefix` are the natural primitives; the
    /// `gcs://bucket/prefix` DSN form is parsed by [`crate::blobs::open`]
    /// before reaching this constructor.
    pub fn new(bucket: &str, prefix: String) -> Result<Self, BlobError> {
        let store = GoogleCloudStorageBuilder::from_env()
            .with_bucket_name(bucket)
            .build()
            .map_err(|e| {
                BlobError::Backend(format!("build GCS client for bucket {bucket:?}: {e}"))
            })?;
        Ok(Self {
            inner: ObjectStoreAdapter::new(store, prefix, "gcs"),
        })
    }
}

#[async_trait]
impl BlobStore for GcsBlobStore {
    async fn put(&self, bucket: &str, key: &str, data: &[u8]) -> Result<String, BlobError> {
        self.inner.put(bucket, key, data).await
    }

    async fn get(&self, location: &str) -> Result<Vec<u8>, BlobError> {
        self.inner.get(location).await
    }

    async fn delete(&self, location: &str) -> Result<(), BlobError> {
        self.inner.delete(location).await
    }
}
