//! Amazon S3 / S3-compatible backend for [`BlobStore`].
//!
//! Auth and region come from the AWS SDK's standard credential chain
//! — env vars (`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` /
//! `AWS_REGION` / `AWS_ENDPOINT_URL`), shared `~/.aws/credentials`,
//! IMDS, EKS pod identity, etc.
//!
//! The same DSN works for any S3-API-compatible backend (MinIO,
//! Cloudflare R2, Wasabi, Tigris) — set `AWS_ENDPOINT_URL` to point
//! at it.

use async_trait::async_trait;
use object_store::aws::{AmazonS3, AmazonS3Builder};

use super::{BlobError, BlobStore, object_store_adapter::ObjectStoreAdapter};

#[derive(Debug)]
pub struct S3BlobStore {
    inner: ObjectStoreAdapter<AmazonS3>,
}

impl S3BlobStore {
    /// Construct an S3-backed [`BlobStore`] for `bucket`, with all
    /// objects prefixed by `prefix` (empty string = bucket root).
    /// `bucket` and `prefix` are the natural primitives; the
    /// `s3://bucket/prefix` DSN form is parsed by [`crate::blobs::open`]
    /// before reaching this constructor.
    pub fn new(bucket: &str, prefix: String) -> Result<Self, BlobError> {
        let store = AmazonS3Builder::from_env()
            .with_bucket_name(bucket)
            .build()
            .map_err(|e| {
                BlobError::Backend(format!("build S3 client for bucket {bucket:?}: {e}"))
            })?;
        Ok(Self {
            inner: ObjectStoreAdapter::new(store, prefix, "s3"),
        })
    }
}

#[async_trait]
impl BlobStore for S3BlobStore {
    fn backend(&self) -> super::BlobStoreBackend {
        super::BlobStoreBackend::S3
    }

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
