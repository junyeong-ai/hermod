//! In-memory [`BlobStore`] for tests. Not exported behind a feature
//! flag because it's small, has no production deps, and serves as the
//! reference implementation for trait conformance.

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Mutex;

use super::{BlobError, BlobStore, sanitize_segment};

const URI_SCHEME: &str = "memory://";

#[derive(Debug, Default)]
pub struct MemoryBlobStore {
    contents: Mutex<HashMap<String, Vec<u8>>>,
}

impl MemoryBlobStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl BlobStore for MemoryBlobStore {
    async fn put(&self, bucket: &str, key: &str, data: &[u8]) -> Result<String, BlobError> {
        let location = format!(
            "{URI_SCHEME}{}/{}",
            sanitize_segment(bucket),
            sanitize_segment(key)
        );
        self.contents
            .lock()
            .expect("memory blob store mutex poisoned")
            .insert(location.clone(), data.to_vec());
        Ok(location)
    }

    async fn get(&self, location: &str) -> Result<Vec<u8>, BlobError> {
        if !location.starts_with(URI_SCHEME) {
            return Err(BlobError::InvalidLocation(location.to_string()));
        }
        self.contents
            .lock()
            .expect("memory blob store mutex poisoned")
            .get(location)
            .cloned()
            .ok_or_else(|| BlobError::NotFound(location.to_string()))
    }

    async fn delete(&self, location: &str) -> Result<(), BlobError> {
        if !location.starts_with(URI_SCHEME) {
            return Err(BlobError::InvalidLocation(location.to_string()));
        }
        self.contents
            .lock()
            .expect("memory blob store mutex poisoned")
            .remove(location);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blobs::tests::blob_store_conformance;

    #[tokio::test]
    async fn memory_conforms() {
        let store = MemoryBlobStore::new();
        blob_store_conformance(&store).await;
    }
}
