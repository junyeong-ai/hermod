//! Cross-backend conformance sweep — every [`BlobStore`] impl drives
//! the same fixture in [`hermod_storage::blobs::testing::blob_store_conformance`].
//!
//! `LocalFs` and `Memory` run by default. The cloud impls (`gcs`, `s3`)
//! gate on their cargo features and are `#[ignore]`-marked because
//! they need real credentials or an emulator (fake-gcs-server / minio).
//! Manual run:
//!
//! ```bash
//! # GCS — point at fake-gcs-server (Docker: fsouza/fake-gcs-server -port 4443)
//! GOOGLE_SERVICE_ACCOUNT=... \
//!   cargo test -p hermod-storage --features gcs \
//!   --test blob_conformance gcs_via_dsn -- --ignored --exact
//!
//! # S3 — point at minio (Docker: minio/minio server /data)
//! AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_REGION=us-east-1 \
//!   AWS_ENDPOINT_URL=http://localhost:9000 \
//!   cargo test -p hermod-storage --features s3 \
//!   --test blob_conformance s3_via_dsn -- --ignored --exact
//! ```

use hermod_storage::{
    LocalFsBlobStore, MemoryBlobStore, blobs::testing::blob_store_conformance, open_blob_store,
};

#[tokio::test]
async fn local_fs_via_struct() {
    let dir = tempfile::tempdir().unwrap();
    let store = LocalFsBlobStore::new(dir.path().to_path_buf()).expect("local_fs new");
    blob_store_conformance(&store).await;
}

#[tokio::test]
async fn local_fs_via_dsn() {
    let dir = tempfile::tempdir().unwrap();
    let dsn = format!("file://{}", dir.path().display());
    let store = open_blob_store(&dsn).await.expect("open file dsn");
    blob_store_conformance(&*store).await;
}

#[tokio::test]
async fn memory_via_struct() {
    let store = MemoryBlobStore::new();
    blob_store_conformance(&store).await;
}

#[tokio::test]
async fn memory_via_dsn() {
    let store = open_blob_store("memory://").await.expect("open memory dsn");
    blob_store_conformance(&*store).await;
}

#[cfg(feature = "gcs")]
#[tokio::test]
#[ignore = "needs GCS credentials or fake-gcs-server (set GOOGLE_SERVICE_ACCOUNT and HERMOD_TEST_GCS_DSN)"]
async fn gcs_via_dsn() {
    let dsn =
        std::env::var("HERMOD_TEST_GCS_DSN").expect("set HERMOD_TEST_GCS_DSN=gcs://bucket/prefix");
    let store = open_blob_store(&dsn).await.expect("open gcs dsn");
    blob_store_conformance(&*store).await;
}

#[cfg(feature = "s3")]
#[tokio::test]
#[ignore = "needs AWS credentials or minio (set AWS_REGION and HERMOD_TEST_S3_DSN)"]
async fn s3_via_dsn() {
    let dsn =
        std::env::var("HERMOD_TEST_S3_DSN").expect("set HERMOD_TEST_S3_DSN=s3://bucket/prefix");
    let store = open_blob_store(&dsn).await.expect("open s3 dsn");
    blob_store_conformance(&*store).await;
}
