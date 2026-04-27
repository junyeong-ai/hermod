//! Audit-log day-bucket archival.
//!
//! `audit_log` accumulates one row per audited event and would
//! otherwise grow unboundedly. The hash-chain forbids deleting middle
//! rows directly. The pattern is: at the day boundary, freeze every
//! row from the previous day into a gzip-compressed JSONL file and
//! hand it to the [`BlobStore`]; index the chunk in
//! `audit_archive_index`; only then DELETE the rows from `audit_log`.
//!
//! Chain continuity across archives is preserved by recording each
//! archive's `first_prev_hash` and `last_row_hash`. `verify_chain`
//! follows the chain through every archive, then through the live
//! tail, with no gaps.
//!
//! ## File layout
//!
//! `audit-YYYY-MM-DD.jsonl.gz`. The first JSONL line is a manifest
//! record (`{"_manifest": true, ...}`); subsequent lines are the
//! actual audit rows in `id ASC` order. The manifest carries the
//! row-count, first / last row IDs, first_prev_hash, last_row_hash,
//! archived_at, and an ed25519 `manifest_sig` over the canonical CBOR
//! of all preceding fields. A reader that doesn't recognise the
//! manifest skips it; a reader that does verifies the signature
//! before trusting any row.

use serde::{Deserialize, Serialize};

use crate::repositories::audit::AuditEntry;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveManifest {
    /// Always `true` — discriminates manifest from regular rows when
    /// re-parsing JSONL.
    #[serde(rename = "_manifest")]
    pub manifest: bool,
    pub epoch_start_ms: i64,
    pub epoch_end_ms: i64,
    pub first_row_id: i64,
    pub last_row_id: i64,
    pub row_count: u64,
    pub first_prev_hash_hex: String,
    pub last_row_hash_hex: String,
    pub archived_at_ms: i64,
}

impl ArchiveManifest {
    /// Bytes the manifest signature is computed over: canonical CBOR
    /// of every field EXCEPT the eventually-attached signature itself.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        // serde over Self serialises the `manifest: true` flag too,
        // which is fine because it's part of the message envelope; the
        // signature only excludes itself.
        ciborium::into_writer(self, &mut buf).expect("manifest serialisation cannot fail");
        buf
    }
}

/// Audit row as it appears inside the JSONL archive. Fields mirror
/// the source `audit_log` columns 1:1 — readers can re-import an
/// archive into a fresh DB without loss.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchivedRow {
    pub id: i64,
    pub ts_ms: i64,
    pub actor: String,
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
    pub prev_hash_hex: String,
    pub row_hash_hex: String,
    pub sig_hex: String,
}

impl ArchivedRow {
    pub fn from_entry(entry: &AuditEntry, prev_hash: &[u8], row_hash: &[u8], sig: &[u8]) -> Self {
        Self {
            id: entry.id.unwrap_or(0),
            ts_ms: entry.ts.unix_ms(),
            actor: entry.actor.to_string(),
            action: entry.action.clone(),
            target: entry.target.clone(),
            details: entry.details.clone(),
            prev_hash_hex: hex::encode(prev_hash),
            row_hash_hex: hex::encode(row_hash),
            sig_hex: hex::encode(sig),
        }
    }
}

/// Compress a fully-built JSONL byte stream with gzip. Centralised
/// so the archive writer and any future "re-archive" tooling share
/// one compression backend.
pub fn gzip_compress(bytes: &[u8]) -> std::io::Result<Vec<u8>> {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;

    let mut enc = GzEncoder::new(Vec::with_capacity(bytes.len() / 4), Compression::default());
    enc.write_all(bytes)?;
    enc.finish()
}

pub fn gzip_decompress(bytes: &[u8]) -> std::io::Result<Vec<u8>> {
    use flate2::read::GzDecoder;
    use std::io::Read;

    let mut dec = GzDecoder::new(bytes);
    let mut out = Vec::new();
    dec.read_to_end(&mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_canonical_bytes_are_stable() {
        let m = ArchiveManifest {
            manifest: true,
            epoch_start_ms: 1_700_000_000_000,
            epoch_end_ms: 1_700_086_400_000,
            first_row_id: 1,
            last_row_id: 100,
            row_count: 100,
            first_prev_hash_hex: "00".repeat(32),
            last_row_hash_hex: "ff".repeat(32),
            archived_at_ms: 1_700_086_500_000,
        };
        let a = m.canonical_bytes();
        let b = m.canonical_bytes();
        assert_eq!(a, b);
        assert!(!a.is_empty());
    }

    #[test]
    fn gzip_roundtrip_preserves_jsonl() {
        let raw = b"{\"a\":1}\n{\"b\":2}\n";
        let z = gzip_compress(raw).unwrap();
        let back = gzip_decompress(&z).unwrap();
        assert_eq!(back, raw);
    }
}
