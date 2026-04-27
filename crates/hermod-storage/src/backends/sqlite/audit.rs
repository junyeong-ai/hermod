//! SQLite implementation of `AuditRepository`.
//!
//! Hash-chained, signed audit log: each row carries `prev_hash`,
//! `row_hash` (blake3 over the row content + prev_hash with explicit
//! length prefixes), and `sig` (ed25519 signature of `row_hash` by the
//! daemon's keypair). `verify_chain` walks rows in id order, recomputes
//! each hash, checks the link, and verifies the signature.

use async_trait::async_trait;
use hermod_core::{AgentId, SignatureBytes, Timestamp};
use hermod_crypto::Signer;
use sqlx::{Row, SqlitePool};
use std::str::FromStr;
use std::sync::Arc;

use crate::audit_archive::{ArchiveManifest, ArchivedRow, gzip_compress, gzip_decompress};
use crate::blobs::BlobStore;
use crate::error::{Result, StorageError};
use crate::repositories::audit::{
    ArchiveIndexEntry, ArchiveSummary, ArchiveVerification, AuditEntry, AuditRepository,
    ChainVerification,
};

/// 32-byte zero — used as `prev_hash` for the first chained row.
const ZERO32: [u8; 32] = [0u8; 32];

#[derive(Debug, Clone)]
pub struct SqliteAuditRepository {
    pool: SqlitePool,
    signer: Arc<dyn Signer>,
}

impl SqliteAuditRepository {
    pub fn new(pool: SqlitePool, signer: Arc<dyn Signer>) -> Self {
        Self { pool, signer }
    }

    async fn append_locked(
        &self,
        conn: &mut sqlx::SqliteConnection,
        entry: &AuditEntry,
        details: Option<&str>,
    ) -> Result<i64> {
        let prev_hash: Vec<u8> = match sqlx::query_scalar::<_, Vec<u8>>(
            r#"SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1"#,
        )
        .fetch_optional(&mut *conn)
        .await?
        {
            Some(h) if h.len() == 32 => h,
            _ => ZERO32.to_vec(),
        };

        let row_hash = compute_row_hash(
            entry.ts.unix_ms(),
            entry.actor.as_str(),
            &entry.action,
            entry.target.as_deref(),
            details,
            &prev_hash,
        );
        let sig = self
            .signer
            .sign_bytes(&row_hash)
            .await
            .map_err(|e| StorageError::decode("audit signer", e.to_string()))?;

        let res = sqlx::query(
            r#"INSERT INTO audit_log
               (ts, actor, action, target, details_json, prev_hash, row_hash, sig)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)"#,
        )
        .bind(entry.ts.unix_ms())
        .bind(entry.actor.as_str())
        .bind(&entry.action)
        .bind(&entry.target)
        .bind(details)
        .bind(&prev_hash)
        .bind(row_hash.to_vec())
        .bind(sig.as_slice().to_vec())
        .execute(&mut *conn)
        .await?;
        Ok(res.last_insert_rowid())
    }
}

#[async_trait]
impl AuditRepository for SqliteAuditRepository {
    async fn append(&self, entry: &AuditEntry) -> Result<i64> {
        let details = entry
            .details
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;

        // BEGIN IMMEDIATE serializes concurrent appends through SQLite's
        // write lock so the chain link is always taken against the most
        // recent row. Raw BEGIN bypasses sqlx's txn-depth tracking; pair
        // every BEGIN with explicit COMMIT (success) or ROLLBACK
        // (any inner failure).
        let mut conn = self.pool.acquire().await?;
        sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;

        let inner = self
            .append_locked(&mut conn, entry, details.as_deref())
            .await;

        match &inner {
            Ok(_) => {
                sqlx::query("COMMIT").execute(&mut *conn).await?;
            }
            Err(_) => {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            }
        }
        inner
    }

    async fn query(
        &self,
        actor: Option<&AgentId>,
        action: Option<&str>,
        since: Option<Timestamp>,
        limit: u32,
    ) -> Result<Vec<AuditEntry>> {
        let mut sql = String::from(
            r#"SELECT id, ts, actor, action, target, details_json
               FROM audit_log WHERE 1=1"#,
        );
        if actor.is_some() {
            sql.push_str(" AND actor = ?");
        }
        if action.is_some() {
            sql.push_str(" AND action = ?");
        }
        if since.is_some() {
            sql.push_str(" AND ts >= ?");
        }
        sql.push_str(" ORDER BY ts DESC LIMIT ?");

        let mut q = sqlx::query(&sql);
        if let Some(a) = actor {
            q = q.bind(a.as_str());
        }
        if let Some(act) = action {
            q = q.bind(act);
        }
        if let Some(s) = since {
            q = q.bind(s.unix_ms());
        }
        q = q.bind(limit as i64);

        let rows = q.fetch_all(&self.pool).await?;
        rows.into_iter().map(row_to_entry).collect()
    }

    async fn verify_chain(&self) -> Result<ChainVerification> {
        let pk = self.signer.public_key();

        // Walk archive index first so the chain check spans every
        // archived day-bucket plus the live tail.
        let archives = sqlx::query(
            r#"SELECT first_prev_hash, last_row_hash, row_count
               FROM audit_archive_index
               ORDER BY epoch_start ASC"#,
        )
        .fetch_all(&self.pool)
        .await?;

        let mut count: u64 = 0;
        let mut last_hash: Vec<u8> = ZERO32.to_vec();
        for arch in archives {
            let first_prev: Vec<u8> = arch.try_get("first_prev_hash")?;
            let last_row: Vec<u8> = arch.try_get("last_row_hash")?;
            let row_count: i64 = arch.try_get("row_count")?;
            if first_prev != last_hash {
                return Ok(ChainVerification::BrokenLink { row_id: -1 });
            }
            if last_row.len() != 32 || first_prev.len() != 32 {
                return Ok(ChainVerification::HashMismatch { row_id: -1 });
            }
            count = count.saturating_add(row_count.max(0) as u64);
            last_hash = last_row;
        }

        let rows = sqlx::query(
            r#"SELECT id, ts, actor, action, target, details_json,
                      prev_hash, row_hash, sig
               FROM audit_log ORDER BY id ASC"#,
        )
        .fetch_all(&self.pool)
        .await?;

        for row in rows {
            let id: i64 = row.try_get("id")?;
            let prev_hash: Vec<u8> = row.try_get("prev_hash")?;
            let row_hash: Vec<u8> = row.try_get("row_hash")?;
            let sig_blob: Vec<u8> = row.try_get("sig")?;
            if row_hash.len() != 32 || sig_blob.len() != 64 {
                return Ok(ChainVerification::HashMismatch { row_id: id });
            }
            if prev_hash != last_hash {
                return Ok(ChainVerification::BrokenLink { row_id: id });
            }
            let ts: i64 = row.try_get("ts")?;
            let actor: String = row.try_get("actor")?;
            let action: String = row.try_get("action")?;
            let target: Option<String> = row.try_get("target")?;
            let details: Option<String> = row.try_get("details_json")?;
            let computed = compute_row_hash(
                ts,
                &actor,
                &action,
                target.as_deref(),
                details.as_deref(),
                &prev_hash,
            );
            if computed.as_slice() != row_hash.as_slice() {
                return Ok(ChainVerification::HashMismatch { row_id: id });
            }
            let mut sig_arr = [0u8; SignatureBytes::LEN];
            sig_arr.copy_from_slice(&sig_blob);
            let sig = SignatureBytes(sig_arr);
            if pk.verify_bytes(&row_hash, &sig).is_err() {
                return Ok(ChainVerification::BadSignature { row_id: id });
            }
            count += 1;
            last_hash = row_hash;
        }
        Ok(ChainVerification::Ok { rows: count })
    }

    async fn archive_day(
        &self,
        blobs: &dyn BlobStore,
        epoch_start_ms: i64,
        epoch_end_ms: i64,
    ) -> Result<Option<ArchiveSummary>> {
        let rows = sqlx::query(
            r#"SELECT id, ts, actor, action, target, details_json,
                      prev_hash, row_hash, sig
               FROM audit_log
               WHERE ts >= ? AND ts < ?
               ORDER BY id ASC"#,
        )
        .bind(epoch_start_ms)
        .bind(epoch_end_ms)
        .fetch_all(&self.pool)
        .await?;

        if rows.is_empty() {
            return Ok(None);
        }

        let first_id: i64 = rows.first().unwrap().try_get("id")?;
        let last_id: i64 = rows.last().unwrap().try_get("id")?;
        let row_count = rows.len() as u64;
        let first_prev: Vec<u8> = rows.first().unwrap().try_get("prev_hash")?;
        let last_row: Vec<u8> = rows.last().unwrap().try_get("row_hash")?;
        let archived_at_ms = Timestamp::now().unix_ms();

        let manifest = ArchiveManifest {
            manifest: true,
            epoch_start_ms,
            epoch_end_ms,
            first_row_id: first_id,
            last_row_id: last_id,
            row_count,
            first_prev_hash_hex: hex::encode(&first_prev),
            last_row_hash_hex: hex::encode(&last_row),
            archived_at_ms,
        };
        let manifest_sig_bytes = self
            .signer
            .sign_bytes(&manifest.canonical_bytes())
            .await
            .map_err(|e| StorageError::decode("audit signer", e.to_string()))?
            .0
            .to_vec();

        let mut jsonl = Vec::with_capacity(rows.len() * 256);
        let mut manifest_value =
            serde_json::to_value(&manifest).map_err(StorageError::Json)?;
        if let Some(obj) = manifest_value.as_object_mut() {
            obj.insert(
                "manifest_sig_hex".into(),
                serde_json::Value::String(hex::encode(&manifest_sig_bytes)),
            );
        }
        jsonl.extend(serde_json::to_vec(&manifest_value).map_err(StorageError::Json)?);
        jsonl.push(b'\n');
        for row in &rows {
            let entry = AuditEntry {
                id: Some(row.try_get("id")?),
                ts: Timestamp::from_unix_ms(row.try_get("ts")?).map_err(StorageError::Core)?,
                actor: AgentId::from_str(&row.try_get::<String, _>("actor")?)
                    .map_err(StorageError::Core)?,
                action: row.try_get("action")?,
                target: row.try_get("target")?,
                details: row
                    .try_get::<Option<String>, _>("details_json")?
                    .map(|s| serde_json::from_str(&s))
                    .transpose()
                    .map_err(StorageError::Json)?,
                federation: crate::AuditFederationPolicy::Default,
            };
            let archived = ArchivedRow::from_entry(
                &entry,
                &row.try_get::<Vec<u8>, _>("prev_hash")?,
                &row.try_get::<Vec<u8>, _>("row_hash")?,
                &row.try_get::<Vec<u8>, _>("sig")?,
            );
            jsonl.extend(serde_json::to_vec(&archived).map_err(StorageError::Json)?);
            jsonl.push(b'\n');
        }
        let gz = gzip_compress(&jsonl)
            .map_err(|e| StorageError::Backend(format!("gzip compress audit archive: {e}")))?;
        let file_size = gz.len() as i64;

        // Persist the blob first so the index never points at nothing.
        let key = format!("audit-{}", iso_day_key(epoch_start_ms));
        let blob_location = blobs
            .put(crate::blobs::bucket::AUDIT_ARCHIVE, &key, &gz)
            .await
            .map_err(|e| StorageError::Backend(format!("blob put audit archive: {e}")))?;

        // Now atomically index + delete.
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            r#"INSERT INTO audit_archive_index
                   (epoch_start, epoch_end, first_row_id, last_row_id, row_count,
                    first_prev_hash, last_row_hash, blob_location, file_size,
                    archived_at, manifest_sig)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"#,
        )
        .bind(epoch_start_ms)
        .bind(epoch_end_ms)
        .bind(first_id)
        .bind(last_id)
        .bind(row_count as i64)
        .bind(&first_prev)
        .bind(&last_row)
        .bind(&blob_location)
        .bind(file_size)
        .bind(archived_at_ms)
        .bind(&manifest_sig_bytes)
        .execute(&mut *tx)
        .await?;

        let res = sqlx::query(
            r#"DELETE FROM audit_log WHERE ts >= ? AND ts < ?"#,
        )
        .bind(epoch_start_ms)
        .bind(epoch_end_ms)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(Some(ArchiveSummary {
            epoch_start_ms,
            epoch_end_ms,
            blob_location,
            row_count,
            file_size: file_size as u64,
            deleted_rows: res.rows_affected(),
        }))
    }

    async fn list_archives(&self, limit: u32) -> Result<Vec<ArchiveIndexEntry>> {
        let rows = sqlx::query(
            r#"SELECT epoch_start, epoch_end, row_count, file_size, blob_location, archived_at
               FROM audit_archive_index
               ORDER BY epoch_start DESC
               LIMIT ?"#,
        )
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|r| {
                Ok(ArchiveIndexEntry {
                    epoch_start_ms: r.try_get("epoch_start")?,
                    epoch_end_ms: r.try_get("epoch_end")?,
                    row_count: r.try_get::<i64, _>("row_count")?.max(0) as u64,
                    file_size: r.try_get::<i64, _>("file_size")?.max(0) as u64,
                    blob_location: r.try_get("blob_location")?,
                    archived_at_ms: r.try_get("archived_at")?,
                })
            })
            .collect()
    }

    async fn verify_archive(
        &self,
        blobs: &dyn BlobStore,
        epoch_start_ms: i64,
    ) -> Result<ArchiveVerification> {
        let row = sqlx::query(
            r#"SELECT blob_location, manifest_sig, first_prev_hash, last_row_hash, row_count
               FROM audit_archive_index WHERE epoch_start = ?"#,
        )
        .bind(epoch_start_ms)
        .fetch_optional(&self.pool)
        .await?;
        let row = match row {
            Some(r) => r,
            None => return Ok(ArchiveVerification::IndexMissing),
        };
        let blob_location: String = row.try_get("blob_location")?;
        let expected_sig: Vec<u8> = row.try_get("manifest_sig")?;
        let expected_first_prev: Vec<u8> = row.try_get("first_prev_hash")?;
        let expected_last_row: Vec<u8> = row.try_get("last_row_hash")?;

        let gz = match blobs.get(&blob_location).await {
            Ok(b) => b,
            Err(_) => return Ok(ArchiveVerification::BlobMissing { blob_location }),
        };
        let raw = gzip_decompress(&gz)
            .map_err(|e| StorageError::Backend(format!("gzip decompress audit archive: {e}")))?;

        let mut iter = raw.split(|b| *b == b'\n').filter(|l| !l.is_empty());
        let manifest_line = match iter.next() {
            Some(l) => l,
            None => return Ok(ArchiveVerification::ParseError),
        };
        let manifest_value: serde_json::Value =
            match serde_json::from_slice(manifest_line) {
                Ok(v) => v,
                Err(_) => return Ok(ArchiveVerification::ParseError),
            };
        let mut manifest_obj = match manifest_value.as_object().cloned() {
            Some(o) => o,
            None => return Ok(ArchiveVerification::ParseError),
        };
        let sig_in_file = manifest_obj
            .remove("manifest_sig_hex")
            .and_then(|v| v.as_str().map(str::to_string));
        let manifest_only: ArchiveManifest =
            match serde_json::from_value(serde_json::Value::Object(manifest_obj)) {
                Ok(m) => m,
                Err(_) => return Ok(ArchiveVerification::ParseError),
            };
        if manifest_only.first_prev_hash_hex != hex::encode(&expected_first_prev)
            || manifest_only.last_row_hash_hex != hex::encode(&expected_last_row)
        {
            return Ok(ArchiveVerification::ManifestMismatch);
        }
        let recomputed = manifest_only.canonical_bytes();
        let mut sig_arr = [0u8; SignatureBytes::LEN];
        if expected_sig.len() != SignatureBytes::LEN {
            return Ok(ArchiveVerification::SigInvalid);
        }
        sig_arr.copy_from_slice(&expected_sig);
        let sig = SignatureBytes(sig_arr);
        let pk = self.signer.public_key();
        if pk.verify_bytes(&recomputed, &sig).is_err() {
            return Ok(ArchiveVerification::SigInvalid);
        }
        if let Some(file_sig_hex) = sig_in_file
            && file_sig_hex != hex::encode(&expected_sig)
        {
            return Ok(ArchiveVerification::SigInvalid);
        }

        // Walk inner rows.
        let mut rows_seen: u64 = 0;
        let mut last_hash: Vec<u8> = expected_first_prev.clone();
        for line in iter {
            let archived: ArchivedRow = match serde_json::from_slice(line) {
                Ok(r) => r,
                Err(_) => return Ok(ArchiveVerification::ParseError),
            };
            let prev = match hex::decode(&archived.prev_hash_hex) {
                Ok(b) => b,
                Err(_) => return Ok(ArchiveVerification::ParseError),
            };
            let claimed_row_hash = match hex::decode(&archived.row_hash_hex) {
                Ok(b) => b,
                Err(_) => return Ok(ArchiveVerification::ParseError),
            };
            if prev != last_hash {
                return Ok(ArchiveVerification::BrokenLink {
                    row_id: archived.id,
                });
            }
            let computed = compute_row_hash(
                archived.ts_ms,
                &archived.actor,
                &archived.action,
                archived.target.as_deref(),
                archived
                    .details
                    .as_ref()
                    .map(|v| serde_json::to_string(v).unwrap_or_default())
                    .as_deref(),
                &prev,
            );
            if computed.as_slice() != claimed_row_hash.as_slice() {
                return Ok(ArchiveVerification::HashMismatch {
                    row_id: archived.id,
                });
            }
            last_hash = claimed_row_hash;
            rows_seen += 1;
        }
        if last_hash != expected_last_row {
            return Ok(ArchiveVerification::ManifestMismatch);
        }
        Ok(ArchiveVerification::Ok { rows: rows_seen })
    }

    async fn earliest_ts(&self) -> Result<Option<i64>> {
        let v: Option<i64> =
            sqlx::query_scalar::<_, Option<i64>>("SELECT MIN(ts) FROM audit_log")
                .fetch_one(&self.pool)
                .await?;
        Ok(v)
    }
}

fn iso_day_key(epoch_ms: i64) -> String {
    use time::{OffsetDateTime, format_description::well_known::Rfc3339};
    let secs = epoch_ms / 1000;
    let dt = OffsetDateTime::from_unix_timestamp(secs).unwrap_or(OffsetDateTime::UNIX_EPOCH);
    let s = dt.format(&Rfc3339).unwrap_or_else(|_| "unknown".into());
    s.split('T').next().unwrap_or(&s).to_string() + ".jsonl.gz"
}

/// Canonical row hash. Length prefixes on every variable-length field so
/// `"abc" | "def"` can't collide with `"ab" | "cdef"`. Numbers are encoded
/// little-endian for cross-platform determinism.
pub fn compute_row_hash(
    ts_ms: i64,
    actor: &str,
    action: &str,
    target: Option<&str>,
    details_json: Option<&str>,
    prev_hash: &[u8],
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(&ts_ms.to_le_bytes());
    write_lp(&mut h, actor.as_bytes());
    write_lp(&mut h, action.as_bytes());
    write_lp_opt(&mut h, target.map(|s| s.as_bytes()));
    write_lp_opt(&mut h, details_json.map(|s| s.as_bytes()));
    write_lp(&mut h, prev_hash);
    *h.finalize().as_bytes()
}

fn write_lp(h: &mut blake3::Hasher, bytes: &[u8]) {
    h.update(&(bytes.len() as u64).to_le_bytes());
    h.update(bytes);
}

fn write_lp_opt(h: &mut blake3::Hasher, bytes: Option<&[u8]>) {
    match bytes {
        Some(b) => {
            h.update(&[1u8]);
            write_lp(h, b);
        }
        None => {
            h.update(&[0u8]);
        }
    }
}

fn row_to_entry(row: sqlx::sqlite::SqliteRow) -> Result<AuditEntry> {
    let id: i64 = row.try_get("id")?;
    let ts = Timestamp::from_unix_ms(row.try_get("ts")?).map_err(StorageError::Core)?;
    let actor_s: String = row.try_get("actor")?;
    let actor = AgentId::from_str(&actor_s).map_err(StorageError::Core)?;
    let action: String = row.try_get("action")?;
    let target: Option<String> = row.try_get("target")?;
    let details_str: Option<String> = row.try_get("details_json")?;
    let details = details_str
        .map(|s| serde_json::from_str::<serde_json::Value>(&s))
        .transpose()?;
    Ok(AuditEntry {
        id: Some(id),
        ts,
        actor,
        action,
        target,
        details,
        // Hydrated rows are read-only; the federation flag was decided
        // at original emission and isn't persisted in the row schema
        // (federation is a one-shot decision, not a queryable
        // attribute). Default is the safe stand-in for surfaces that
        // re-render historical rows.
        federation: crate::AuditFederationPolicy::Default,
    })
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // tests exercise append directly
mod tests {
    use super::*;
    use crate::Database;
    use crate::backends::sqlite::SqliteDatabase;

    async fn fresh_db() -> SqliteDatabase {
        let mut p = std::env::temp_dir();
        p.push(format!("hermod-audit-{}.sqlite", ulid::Ulid::new()));
        let signer: Arc<dyn Signer> = Arc::new(hermod_crypto::LocalKeySigner::new(Arc::new(
            hermod_crypto::Keypair::generate(),
        )));
        SqliteDatabase::connect(
            &p,
            signer,
            Arc::new(crate::blobs::MemoryBlobStore::new()),
        )
        .await
        .unwrap()
    }

    fn fake_actor() -> AgentId {
        let pk = hermod_core::PubkeyBytes([1u8; 32]);
        hermod_crypto::agent_id_from_pubkey(&pk)
    }

    #[tokio::test]
    async fn signed_chain_verifies() {
        let db = fresh_db().await;
        let actor = fake_actor();
        for i in 0..5 {
            db.audit()
                .append(&AuditEntry {
                    id: None,
                    ts: Timestamp::now(),
                    actor: actor.clone(),
                    action: format!("test.{i}"),
                    target: Some(format!("t{i}")),
                    details: Some(serde_json::json!({"i": i})),
                    federation: crate::AuditFederationPolicy::Default,
                })
                .await
                .unwrap();
        }
        let v = db.audit().verify_chain().await.unwrap();
        assert_eq!(v, ChainVerification::Ok { rows: 5 });
    }

    #[tokio::test]
    async fn tamper_detected_as_hash_mismatch() {
        let db = fresh_db().await;
        let actor = fake_actor();
        let id = db
            .audit()
            .append(&AuditEntry {
                id: None,
                ts: Timestamp::now(),
                actor: actor.clone(),
                action: "honest".into(),
                target: None,
                details: None,
                federation: crate::AuditFederationPolicy::Default,
            })
            .await
            .unwrap();
        sqlx::query("UPDATE audit_log SET action = 'tampered' WHERE id = ?")
            .bind(id)
            .execute(db.pool())
            .await
            .unwrap();
        let v = db.audit().verify_chain().await.unwrap();
        assert_eq!(v, ChainVerification::HashMismatch { row_id: id });
    }

    #[tokio::test]
    async fn concurrent_appends_chain_correctly() {
        let db = fresh_db().await;
        let actor = fake_actor();
        let mut handles = Vec::new();
        for i in 0..16u32 {
            let dbx = db.clone();
            let actor = actor.clone();
            handles.push(tokio::spawn(async move {
                dbx.audit()
                    .append(&AuditEntry {
                        id: None,
                        ts: Timestamp::now(),
                        actor,
                        action: format!("race.{i}"),
                        target: None,
                        details: None,
                        federation: crate::AuditFederationPolicy::Default,
                    })
                    .await
                    .expect("append must succeed under contention")
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        let v = db.audit().verify_chain().await.unwrap();
        assert_eq!(v, ChainVerification::Ok { rows: 16 });
    }

    #[tokio::test]
    async fn missing_link_detected() {
        let db = fresh_db().await;
        let actor = fake_actor();
        for i in 0..3 {
            db.audit()
                .append(&AuditEntry {
                    id: None,
                    ts: Timestamp::now(),
                    actor: actor.clone(),
                    action: format!("step.{i}"),
                    target: None,
                    details: None,
                    federation: crate::AuditFederationPolicy::Default,
                })
                .await
                .unwrap();
        }
        sqlx::query("DELETE FROM audit_log WHERE id = 2")
            .execute(db.pool())
            .await
            .unwrap();
        let v = db.audit().verify_chain().await.unwrap();
        assert_eq!(v, ChainVerification::BrokenLink { row_id: 3 });
    }
}
