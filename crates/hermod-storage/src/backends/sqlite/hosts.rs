//! SQLite implementation of `HostRepository`.

use async_trait::async_trait;
use hermod_core::{AgentAlias, AgentId, Endpoint, PubkeyBytes, Timestamp};
use sqlx::{Row, SqlitePool};
use std::str::FromStr;

use crate::error::{Result, StorageError};
use crate::repositories::hosts::{ForgetOutcome, HostRecord, HostRepository, RepinOutcome};

#[derive(Debug, Clone)]
pub struct SqliteHostRepository {
    pool: SqlitePool,
}

impl SqliteHostRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl HostRepository for SqliteHostRepository {
    async fn upsert(&self, record: &HostRecord) -> Result<()> {
        let endpoint = record.endpoint.as_ref().map(|e| e.to_string());
        let pubkey = record.pubkey.as_slice().to_vec();
        sqlx::query(
            r#"
            INSERT INTO hosts
                (id, pubkey, endpoint, tls_fingerprint, peer_asserted_alias,
                 first_seen, last_seen)
            VALUES
                (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                endpoint            = COALESCE(excluded.endpoint, hosts.endpoint),
                tls_fingerprint     = COALESCE(excluded.tls_fingerprint, hosts.tls_fingerprint),
                peer_asserted_alias = COALESCE(excluded.peer_asserted_alias, hosts.peer_asserted_alias),
                last_seen           = excluded.last_seen
            "#,
        )
        .bind(record.id.as_str())
        .bind(pubkey)
        .bind(endpoint)
        .bind(&record.tls_fingerprint)
        .bind(record.peer_asserted_alias.as_ref().map(|a| a.as_str()))
        .bind(record.first_seen.unix_ms())
        .bind(record.last_seen.map(|t| t.unix_ms()))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get(&self, id: &AgentId) -> Result<Option<HostRecord>> {
        let row = sqlx::query(&select("WHERE id = ?"))
            .bind(id.as_str())
            .fetch_optional(&self.pool)
            .await?;
        row.map(row_to_host).transpose()
    }

    async fn get_by_pubkey(&self, pubkey: &PubkeyBytes) -> Result<Option<HostRecord>> {
        let row = sqlx::query(&select("WHERE pubkey = ?"))
            .bind(pubkey.as_slice().to_vec())
            .fetch_optional(&self.pool)
            .await?;
        row.map(row_to_host).transpose()
    }

    async fn list(&self) -> Result<Vec<HostRecord>> {
        let rows = sqlx::query(&select("ORDER BY id"))
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter().map(row_to_host).collect()
    }

    async fn pin_or_match_tls_fingerprint(&self, id: &AgentId, observed: &str) -> Result<bool> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query(r#"SELECT tls_fingerprint FROM hosts WHERE id = ?"#)
            .bind(id.as_str())
            .fetch_optional(&mut *tx)
            .await?;
        let stored: Option<String> = match row {
            None => return Ok(false),
            Some(r) => r.try_get("tls_fingerprint")?,
        };
        let outcome = match stored {
            Some(s) if s == observed => true,
            Some(_) => false,
            None => {
                sqlx::query(r#"UPDATE hosts SET tls_fingerprint = ? WHERE id = ?"#)
                    .bind(observed)
                    .bind(id.as_str())
                    .execute(&mut *tx)
                    .await?;
                true
            }
        };
        tx.commit().await?;
        Ok(outcome)
    }

    async fn replace_tls_fingerprint(&self, id: &AgentId, new: &str) -> Result<RepinOutcome> {
        let mut conn = self.pool.acquire().await?;
        sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;

        let inner = async {
            let row = sqlx::query(r#"SELECT tls_fingerprint, endpoint FROM hosts WHERE id = ?"#)
                .bind(id.as_str())
                .fetch_optional(&mut *conn)
                .await?;
            let Some(row) = row else {
                return Ok::<RepinOutcome, StorageError>(RepinOutcome::NotFound);
            };
            let prev: Option<String> = row.try_get("tls_fingerprint")?;
            let endpoint_str: Option<String> = row.try_get("endpoint")?;
            let endpoint = endpoint_str
                .as_deref()
                .and_then(|s| Endpoint::from_str(s).ok());
            sqlx::query(r#"UPDATE hosts SET tls_fingerprint = ? WHERE id = ?"#)
                .bind(new)
                .bind(id.as_str())
                .execute(&mut *conn)
                .await?;
            Ok(RepinOutcome::Replaced {
                previous: prev,
                endpoint,
            })
        }
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

    async fn forget(&self, id: &AgentId) -> Result<ForgetOutcome> {
        let mut conn = self.pool.acquire().await?;
        sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;

        let inner = async {
            let prior: Option<String> =
                sqlx::query_scalar(r#"SELECT endpoint FROM hosts WHERE id = ?"#)
                    .bind(id.as_str())
                    .fetch_optional(&mut *conn)
                    .await?
                    .flatten();
            let res = sqlx::query(
                r#"UPDATE hosts
                   SET endpoint = NULL, tls_fingerprint = NULL
                   WHERE id = ?"#,
            )
            .bind(id.as_str())
            .execute(&mut *conn)
            .await?;
            Ok::<ForgetOutcome, StorageError>(ForgetOutcome {
                existed: res.rows_affected() > 0,
                prior_endpoint: prior.as_deref().and_then(|s| Endpoint::from_str(s).ok()),
            })
        }
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

    async fn touch(&self, id: &AgentId, at: Timestamp) -> Result<()> {
        sqlx::query(r#"UPDATE hosts SET last_seen = ? WHERE id = ?"#)
            .bind(at.unix_ms())
            .bind(id.as_str())
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

const COLUMNS: &str =
    "id, pubkey, endpoint, tls_fingerprint, peer_asserted_alias, first_seen, last_seen";

fn select(predicate: &str) -> String {
    format!("SELECT {COLUMNS} FROM hosts {predicate}")
}

fn row_to_host(row: sqlx::sqlite::SqliteRow) -> Result<HostRecord> {
    let id_str: String = row.try_get("id")?;
    let id = AgentId::from_str(&id_str).map_err(StorageError::Core)?;

    let pubkey_bytes: Vec<u8> = row.try_get("pubkey")?;
    if pubkey_bytes.len() != PubkeyBytes::LEN {
        return Err(StorageError::decode(
            "pubkey",
            format!(
                "expected {} bytes, got {}",
                PubkeyBytes::LEN,
                pubkey_bytes.len()
            ),
        ));
    }
    let mut arr = [0u8; PubkeyBytes::LEN];
    arr.copy_from_slice(&pubkey_bytes);
    let pubkey = PubkeyBytes(arr);

    let endpoint: Option<String> = row.try_get("endpoint")?;
    let endpoint = endpoint
        .map(|s| Endpoint::from_str(&s))
        .transpose()
        .map_err(StorageError::Core)?;

    let tls_fingerprint: Option<String> = row.try_get("tls_fingerprint")?;

    let peer_asserted_alias: Option<String> = row.try_get("peer_asserted_alias")?;
    let peer_asserted_alias = peer_asserted_alias
        .map(|s| AgentAlias::from_str(&s))
        .transpose()
        .map_err(StorageError::Core)?;

    let first_seen_ms: i64 = row.try_get("first_seen")?;
    let first_seen = Timestamp::from_unix_ms(first_seen_ms).map_err(StorageError::Core)?;

    let last_seen_ms: Option<i64> = row.try_get("last_seen")?;
    let last_seen = last_seen_ms
        .map(Timestamp::from_unix_ms)
        .transpose()
        .map_err(StorageError::Core)?;

    Ok(HostRecord {
        id,
        pubkey,
        endpoint,
        tls_fingerprint,
        peer_asserted_alias,
        first_seen,
        last_seen,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Database;
    use crate::backends::sqlite::SqliteDatabase;

    async fn fresh_db() -> SqliteDatabase {
        let mut p = std::env::temp_dir();
        p.push(format!("hermod-hosts-{}.sqlite", ulid::Ulid::new()));
        SqliteDatabase::connect(
            &p,
            std::sync::Arc::new(hermod_crypto::LocalKeySigner::new(std::sync::Arc::new(
                hermod_crypto::Keypair::generate(),
            ))) as std::sync::Arc<dyn hermod_crypto::Signer>,
            std::sync::Arc::new(crate::blobs::MemoryBlobStore::new()),
        )
        .await
        .unwrap()
    }

    fn fake_host(b: u8) -> HostRecord {
        let pubkey = PubkeyBytes([b; 32]);
        let id = hermod_crypto::agent_id_from_pubkey(&pubkey);
        // Truncate to ms — the storage column is millisecond
        // resolution, so a `Timestamp::now()` carrying sub-ms
        // precision would round-trip-mismatch on equality compares.
        let now = Timestamp::from_unix_ms(Timestamp::now().unix_ms()).unwrap();
        HostRecord {
            id,
            pubkey,
            endpoint: Some(Endpoint::from_str("wss://example:7823").unwrap()),
            tls_fingerprint: None,
            peer_asserted_alias: None,
            first_seen: now,
            last_seen: Some(now),
        }
    }

    #[tokio::test]
    async fn upsert_persists_and_reads_back() {
        let db = fresh_db().await;
        let h = fake_host(1);
        db.hosts().upsert(&h).await.unwrap();
        let got = db.hosts().get(&h.id).await.unwrap().unwrap();
        assert_eq!(got, h);
    }

    /// `upsert` preserves prior endpoint / fingerprint / alias when the
    /// new record carries `None` — re-observation must not blank known
    /// values.
    #[tokio::test]
    async fn upsert_coalesces_on_partial_reobservation() {
        let db = fresh_db().await;
        let mut h = fake_host(1);
        h.tls_fingerprint = Some("AA:BB".into());
        db.hosts().upsert(&h).await.unwrap();

        let mut partial = fake_host(1);
        partial.endpoint = None;
        partial.tls_fingerprint = None;
        db.hosts().upsert(&partial).await.unwrap();

        let got = db.hosts().get(&h.id).await.unwrap().unwrap();
        assert!(got.endpoint.is_some(), "endpoint should be preserved");
        assert_eq!(got.tls_fingerprint.as_deref(), Some("AA:BB"));
    }

    #[tokio::test]
    async fn pin_or_match_pins_when_null_then_matches() {
        let db = fresh_db().await;
        let h = fake_host(1);
        db.hosts().upsert(&h).await.unwrap();

        assert!(
            db.hosts()
                .pin_or_match_tls_fingerprint(&h.id, "FP1")
                .await
                .unwrap()
        );
        assert!(
            db.hosts()
                .pin_or_match_tls_fingerprint(&h.id, "FP1")
                .await
                .unwrap()
        );
        assert!(
            !db.hosts()
                .pin_or_match_tls_fingerprint(&h.id, "FP2")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn replace_tls_fingerprint_returns_previous() {
        let db = fresh_db().await;
        let h = fake_host(1);
        db.hosts().upsert(&h).await.unwrap();
        db.hosts()
            .pin_or_match_tls_fingerprint(&h.id, "OLD")
            .await
            .unwrap();
        let outcome = db
            .hosts()
            .replace_tls_fingerprint(&h.id, "NEW")
            .await
            .unwrap();
        match outcome {
            RepinOutcome::Replaced { previous, endpoint } => {
                assert_eq!(previous.as_deref(), Some("OLD"));
                assert!(endpoint.is_some());
            }
            other => panic!("unexpected outcome: {other:?}"),
        }
    }

    #[tokio::test]
    async fn forget_clears_endpoint_and_fingerprint() {
        let db = fresh_db().await;
        let h = fake_host(1);
        db.hosts().upsert(&h).await.unwrap();
        db.hosts()
            .pin_or_match_tls_fingerprint(&h.id, "FP")
            .await
            .unwrap();
        let outcome = db.hosts().forget(&h.id).await.unwrap();
        assert!(outcome.existed);
        assert!(outcome.prior_endpoint.is_some());
        let got = db.hosts().get(&h.id).await.unwrap().unwrap();
        assert!(got.endpoint.is_none());
        assert!(got.tls_fingerprint.is_none());
    }
}
