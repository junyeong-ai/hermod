//! SQLite implementation of `RateLimitRepository`.

use async_trait::async_trait;
use hermod_core::Timestamp;
use sqlx::{Row, SqlitePool};

use crate::error::Result;
use crate::repositories::rate_limit::RateLimitRepository;

#[derive(Debug, Clone)]
pub struct SqliteRateLimitRepository {
    pool: SqlitePool,
}

impl SqliteRateLimitRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    async fn try_consume_locked(
        &self,
        conn: &mut sqlx::SqliteConnection,
        pair_key: &str,
        capacity: u32,
        refill_per_min: u32,
        now: Timestamp,
    ) -> Result<bool> {
        let row = sqlx::query(r#"SELECT tokens, updated_at FROM rate_buckets WHERE pair_key = ?"#)
            .bind(pair_key)
            .fetch_optional(&mut *conn)
            .await?;

        let (cur_tokens, last_at_ms): (f64, i64) = match row {
            Some(r) => (r.try_get("tokens")?, r.try_get("updated_at")?),
            None => (capacity as f64, now.unix_ms()),
        };

        let elapsed_secs = ((now.unix_ms() - last_at_ms).max(0) as f64) / 1000.0;
        let refill_per_sec = refill_per_min as f64 / 60.0;
        let refilled = (cur_tokens + elapsed_secs * refill_per_sec).min(capacity as f64);

        let (after, granted) = if refilled < 1.0 {
            (refilled, false)
        } else {
            (refilled - 1.0, true)
        };

        sqlx::query(
            r#"INSERT INTO rate_buckets (pair_key, tokens, updated_at)
               VALUES (?, ?, ?)
               ON CONFLICT(pair_key) DO UPDATE SET
                 tokens = excluded.tokens,
                 updated_at = excluded.updated_at"#,
        )
        .bind(pair_key)
        .bind(after)
        .bind(now.unix_ms())
        .execute(&mut *conn)
        .await?;
        Ok(granted)
    }
}

#[async_trait]
impl RateLimitRepository for SqliteRateLimitRepository {
    async fn try_consume_one(
        &self,
        pair_key: &str,
        capacity: u32,
        refill_per_min: u32,
        now: Timestamp,
    ) -> Result<bool> {
        // BEGIN IMMEDIATE serialises the read-modify-write cycle through
        // SQLite's reserved lock. With BEGIN DEFERRED, two concurrent
        // consumers could both observe the same `cur_tokens` snapshot and
        // both decrement, over-delivering by one. sqlx's `Pool::begin()`
        // hardcodes DEFERRED, hence the manual BEGIN here paired with
        // explicit ROLLBACK on any inner failure.
        let mut conn = self.pool.acquire().await?;
        sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;

        let inner = self
            .try_consume_locked(&mut conn, pair_key, capacity, refill_per_min, now)
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

    async fn prune_idle(&self, cutoff_ms: i64, capacity: u32) -> Result<u64> {
        let res = sqlx::query(
            r#"DELETE FROM rate_buckets
               WHERE updated_at < ? AND tokens >= ?"#,
        )
        .bind(cutoff_ms)
        .bind(capacity as f64)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backends::sqlite::SqliteDatabase;

    async fn fresh_db() -> SqliteDatabase {
        // ULID gives a monotonic-unique filename — wall-clock nanoseconds
        // collide under fast parallel test execution.
        let mut p = std::env::temp_dir();
        p.push(format!("hermod-rate-{}.sqlite", ulid::Ulid::new()));
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

    #[tokio::test]
    async fn bucket_refills_and_drains() {
        let db = fresh_db().await;
        let rl = SqliteRateLimitRepository::new(db.pool().clone());
        let now = Timestamp::now();
        assert!(rl.try_consume_one("a|b", 2, 60, now).await.unwrap());
        assert!(rl.try_consume_one("a|b", 2, 60, now).await.unwrap());
        assert!(!rl.try_consume_one("a|b", 2, 60, now).await.unwrap());
        let later = Timestamp::from_unix_ms(now.unix_ms() + 2_000).unwrap();
        assert!(rl.try_consume_one("a|b", 2, 60, later).await.unwrap());
    }

    #[tokio::test]
    async fn prune_idle_drops_only_full_idle_buckets() {
        let db = fresh_db().await;
        let rl = SqliteRateLimitRepository::new(db.pool().clone());
        let t0 = Timestamp::now();

        assert!(rl.try_consume_one("a|b", 2, 60, t0).await.unwrap());
        let t1 = Timestamp::from_unix_ms(t0.unix_ms() + 60_000).unwrap();
        assert!(rl.try_consume_one("c|d", 2, 60, t0).await.unwrap());
        assert!(rl.try_consume_one("c|d", 2, 60, t1).await.unwrap());
        let t2 = Timestamp::from_unix_ms(t1.unix_ms() + 120_000).unwrap();

        let cutoff = t2.unix_ms() + 1;
        let pruned = rl.prune_idle(cutoff, 2).await.unwrap();
        assert_eq!(pruned, 0);

        assert!(rl.try_consume_one("e|f", 2, 60, t0).await.unwrap());
        let very_late = Timestamp::from_unix_ms(t0.unix_ms() + 300_000).unwrap();
        assert!(rl.try_consume_one("e|f", 2, 60, very_late).await.unwrap());
        let pruned2 = rl
            .prune_idle(very_late.unix_ms() + 1_000_000, 2)
            .await
            .unwrap();
        assert_eq!(pruned2, 0, "partially-drained buckets must be preserved");
    }

    #[tokio::test]
    async fn concurrent_consumers_never_over_deliver() {
        let db = fresh_db().await;
        let rl = SqliteRateLimitRepository::new(db.pool().clone());
        let now = Timestamp::now();

        let mut handles = Vec::new();
        for _ in 0..16u32 {
            let rl = rl.clone();
            handles.push(tokio::spawn(async move {
                rl.try_consume_one("racer|target", 4, 0, now).await.unwrap()
            }));
        }
        let mut granted = 0u32;
        for h in handles {
            if h.await.unwrap() {
                granted += 1;
            }
        }
        assert_eq!(granted, 4, "exactly capacity must be granted under race");
    }
}
