//! PostgreSQL implementation of `RateLimitRepository`.
//!
//! ## Concurrency model
//!
//! Token-bucket consume is a read-modify-write that needs strict
//! serialisation per `pair_key`. The dialect-correct path on Postgres
//! is `pg_advisory_xact_lock(hashtext(key))` — a transaction-scoped
//! advisory lock keyed on a hash of the pair_key. Concurrent callers
//! on the same key block in PG until the lock-holder commits; callers
//! on *different* keys proceed in parallel. This mirrors the
//! pessimistic semantics of SQLite's `BEGIN IMMEDIATE` while
//! restricting contention to the row that's actually being mutated.
//!
//! Why not SERIALIZABLE + retry: Postgres's optimistic isolation
//! detects the conflict at commit time and aborts losers with
//! SQLSTATE `40001`. Under high contention (16+ concurrent consumers
//! on one key), every retry batch loses to a fresh winner; the
//! caller never makes progress without ever-larger backoff. Advisory
//! locks queue cleanly without that thrash.
//!
//! Why not `SELECT ... FOR UPDATE`: row-level locks only attach to
//! existing rows. The first call for a key sees an empty row,
//! `FOR UPDATE` locks nothing, and concurrent first-calls all
//! collide on the subsequent INSERT.

use async_trait::async_trait;
use hermod_core::Timestamp;
use sqlx::{PgPool, Row};

use crate::error::Result;
use crate::repositories::rate_limit::RateLimitRepository;

#[derive(Debug, Clone)]
pub struct PostgresRateLimitRepository {
    pool: PgPool,
}

impl PostgresRateLimitRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    async fn try_consume_locked(
        &self,
        conn: &mut sqlx::PgConnection,
        pair_key: &str,
        capacity: u32,
        refill_per_min: u32,
        now: Timestamp,
    ) -> Result<bool> {
        let row = sqlx::query(r#"SELECT tokens, updated_at FROM rate_buckets WHERE pair_key = $1"#)
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
               VALUES ($1, $2, $3)
               ON CONFLICT(pair_key) DO UPDATE SET
                 tokens = EXCLUDED.tokens,
                 updated_at = EXCLUDED.updated_at"#,
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
impl RateLimitRepository for PostgresRateLimitRepository {
    async fn try_consume_one(
        &self,
        pair_key: &str,
        capacity: u32,
        refill_per_min: u32,
        now: Timestamp,
    ) -> Result<bool> {
        let mut tx = self.pool.begin().await?;

        // Per-key pessimistic lock. `pg_advisory_xact_lock` blocks
        // until the lock is granted, then releases on COMMIT/ROLLBACK
        // automatically. `hashtext($1)` reduces the variable-length
        // pair_key to the int4 the advisory-lock API requires; the
        // collision space is 2^32, well above the few-thousand
        // distinct (sender, recipient) pairs a Hermod deployment ever
        // sees concurrently — collision impact is benign (extra
        // serialisation), not incorrectness.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1)::bigint)")
            .bind(pair_key)
            .execute(&mut *tx)
            .await?;

        let granted = self
            .try_consume_locked(&mut tx, pair_key, capacity, refill_per_min, now)
            .await?;

        tx.commit().await?;
        Ok(granted)
    }

    async fn prune_idle(&self, cutoff_ms: i64, capacity: u32) -> Result<u64> {
        let res = sqlx::query(
            r#"DELETE FROM rate_buckets
               WHERE updated_at < $1 AND tokens >= $2"#,
        )
        .bind(cutoff_ms)
        .bind(capacity as f64)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }
}
