//! PostgreSQL implementation of `ConfirmationRepository`.
//!
//! Functional twin of `backends::sqlite::SqliteConfirmationRepository`. The
//! enqueue path's actor-quota check + INSERT is a read-modify-write
//! and uses `pg_advisory_xact_lock(hashtext(actor))` for the same
//! reasons documented on `backends::postgres::rate_limit`: serialise
//! per-key concurrent enqueues without optimistic-conflict thrash.
//!
//! INSERT OR IGNORE has no exact Postgres equivalent for the partial
//! unique index. The ergonomic substitute is `ON CONFLICT DO NOTHING`
//! combined with `RETURNING id` to detect whether the row actually
//! inserted — that's how the `enqueue` function reports
//! "already-pending" back to the caller.

use async_trait::async_trait;
use hermod_core::{AgentId, Timestamp, TrustLevel};
use sqlx::{PgPool, Row};
use std::str::FromStr;
use ulid::Ulid;

use crate::error::{Result, StorageError};
use crate::repositories::confirmations::{
    ConfirmationRepository, ConfirmationStatus, HoldRequest, MAX_PENDING_PER_ACTOR,
    PendingConfirmation,
};

#[derive(Debug, Clone)]
pub struct PostgresConfirmationRepository {
    pool: PgPool,
}

impl PostgresConfirmationRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    async fn enqueue_locked(
        &self,
        conn: &mut sqlx::PgConnection,
        req: &HoldRequest<'_>,
        id: &str,
        now: Timestamp,
    ) -> Result<Option<String>> {
        let pending: i64 = sqlx::query_scalar(
            r#"SELECT COUNT(*) FROM pending_confirmations
               WHERE actor = $1 AND status = 'pending'"#,
        )
        .bind(req.actor.as_str())
        .fetch_one(&mut *conn)
        .await?;
        if pending as u64 >= MAX_PENDING_PER_ACTOR {
            return Err(StorageError::QuotaExceeded(format!(
                "actor {} has {} pending confirmations (cap {MAX_PENDING_PER_ACTOR})",
                req.actor.as_str(),
                pending,
            )));
        }

        // Postgres `ON CONFLICT (envelope_id) WHERE status = 'pending'
        // DO NOTHING` honours the partial unique index
        // `idx_pending_confirmations_envelope_pending`. `RETURNING id`
        // distinguishes "inserted" (one row returned) from
        // "deduplicated" (no rows returned).
        let inserted = sqlx::query_scalar::<_, String>(
            r#"
            INSERT INTO pending_confirmations
              (id, envelope_id, requested_at, actor, intent, sensitivity,
               trust_level, summary, envelope_cbor, status)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'pending')
            ON CONFLICT (envelope_id) WHERE status = 'pending'
            DO NOTHING
            RETURNING id
            "#,
        )
        .bind(id)
        .bind(req.envelope_id.to_string())
        .bind(now.unix_ms())
        .bind(req.actor.as_str())
        .bind(req.intent.as_str())
        .bind(req.sensitivity)
        .bind(req.trust_level.as_str())
        .bind(req.summary)
        .bind(req.envelope_cbor)
        .fetch_optional(&mut *conn)
        .await?;
        Ok(inserted)
    }
}

#[async_trait]
impl ConfirmationRepository for PostgresConfirmationRepository {
    async fn enqueue(&self, req: HoldRequest<'_>) -> Result<Option<String>> {
        let id = Ulid::new().to_string();
        let now = Timestamp::now();

        let mut tx = self.pool.begin().await?;
        // Per-actor pessimistic lock: serialises concurrent enqueues
        // for the same actor so the quota check + INSERT is atomic
        // without SERIALIZABLE retry storms. Other actors proceed in
        // parallel.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1)::bigint)")
            .bind(req.actor.as_str())
            .execute(&mut *tx)
            .await?;
        let outcome = self.enqueue_locked(&mut tx, &req, &id, now).await?;
        tx.commit().await?;
        Ok(outcome)
    }

    async fn list_pending(
        &self,
        limit: u32,
        after_id: Option<&str>,
    ) -> Result<Vec<PendingConfirmation>> {
        // Two SQL forms because the parameter index of LIMIT differs
        // depending on whether the cursor filter is present.
        let rows = match after_id {
            Some(after) => {
                sqlx::query(
                    r#"SELECT id, requested_at, actor, intent, sensitivity, trust_level,
                              summary, envelope_cbor, status, decided_at, decided_by
                       FROM pending_confirmations
                       WHERE status = 'pending' AND id > $1
                       ORDER BY id ASC
                       LIMIT $2"#,
                )
                .bind(after)
                .bind(limit as i64)
                .fetch_all(&self.pool)
                .await?
            }
            None => {
                sqlx::query(
                    r#"SELECT id, requested_at, actor, intent, sensitivity, trust_level,
                              summary, envelope_cbor, status, decided_at, decided_by
                       FROM pending_confirmations
                       WHERE status = 'pending'
                       ORDER BY id ASC
                       LIMIT $1"#,
                )
                .bind(limit as i64)
                .fetch_all(&self.pool)
                .await?
            }
        };
        rows.into_iter().map(row_to_pending).collect()
    }

    async fn get(&self, id: &str) -> Result<Option<PendingConfirmation>> {
        let row = sqlx::query(
            r#"SELECT id, requested_at, actor, intent, sensitivity, trust_level,
                      summary, envelope_cbor, status, decided_at, decided_by
               FROM pending_confirmations
               WHERE id = $1"#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(row_to_pending).transpose()
    }

    async fn expire_pending_older_than(&self, cutoff_ms: i64) -> Result<u64> {
        let res = sqlx::query(
            r#"UPDATE pending_confirmations
               SET status = 'expired', decided_at = $1
               WHERE status = 'pending' AND requested_at <= $2"#,
        )
        .bind(cutoff_ms)
        .bind(cutoff_ms)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    async fn decide(
        &self,
        id: &str,
        new_status: ConfirmationStatus,
        decided_by: &AgentId,
        now: Timestamp,
    ) -> Result<bool> {
        let res = sqlx::query(
            r#"UPDATE pending_confirmations
               SET status = $1, decided_at = $2, decided_by = $3
               WHERE id = $4 AND status = 'pending'"#,
        )
        .bind(new_status.as_str())
        .bind(now.unix_ms())
        .bind(decided_by.as_str())
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }
}

fn row_to_pending(row: sqlx::postgres::PgRow) -> Result<PendingConfirmation> {
    let id: String = row.try_get("id")?;
    let requested_at =
        Timestamp::from_unix_ms(row.try_get("requested_at")?).map_err(StorageError::Core)?;
    let actor_str: String = row.try_get("actor")?;
    let actor = AgentId::from_str(&actor_str).map_err(StorageError::Core)?;
    let intent_s: String = row.try_get("intent")?;
    let intent =
        crate::HoldedIntent::from_str(&intent_s).map_err(crate::error::StorageError::Core)?;
    let sensitivity: String = row.try_get("sensitivity")?;
    let trust_str: String = row.try_get("trust_level")?;
    let trust_level = TrustLevel::from_str(&trust_str).map_err(StorageError::Core)?;
    let summary: String = row.try_get("summary")?;
    let envelope_cbor: Vec<u8> = row.try_get("envelope_cbor")?;
    let status_str: String = row.try_get("status")?;
    let status = ConfirmationStatus::from_str(&status_str).map_err(StorageError::Core)?;
    let decided_at = row
        .try_get::<Option<i64>, _>("decided_at")?
        .map(Timestamp::from_unix_ms)
        .transpose()
        .map_err(StorageError::Core)?;
    let decided_by_str: Option<String> = row.try_get("decided_by")?;
    let decided_by = match decided_by_str {
        Some(s) => Some(AgentId::from_str(&s).map_err(StorageError::Core)?),
        None => None,
    };
    Ok(PendingConfirmation {
        id,
        requested_at,
        actor,
        intent,
        sensitivity,
        trust_level,
        summary,
        envelope_cbor,
        status,
        decided_at,
        decided_by,
    })
}
