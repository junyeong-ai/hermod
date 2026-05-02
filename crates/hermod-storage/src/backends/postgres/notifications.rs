//! PostgreSQL implementation of [`NotificationRepository`].
//!
//! Functional twin of `backends::sqlite::SqliteNotificationRepository`.
//! Dialect substitutions: `?N` → `$N` placeholders; outbox claim uses
//! `FOR UPDATE SKIP LOCKED` on the inner SELECT instead of relying on
//! SQLite's writer lock.

use async_trait::async_trait;
use hermod_core::{AgentId, MessageId, NotificationStatus, Timestamp};
use sqlx::{PgPool, Row};
use std::str::FromStr;

use crate::error::{Result, StorageError};
use crate::repositories::messages::TransitionOutcome;
use crate::repositories::notifications::{
    EnqueueOutcome, EnqueueRequest, NotificationRecord, NotificationRepository,
};

#[derive(Debug, Clone)]
pub struct PostgresNotificationRepository {
    pool: PgPool,
}

impl PostgresNotificationRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl NotificationRepository for PostgresNotificationRepository {
    async fn enqueue(&self, req: &EnqueueRequest, max_pending: u32) -> Result<EnqueueOutcome> {
        let res = sqlx::query(
            r#"INSERT INTO notifications
                  (id, recipient_agent_id, message_id, status, sound, attempts, created_at)
               SELECT $1, $2, $3, 'pending', $4, 0, $5
               WHERE (
                  SELECT COUNT(*) FROM notifications
                   WHERE recipient_agent_id = $2
                     AND status IN ('pending','failed')
               ) < $6"#,
        )
        .bind(&req.id)
        .bind(req.recipient_agent_id.as_str())
        .bind(req.message_id.to_string())
        .bind(req.sound.as_deref())
        .bind(req.created_at.unix_ms())
        .bind(max_pending as i64)
        .execute(&self.pool)
        .await?;
        Ok(if res.rows_affected() == 0 {
            EnqueueOutcome::BackPressure
        } else {
            EnqueueOutcome::Inserted
        })
    }

    async fn claim_pending(
        &self,
        worker_id: &str,
        recipient: &AgentId,
        now: Timestamp,
        claim_ttl_ms: i64,
        limit: u32,
    ) -> Result<Vec<NotificationRecord>> {
        let now_ms = now.unix_ms();
        let stale_before = now_ms - claim_ttl_ms;
        let rows = sqlx::query(
            r#"UPDATE notifications
                  SET claim_token = $1, claimed_at = $2
                WHERE id IN (
                  SELECT id FROM notifications
                   WHERE recipient_agent_id = $3
                     AND status = 'pending'
                     AND (claim_token IS NULL OR claimed_at < $4)
                   ORDER BY created_at ASC
                   LIMIT $5
                   FOR UPDATE SKIP LOCKED
                )
                RETURNING id, recipient_agent_id, message_id, status, sound,
                          attempts, claim_token, claimed_at, dispatched_at,
                          failed_reason, created_at"#,
        )
        .bind(worker_id)
        .bind(now_ms)
        .bind(recipient.as_str())
        .bind(stale_before)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_notification).collect()
    }

    async fn mark_dispatched(
        &self,
        id: &str,
        claim_token: &str,
        at: Timestamp,
    ) -> Result<TransitionOutcome> {
        let res = sqlx::query(
            r#"UPDATE notifications
                  SET status = 'dispatched',
                      dispatched_at = $1,
                      attempts = attempts + 1,
                      claim_token = NULL,
                      claimed_at = NULL
                WHERE id = $2 AND claim_token = $3 AND status = 'pending'"#,
        )
        .bind(at.unix_ms())
        .bind(id)
        .bind(claim_token)
        .execute(&self.pool)
        .await?;
        Ok(if res.rows_affected() > 0 {
            TransitionOutcome::Applied
        } else {
            TransitionOutcome::NoOp
        })
    }

    async fn mark_failed(
        &self,
        id: &str,
        claim_token: &str,
        reason: &str,
    ) -> Result<TransitionOutcome> {
        let res = sqlx::query(
            r#"UPDATE notifications
                  SET status = 'failed',
                      failed_reason = $1,
                      attempts = attempts + 1,
                      claim_token = NULL,
                      claimed_at = NULL
                WHERE id = $2 AND claim_token = $3 AND status = 'pending'"#,
        )
        .bind(reason)
        .bind(id)
        .bind(claim_token)
        .execute(&self.pool)
        .await?;
        Ok(if res.rows_affected() > 0 {
            TransitionOutcome::Applied
        } else {
            TransitionOutcome::NoOp
        })
    }

    async fn dismiss(&self, id: &str, recipient: &AgentId) -> Result<TransitionOutcome> {
        let res = sqlx::query(
            r#"UPDATE notifications
                  SET status = 'dismissed',
                      claim_token = NULL,
                      claimed_at = NULL
                WHERE id = $1 AND recipient_agent_id = $2
                  AND status IN ('pending','failed')"#,
        )
        .bind(id)
        .bind(recipient.as_str())
        .execute(&self.pool)
        .await?;
        Ok(if res.rows_affected() > 0 {
            TransitionOutcome::Applied
        } else {
            TransitionOutcome::NoOp
        })
    }

    async fn list(
        &self,
        recipient: &AgentId,
        statuses: Option<&[NotificationStatus]>,
        limit: u32,
    ) -> Result<Vec<NotificationRecord>> {
        let mut sql = String::from(
            r#"SELECT id, recipient_agent_id, message_id, status, sound,
                      attempts, claim_token, claimed_at, dispatched_at,
                      failed_reason, created_at
                 FROM notifications
                WHERE recipient_agent_id = $1"#,
        );
        let mut next_arg = 2;
        if let Some(s) = statuses
            && !s.is_empty()
        {
            let placeholders = (next_arg..next_arg + s.len())
                .map(|i| format!("${i}"))
                .collect::<Vec<_>>()
                .join(",");
            sql.push_str(&format!(" AND status IN ({placeholders})"));
            next_arg += s.len();
        }
        sql.push_str(&format!(" ORDER BY created_at DESC LIMIT ${next_arg}"));
        let mut q = sqlx::query(&sql).bind(recipient.as_str());
        if let Some(s) = statuses {
            for v in s {
                q = q.bind(v.as_str());
            }
        }
        q = q.bind(limit as i64);
        let rows = q.fetch_all(&self.pool).await?;
        rows.into_iter().map(row_to_notification).collect()
    }

    async fn purge_terminal_older_than(&self, cutoff_ms: i64) -> Result<u64> {
        let res = sqlx::query(
            r#"DELETE FROM notifications
                WHERE status IN ('dispatched','failed','dismissed')
                  AND created_at <= $1"#,
        )
        .bind(cutoff_ms)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    async fn count_open_for(&self, recipient: &AgentId) -> Result<u64> {
        let row = sqlx::query(
            r#"SELECT COUNT(*) AS n FROM notifications
                WHERE recipient_agent_id = $1
                  AND status IN ('pending','failed')"#,
        )
        .bind(recipient.as_str())
        .fetch_one(&self.pool)
        .await?;
        let n: i64 = row.try_get("n")?;
        Ok(n.max(0) as u64)
    }
}

fn row_to_notification(row: sqlx::postgres::PgRow) -> Result<NotificationRecord> {
    let status: String = row.try_get("status")?;
    let status = NotificationStatus::from_str(&status).map_err(StorageError::Core)?;
    let recipient_str: String = row.try_get("recipient_agent_id")?;
    let recipient_agent_id = AgentId::from_str(&recipient_str).map_err(StorageError::Core)?;
    let message_id_str: String = row.try_get("message_id")?;
    let message_id = MessageId::from_str(&message_id_str).map_err(StorageError::Core)?;
    let claimed_at = row
        .try_get::<Option<i64>, _>("claimed_at")?
        .map(Timestamp::from_unix_ms)
        .transpose()
        .map_err(StorageError::Core)?;
    let dispatched_at = row
        .try_get::<Option<i64>, _>("dispatched_at")?
        .map(Timestamp::from_unix_ms)
        .transpose()
        .map_err(StorageError::Core)?;
    let created_at =
        Timestamp::from_unix_ms(row.try_get("created_at")?).map_err(StorageError::Core)?;
    let attempts: i64 = row.try_get("attempts").unwrap_or(0);
    Ok(NotificationRecord {
        id: row.try_get("id")?,
        recipient_agent_id,
        message_id,
        status,
        sound: row.try_get("sound")?,
        attempts: attempts.max(0) as u32,
        claim_token: row.try_get("claim_token")?,
        claimed_at,
        dispatched_at,
        failed_reason: row.try_get("failed_reason")?,
        created_at,
    })
}
