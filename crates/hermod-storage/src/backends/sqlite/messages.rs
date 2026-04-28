//! SQLite implementation of `MessageRepository`.

use async_trait::async_trait;
use hermod_core::{
    AgentId, MessageBody, MessageId, MessageKind, MessagePriority, MessageStatus, Timestamp,
};
use sqlx::{Row, SqlitePool};
use std::str::FromStr;

use crate::error::{Result, StorageError};
use crate::repositories::messages::{
    InboxFilter, MessagePruneOutcome, MessageRecord, MessageRepository, TransitionOutcome,
};

#[derive(Debug, Clone)]
pub struct SqliteMessageRepository {
    pool: SqlitePool,
}

impl SqliteMessageRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

const SELECT_BY_ID: &str = r#"
    SELECT id, thread_id, from_agent, to_agent, kind, priority, body_json,
           envelope_cbor, status, created_at, delivered_at, read_at, expires_at,
           file_blob_location, delivery_endpoint
    FROM messages WHERE id = ?
"#;

#[async_trait]
impl MessageRepository for SqliteMessageRepository {
    async fn enqueue(&self, record: &MessageRecord) -> Result<()> {
        let body_json = serde_json::to_string(&record.body.summary_json())?;

        sqlx::query(
            r#"
            INSERT INTO messages
                (id, thread_id, from_agent, to_agent, kind, priority, body_json,
                 envelope_cbor, status, created_at, delivered_at, read_at, expires_at,
                 attempts, next_attempt_at, file_blob_location, delivery_endpoint)
            VALUES
                (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO NOTHING
            "#,
        )
        .bind(record.id.to_string())
        .bind(record.thread_id.map(|id| id.to_string()))
        .bind(record.from_agent.as_str())
        .bind(record.to_agent.as_str())
        .bind(record.kind.as_str())
        .bind(record.priority.as_str())
        .bind(body_json)
        .bind(&record.envelope_cbor)
        .bind(record.status.as_str())
        .bind(record.created_at.unix_ms())
        .bind(record.delivered_at.map(|t| t.unix_ms()))
        .bind(record.read_at.map(|t| t.unix_ms()))
        .bind(record.expires_at.map(|t| t.unix_ms()))
        .bind(record.attempts as i64)
        .bind(record.next_attempt_at.map(|t| t.unix_ms()))
        .bind(record.file_blob_location.as_deref())
        .bind(record.delivery_endpoint.as_deref())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn claim_pending_remote(
        &self,
        worker_id: &str,
        now: Timestamp,
        claim_ttl_ms: i64,
        limit: u32,
    ) -> Result<Vec<MessageRecord>> {
        let now_ms = now.unix_ms();
        let stale_before = now_ms - claim_ttl_ms;

        // Single atomic claim. SQLite executes the UPDATE (incl. its
        // SELECT subquery) under one writer lock; concurrent workers
        // serialise here without needing an explicit transaction. The
        // router stamps `delivery_endpoint` at send time, so the outbox
        // path never reads `agents.endpoint` — brokered envelopes
        // (recipient with no directory endpoint, delivered via the
        // configured upstream broker) and standard remote envelopes
        // share one retry mechanism.
        let rows = sqlx::query(
            r#"
            UPDATE messages
            SET claim_token = ?1, claimed_at = ?2
            WHERE id IN (
              SELECT m.id
              FROM messages m
              WHERE m.status = 'pending'
                AND m.delivery_endpoint IS NOT NULL
                AND (m.next_attempt_at IS NULL OR m.next_attempt_at <= ?2)
                AND (m.claim_token IS NULL OR m.claimed_at < ?3)
              ORDER BY
                CASE m.priority
                  WHEN 'urgent' THEN 0
                  WHEN 'high'   THEN 1
                  WHEN 'normal' THEN 2
                  WHEN 'low'    THEN 3
                  ELSE 4
                END ASC,
                COALESCE(m.next_attempt_at, m.created_at) ASC
              LIMIT ?4
            )
            RETURNING id, thread_id, from_agent, to_agent, kind, priority,
                      body_json, envelope_cbor, status, created_at,
                      delivered_at, read_at, expires_at, attempts, next_attempt_at,
                      file_blob_location, delivery_endpoint
            "#,
        )
        .bind(worker_id)
        .bind(now_ms)
        .bind(stale_before)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(row_to_message).collect()
    }

    async fn release_claim(&self, id: &MessageId) -> Result<()> {
        sqlx::query(r#"UPDATE messages SET claim_token = NULL, claimed_at = NULL WHERE id = ?"#)
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn record_send_attempt(
        &self,
        id: &MessageId,
        attempts: u32,
        next_attempt_at: Option<Timestamp>,
    ) -> Result<()> {
        sqlx::query(
            r#"UPDATE messages
               SET attempts = ?, next_attempt_at = ?
               WHERE id = ?"#,
        )
        .bind(attempts as i64)
        .bind(next_attempt_at.map(|t| t.unix_ms()))
        .bind(id.to_string())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn try_fail_pending_or_delivered(&self, id: &MessageId) -> Result<TransitionOutcome> {
        let res = sqlx::query(
            r#"UPDATE messages
               SET status = 'failed', claim_token = NULL, claimed_at = NULL
               WHERE id = ? AND status IN ('pending','delivered')"#,
        )
        .bind(id.to_string())
        .execute(&self.pool)
        .await?;
        Ok(if res.rows_affected() > 0 {
            TransitionOutcome::Applied
        } else {
            TransitionOutcome::NoOp
        })
    }

    async fn fail_pending_to(&self, recipient: &AgentId) -> Result<u64> {
        let res = sqlx::query(
            r#"UPDATE messages
               SET status = 'failed', claim_token = NULL, claimed_at = NULL
               WHERE to_agent = ? AND status IN ('pending','delivered')"#,
        )
        .bind(recipient.as_str())
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    async fn prune_expired(&self, now_ms: i64) -> Result<MessagePruneOutcome> {
        let projected: Vec<Option<String>> = sqlx::query_scalar(
            r#"DELETE FROM messages
               WHERE expires_at IS NOT NULL AND expires_at <= ?
               RETURNING file_blob_location"#,
        )
        .bind(now_ms)
        .fetch_all(&self.pool)
        .await?;
        Ok(prune_outcome_from_projected(projected))
    }

    async fn prune_terminal_older_than(&self, cutoff_ms: i64) -> Result<MessagePruneOutcome> {
        let projected: Vec<Option<String>> = sqlx::query_scalar(
            r#"DELETE FROM messages
               WHERE status IN ('read','failed')
                 AND COALESCE(read_at, delivered_at, created_at) <= ?
               RETURNING file_blob_location"#,
        )
        .bind(cutoff_ms)
        .fetch_all(&self.pool)
        .await?;
        Ok(prune_outcome_from_projected(projected))
    }

    async fn try_deliver_pending(
        &self,
        id: &MessageId,
        at: Timestamp,
    ) -> Result<TransitionOutcome> {
        let res = sqlx::query(
            r#"UPDATE messages
               SET status = 'delivered',
                   delivered_at = ?,
                   claim_token = NULL,
                   claimed_at = NULL
               WHERE id = ? AND status = 'pending'"#,
        )
        .bind(at.unix_ms())
        .bind(id.to_string())
        .execute(&self.pool)
        .await?;
        Ok(if res.rows_affected() > 0 {
            TransitionOutcome::Applied
        } else {
            TransitionOutcome::NoOp
        })
    }

    async fn get(&self, id: &MessageId) -> Result<Option<MessageRecord>> {
        let row = sqlx::query(SELECT_BY_ID)
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await?;
        row.map(row_to_message).transpose()
    }

    async fn list_inbox(&self, to: &AgentId, filter: &InboxFilter) -> Result<Vec<MessageRecord>> {
        let statuses = filter
            .statuses
            .clone()
            .unwrap_or_else(|| vec![MessageStatus::Pending, MessageStatus::Delivered]);
        let status_placeholders = comma_placeholders(statuses.len());

        let priorities = filter
            .priority_min
            .map(priorities_at_least)
            .unwrap_or_default();
        let priority_filter = if priorities.is_empty() {
            String::new()
        } else {
            format!(
                " AND priority IN ({}) ",
                comma_placeholders(priorities.len())
            )
        };

        let cursor_filter = if filter.after_id.is_some() {
            " AND id > ? "
        } else {
            ""
        };

        let limit_clause = match filter.limit {
            Some(_) => " LIMIT ? ",
            None => "",
        };

        let sql = format!(
            r#"SELECT id, thread_id, from_agent, to_agent, kind, priority, body_json,
                      envelope_cbor, status, created_at, delivered_at, read_at, expires_at,
                      file_blob_location, delivery_endpoint
               FROM messages
               WHERE to_agent = ? AND status IN ({status_placeholders})
               {priority_filter}
               {cursor_filter}
               ORDER BY id ASC
               {limit_clause}"#
        );

        let mut q = sqlx::query(&sql).bind(to.as_str());
        for s in &statuses {
            q = q.bind(s.as_str());
        }
        for p in &priorities {
            q = q.bind(p.as_str());
        }
        if let Some(after) = &filter.after_id {
            q = q.bind(after.to_string());
        }
        if let Some(limit) = filter.limit {
            q = q.bind(limit as i64);
        }

        let rows = q.fetch_all(&self.pool).await?;
        rows.into_iter().map(row_to_message).collect()
    }

    async fn ack(&self, id: &MessageId, recipient: &AgentId, at: Timestamp) -> Result<bool> {
        let res = sqlx::query(
            r#"UPDATE messages
               SET status = 'read', read_at = ?
               WHERE id = ? AND to_agent = ? AND status IN ('pending','delivered')"#,
        )
        .bind(at.unix_ms())
        .bind(id.to_string())
        .bind(recipient.as_str())
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn count_pending_to(&self, to: &AgentId) -> Result<i64> {
        let row = sqlx::query(
            r#"SELECT COUNT(*) AS n FROM messages
               WHERE to_agent = ? AND status IN ('pending','delivered')"#,
        )
        .bind(to.as_str())
        .fetch_one(&self.pool)
        .await?;
        Ok(row.try_get("n")?)
    }
}

fn priorities_at_least(min: MessagePriority) -> Vec<MessagePriority> {
    [
        MessagePriority::Low,
        MessagePriority::Normal,
        MessagePriority::High,
        MessagePriority::Urgent,
    ]
    .into_iter()
    .filter(|p| *p >= min)
    .collect()
}

fn comma_placeholders(n: usize) -> String {
    std::iter::repeat_n("?", n).collect::<Vec<_>>().join(",")
}

fn prune_outcome_from_projected(projected: Vec<Option<String>>) -> MessagePruneOutcome {
    let rows = projected.len() as u64;
    let blob_locations = projected.into_iter().flatten().collect();
    MessagePruneOutcome {
        rows,
        blob_locations,
    }
}

fn row_to_message(row: sqlx::sqlite::SqliteRow) -> Result<MessageRecord> {
    let id: String = row.try_get("id")?;
    let id = MessageId::from_str(&id).map_err(StorageError::Core)?;

    let thread_id: Option<String> = row.try_get("thread_id")?;
    let thread_id = thread_id
        .map(|s| MessageId::from_str(&s))
        .transpose()
        .map_err(StorageError::Core)?;

    let from_agent: String = row.try_get("from_agent")?;
    let from_agent = AgentId::from_str(&from_agent).map_err(StorageError::Core)?;
    let to_agent: String = row.try_get("to_agent")?;
    let to_agent = AgentId::from_str(&to_agent).map_err(StorageError::Core)?;

    let kind: String = row.try_get("kind")?;
    let kind = MessageKind::from_str(&kind).map_err(StorageError::Core)?;

    let priority: String = row.try_get("priority")?;
    let priority = MessagePriority::from_str(&priority).map_err(StorageError::Core)?;

    let body_json: String = row.try_get("body_json")?;
    let kind_for_body =
        MessageKind::from_str(&row.try_get::<String, _>("kind")?).map_err(StorageError::Core)?;
    let (body, file_size) = if matches!(kind_for_body, MessageKind::File) {
        let meta: FileBodyMeta = serde_json::from_str(&body_json)?;
        let body = MessageBody::File {
            name: meta.name,
            mime: meta.mime,
            hash: serde_bytes::ByteBuf::from(
                hex::decode(&meta.hash)
                    .map_err(|e| StorageError::decode("body_json.hash", e.to_string()))?,
            ),
            data: serde_bytes::ByteBuf::default(),
        };
        (body, Some(meta.size))
    } else {
        (serde_json::from_str::<MessageBody>(&body_json)?, None)
    };

    let envelope_cbor: Vec<u8> = row.try_get("envelope_cbor")?;

    let status: String = row.try_get("status")?;
    let status = MessageStatus::from_str(&status).map_err(StorageError::Core)?;

    let created_at =
        Timestamp::from_unix_ms(row.try_get("created_at")?).map_err(StorageError::Core)?;
    let delivered_at = row
        .try_get::<Option<i64>, _>("delivered_at")?
        .map(Timestamp::from_unix_ms)
        .transpose()
        .map_err(StorageError::Core)?;
    let read_at = row
        .try_get::<Option<i64>, _>("read_at")?
        .map(Timestamp::from_unix_ms)
        .transpose()
        .map_err(StorageError::Core)?;
    let expires_at = row
        .try_get::<Option<i64>, _>("expires_at")?
        .map(Timestamp::from_unix_ms)
        .transpose()
        .map_err(StorageError::Core)?;

    let attempts: i64 = row.try_get("attempts").unwrap_or(0);
    let next_attempt_at = row
        .try_get::<Option<i64>, _>("next_attempt_at")
        .ok()
        .flatten()
        .map(Timestamp::from_unix_ms)
        .transpose()
        .map_err(StorageError::Core)?;

    let file_blob_location: Option<String> = row
        .try_get::<Option<String>, _>("file_blob_location")
        .ok()
        .flatten();

    let delivery_endpoint: Option<String> = row
        .try_get::<Option<String>, _>("delivery_endpoint")
        .ok()
        .flatten();

    Ok(MessageRecord {
        id,
        thread_id,
        from_agent,
        to_agent,
        kind,
        priority,
        body,
        envelope_cbor,
        status,
        created_at,
        delivered_at,
        read_at,
        expires_at,
        attempts: attempts.max(0) as u32,
        next_attempt_at,
        file_blob_location,
        file_size,
        delivery_endpoint,
    })
}

/// Metadata-only projection of a `MessageBody::File` as it appears in
/// the `messages.body_json` column. Mirrors `MessageBody::summary_json`.
#[derive(serde::Deserialize)]
struct FileBodyMeta {
    name: String,
    mime: String,
    #[allow(dead_code)] // surfaced via the metadata projection
    size: u64,
    hash: String,
}
