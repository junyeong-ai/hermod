//! PostgreSQL implementation of `MessageRepository`.
//!
//! Functional twin of `backends::sqlite::SqliteMessageRepository`. Two dialect
//! differences worth noting:
//!
//!   1. **Outbox claim concurrency.** SQLite serialises concurrent
//!      `UPDATE ... WHERE id IN (SELECT ... LIMIT N)` through its
//!      single writer lock, so two workers never see the same set.
//!      Postgres' MVCC lets both workers' SELECTs see the same rows
//!      before either UPDATE commits — a race that would
//!      double-claim. The fix is `FOR UPDATE SKIP LOCKED` on the
//!      inner SELECT: rows already locked by another worker's
//!      in-flight UPDATE are skipped, so each worker gets a disjoint
//!      slice. This is the canonical Postgres outbox-worker
//!      pattern.
//!
//!   2. **Dynamic SQL placeholders.** `list_inbox` composes a WHERE
//!      from up to four conditional clauses (statuses, priorities,
//!      cursor, limit). SQLite's `?` placeholders are positional and
//!      auto-renumber as the SQL grows; Postgres' `$N` requires
//!      explicit numbering that must stay in lock-step with the
//!      bind order, so the builder threads `next_param: u32` through
//!      every conditional append.

use async_trait::async_trait;
use hermod_core::{
    AgentId, MessageBody, MessageDisposition, MessageId, MessageKind, MessagePriority,
    MessageStatus, Timestamp,
};
use sqlx::{PgPool, Row};
use std::str::FromStr;

use crate::error::{Result, StorageError};
use crate::repositories::messages::{
    InboxFilter, MessagePruneOutcome, MessageRecord, MessageRepository, TransitionOutcome,
};

#[derive(Debug, Clone)]
pub struct PostgresMessageRepository {
    pool: PgPool,
}

impl PostgresMessageRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

const SELECT_BY_ID: &str = r#"
    SELECT id, thread_id, from_agent, to_agent, kind, priority, body_json,
           envelope_cbor, status, created_at, delivered_at, read_at, expires_at,
           file_blob_location, delivery_endpoint, disposition
    FROM messages WHERE id = $1
"#;

#[async_trait]
impl MessageRepository for PostgresMessageRepository {
    async fn enqueue(&self, record: &MessageRecord) -> Result<()> {
        let body_json = serde_json::to_string(&record.body.summary_json())?;

        sqlx::query(
            r#"
            INSERT INTO messages
                (id, thread_id, from_agent, to_agent, kind, priority, body_json,
                 envelope_cbor, status, created_at, delivered_at, read_at, expires_at,
                 attempts, next_attempt_at, file_blob_location, delivery_endpoint, disposition)
            VALUES
                ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
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
        .bind(record.disposition.as_str())
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

        // Atomic claim with `FOR UPDATE SKIP LOCKED` so two workers
        // racing on this UPDATE see disjoint candidate sets — see
        // module docs for why this is required on Postgres but not
        // on SQLite. The router stamps `delivery_endpoint` at send
        // time, so the outbox path never reads `agents.endpoint` —
        // brokered envelopes (recipient with no directory endpoint,
        // delivered via the configured upstream broker) and standard
        // remote envelopes share one retry mechanism.
        let rows = sqlx::query(
            r#"
            UPDATE messages
            SET claim_token = $1, claimed_at = $2
            WHERE id IN (
              SELECT m.id
              FROM messages m
              WHERE m.status = 'pending'
                AND m.delivery_endpoint IS NOT NULL
                AND (m.next_attempt_at IS NULL OR m.next_attempt_at <= $2)
                AND (m.claim_token IS NULL OR m.claimed_at < $3)
              ORDER BY
                CASE m.priority
                  WHEN 'urgent' THEN 0
                  WHEN 'high'   THEN 1
                  WHEN 'normal' THEN 2
                  WHEN 'low'    THEN 3
                  ELSE 4
                END ASC,
                COALESCE(m.next_attempt_at, m.created_at) ASC
              LIMIT $4
              FOR UPDATE SKIP LOCKED
            )
            RETURNING id, thread_id, from_agent, to_agent, kind, priority,
                      body_json, envelope_cbor, status, created_at,
                      delivered_at, read_at, expires_at, attempts, next_attempt_at,
                      file_blob_location, delivery_endpoint, disposition
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
        sqlx::query(r#"UPDATE messages SET claim_token = NULL, claimed_at = NULL WHERE id = $1"#)
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
               SET attempts = $1, next_attempt_at = $2
               WHERE id = $3"#,
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
               WHERE id = $1 AND status IN ('pending','delivered')"#,
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
               WHERE to_agent = $1 AND status IN ('pending','delivered')"#,
        )
        .bind(recipient.as_str())
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    async fn prune_expired(&self, now_ms: i64) -> Result<MessagePruneOutcome> {
        let projected: Vec<Option<String>> = sqlx::query_scalar(
            r#"DELETE FROM messages
               WHERE expires_at IS NOT NULL AND expires_at <= $1
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
                 AND COALESCE(read_at, delivered_at, created_at) <= $1
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
                   delivered_at = $1,
                   claim_token = NULL,
                   claimed_at = NULL
               WHERE id = $2 AND status = 'pending'"#,
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
        use std::fmt::Write;

        let statuses = filter
            .statuses
            .clone()
            .unwrap_or_else(|| vec![MessageStatus::Pending, MessageStatus::Delivered]);
        let priorities = filter
            .priority_min
            .map(priorities_at_least)
            .unwrap_or_default();

        // Bind order: $1 = to_agent, then statuses, then priorities,
        // then cursor, then limit. Track the next free param index
        // throughout so each placeholder string matches its bind
        // position.
        let mut next_param: u32 = 2;

        let status_placeholders = numbered_placeholders(next_param as usize, statuses.len());
        next_param += statuses.len() as u32;

        let priority_filter = if priorities.is_empty() {
            String::new()
        } else {
            let p = numbered_placeholders(next_param as usize, priorities.len());
            next_param += priorities.len() as u32;
            format!(" AND priority IN ({p}) ")
        };

        let dispositions = filter.dispositions.clone();
        let disposition_filter = match &dispositions {
            Some(d) if !d.is_empty() => {
                let p = numbered_placeholders(next_param as usize, d.len());
                next_param += d.len() as u32;
                format!(" AND disposition IN ({p}) ")
            }
            _ => String::new(),
        };

        let cursor_filter = if filter.after_id.is_some() {
            let c = format!(" AND id > ${next_param} ");
            next_param += 1;
            c
        } else {
            String::new()
        };

        let limit_clause = match filter.limit {
            Some(_) => {
                let l = format!(" LIMIT ${next_param} ");
                // next_param += 1; — last conditional, no further use
                l
            }
            None => String::new(),
        };

        let mut sql = String::with_capacity(448);
        let _ = write!(
            sql,
            "SELECT id, thread_id, from_agent, to_agent, kind, priority, body_json, \
             envelope_cbor, status, created_at, delivered_at, read_at, expires_at, \
             file_blob_location, delivery_endpoint, disposition \
             FROM messages \
             WHERE to_agent = $1 AND status IN ({status_placeholders}) \
             {priority_filter}{disposition_filter}{cursor_filter} \
             ORDER BY id ASC{limit_clause}"
        );

        let mut q = sqlx::query(&sql).bind(to.as_str());
        for s in &statuses {
            q = q.bind(s.as_str());
        }
        for p in &priorities {
            q = q.bind(p.as_str());
        }
        if let Some(d) = &dispositions {
            for v in d {
                q = q.bind(v.as_str());
            }
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
               SET status = 'read', read_at = $1
               WHERE id = $2 AND to_agent = $3 AND status IN ('pending','delivered')"#,
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
               WHERE to_agent = $1 AND status IN ('pending','delivered')"#,
        )
        .bind(to.as_str())
        .fetch_one(&self.pool)
        .await?;
        Ok(row.try_get("n")?)
    }

    async fn promote_to_push(
        &self,
        id: &MessageId,
        recipient: &AgentId,
    ) -> Result<TransitionOutcome> {
        let res = sqlx::query(
            r#"UPDATE messages
                  SET disposition = 'push'
                WHERE id = $1 AND to_agent = $2 AND disposition = 'silent'"#,
        )
        .bind(id.to_string())
        .bind(recipient.as_str())
        .execute(&self.pool)
        .await?;
        Ok(if res.rows_affected() > 0 {
            TransitionOutcome::Applied
        } else {
            TransitionOutcome::NoOp
        })
    }

    async fn count_silent_to(&self, to: &AgentId) -> Result<i64> {
        let row = sqlx::query(
            r#"SELECT COUNT(*) AS n FROM messages
               WHERE to_agent = $1 AND status IN ('pending','delivered')
                 AND disposition = 'silent'"#,
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

/// `$start, $start+1, …, $start+n-1` — Postgres needs explicit
/// placeholder numbering when building dynamic IN-lists.
fn numbered_placeholders(start: usize, n: usize) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(n * 5);
    for i in 0..n {
        if i > 0 {
            s.push(',');
        }
        let _ = write!(s, "${}", start + i);
    }
    s
}

fn prune_outcome_from_projected(projected: Vec<Option<String>>) -> MessagePruneOutcome {
    let rows = projected.len() as u64;
    let blob_locations = projected.into_iter().flatten().collect();
    MessagePruneOutcome {
        rows,
        blob_locations,
    }
}

fn row_to_message(row: sqlx::postgres::PgRow) -> Result<MessageRecord> {
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

    let disposition: String = row.try_get("disposition")?;
    let disposition = MessageDisposition::from_str(&disposition).map_err(StorageError::Core)?;

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
        disposition,
    })
}

#[derive(serde::Deserialize)]
struct FileBodyMeta {
    name: String,
    mime: String,
    #[allow(dead_code)]
    size: u64,
    hash: String,
}
