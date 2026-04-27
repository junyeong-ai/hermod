//! SQLite implementation of `BriefRepository`.

use async_trait::async_trait;
use hermod_core::{AgentId, Timestamp};
use sqlx::{Row, SqlitePool};
use std::str::FromStr;

use crate::error::{Result, StorageError};
use crate::repositories::briefs::{BriefRecord, BriefRepository};

#[derive(Debug, Clone)]
pub struct SqliteBriefRepository {
    pool: SqlitePool,
}

impl SqliteBriefRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl BriefRepository for SqliteBriefRepository {
    async fn prune_expired(&self, now_ms: i64) -> Result<u64> {
        let res =
            sqlx::query(r#"DELETE FROM briefs WHERE expires_at IS NOT NULL AND expires_at <= ?"#)
                .bind(now_ms)
                .execute(&self.pool)
                .await?;
        Ok(res.rows_affected())
    }

    async fn upsert(&self, record: &BriefRecord) -> Result<()> {
        // The unique constraint is on (agent_id, topic_key) where
        // topic_key = COALESCE(topic, ''). To upsert correctly with a
        // nullable column, resolve via DELETE + INSERT inside a tx.
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            r#"DELETE FROM briefs
               WHERE agent_id = ? AND COALESCE(topic, '') = COALESCE(?, '')"#,
        )
        .bind(record.agent_id.as_str())
        .bind(record.topic.as_deref())
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            r#"INSERT INTO briefs (agent_id, topic, summary, published_at, expires_at)
               VALUES (?, ?, ?, ?, ?)"#,
        )
        .bind(record.agent_id.as_str())
        .bind(record.topic.as_deref())
        .bind(&record.summary)
        .bind(record.published_at.unix_ms())
        .bind(record.expires_at.map(|t| t.unix_ms()))
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn latest(
        &self,
        agent: &AgentId,
        topic: Option<&str>,
        now_ms: i64,
    ) -> Result<Option<BriefRecord>> {
        let row = match topic {
            Some(t) => {
                sqlx::query(
                    r#"SELECT agent_id, topic, summary, published_at, expires_at
                       FROM briefs
                       WHERE agent_id = ? AND topic = ?
                         AND (expires_at IS NULL OR expires_at > ?)
                       LIMIT 1"#,
                )
                .bind(agent.as_str())
                .bind(t)
                .bind(now_ms)
                .fetch_optional(&self.pool)
                .await?
            }
            None => {
                sqlx::query(
                    r#"SELECT agent_id, topic, summary, published_at, expires_at
                       FROM briefs
                       WHERE agent_id = ?
                         AND (expires_at IS NULL OR expires_at > ?)
                       ORDER BY published_at DESC
                       LIMIT 1"#,
                )
                .bind(agent.as_str())
                .bind(now_ms)
                .fetch_optional(&self.pool)
                .await?
            }
        };
        row.map(row_to_brief).transpose()
    }
}

fn row_to_brief(row: sqlx::sqlite::SqliteRow) -> Result<BriefRecord> {
    let agent_str: String = row.try_get("agent_id")?;
    let agent_id = AgentId::from_str(&agent_str).map_err(StorageError::Core)?;
    let topic: Option<String> = row.try_get("topic")?;
    let summary: String = row.try_get("summary")?;
    let published_at =
        Timestamp::from_unix_ms(row.try_get("published_at")?).map_err(StorageError::Core)?;
    let expires_at = row
        .try_get::<Option<i64>, _>("expires_at")?
        .map(Timestamp::from_unix_ms)
        .transpose()
        .map_err(StorageError::Core)?;
    Ok(BriefRecord {
        agent_id,
        topic,
        summary,
        published_at,
        expires_at,
    })
}
