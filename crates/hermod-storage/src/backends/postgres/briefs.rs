//! PostgreSQL implementation of `BriefRepository`.
//!
//! Functional twin of `backends::sqlite::SqliteBriefRepository`. Same DELETE +
//! INSERT pattern under a transaction to handle the
//! `(agent_id, COALESCE(topic, ''))` uniqueness across NULL topic.

use async_trait::async_trait;
use hermod_core::{AgentId, Timestamp};
use sqlx::{PgPool, Row};
use std::str::FromStr;

use crate::error::{Result, StorageError};
use crate::repositories::briefs::{BriefRecord, BriefRepository};

#[derive(Debug, Clone)]
pub struct PostgresBriefRepository {
    pool: PgPool,
}

impl PostgresBriefRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl BriefRepository for PostgresBriefRepository {
    async fn prune_expired(&self, now_ms: i64) -> Result<u64> {
        let res =
            sqlx::query(r#"DELETE FROM briefs WHERE expires_at IS NOT NULL AND expires_at <= $1"#)
                .bind(now_ms)
                .execute(&self.pool)
                .await?;
        Ok(res.rows_affected())
    }

    async fn upsert(&self, record: &BriefRecord) -> Result<()> {
        // Same shape as SqliteBriefRepository::upsert — DELETE + INSERT inside
        // a tx because the natural-key uniqueness is over a generated
        // column (`COALESCE(topic, '')`) that we can't directly target
        // with `ON CONFLICT`.
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            r#"DELETE FROM briefs
               WHERE agent_id = $1 AND COALESCE(topic, '') = COALESCE($2, '')"#,
        )
        .bind(record.agent_id.as_str())
        .bind(record.topic.as_deref())
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            r#"INSERT INTO briefs (agent_id, topic, summary, published_at, expires_at)
               VALUES ($1, $2, $3, $4, $5)"#,
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
                       WHERE agent_id = $1 AND topic = $2
                         AND (expires_at IS NULL OR expires_at > $3)
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
                       WHERE agent_id = $1
                         AND (expires_at IS NULL OR expires_at > $2)
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

fn row_to_brief(row: sqlx::postgres::PgRow) -> Result<BriefRecord> {
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
