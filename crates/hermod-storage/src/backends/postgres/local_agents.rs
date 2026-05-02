//! Postgres implementation of [`LocalAgentRepository`].
//!
//! Mirrors `backends::sqlite::local_agents::SqliteLocalAgentRepository`
//! shape-for-shape. Dialect substitutions: `?` → `$N` placeholders,
//! `INSERT OR IGNORE` → `INSERT ... ON CONFLICT DO NOTHING`. Every
//! method's behaviour is byte-identical with the SQLite variant.

use async_trait::async_trait;
use hermod_core::{AgentId, CapabilityTagSet, Timestamp};
use sqlx::{PgPool, Row};
use std::str::FromStr;

use crate::error::{Result, StorageError};
use crate::repositories::local_agents::{
    LocalAgentInsertOutcome, LocalAgentRecord, LocalAgentRemoveOutcome, LocalAgentRepository,
};

#[derive(Debug, Clone)]
pub struct PostgresLocalAgentRepository {
    pool: PgPool,
}

impl PostgresLocalAgentRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl LocalAgentRepository for PostgresLocalAgentRepository {
    async fn insert(&self, record: &LocalAgentRecord) -> Result<LocalAgentInsertOutcome> {
        let tags_json = serde_json::to_string(&record.tags)?;
        let res = sqlx::query(
            r#"INSERT INTO local_agents
               (agent_id, bearer_hash, workspace_root, created_at, tags)
               VALUES ($1, $2, $3, $4, $5)
               ON CONFLICT (agent_id) DO NOTHING"#,
        )
        .bind(record.agent_id.as_str())
        .bind(record.bearer_hash.as_slice())
        .bind(record.workspace_root.as_deref())
        .bind(record.created_at.unix_ms())
        .bind(&tags_json)
        .execute(&self.pool)
        .await?;
        Ok(if res.rows_affected() == 0 {
            LocalAgentInsertOutcome::AlreadyHosted
        } else {
            LocalAgentInsertOutcome::Created
        })
    }

    async fn list(&self) -> Result<Vec<LocalAgentRecord>> {
        let rows = sqlx::query(
            r#"SELECT agent_id, bearer_hash, workspace_root, created_at, tags
               FROM local_agents
               ORDER BY created_at ASC"#,
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_local_agent).collect()
    }

    async fn lookup_by_id(&self, id: &AgentId) -> Result<Option<LocalAgentRecord>> {
        let row = sqlx::query(
            r#"SELECT agent_id, bearer_hash, workspace_root, created_at, tags
               FROM local_agents WHERE agent_id = $1"#,
        )
        .bind(id.as_str())
        .fetch_optional(&self.pool)
        .await?;
        row.map(row_to_local_agent).transpose()
    }

    async fn lookup_by_bearer_hash(&self, hash: &[u8; 32]) -> Result<Option<AgentId>> {
        let row: Option<String> =
            sqlx::query_scalar(r#"SELECT agent_id FROM local_agents WHERE bearer_hash = $1"#)
                .bind(hash.as_slice())
                .fetch_optional(&self.pool)
                .await?;
        row.map(|s| AgentId::from_str(&s).map_err(StorageError::Core))
            .transpose()
    }

    async fn rotate_bearer(&self, id: &AgentId, new_hash: [u8; 32]) -> Result<bool> {
        let res = sqlx::query(r#"UPDATE local_agents SET bearer_hash = $1 WHERE agent_id = $2"#)
            .bind(new_hash.as_slice())
            .bind(id.as_str())
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn remove(&self, id: &AgentId) -> Result<LocalAgentRemoveOutcome> {
        let res = sqlx::query(r#"DELETE FROM local_agents WHERE agent_id = $1"#)
            .bind(id.as_str())
            .execute(&self.pool)
            .await?;
        Ok(if res.rows_affected() == 0 {
            LocalAgentRemoveOutcome::NotFound
        } else {
            LocalAgentRemoveOutcome::Removed
        })
    }

    async fn set_tags(&self, id: &AgentId, tags: &CapabilityTagSet) -> Result<bool> {
        let json = serde_json::to_string(tags)?;
        let res = sqlx::query(r#"UPDATE local_agents SET tags = $1 WHERE agent_id = $2"#)
            .bind(&json)
            .bind(id.as_str())
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }
}

fn row_to_local_agent(row: sqlx::postgres::PgRow) -> Result<LocalAgentRecord> {
    let id_str: String = row.try_get("agent_id")?;
    let agent_id = AgentId::from_str(&id_str).map_err(StorageError::Core)?;
    let bearer_bytes: Vec<u8> = row.try_get("bearer_hash")?;
    if bearer_bytes.len() != 32 {
        return Err(StorageError::decode(
            "bearer_hash",
            format!("expected 32 bytes, got {}", bearer_bytes.len()),
        ));
    }
    let mut bearer_hash = [0u8; 32];
    bearer_hash.copy_from_slice(&bearer_bytes);
    let workspace_root: Option<String> = row.try_get("workspace_root")?;
    let created_at_ms: i64 = row.try_get("created_at")?;
    let created_at = Timestamp::from_unix_ms(created_at_ms).map_err(StorageError::Core)?;
    let tags_json: String = row.try_get("tags")?;
    let raw: Vec<String> = serde_json::from_str(&tags_json)?;
    let (tags, _dropped) = CapabilityTagSet::parse_lossy(raw);
    Ok(LocalAgentRecord {
        agent_id,
        bearer_hash,
        workspace_root,
        created_at,
        tags,
    })
}
