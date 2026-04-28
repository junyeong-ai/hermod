//! PostgreSQL implementations of `AgentPresenceRepository` and
//! `McpSessionRepository`.
//!
//! Functional twins of `backends::sqlite::{SqliteAgentPresenceRepository,
//! SqliteMcpSessionRepository}`. The MCP-session repo's atomic
//! attach/detach/prune routines wrap their COUNT + write under a
//! transaction so the `was_live` / `is_live` snapshot is internally
//! consistent.

use async_trait::async_trait;
use hermod_core::{AgentId, PresenceStatus, Timestamp};
use sqlx::{PgPool, Row};
use std::str::FromStr;

use crate::error::{Result, StorageError};
use crate::repositories::presence::{
    AgentPresenceRecord, AgentPresenceRepository, DetachOutcome, McpSession, McpSessionRepository,
    ObservedPresence, PruneOutcome,
};

#[derive(Debug, Clone)]
pub struct PostgresAgentPresenceRepository {
    pool: PgPool,
}

impl PostgresAgentPresenceRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl AgentPresenceRepository for PostgresAgentPresenceRepository {
    async fn set_manual(
        &self,
        agent: &AgentId,
        status: PresenceStatus,
        set_at: Timestamp,
        expires_at: Option<Timestamp>,
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO agent_presence
                (agent_id, manual_status, manual_status_set_at, manual_status_expires_at)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT(agent_id) DO UPDATE SET
                manual_status            = EXCLUDED.manual_status,
                manual_status_set_at     = EXCLUDED.manual_status_set_at,
                manual_status_expires_at = EXCLUDED.manual_status_expires_at
            "#,
        )
        .bind(agent.as_str())
        .bind(status.as_str())
        .bind(set_at.unix_ms())
        .bind(expires_at.map(|t| t.unix_ms()))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn observe_peer(&self, peer: &AgentId, observed: ObservedPresence) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO agent_presence
                (agent_id, manual_status, manual_status_set_at,
                 manual_status_expires_at,
                 peer_live, peer_live_updated_at, peer_live_expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT(agent_id) DO UPDATE SET
                manual_status            = EXCLUDED.manual_status,
                manual_status_set_at     = EXCLUDED.manual_status_set_at,
                manual_status_expires_at = EXCLUDED.manual_status_expires_at,
                peer_live                = EXCLUDED.peer_live,
                peer_live_updated_at     = EXCLUDED.peer_live_updated_at,
                peer_live_expires_at     = EXCLUDED.peer_live_expires_at
            "#,
        )
        .bind(peer.as_str())
        .bind(observed.manual_status.map(|s| s.as_str()))
        .bind(observed.observed_at.unix_ms())
        .bind(observed.expires_at.unix_ms())
        // Postgres column is BIGINT (matches SQLite layout) — bind
        // i64 explicitly so the bool↔int coercion is unambiguous.
        .bind(observed.live as i64)
        .bind(observed.observed_at.unix_ms())
        .bind(observed.expires_at.unix_ms())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn clear_manual(&self, agent: &AgentId) -> Result<()> {
        sqlx::query(
            r#"UPDATE agent_presence
               SET manual_status            = NULL,
                   manual_status_set_at     = NULL,
                   manual_status_expires_at = NULL
               WHERE agent_id = $1"#,
        )
        .bind(agent.as_str())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get(&self, agent: &AgentId) -> Result<Option<AgentPresenceRecord>> {
        let row = sqlx::query(
            r#"SELECT agent_id, manual_status, manual_status_set_at, manual_status_expires_at,
                      peer_live, peer_live_updated_at, peer_live_expires_at
               FROM agent_presence
               WHERE agent_id = $1"#,
        )
        .bind(agent.as_str())
        .fetch_optional(&self.pool)
        .await?;
        row.map(row_to_presence).transpose()
    }
}

#[derive(Debug, Clone)]
pub struct PostgresMcpSessionRepository {
    pool: PgPool,
}

impl PostgresMcpSessionRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl McpSessionRepository for PostgresMcpSessionRepository {
    async fn attach_atomic(&self, session: &McpSession, ttl_ms: i64) -> Result<bool> {
        let mut tx = self.pool.begin().await?;
        let cutoff = session.attached_at.unix_ms() - ttl_ms;
        let row =
            sqlx::query(r#"SELECT COUNT(*) AS n FROM mcp_sessions WHERE last_heartbeat_at > $1"#)
                .bind(cutoff)
                .fetch_one(&mut *tx)
                .await?;
        let prior: i64 = row.try_get("n")?;
        sqlx::query(
            r#"INSERT INTO mcp_sessions
                  (session_id, attached_at, last_heartbeat_at, client_name, client_version)
               VALUES ($1, $2, $3, $4, $5)"#,
        )
        .bind(&session.session_id)
        .bind(session.attached_at.unix_ms())
        .bind(session.last_heartbeat_at.unix_ms())
        .bind(session.client_name.as_deref())
        .bind(session.client_version.as_deref())
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(prior > 0)
    }

    async fn heartbeat(&self, session_id: &str, now: Timestamp) -> Result<bool> {
        let res = sqlx::query(
            r#"UPDATE mcp_sessions
               SET last_heartbeat_at = $1
               WHERE session_id = $2"#,
        )
        .bind(now.unix_ms())
        .bind(session_id)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn detach_atomic(
        &self,
        session_id: &str,
        now: Timestamp,
        ttl_ms: i64,
    ) -> Result<DetachOutcome> {
        let mut tx = self.pool.begin().await?;
        let cutoff = now.unix_ms() - ttl_ms;
        let prior_row =
            sqlx::query(r#"SELECT COUNT(*) AS n FROM mcp_sessions WHERE last_heartbeat_at > $1"#)
                .bind(cutoff)
                .fetch_one(&mut *tx)
                .await?;
        let prior: i64 = prior_row.try_get("n")?;
        sqlx::query(r#"DELETE FROM mcp_sessions WHERE session_id = $1"#)
            .bind(session_id)
            .execute(&mut *tx)
            .await?;
        let post_row =
            sqlx::query(r#"SELECT COUNT(*) AS n FROM mcp_sessions WHERE last_heartbeat_at > $1"#)
                .bind(cutoff)
                .fetch_one(&mut *tx)
                .await?;
        let post: i64 = post_row.try_get("n")?;
        tx.commit().await?;
        Ok(DetachOutcome {
            was_live: prior > 0,
            is_live: post > 0,
        })
    }

    async fn count_live(&self, now: Timestamp, ttl_ms: i64) -> Result<u64> {
        let cutoff = now.unix_ms() - ttl_ms;
        let row =
            sqlx::query(r#"SELECT COUNT(*) AS n FROM mcp_sessions WHERE last_heartbeat_at > $1"#)
                .bind(cutoff)
                .fetch_one(&self.pool)
                .await?;
        let n: i64 = row.try_get("n")?;
        Ok(n.max(0) as u64)
    }

    async fn prune_with_transition(&self, now: Timestamp, ttl_ms: i64) -> Result<PruneOutcome> {
        let mut tx = self.pool.begin().await?;
        let cutoff = now.unix_ms() - ttl_ms;
        let prior_row =
            sqlx::query(r#"SELECT COUNT(*) AS n FROM mcp_sessions WHERE last_heartbeat_at > $1"#)
                .bind(cutoff)
                .fetch_one(&mut *tx)
                .await?;
        let prior: i64 = prior_row.try_get("n")?;
        let pruned = sqlx::query(r#"DELETE FROM mcp_sessions WHERE last_heartbeat_at <= $1"#)
            .bind(cutoff)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        let post_row =
            sqlx::query(r#"SELECT COUNT(*) AS n FROM mcp_sessions WHERE last_heartbeat_at > $1"#)
                .bind(cutoff)
                .fetch_one(&mut *tx)
                .await?;
        let post: i64 = post_row.try_get("n")?;
        tx.commit().await?;
        Ok(PruneOutcome {
            pruned,
            was_live: prior > 0,
            is_live: post > 0,
        })
    }
}

fn row_to_presence(row: sqlx::postgres::PgRow) -> Result<AgentPresenceRecord> {
    let agent_str: String = row.try_get("agent_id")?;
    let agent_id = AgentId::from_str(&agent_str).map_err(StorageError::Core)?;
    let manual_status = row
        .try_get::<Option<String>, _>("manual_status")?
        .map(|s| PresenceStatus::from_str(&s))
        .transpose()
        .map_err(StorageError::Core)?;
    let manual_status_set_at = row
        .try_get::<Option<i64>, _>("manual_status_set_at")?
        .map(Timestamp::from_unix_ms)
        .transpose()
        .map_err(StorageError::Core)?;
    let manual_status_expires_at = row
        .try_get::<Option<i64>, _>("manual_status_expires_at")?
        .map(Timestamp::from_unix_ms)
        .transpose()
        .map_err(StorageError::Core)?;
    let peer_live = row.try_get::<Option<i64>, _>("peer_live")?.map(|n| n != 0);
    let peer_live_updated_at = row
        .try_get::<Option<i64>, _>("peer_live_updated_at")?
        .map(Timestamp::from_unix_ms)
        .transpose()
        .map_err(StorageError::Core)?;
    let peer_live_expires_at = row
        .try_get::<Option<i64>, _>("peer_live_expires_at")?
        .map(Timestamp::from_unix_ms)
        .transpose()
        .map_err(StorageError::Core)?;
    Ok(AgentPresenceRecord {
        agent_id,
        manual_status,
        manual_status_set_at,
        manual_status_expires_at,
        peer_live,
        peer_live_updated_at,
        peer_live_expires_at,
    })
}
