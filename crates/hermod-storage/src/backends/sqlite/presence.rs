//! SQLite implementations of `AgentPresenceRepository` and `McpSessionRepository`.

use async_trait::async_trait;
use hermod_core::{AgentId, McpSessionId, MessageId, PresenceStatus, SessionLabel, Timestamp};
use sqlx::{Row, SqlitePool};
use std::str::FromStr;

use crate::error::{Result, StorageError};
use crate::repositories::presence::{
    AgentPresenceRecord, AgentPresenceRepository, AttachOutcome, AttachParams, CursorAdvance,
    DetachOutcome, McpSession, McpSessionRepository, ObservedPresence, PruneOutcome,
};

#[derive(Debug, Clone)]
pub struct SqliteAgentPresenceRepository {
    pool: SqlitePool,
}

impl SqliteAgentPresenceRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl AgentPresenceRepository for SqliteAgentPresenceRepository {
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
            VALUES (?, ?, ?, ?)
            ON CONFLICT(agent_id) DO UPDATE SET
                manual_status            = excluded.manual_status,
                manual_status_set_at     = excluded.manual_status_set_at,
                manual_status_expires_at = excluded.manual_status_expires_at
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
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(agent_id) DO UPDATE SET
                manual_status            = excluded.manual_status,
                manual_status_set_at     = excluded.manual_status_set_at,
                manual_status_expires_at = excluded.manual_status_expires_at,
                peer_live                = excluded.peer_live,
                peer_live_updated_at     = excluded.peer_live_updated_at,
                peer_live_expires_at     = excluded.peer_live_expires_at
            "#,
        )
        .bind(peer.as_str())
        .bind(observed.manual_status.map(|s| s.as_str()))
        .bind(observed.observed_at.unix_ms())
        .bind(observed.expires_at.unix_ms())
        .bind(observed.live as i32)
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
               WHERE agent_id = ?"#,
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
               WHERE agent_id = ?"#,
        )
        .bind(agent.as_str())
        .fetch_optional(&self.pool)
        .await?;
        row.map(row_to_presence).transpose()
    }
}

#[derive(Debug, Clone)]
pub struct SqliteMcpSessionRepository {
    pool: SqlitePool,
}

impl SqliteMcpSessionRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl McpSessionRepository for SqliteMcpSessionRepository {
    async fn attach(&self, params: AttachParams) -> Result<AttachOutcome> {
        let mut tx = self.pool.begin().await?;
        let cutoff = params.attached_at.unix_ms() - params.ttl_ms;

        // Live-count BEFORE the insert — drives offline → online presence broadcast.
        let prior_live: i64 =
            sqlx::query(r#"SELECT COUNT(*) AS n FROM mcp_sessions WHERE last_heartbeat_at > ?"#)
                .bind(cutoff)
                .fetch_one(&mut *tx)
                .await?
                .try_get("n")?;

        // Label-collision resolution: if the operator supplied a
        // label, look for an existing row holding it for the same
        // agent. Live ⇒ reject; stale ⇒ carry cursors and delete.
        let mut carried_message: Option<MessageId> = None;
        let mut carried_confirmation: Option<String> = None;
        let mut carried_resolved: Option<u64> = None;
        let mut resumed = false;
        if let Some(label) = params.session_label.as_ref()
            && let Some(row) = sqlx::query(
                r#"SELECT session_id, last_heartbeat_at,
                          last_message_id, last_confirmation_id, last_resolved_seq
                     FROM mcp_sessions
                    WHERE agent_id = ? AND session_label = ?"#,
            )
            .bind(params.agent_id.as_str())
            .bind(label.as_str())
            .fetch_optional(&mut *tx)
            .await?
        {
            let last_heartbeat: i64 = row.try_get("last_heartbeat_at")?;
            if last_heartbeat > cutoff {
                // Live holder ⇒ surface the conflict.
                let live_session_id = McpSessionId::from_raw(row.try_get("session_id")?);
                let last_heartbeat_at =
                    Timestamp::from_unix_ms(last_heartbeat).map_err(StorageError::Core)?;
                tx.rollback().await?;
                return Ok(AttachOutcome::LabelInUse {
                    live_session_id,
                    last_heartbeat_at,
                });
            }
            // Stale ⇒ harvest cursors and delete.
            carried_message = row
                .try_get::<Option<String>, _>("last_message_id")?
                .map(|s| s.parse::<MessageId>())
                .transpose()
                .map_err(StorageError::Core)?;
            carried_confirmation = row.try_get::<Option<String>, _>("last_confirmation_id")?;
            carried_resolved = row
                .try_get::<Option<i64>, _>("last_resolved_seq")?
                .map(|n| n.max(0) as u64);
            let stale_id: String = row.try_get("session_id")?;
            sqlx::query(r#"DELETE FROM mcp_sessions WHERE session_id = ?"#)
                .bind(&stale_id)
                .execute(&mut *tx)
                .await?;
            resumed = true;
        }

        sqlx::query(
            r#"INSERT INTO mcp_sessions
                  (session_id, agent_id, session_label, attached_at, last_heartbeat_at,
                   client_name, client_version,
                   last_message_id, last_confirmation_id, last_resolved_seq)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"#,
        )
        .bind(params.session_id.as_str())
        .bind(params.agent_id.as_str())
        .bind(params.session_label.as_ref().map(|l| l.as_str()))
        .bind(params.attached_at.unix_ms())
        .bind(params.attached_at.unix_ms())
        .bind(params.client_name.as_deref())
        .bind(params.client_version.as_deref())
        .bind(carried_message.as_ref().map(|m| m.to_string()))
        .bind(carried_confirmation.as_deref())
        .bind(carried_resolved.map(|n| n as i64))
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;

        Ok(AttachOutcome::Inserted {
            session: McpSession {
                session_id: params.session_id,
                agent_id: params.agent_id,
                session_label: params.session_label,
                attached_at: params.attached_at,
                last_heartbeat_at: params.attached_at,
                client_name: params.client_name,
                client_version: params.client_version,
                last_message_id: carried_message,
                last_confirmation_id: carried_confirmation,
                last_resolved_seq: carried_resolved,
            },
            was_live: prior_live > 0,
            resumed,
        })
    }

    async fn heartbeat(&self, session_id: &McpSessionId, now: Timestamp) -> Result<bool> {
        let res = sqlx::query(
            r#"UPDATE mcp_sessions
               SET last_heartbeat_at = ?
               WHERE session_id = ?"#,
        )
        .bind(now.unix_ms())
        .bind(session_id.as_str())
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn cursor_advance(
        &self,
        session_id: &McpSessionId,
        advance: &CursorAdvance,
    ) -> Result<bool> {
        // Per-column UPDATE with COALESCE so callers that pass `None`
        // for a cursor leave it untouched (idempotent partial advance).
        let res = sqlx::query(
            r#"UPDATE mcp_sessions
                  SET last_message_id      = COALESCE(?, last_message_id),
                      last_confirmation_id = COALESCE(?, last_confirmation_id),
                      last_resolved_seq    = COALESCE(?, last_resolved_seq)
                WHERE session_id = ?"#,
        )
        .bind(advance.last_message_id.as_ref().map(|m| m.to_string()))
        .bind(advance.last_confirmation_id.as_deref())
        .bind(advance.last_resolved_seq.map(|n| n as i64))
        .bind(session_id.as_str())
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn detach_atomic(
        &self,
        session_id: &McpSessionId,
        now: Timestamp,
        ttl_ms: i64,
    ) -> Result<DetachOutcome> {
        let mut tx = self.pool.begin().await?;
        let cutoff = now.unix_ms() - ttl_ms;
        let prior_row =
            sqlx::query(r#"SELECT COUNT(*) AS n FROM mcp_sessions WHERE last_heartbeat_at > ?"#)
                .bind(cutoff)
                .fetch_one(&mut *tx)
                .await?;
        let prior: i64 = prior_row.try_get("n")?;
        sqlx::query(r#"DELETE FROM mcp_sessions WHERE session_id = ?"#)
            .bind(session_id.as_str())
            .execute(&mut *tx)
            .await?;
        let post_row =
            sqlx::query(r#"SELECT COUNT(*) AS n FROM mcp_sessions WHERE last_heartbeat_at > ?"#)
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
            sqlx::query(r#"SELECT COUNT(*) AS n FROM mcp_sessions WHERE last_heartbeat_at > ?"#)
                .bind(cutoff)
                .fetch_one(&self.pool)
                .await?;
        let n: i64 = row.try_get("n")?;
        Ok(n.max(0) as u64)
    }

    async fn count_live_for(&self, agent_id: &AgentId, now: Timestamp, ttl_ms: i64) -> Result<u64> {
        let cutoff = now.unix_ms() - ttl_ms;
        let row = sqlx::query(
            r#"SELECT COUNT(*) AS n FROM mcp_sessions
               WHERE agent_id = ? AND last_heartbeat_at > ?"#,
        )
        .bind(agent_id.as_str())
        .bind(cutoff)
        .fetch_one(&self.pool)
        .await?;
        let n: i64 = row.try_get("n")?;
        Ok(n.max(0) as u64)
    }

    async fn list_for_agent(
        &self,
        agent_id: &AgentId,
        now: Timestamp,
        ttl_ms: i64,
    ) -> Result<Vec<McpSession>> {
        let cutoff = now.unix_ms() - ttl_ms;
        let rows = sqlx::query(
            r#"SELECT session_id, agent_id, session_label, attached_at, last_heartbeat_at,
                      client_name, client_version,
                      last_message_id, last_confirmation_id, last_resolved_seq
                 FROM mcp_sessions
                WHERE agent_id = ? AND last_heartbeat_at > ?
                ORDER BY attached_at ASC"#,
        )
        .bind(agent_id.as_str())
        .bind(cutoff)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_mcp_session).collect()
    }

    async fn get(&self, session_id: &McpSessionId) -> Result<Option<McpSession>> {
        let row = sqlx::query(
            r#"SELECT session_id, agent_id, session_label, attached_at, last_heartbeat_at,
                      client_name, client_version,
                      last_message_id, last_confirmation_id, last_resolved_seq
                 FROM mcp_sessions
                WHERE session_id = ?"#,
        )
        .bind(session_id.as_str())
        .fetch_optional(&self.pool)
        .await?;
        row.map(row_to_mcp_session).transpose()
    }

    async fn prune_with_transition(&self, now: Timestamp, ttl_ms: i64) -> Result<PruneOutcome> {
        let mut tx = self.pool.begin().await?;
        let cutoff = now.unix_ms() - ttl_ms;
        let prior_row =
            sqlx::query(r#"SELECT COUNT(*) AS n FROM mcp_sessions WHERE last_heartbeat_at > ?"#)
                .bind(cutoff)
                .fetch_one(&mut *tx)
                .await?;
        let prior: i64 = prior_row.try_get("n")?;
        let pruned = sqlx::query(r#"DELETE FROM mcp_sessions WHERE last_heartbeat_at <= ?"#)
            .bind(cutoff)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        let post_row =
            sqlx::query(r#"SELECT COUNT(*) AS n FROM mcp_sessions WHERE last_heartbeat_at > ?"#)
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

fn row_to_mcp_session(row: sqlx::sqlite::SqliteRow) -> Result<McpSession> {
    let session_id = McpSessionId::from_raw(row.try_get("session_id")?);
    let agent_id = AgentId::from_str(row.try_get("agent_id")?).map_err(StorageError::Core)?;
    let session_label = row
        .try_get::<Option<String>, _>("session_label")?
        .map(|s| s.parse::<SessionLabel>())
        .transpose()
        .map_err(StorageError::Core)?;
    let attached_at =
        Timestamp::from_unix_ms(row.try_get("attached_at")?).map_err(StorageError::Core)?;
    let last_heartbeat_at =
        Timestamp::from_unix_ms(row.try_get("last_heartbeat_at")?).map_err(StorageError::Core)?;
    let last_message_id = row
        .try_get::<Option<String>, _>("last_message_id")?
        .map(|s| s.parse::<MessageId>())
        .transpose()
        .map_err(StorageError::Core)?;
    let last_confirmation_id = row.try_get::<Option<String>, _>("last_confirmation_id")?;
    let last_resolved_seq = row
        .try_get::<Option<i64>, _>("last_resolved_seq")?
        .map(|n| n.max(0) as u64);
    Ok(McpSession {
        session_id,
        agent_id,
        session_label,
        attached_at,
        last_heartbeat_at,
        client_name: row.try_get("client_name")?,
        client_version: row.try_get("client_version")?,
        last_message_id,
        last_confirmation_id,
        last_resolved_seq,
    })
}

fn row_to_presence(row: sqlx::sqlite::SqliteRow) -> Result<AgentPresenceRecord> {
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
