//! PostgreSQL implementations of `WorkspaceRepository`,
//! `ChannelRepository`, `DiscoveredChannelRepository`, and
//! `WorkspaceMemberRepository`.
//!
//! Functional twins of the SQLite backends. No concurrency primitives
//! beyond standard transactions are needed — every operation is
//! either a single INSERT/UPDATE/DELETE or a SELECT, and the FK
//! cascades on `workspaces`/`channels` are identical in both engines.

use async_trait::async_trait;
use hermod_core::{AgentId, Timestamp, WorkspaceVisibility};
use hermod_crypto::{ChannelId, ChannelMacKey, WorkspaceId, WorkspaceSecret};
use sqlx::{PgPool, Row};
use std::str::FromStr;

use crate::error::{Result, StorageError};
use crate::repositories::workspaces::{
    ChannelMessage, ChannelRecord, ChannelRepository, DiscoveredChannel,
    DiscoveredChannelRepository, WorkspaceMemberRepository, WorkspaceRecord, WorkspaceRepository,
};

#[derive(Debug, Clone)]
pub struct PostgresWorkspaceRepository {
    pool: PgPool,
}

impl PostgresWorkspaceRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl WorkspaceRepository for PostgresWorkspaceRepository {
    async fn upsert(&self, w: &WorkspaceRecord) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO workspaces
                (id, name, visibility, secret, created_locally, muted,
                 joined_at, last_active)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT(id) DO UPDATE SET
                name             = EXCLUDED.name,
                visibility       = EXCLUDED.visibility,
                secret           = EXCLUDED.secret,
                created_locally  = EXCLUDED.created_locally,
                muted            = EXCLUDED.muted,
                last_active      = EXCLUDED.last_active
            "#,
        )
        .bind(w.id.to_hex())
        .bind(&w.name)
        .bind(w.visibility.as_str())
        .bind(w.secret.as_ref().map(|s| s.as_bytes().to_vec()))
        .bind(w.created_locally as i64)
        .bind(w.muted as i64)
        .bind(w.joined_at.unix_ms())
        .bind(w.last_active.map(|t| t.unix_ms()))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get(&self, id: &WorkspaceId) -> Result<Option<WorkspaceRecord>> {
        let row = sqlx::query(
            r#"SELECT id, name, visibility, secret, created_locally, muted,
                      joined_at, last_active
               FROM workspaces WHERE id = $1"#,
        )
        .bind(id.to_hex())
        .fetch_optional(&self.pool)
        .await?;
        row.map(row_to_workspace).transpose()
    }

    async fn list(&self) -> Result<Vec<WorkspaceRecord>> {
        let rows = sqlx::query(
            r#"SELECT id, name, visibility, secret, created_locally, muted,
                      joined_at, last_active
               FROM workspaces ORDER BY joined_at DESC"#,
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_workspace).collect()
    }

    async fn delete(&self, id: &WorkspaceId) -> Result<bool> {
        let res = sqlx::query(r#"DELETE FROM workspaces WHERE id = $1"#)
            .bind(id.to_hex())
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn set_muted(&self, id: &WorkspaceId, muted: bool) -> Result<bool> {
        let res = sqlx::query(r#"UPDATE workspaces SET muted = $1 WHERE id = $2"#)
            .bind(muted as i64)
            .bind(id.to_hex())
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }
}

#[derive(Debug, Clone)]
pub struct PostgresChannelRepository {
    pool: PgPool,
}

impl PostgresChannelRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ChannelRepository for PostgresChannelRepository {
    async fn upsert(&self, c: &ChannelRecord) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO channels (id, workspace_id, name, mac_key, muted, joined_at, last_active)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT(id) DO UPDATE SET
                name        = EXCLUDED.name,
                mac_key     = EXCLUDED.mac_key,
                muted       = EXCLUDED.muted,
                last_active = EXCLUDED.last_active
            "#,
        )
        .bind(c.id.to_hex())
        .bind(c.workspace_id.to_hex())
        .bind(&c.name)
        .bind(c.mac_key.as_ref().map(|k| k.as_bytes().to_vec()))
        .bind(c.muted as i64)
        .bind(c.joined_at.unix_ms())
        .bind(c.last_active.map(|t| t.unix_ms()))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get(&self, id: &ChannelId) -> Result<Option<ChannelRecord>> {
        let row = sqlx::query(
            r#"SELECT id, workspace_id, name, mac_key, muted, joined_at, last_active
               FROM channels WHERE id = $1"#,
        )
        .bind(id.to_hex())
        .fetch_optional(&self.pool)
        .await?;
        row.map(row_to_channel).transpose()
    }

    async fn list_in(&self, workspace: &WorkspaceId) -> Result<Vec<ChannelRecord>> {
        let rows = sqlx::query(
            r#"SELECT id, workspace_id, name, mac_key, muted, joined_at, last_active
               FROM channels WHERE workspace_id = $1 ORDER BY name"#,
        )
        .bind(workspace.to_hex())
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_channel).collect()
    }

    async fn delete(&self, id: &ChannelId) -> Result<bool> {
        let res = sqlx::query(r#"DELETE FROM channels WHERE id = $1"#)
            .bind(id.to_hex())
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn set_muted(&self, id: &ChannelId, muted: bool) -> Result<bool> {
        let res = sqlx::query(r#"UPDATE channels SET muted = $1 WHERE id = $2"#)
            .bind(muted as i64)
            .bind(id.to_hex())
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn record_message(&self, m: &ChannelMessage) -> Result<()> {
        sqlx::query(
            r#"INSERT INTO channel_messages
               (id, channel_id, from_agent, body_text, received_at)
               VALUES ($1, $2, $3, $4, $5)
               ON CONFLICT(id) DO NOTHING"#,
        )
        .bind(m.id.to_string())
        .bind(m.channel_id.to_hex())
        .bind(m.from_agent.as_str())
        .bind(&m.body_text)
        .bind(m.received_at.unix_ms())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn history(&self, channel: &ChannelId, limit: u32) -> Result<Vec<ChannelMessage>> {
        let rows = sqlx::query(
            r#"SELECT id, channel_id, from_agent, body_text, received_at
               FROM channel_messages WHERE channel_id = $1
               ORDER BY received_at DESC LIMIT $2"#,
        )
        .bind(channel.to_hex())
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_channel_message).collect()
    }
}

#[derive(Debug, Clone)]
pub struct PostgresDiscoveredChannelRepository {
    pool: PgPool,
}

impl PostgresDiscoveredChannelRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl DiscoveredChannelRepository for PostgresDiscoveredChannelRepository {
    async fn observe(
        &self,
        workspace_id: &WorkspaceId,
        channel_id: &ChannelId,
        channel_name: &str,
        advertised_by: &AgentId,
        now: Timestamp,
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO discovered_channels
              (workspace_id, channel_id, channel_name, advertised_by,
               discovered_at, last_seen)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT(workspace_id, channel_id) DO UPDATE SET
                channel_name  = EXCLUDED.channel_name,
                advertised_by = EXCLUDED.advertised_by,
                last_seen     = EXCLUDED.last_seen
            "#,
        )
        .bind(workspace_id.to_hex())
        .bind(channel_id.to_hex())
        .bind(channel_name)
        .bind(advertised_by.as_str())
        .bind(now.unix_ms())
        .bind(now.unix_ms())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn list_in(&self, workspace_id: &WorkspaceId) -> Result<Vec<DiscoveredChannel>> {
        let rows = sqlx::query(
            r#"SELECT workspace_id, channel_id, channel_name, advertised_by,
                      discovered_at, last_seen
               FROM discovered_channels WHERE workspace_id = $1
               ORDER BY last_seen DESC"#,
        )
        .bind(workspace_id.to_hex())
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_discovered).collect()
    }

    async fn get(&self, channel_id: &ChannelId) -> Result<Option<DiscoveredChannel>> {
        let row = sqlx::query(
            r#"SELECT workspace_id, channel_id, channel_name, advertised_by,
                      discovered_at, last_seen
               FROM discovered_channels WHERE channel_id = $1"#,
        )
        .bind(channel_id.to_hex())
        .fetch_optional(&self.pool)
        .await?;
        row.map(row_to_discovered).transpose()
    }

    async fn prune_older_than(&self, cutoff_ms: i64) -> Result<u64> {
        let res = sqlx::query(r#"DELETE FROM discovered_channels WHERE last_seen < $1"#)
            .bind(cutoff_ms)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected())
    }
}

#[derive(Debug, Clone)]
pub struct PostgresWorkspaceMemberRepository {
    pool: PgPool,
}

impl PostgresWorkspaceMemberRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl WorkspaceMemberRepository for PostgresWorkspaceMemberRepository {
    async fn touch(
        &self,
        workspace: &WorkspaceId,
        agent: &AgentId,
        now: Timestamp,
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO workspace_members (workspace_id, agent_id, first_seen, last_seen)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT(workspace_id, agent_id) DO UPDATE SET
                last_seen = EXCLUDED.last_seen
            "#,
        )
        .bind(workspace.to_hex())
        .bind(agent.as_str())
        .bind(now.unix_ms())
        .bind(now.unix_ms())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn list(&self, workspace: &WorkspaceId) -> Result<Vec<AgentId>> {
        let rows = sqlx::query(r#"SELECT agent_id FROM workspace_members WHERE workspace_id = $1"#)
            .bind(workspace.to_hex())
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter()
            .map(|row| {
                let s: String = row.try_get("agent_id")?;
                AgentId::from_str(&s).map_err(StorageError::Core)
            })
            .collect()
    }

    async fn list_distinct_excluding(&self, exclude: &AgentId) -> Result<Vec<AgentId>> {
        // ORDER BY agent_id makes the result deterministic — fanout
        // truncates at MAX_FANOUT_PER_CALL, and without a stable order
        // the same publish would deliver to a different subset each
        // call.
        let rows = sqlx::query(
            r#"SELECT DISTINCT agent_id FROM workspace_members
               WHERE agent_id != $1 ORDER BY agent_id"#,
        )
        .bind(exclude.as_str())
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|row| {
                let s: String = row.try_get("agent_id")?;
                AgentId::from_str(&s).map_err(StorageError::Core)
            })
            .collect()
    }
}

fn row_to_workspace(row: sqlx::postgres::PgRow) -> Result<WorkspaceRecord> {
    let id_hex: String = row.try_get("id")?;
    let id = WorkspaceId::from_hex(&id_hex)
        .map_err(|e| StorageError::decode("id", format!("workspace id: {e}")))?;
    let name: String = row.try_get("name")?;
    let visibility_str: String = row.try_get("visibility")?;
    let visibility = WorkspaceVisibility::from_str(&visibility_str).map_err(StorageError::Core)?;
    let secret_blob: Option<Vec<u8>> = row.try_get("secret")?;
    let secret = match secret_blob {
        Some(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            Some(WorkspaceSecret::from_bytes(arr))
        }
        Some(_) => {
            return Err(StorageError::decode(
                "secret",
                "workspace secret blob has wrong length",
            ));
        }
        None => None,
    };
    let created_locally: i64 = row.try_get("created_locally")?;
    let muted: i64 = row.try_get("muted")?;
    let joined_at =
        Timestamp::from_unix_ms(row.try_get("joined_at")?).map_err(StorageError::Core)?;
    let last_active = row
        .try_get::<Option<i64>, _>("last_active")?
        .map(Timestamp::from_unix_ms)
        .transpose()
        .map_err(StorageError::Core)?;
    Ok(WorkspaceRecord {
        id,
        name,
        visibility,
        secret,
        created_locally: created_locally != 0,
        muted: muted != 0,
        joined_at,
        last_active,
    })
}

fn row_to_channel(row: sqlx::postgres::PgRow) -> Result<ChannelRecord> {
    let id_hex: String = row.try_get("id")?;
    let id = ChannelId::from_hex(&id_hex)
        .map_err(|e| StorageError::decode("id", format!("channel id: {e}")))?;
    let ws_hex: String = row.try_get("workspace_id")?;
    let workspace_id = WorkspaceId::from_hex(&ws_hex)
        .map_err(|e| StorageError::decode("workspace_id", format!("workspace id: {e}")))?;
    let name: String = row.try_get("name")?;
    let mac_blob: Option<Vec<u8>> = row.try_get("mac_key")?;
    let mac_key = match mac_blob {
        Some(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            Some(ChannelMacKey::from_bytes(arr))
        }
        Some(_) => {
            return Err(StorageError::decode(
                "mac_key",
                "channel mac_key wrong length",
            ));
        }
        None => None,
    };
    let muted: i64 = row.try_get("muted")?;
    let joined_at =
        Timestamp::from_unix_ms(row.try_get("joined_at")?).map_err(StorageError::Core)?;
    let last_active = row
        .try_get::<Option<i64>, _>("last_active")?
        .map(Timestamp::from_unix_ms)
        .transpose()
        .map_err(StorageError::Core)?;
    Ok(ChannelRecord {
        id,
        workspace_id,
        name,
        mac_key,
        muted: muted != 0,
        joined_at,
        last_active,
    })
}

fn row_to_channel_message(row: sqlx::postgres::PgRow) -> Result<ChannelMessage> {
    let id_str: String = row.try_get("id")?;
    let id = hermod_core::MessageId::from_str(&id_str).map_err(StorageError::Core)?;
    let channel_id_hex: String = row.try_get("channel_id")?;
    let channel_id = ChannelId::from_hex(&channel_id_hex)
        .map_err(|e| StorageError::decode("channel_id", format!("channel id: {e}")))?;
    let from_agent_str: String = row.try_get("from_agent")?;
    let from_agent = AgentId::from_str(&from_agent_str).map_err(StorageError::Core)?;
    let body_text: String = row.try_get("body_text")?;
    let received_at =
        Timestamp::from_unix_ms(row.try_get("received_at")?).map_err(StorageError::Core)?;
    Ok(ChannelMessage {
        id,
        channel_id,
        from_agent,
        body_text,
        received_at,
    })
}

fn row_to_discovered(row: sqlx::postgres::PgRow) -> Result<DiscoveredChannel> {
    let ws_hex: String = row.try_get("workspace_id")?;
    let workspace_id = WorkspaceId::from_hex(&ws_hex)
        .map_err(|e| StorageError::decode("workspace_id", format!("{e}")))?;
    let ch_hex: String = row.try_get("channel_id")?;
    let channel_id = ChannelId::from_hex(&ch_hex)
        .map_err(|e| StorageError::decode("channel_id", format!("{e}")))?;
    let channel_name: String = row.try_get("channel_name")?;
    let advertised_by_str: String = row.try_get("advertised_by")?;
    let advertised_by = AgentId::from_str(&advertised_by_str).map_err(StorageError::Core)?;
    let discovered_at =
        Timestamp::from_unix_ms(row.try_get("discovered_at")?).map_err(StorageError::Core)?;
    let last_seen =
        Timestamp::from_unix_ms(row.try_get("last_seen")?).map_err(StorageError::Core)?;
    Ok(DiscoveredChannel {
        workspace_id,
        channel_id,
        channel_name,
        advertised_by,
        discovered_at,
        last_seen,
    })
}
