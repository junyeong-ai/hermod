//! SQLite implementations of `WorkspaceRepository`, `ChannelRepository`,
//! `DiscoveredChannelRepository`, and `WorkspaceMemberRepository`.

use async_trait::async_trait;
use hermod_core::{AgentId, Timestamp, WorkspaceVisibility};
use hermod_crypto::{ChannelId, ChannelMacKey, WorkspaceId, WorkspaceSecret};
use sqlx::{Row, SqlitePool};
use std::str::FromStr;

use crate::error::{Result, StorageError};
use crate::repositories::workspaces::{
    ChannelMessage, ChannelRecord, ChannelRepository, DiscoveredChannel,
    DiscoveredChannelRepository, WorkspaceMemberRepository, WorkspaceRecord, WorkspaceRepository,
};

#[derive(Debug, Clone)]
pub struct SqliteWorkspaceRepository {
    pool: SqlitePool,
}

impl SqliteWorkspaceRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl WorkspaceRepository for SqliteWorkspaceRepository {
    async fn upsert(&self, w: &WorkspaceRecord) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO workspaces
                (id, name, visibility, secret, created_locally, muted,
                 joined_at, last_active)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                name             = excluded.name,
                visibility       = excluded.visibility,
                secret           = excluded.secret,
                created_locally  = excluded.created_locally,
                muted            = excluded.muted,
                last_active      = excluded.last_active
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
               FROM workspaces WHERE id = ?"#,
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
        let res = sqlx::query(r#"DELETE FROM workspaces WHERE id = ?"#)
            .bind(id.to_hex())
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn set_muted(&self, id: &WorkspaceId, muted: bool) -> Result<bool> {
        let res = sqlx::query(r#"UPDATE workspaces SET muted = ? WHERE id = ?"#)
            .bind(muted as i64)
            .bind(id.to_hex())
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }
}

#[derive(Debug, Clone)]
pub struct SqliteChannelRepository {
    pool: SqlitePool,
}

impl SqliteChannelRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ChannelRepository for SqliteChannelRepository {
    async fn upsert(&self, c: &ChannelRecord) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO channels (id, workspace_id, name, mac_key, muted, joined_at, last_active)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                name        = excluded.name,
                mac_key     = excluded.mac_key,
                muted       = excluded.muted,
                last_active = excluded.last_active
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
               FROM channels WHERE id = ?"#,
        )
        .bind(id.to_hex())
        .fetch_optional(&self.pool)
        .await?;
        row.map(row_to_channel).transpose()
    }

    async fn list_in(&self, workspace: &WorkspaceId) -> Result<Vec<ChannelRecord>> {
        let rows = sqlx::query(
            r#"SELECT id, workspace_id, name, mac_key, muted, joined_at, last_active
               FROM channels WHERE workspace_id = ? ORDER BY name"#,
        )
        .bind(workspace.to_hex())
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_channel).collect()
    }

    async fn delete(&self, id: &ChannelId) -> Result<bool> {
        let res = sqlx::query(r#"DELETE FROM channels WHERE id = ?"#)
            .bind(id.to_hex())
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn set_muted(&self, id: &ChannelId, muted: bool) -> Result<bool> {
        let res = sqlx::query(r#"UPDATE channels SET muted = ? WHERE id = ?"#)
            .bind(muted as i64)
            .bind(id.to_hex())
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn record_message(&self, m: &ChannelMessage) -> Result<()> {
        sqlx::query(
            r#"INSERT OR IGNORE INTO channel_messages
               (id, channel_id, from_agent, body_text, received_at)
               VALUES (?, ?, ?, ?, ?)"#,
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
               FROM channel_messages WHERE channel_id = ?
               ORDER BY received_at DESC LIMIT ?"#,
        )
        .bind(channel.to_hex())
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_channel_message).collect()
    }
}

#[derive(Debug, Clone)]
pub struct SqliteDiscoveredChannelRepository {
    pool: SqlitePool,
}

impl SqliteDiscoveredChannelRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl DiscoveredChannelRepository for SqliteDiscoveredChannelRepository {
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
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(workspace_id, channel_id) DO UPDATE SET
                channel_name  = excluded.channel_name,
                advertised_by = excluded.advertised_by,
                last_seen     = excluded.last_seen
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
               FROM discovered_channels WHERE workspace_id = ?
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
               FROM discovered_channels WHERE channel_id = ?"#,
        )
        .bind(channel_id.to_hex())
        .fetch_optional(&self.pool)
        .await?;
        row.map(row_to_discovered).transpose()
    }

    async fn prune_older_than(&self, cutoff_ms: i64) -> Result<u64> {
        let res = sqlx::query(r#"DELETE FROM discovered_channels WHERE last_seen < ?"#)
            .bind(cutoff_ms)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected())
    }
}

#[derive(Debug, Clone)]
pub struct SqliteWorkspaceMemberRepository {
    pool: SqlitePool,
}

impl SqliteWorkspaceMemberRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl WorkspaceMemberRepository for SqliteWorkspaceMemberRepository {
    async fn touch(&self, workspace: &WorkspaceId, agent: &AgentId, now: Timestamp) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO workspace_members (workspace_id, agent_id, first_seen, last_seen)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(workspace_id, agent_id) DO UPDATE SET
                last_seen = excluded.last_seen
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
        let rows = sqlx::query(r#"SELECT agent_id FROM workspace_members WHERE workspace_id = ?"#)
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
        // the same publish would deliver to a different subset each call.
        let rows = sqlx::query(
            r#"SELECT DISTINCT agent_id FROM workspace_members
               WHERE agent_id != ? ORDER BY agent_id"#,
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

fn row_to_workspace(row: sqlx::sqlite::SqliteRow) -> Result<WorkspaceRecord> {
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

fn row_to_channel(row: sqlx::sqlite::SqliteRow) -> Result<ChannelRecord> {
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

fn row_to_channel_message(row: sqlx::sqlite::SqliteRow) -> Result<ChannelMessage> {
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

fn row_to_discovered(row: sqlx::sqlite::SqliteRow) -> Result<DiscoveredChannel> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Database;
    use crate::backends::sqlite::SqliteDatabase;
    use crate::repositories::agents::AgentRecord;
    use hermod_core::{PubkeyBytes, TrustLevel};

    async fn fresh_db() -> SqliteDatabase {
        let mut p = std::env::temp_dir();
        p.push(format!("hermod-ws-{}.sqlite", ulid::Ulid::new()));
        SqliteDatabase::connect(
            &p,
            std::sync::Arc::new(hermod_crypto::LocalKeySigner::new(std::sync::Arc::new(
                hermod_crypto::Keypair::generate(),
            ))) as std::sync::Arc<dyn hermod_crypto::Signer>,
            std::sync::Arc::new(crate::blobs::MemoryBlobStore::new()),
        )
        .await
        .unwrap()
    }

    fn fake_agent(byte: u8) -> AgentId {
        let pk = PubkeyBytes([byte; 32]);
        hermod_crypto::agent_id_from_pubkey(&pk)
    }

    async fn ensure_agent(db: &SqliteDatabase, id: &AgentId, byte: u8) {
        let now = Timestamp::now();
        db.agents()
            .upsert(&AgentRecord {
                id: id.clone(),
                pubkey: PubkeyBytes([byte; 32]),
                host_pubkey: None,
                endpoint: None,
                via_agent: None,
                local_alias: None,
                peer_asserted_alias: None,
                trust_level: TrustLevel::Local,
                tls_fingerprint: None,
                reputation: 0,
                first_seen: now,
                last_seen: Some(now),
            })
            .await
            .unwrap();
    }

    fn workspace(id: WorkspaceId, secret: Option<WorkspaceSecret>) -> WorkspaceRecord {
        let now = Timestamp::now();
        WorkspaceRecord {
            id,
            name: "team".into(),
            visibility: if secret.is_some() {
                WorkspaceVisibility::Private
            } else {
                WorkspaceVisibility::Public
            },
            secret,
            created_locally: true,
            muted: false,
            joined_at: now,
            last_active: Some(now),
        }
    }

    #[tokio::test]
    async fn workspace_roundtrip_private() {
        let db = fresh_db().await;
        ensure_agent(&db, &fake_agent(1), 1).await;
        let secret = WorkspaceSecret::from_bytes([7u8; 32]);
        let id = secret.workspace_id();
        db.workspaces()
            .upsert(&workspace(id, Some(secret)))
            .await
            .unwrap();
        let got = db.workspaces().get(&id).await.unwrap().unwrap();
        assert_eq!(got.name, "team");
        assert_eq!(got.visibility, WorkspaceVisibility::Private);
        assert!(got.secret.is_some());
        assert!(got.created_locally);
        assert!(!got.muted);
    }

    #[tokio::test]
    async fn workspace_delete_cascades() {
        let db = fresh_db().await;
        let creator = fake_agent(2);
        ensure_agent(&db, &creator, 2).await;
        let secret = WorkspaceSecret::from_bytes([8u8; 32]);
        let ws_id = secret.workspace_id();
        let now = Timestamp::now();
        db.workspaces()
            .upsert(&workspace(ws_id, Some(secret.clone())))
            .await
            .unwrap();
        let ch_id = secret.channel_id("general");
        db.channels()
            .upsert(&ChannelRecord {
                id: ch_id,
                workspace_id: ws_id,
                name: "general".into(),
                mac_key: Some(secret.channel_mac_key("general")),
                muted: false,
                joined_at: now,
                last_active: None,
            })
            .await
            .unwrap();
        db.channels()
            .record_message(&ChannelMessage {
                id: hermod_core::MessageId::new(),
                channel_id: ch_id,
                from_agent: creator.clone(),
                body_text: "hi".into(),
                received_at: now,
            })
            .await
            .unwrap();
        db.workspace_members()
            .touch(&ws_id, &creator, now)
            .await
            .unwrap();

        assert!(db.workspaces().delete(&ws_id).await.unwrap());
        assert!(db.workspaces().get(&ws_id).await.unwrap().is_none());
        assert!(db.channels().get(&ch_id).await.unwrap().is_none());
        assert!(db.channels().history(&ch_id, 10).await.unwrap().is_empty());
        assert!(
            db.workspace_members()
                .list(&ws_id)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn channel_history_records_and_orders() {
        let db = fresh_db().await;
        let creator = fake_agent(3);
        ensure_agent(&db, &creator, 3).await;
        let secret = WorkspaceSecret::from_bytes([9u8; 32]);
        let ws_id = secret.workspace_id();
        let now = Timestamp::now();
        db.workspaces()
            .upsert(&workspace(ws_id, Some(secret.clone())))
            .await
            .unwrap();
        let ch_id = secret.channel_id("general");
        db.channels()
            .upsert(&ChannelRecord {
                id: ch_id,
                workspace_id: ws_id,
                name: "general".into(),
                mac_key: Some(secret.channel_mac_key("general")),
                muted: false,
                joined_at: now,
                last_active: None,
            })
            .await
            .unwrap();
        let m1 = ChannelMessage {
            id: hermod_core::MessageId::new(),
            channel_id: ch_id,
            from_agent: creator.clone(),
            body_text: "first".into(),
            received_at: now,
        };
        db.channels().record_message(&m1).await.unwrap();
        let later = Timestamp::from_unix_ms(now.unix_ms() + 1_000).unwrap();
        let m2 = ChannelMessage {
            id: hermod_core::MessageId::new(),
            channel_id: ch_id,
            from_agent: creator.clone(),
            body_text: "second".into(),
            received_at: later,
        };
        db.channels().record_message(&m2).await.unwrap();
        let history = db.channels().history(&ch_id, 10).await.unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].body_text, "second");
        assert_eq!(history[1].body_text, "first");
    }

    #[tokio::test]
    async fn workspace_member_touch_dedupes() {
        let db = fresh_db().await;
        let me = fake_agent(4);
        let other = fake_agent(5);
        ensure_agent(&db, &me, 4).await;
        ensure_agent(&db, &other, 5).await;
        let secret = WorkspaceSecret::from_bytes([10u8; 32]);
        let id = secret.workspace_id();
        let now = Timestamp::now();
        db.workspaces()
            .upsert(&workspace(id, Some(secret)))
            .await
            .unwrap();
        db.workspace_members().touch(&id, &me, now).await.unwrap();
        db.workspace_members()
            .touch(&id, &other, now)
            .await
            .unwrap();
        db.workspace_members().touch(&id, &me, now).await.unwrap();
        let members = db.workspace_members().list(&id).await.unwrap();
        assert_eq!(members.len(), 2);
    }

    #[tokio::test]
    async fn mute_round_trip() {
        let db = fresh_db().await;
        let secret = WorkspaceSecret::from_bytes([11u8; 32]);
        let id = secret.workspace_id();
        db.workspaces()
            .upsert(&workspace(id, Some(secret)))
            .await
            .unwrap();
        assert!(!db.workspaces().get(&id).await.unwrap().unwrap().muted);
        assert!(db.workspaces().set_muted(&id, true).await.unwrap());
        assert!(db.workspaces().get(&id).await.unwrap().unwrap().muted);
    }
}
