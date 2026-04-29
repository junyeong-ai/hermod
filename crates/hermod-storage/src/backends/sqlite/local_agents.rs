//! SQLite implementation of [`LocalAgentRepository`].

use async_trait::async_trait;
use hermod_core::{AgentId, Timestamp};
use sqlx::{Row, SqlitePool};
use std::str::FromStr;

use crate::error::{Result, StorageError};
use crate::repositories::local_agents::{
    LocalAgentInsertOutcome, LocalAgentRecord, LocalAgentRemoveOutcome, LocalAgentRepository,
};

#[derive(Debug, Clone)]
pub struct SqliteLocalAgentRepository {
    pool: SqlitePool,
}

impl SqliteLocalAgentRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl LocalAgentRepository for SqliteLocalAgentRepository {
    async fn insert(&self, record: &LocalAgentRecord) -> Result<LocalAgentInsertOutcome> {
        // INSERT OR IGNORE — silent no-op when the row already exists,
        // surfaced as `AlreadyHosted`. Bearer rotation is the explicit
        // path for refreshing credentials.
        let res = sqlx::query(
            r#"INSERT OR IGNORE INTO local_agents
               (agent_id, bearer_hash, workspace_root, created_at)
               VALUES (?, ?, ?, ?)"#,
        )
        .bind(record.agent_id.as_str())
        .bind(record.bearer_hash.as_slice())
        .bind(record.workspace_root.as_deref())
        .bind(record.created_at.unix_ms())
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
            r#"SELECT agent_id, bearer_hash, workspace_root, created_at
               FROM local_agents
               ORDER BY created_at ASC"#,
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_local_agent).collect()
    }

    async fn lookup_by_id(&self, id: &AgentId) -> Result<Option<LocalAgentRecord>> {
        let row = sqlx::query(
            r#"SELECT agent_id, bearer_hash, workspace_root, created_at
               FROM local_agents WHERE agent_id = ?"#,
        )
        .bind(id.as_str())
        .fetch_optional(&self.pool)
        .await?;
        row.map(row_to_local_agent).transpose()
    }

    async fn lookup_by_bearer_hash(&self, hash: &[u8; 32]) -> Result<Option<AgentId>> {
        let row: Option<String> =
            sqlx::query_scalar(r#"SELECT agent_id FROM local_agents WHERE bearer_hash = ?"#)
                .bind(hash.as_slice())
                .fetch_optional(&self.pool)
                .await?;
        row.map(|s| AgentId::from_str(&s).map_err(StorageError::Core))
            .transpose()
    }

    async fn rotate_bearer(&self, id: &AgentId, new_hash: [u8; 32]) -> Result<bool> {
        let res = sqlx::query(r#"UPDATE local_agents SET bearer_hash = ? WHERE agent_id = ?"#)
            .bind(new_hash.as_slice())
            .bind(id.as_str())
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn remove(&self, id: &AgentId) -> Result<LocalAgentRemoveOutcome> {
        let res = sqlx::query(r#"DELETE FROM local_agents WHERE agent_id = ?"#)
            .bind(id.as_str())
            .execute(&self.pool)
            .await?;
        Ok(if res.rows_affected() == 0 {
            LocalAgentRemoveOutcome::NotFound
        } else {
            LocalAgentRemoveOutcome::Removed
        })
    }
}

fn row_to_local_agent(row: sqlx::sqlite::SqliteRow) -> Result<LocalAgentRecord> {
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
    Ok(LocalAgentRecord {
        agent_id,
        bearer_hash,
        workspace_root,
        created_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Database;
    use crate::backends::sqlite::SqliteDatabase;
    use crate::repositories::agents::AgentRecord;
    use hermod_core::{Endpoint, PubkeyBytes, TrustLevel};
    use hermod_crypto::{Keypair, LocalKeySigner, Signer};
    use std::sync::Arc;

    async fn fresh_db() -> SqliteDatabase {
        let mut p = std::env::temp_dir();
        p.push(format!("hermod-local-agent-{}.sqlite", ulid::Ulid::new()));
        let signer: Arc<dyn Signer> = Arc::new(LocalKeySigner::new(Arc::new(Keypair::generate())));
        SqliteDatabase::connect(&p, signer, Arc::new(crate::blobs::MemoryBlobStore::new()))
            .await
            .unwrap()
    }

    /// Each call returns a distinct record — fresh keypair (so the
    /// `agents` foreign key insert never collides) plus a per-call
    /// bearer hash (so the UNIQUE index on `bearer_hash` doesn't
    /// reject the second test row). `created_at` is stored at
    /// millisecond resolution in the DB, so the test seed uses a
    /// millisecond-aligned timestamp to round-trip cleanly.
    fn make_local_agent_record() -> LocalAgentRecord {
        let kp = Keypair::generate();
        let mut bearer_hash = [0u8; 32];
        bearer_hash[..16].copy_from_slice(&kp.agent_id().as_str().as_bytes()[..16]);
        LocalAgentRecord {
            agent_id: kp.agent_id(),
            bearer_hash,
            workspace_root: Some("/tmp/proj".into()),
            created_at: Timestamp::from_unix_ms(Timestamp::now().unix_ms()).unwrap(),
        }
    }

    /// Insert requires a parent agents row (FK). Helper does both.
    async fn insert_local(
        db: &SqliteDatabase,
        record: &LocalAgentRecord,
    ) -> LocalAgentInsertOutcome {
        let kp_pubkey = PubkeyBytes([1u8; 32]);
        db.agents()
            .upsert(&AgentRecord {
                id: record.agent_id.clone(),
                pubkey: kp_pubkey,
                host_pubkey: Some(kp_pubkey),
                endpoint: Some(Endpoint::Wss(hermod_core::WssEndpoint {
                    host: "host.example".into(),
                    port: 7823,
                })),
                local_alias: None,
                peer_asserted_alias: None,
                trust_level: TrustLevel::Local,
                tls_fingerprint: None,
                reputation: 0,
                first_seen: record.created_at,
                last_seen: Some(record.created_at),
            })
            .await
            .unwrap();
        db.local_agents().insert(record).await.unwrap()
    }

    #[tokio::test]
    async fn insert_then_lookup_by_id_round_trips() {
        let db = fresh_db().await;
        let record = make_local_agent_record();
        assert_eq!(
            insert_local(&db, &record).await,
            LocalAgentInsertOutcome::Created
        );
        let got = db
            .local_agents()
            .lookup_by_id(&record.agent_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got, record);
    }

    #[tokio::test]
    async fn duplicate_insert_reports_already_hosted() {
        let db = fresh_db().await;
        let record = make_local_agent_record();
        insert_local(&db, &record).await;
        assert_eq!(
            db.local_agents().insert(&record).await.unwrap(),
            LocalAgentInsertOutcome::AlreadyHosted
        );
    }

    #[tokio::test]
    async fn lookup_by_bearer_hash_finds_agent() {
        let db = fresh_db().await;
        let record = make_local_agent_record();
        insert_local(&db, &record).await;
        let got = db
            .local_agents()
            .lookup_by_bearer_hash(&record.bearer_hash)
            .await
            .unwrap();
        assert_eq!(got, Some(record.agent_id));
    }

    #[tokio::test]
    async fn lookup_by_unknown_bearer_hash_returns_none() {
        let db = fresh_db().await;
        let got = db
            .local_agents()
            .lookup_by_bearer_hash(&[0u8; 32])
            .await
            .unwrap();
        assert_eq!(got, None);
    }

    #[tokio::test]
    async fn rotate_bearer_changes_lookup_target() {
        let db = fresh_db().await;
        let record = make_local_agent_record();
        insert_local(&db, &record).await;
        let new_hash = [0xAAu8; 32];
        assert!(
            db.local_agents()
                .rotate_bearer(&record.agent_id, new_hash)
                .await
                .unwrap()
        );
        // Old hash no longer resolves.
        assert_eq!(
            db.local_agents()
                .lookup_by_bearer_hash(&record.bearer_hash)
                .await
                .unwrap(),
            None
        );
        // New hash resolves to the same agent.
        assert_eq!(
            db.local_agents()
                .lookup_by_bearer_hash(&new_hash)
                .await
                .unwrap(),
            Some(record.agent_id)
        );
    }

    #[tokio::test]
    async fn rotate_unknown_agent_returns_false() {
        let db = fresh_db().await;
        let kp = Keypair::generate();
        let ok = db
            .local_agents()
            .rotate_bearer(&kp.agent_id(), [0xBBu8; 32])
            .await
            .unwrap();
        assert!(!ok);
    }

    #[tokio::test]
    async fn remove_drops_row() {
        let db = fresh_db().await;
        let record = make_local_agent_record();
        insert_local(&db, &record).await;
        assert_eq!(
            db.local_agents().remove(&record.agent_id).await.unwrap(),
            LocalAgentRemoveOutcome::Removed
        );
        assert_eq!(
            db.local_agents()
                .lookup_by_id(&record.agent_id)
                .await
                .unwrap(),
            None
        );
        // Idempotent — second remove reports NotFound, no error.
        assert_eq!(
            db.local_agents().remove(&record.agent_id).await.unwrap(),
            LocalAgentRemoveOutcome::NotFound
        );
    }

    #[tokio::test]
    async fn list_orders_by_created_at() {
        let db = fresh_db().await;
        let mut a = make_local_agent_record();
        let mut b = make_local_agent_record();
        a.created_at = Timestamp::from_unix_ms(1000).unwrap();
        b.created_at = Timestamp::from_unix_ms(2000).unwrap();
        insert_local(&db, &b).await;
        insert_local(&db, &a).await;
        let listed = db.local_agents().list().await.unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].agent_id, a.agent_id);
        assert_eq!(listed[1].agent_id, b.agent_id);
    }
}
