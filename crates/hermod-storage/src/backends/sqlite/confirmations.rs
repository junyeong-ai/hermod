//! SQLite implementation of `ConfirmationRepository`.

use async_trait::async_trait;
use hermod_core::{AgentId, Timestamp, TrustLevel};
use sqlx::{Row, SqlitePool};
use std::str::FromStr;
use ulid::Ulid;

use crate::error::{Result, StorageError};
use crate::repositories::confirmations::{
    ConfirmationRepository, ConfirmationStatus, HoldRequest, MAX_PENDING_PER_ACTOR,
    PendingConfirmation,
};

#[derive(Debug, Clone)]
pub struct SqliteConfirmationRepository {
    pool: SqlitePool,
}

impl SqliteConfirmationRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    async fn enqueue_locked(
        &self,
        conn: &mut sqlx::SqliteConnection,
        req: &HoldRequest<'_>,
        id: &str,
        now: Timestamp,
    ) -> Result<Option<String>> {
        let pending: i64 = sqlx::query_scalar(
            r#"SELECT COUNT(*) FROM pending_confirmations
               WHERE actor = ? AND status = 'pending'"#,
        )
        .bind(req.actor.as_str())
        .fetch_one(&mut *conn)
        .await?;
        if pending as u64 >= MAX_PENDING_PER_ACTOR {
            return Err(StorageError::QuotaExceeded(format!(
                "actor {} has {} pending confirmations (cap {MAX_PENDING_PER_ACTOR})",
                req.actor.as_str(),
                pending,
            )));
        }

        // INSERT OR IGNORE leans on the partial unique index
        // idx_pending_confirmations_envelope_pending — a duplicate
        // pending envelope is silently ignored.
        let res = sqlx::query(
            r#"
            INSERT OR IGNORE INTO pending_confirmations
              (id, envelope_id, requested_at, actor, recipient, intent,
               sensitivity, trust_level, summary, envelope_cbor, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')
            "#,
        )
        .bind(id)
        .bind(req.envelope_id.to_string())
        .bind(now.unix_ms())
        .bind(req.actor.as_str())
        .bind(req.recipient.as_str())
        .bind(req.intent.as_str())
        .bind(req.sensitivity)
        .bind(req.trust_level.as_str())
        .bind(req.summary)
        .bind(req.envelope_cbor)
        .execute(&mut *conn)
        .await?;
        Ok(if res.rows_affected() > 0 {
            Some(id.to_string())
        } else {
            None
        })
    }
}

#[async_trait]
impl ConfirmationRepository for SqliteConfirmationRepository {
    async fn enqueue(&self, req: HoldRequest<'_>) -> Result<Option<String>> {
        let id = Ulid::new().to_string();
        let now = Timestamp::now();

        let mut conn = self.pool.acquire().await?;
        sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;

        let inner = self.enqueue_locked(&mut conn, &req, &id, now).await;
        match &inner {
            Ok(_) => {
                sqlx::query("COMMIT").execute(&mut *conn).await?;
            }
            Err(_) => {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            }
        }
        inner
    }

    async fn list_pending(
        &self,
        recipient: Option<&AgentId>,
        limit: u32,
        after_id: Option<&str>,
    ) -> Result<Vec<PendingConfirmation>> {
        let recipient_filter = if recipient.is_some() {
            " AND recipient = ? "
        } else {
            ""
        };
        let cursor_filter = if after_id.is_some() {
            " AND id > ? "
        } else {
            ""
        };
        let sql = format!(
            r#"SELECT id, requested_at, actor, recipient, intent, sensitivity, trust_level,
                      summary, envelope_cbor, status, decided_at, decided_by
               FROM pending_confirmations
               WHERE status = 'pending'
               {recipient_filter}
               {cursor_filter}
               ORDER BY id ASC
               LIMIT ?"#
        );
        let mut q = sqlx::query(&sql);
        if let Some(r) = recipient {
            q = q.bind(r.as_str());
        }
        if let Some(after) = after_id {
            q = q.bind(after);
        }
        q = q.bind(limit as i64);
        let rows = q.fetch_all(&self.pool).await?;
        rows.into_iter().map(row_to_pending).collect()
    }

    async fn get(&self, id: &str) -> Result<Option<PendingConfirmation>> {
        let row = sqlx::query(
            r#"SELECT id, requested_at, actor, recipient, intent, sensitivity, trust_level,
                      summary, envelope_cbor, status, decided_at, decided_by
               FROM pending_confirmations
               WHERE id = ?"#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(row_to_pending).transpose()
    }

    async fn expire_pending_older_than(&self, cutoff_ms: i64) -> Result<u64> {
        let res = sqlx::query(
            r#"UPDATE pending_confirmations
               SET status = 'expired', decided_at = ?
               WHERE status = 'pending' AND requested_at <= ?"#,
        )
        .bind(cutoff_ms)
        .bind(cutoff_ms)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    async fn decide(
        &self,
        id: &str,
        new_status: ConfirmationStatus,
        decided_by: &AgentId,
        now: Timestamp,
    ) -> Result<bool> {
        let res = sqlx::query(
            r#"UPDATE pending_confirmations
               SET status = ?, decided_at = ?, decided_by = ?
               WHERE id = ? AND status = 'pending'"#,
        )
        .bind(new_status.as_str())
        .bind(now.unix_ms())
        .bind(decided_by.as_str())
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }
}

fn row_to_pending(row: sqlx::sqlite::SqliteRow) -> Result<PendingConfirmation> {
    let id: String = row.try_get("id")?;
    let requested_at =
        Timestamp::from_unix_ms(row.try_get("requested_at")?).map_err(StorageError::Core)?;
    let actor_str: String = row.try_get("actor")?;
    let actor = AgentId::from_str(&actor_str).map_err(StorageError::Core)?;
    let recipient_str: String = row.try_get("recipient")?;
    let recipient = AgentId::from_str(&recipient_str).map_err(StorageError::Core)?;
    let intent_s: String = row.try_get("intent")?;
    let intent =
        crate::HoldedIntent::from_str(&intent_s).map_err(crate::error::StorageError::Core)?;
    let sensitivity: String = row.try_get("sensitivity")?;
    let trust_str: String = row.try_get("trust_level")?;
    let trust_level = TrustLevel::from_str(&trust_str).map_err(StorageError::Core)?;
    let summary: String = row.try_get("summary")?;
    let envelope_cbor: Vec<u8> = row.try_get("envelope_cbor")?;
    let status_str: String = row.try_get("status")?;
    let status = ConfirmationStatus::from_str(&status_str).map_err(StorageError::Core)?;
    let decided_at = row
        .try_get::<Option<i64>, _>("decided_at")?
        .map(Timestamp::from_unix_ms)
        .transpose()
        .map_err(StorageError::Core)?;
    let decided_by_str: Option<String> = row.try_get("decided_by")?;
    let decided_by = match decided_by_str {
        Some(s) => Some(AgentId::from_str(&s).map_err(StorageError::Core)?),
        None => None,
    };
    Ok(PendingConfirmation {
        id,
        requested_at,
        actor,
        recipient,
        intent,
        sensitivity,
        trust_level,
        summary,
        envelope_cbor,
        status,
        decided_at,
        decided_by,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Database;
    use crate::backends::sqlite::SqliteDatabase;
    use crate::repositories::agents::AgentRecord;
    use hermod_core::{MessageId, PubkeyBytes, TrustLevel};

    async fn fresh_db() -> SqliteDatabase {
        let mut p = std::env::temp_dir();
        p.push(format!("hermod-conf-{}.sqlite", ulid::Ulid::new()));
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

    #[tokio::test]
    async fn duplicate_pending_envelope_dedupes() {
        let db = fresh_db().await;
        let actor = hermod_crypto::agent_id_from_pubkey(&PubkeyBytes([1u8; 32]));
        let recipient = hermod_crypto::agent_id_from_pubkey(&PubkeyBytes([2u8; 32]));
        let now = Timestamp::now();
        for (id, pk) in &[(&actor, [1u8; 32]), (&recipient, [2u8; 32])] {
            db.agents()
                .upsert(&AgentRecord {
                    id: (*id).clone(),
                    pubkey: PubkeyBytes(*pk),
                    host_pubkey: None,
                    endpoint: None,
                    local_alias: None,
                    peer_asserted_alias: None,
                    trust_level: TrustLevel::Tofu,
                    tls_fingerprint: None,
                    reputation: 0,
                    first_seen: now,
                    last_seen: Some(now),
                })
                .await
                .unwrap();
        }

        let env_id = MessageId::new();

        let req = |summary: &'static str| HoldRequest {
            envelope_id: &env_id,
            actor: &actor,
            recipient: &recipient,
            intent: crate::HoldedIntent::DirectMessage,
            sensitivity: "review",
            trust_level: TrustLevel::Tofu,
            summary,
            envelope_cbor: b"\x00",
        };
        let first = db.confirmations().enqueue(req("first")).await.unwrap();
        let second = db.confirmations().enqueue(req("retry")).await.unwrap();
        assert!(first.is_some(), "first call must insert");
        assert!(second.is_none(), "duplicate must dedupe to None");

        let pending = db
            .confirmations()
            .list_pending(None, 10, None)
            .await
            .unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].recipient, recipient);

        // Per-agent isolation: a different recipient sees an empty queue.
        let other = hermod_crypto::agent_id_from_pubkey(&PubkeyBytes([3u8; 32]));
        let scoped = db
            .confirmations()
            .list_pending(Some(&other), 10, None)
            .await
            .unwrap();
        assert!(
            scoped.is_empty(),
            "list_pending must filter by recipient when scoped",
        );
        let scoped_self = db
            .confirmations()
            .list_pending(Some(&recipient), 10, None)
            .await
            .unwrap();
        assert_eq!(scoped_self.len(), 1);

        db.confirmations()
            .decide(
                &first.unwrap(),
                ConfirmationStatus::Rejected,
                &actor,
                Timestamp::now(),
            )
            .await
            .unwrap();
        let third = db.confirmations().enqueue(req("third")).await.unwrap();
        assert!(third.is_some());
    }
}
