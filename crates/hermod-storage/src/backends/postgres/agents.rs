//! PostgreSQL implementation of `AgentRepository`.
//!
//! Functional twin of `backends::sqlite::SqliteAgentRepository`. Differences are
//! dialect-only:
//!
//!   * `?` placeholders → `$N`
//!   * `BEGIN IMMEDIATE` → `BEGIN` (Postgres acquires write locks
//!     lazily; serialisation is provided by the SERIALIZABLE isolation
//!     level which we set explicitly on the txn that needs it)
//!   * `sqlx::sqlite::SqliteRow` → `sqlx::postgres::PgRow`

use async_trait::async_trait;
use hermod_core::{AgentAlias, AgentId, Endpoint, PubkeyBytes, Timestamp, TrustLevel};
use sqlx::{PgPool, Row};
use std::str::FromStr;

use crate::error::{Result, StorageError};
use crate::repositories::agents::{
    AgentRecord, AgentRepository, AliasOutcome, ForgetOutcome, RepinOutcome,
};

#[derive(Debug, Clone)]
pub struct PostgresAgentRepository {
    pool: PgPool,
}

impl PostgresAgentRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    async fn upsert_observed_locked(
        &self,
        conn: &mut sqlx::PgConnection,
        record: &AgentRecord,
    ) -> Result<AliasOutcome> {
        let mut effective_local = record.local_alias.clone();
        let mut outcome = AliasOutcome::Accepted;
        if let Some(proposed) = &record.local_alias {
            let row =
                sqlx::query(r#"SELECT id FROM agents WHERE local_alias = $1 AND id != $2 LIMIT 1"#)
                    .bind(proposed.as_str())
                    .bind(record.id.as_str())
                    .fetch_optional(&mut *conn)
                    .await?;
            if let Some(row) = row {
                let conflict_str: String = row.try_get("id")?;
                let conflicting_id =
                    AgentId::from_str(&conflict_str).map_err(StorageError::Core)?;
                effective_local = None;
                outcome = AliasOutcome::LocalDropped {
                    proposed: proposed.clone(),
                    conflicting_id,
                };
            }
        }

        let endpoint = record.endpoint.as_ref().map(|e| e.to_string());
        let pubkey = record.pubkey.as_slice().to_vec();
        let host_pubkey = record.host_pubkey.as_ref().map(|h| h.as_slice().to_vec());
        let via_agent = record.via_agent.as_ref().map(|a| a.as_str().to_string());
        sqlx::query(
            r#"
            INSERT INTO agents
                (id, pubkey, host_pubkey, endpoint, via_agent, local_alias,
                 peer_asserted_alias, trust_level, tls_fingerprint, reputation,
                 first_seen, last_seen)
            VALUES
                ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            ON CONFLICT(id) DO UPDATE SET
                pubkey              = EXCLUDED.pubkey,
                host_pubkey         = COALESCE(EXCLUDED.host_pubkey, agents.host_pubkey),
                endpoint            = COALESCE(EXCLUDED.endpoint, agents.endpoint),
                via_agent        = COALESCE(EXCLUDED.via_agent, agents.via_agent),
                local_alias         = COALESCE(EXCLUDED.local_alias, agents.local_alias),
                peer_asserted_alias = COALESCE(EXCLUDED.peer_asserted_alias, agents.peer_asserted_alias),
                last_seen           = EXCLUDED.last_seen
            "#,
        )
        .bind(record.id.as_str())
        .bind(pubkey)
        .bind(host_pubkey)
        .bind(endpoint)
        .bind(via_agent)
        .bind(effective_local.as_ref().map(|a| a.as_str()))
        .bind(record.peer_asserted_alias.as_ref().map(|a| a.as_str()))
        .bind(record.trust_level.as_str())
        .bind(&record.tls_fingerprint)
        .bind(record.reputation)
        .bind(record.first_seen.unix_ms())
        .bind(record.last_seen.map(|t| t.unix_ms()))
        .execute(&mut *conn)
        .await?;

        Ok(outcome)
    }

    async fn replace_tls_fingerprint_locked(
        &self,
        conn: &mut sqlx::PgConnection,
        id: &AgentId,
        new: &str,
        require: TrustLevel,
    ) -> Result<RepinOutcome> {
        let row = sqlx::query(
            r#"SELECT tls_fingerprint, trust_level, endpoint FROM agents WHERE id = $1"#,
        )
        .bind(id.as_str())
        .fetch_optional(&mut *conn)
        .await?;
        let Some(row) = row else {
            return Ok(RepinOutcome::NotFound);
        };
        let actual_str: String = row.try_get("trust_level")?;
        let actual = TrustLevel::from_str(&actual_str).map_err(StorageError::Core)?;
        if actual != require {
            return Ok(RepinOutcome::TrustMismatch { actual });
        }
        let prev: Option<String> = row.try_get("tls_fingerprint")?;
        let endpoint_str: Option<String> = row.try_get("endpoint")?;
        let endpoint = endpoint_str
            .as_deref()
            .and_then(|s| Endpoint::from_str(s).ok());
        sqlx::query(r#"UPDATE agents SET tls_fingerprint = $1 WHERE id = $2"#)
            .bind(new)
            .bind(id.as_str())
            .execute(&mut *conn)
            .await?;
        Ok(RepinOutcome::Replaced {
            previous: prev,
            endpoint,
        })
    }

    async fn forget_peer_locked(
        &self,
        conn: &mut sqlx::PgConnection,
        id: &AgentId,
    ) -> Result<ForgetOutcome> {
        let prior: Option<String> =
            sqlx::query_scalar(r#"SELECT endpoint FROM agents WHERE id = $1"#)
                .bind(id.as_str())
                .fetch_optional(&mut *conn)
                .await?
                .flatten();
        let res = sqlx::query(
            r#"UPDATE agents
               SET endpoint = NULL, tls_fingerprint = NULL
               WHERE id = $1"#,
        )
        .bind(id.as_str())
        .execute(&mut *conn)
        .await?;
        Ok(ForgetOutcome {
            existed: res.rows_affected() > 0,
            prior_endpoint: prior.as_deref().and_then(|s| Endpoint::from_str(s).ok()),
        })
    }
}

#[async_trait]
impl AgentRepository for PostgresAgentRepository {
    async fn upsert(&self, record: &AgentRecord) -> Result<()> {
        let endpoint = record.endpoint.as_ref().map(|e| e.to_string());
        let pubkey = record.pubkey.as_slice().to_vec();
        let host_pubkey = record.host_pubkey.as_ref().map(|h| h.as_slice().to_vec());

        // Operator-managed columns intentionally NOT in the conflict
        // update list — see SqliteAgentRepository::upsert for rationale.
        let via_agent = record.via_agent.as_ref().map(|a| a.as_str().to_string());
        sqlx::query(
            r#"
            INSERT INTO agents
                (id, pubkey, host_pubkey, endpoint, via_agent, local_alias,
                 peer_asserted_alias, trust_level, tls_fingerprint, reputation,
                 first_seen, last_seen)
            VALUES
                ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            ON CONFLICT(id) DO UPDATE SET
                pubkey              = EXCLUDED.pubkey,
                host_pubkey         = COALESCE(EXCLUDED.host_pubkey, agents.host_pubkey),
                endpoint            = COALESCE(EXCLUDED.endpoint, agents.endpoint),
                via_agent        = COALESCE(EXCLUDED.via_agent, agents.via_agent),
                local_alias         = COALESCE(EXCLUDED.local_alias, agents.local_alias),
                peer_asserted_alias = COALESCE(EXCLUDED.peer_asserted_alias, agents.peer_asserted_alias),
                last_seen           = EXCLUDED.last_seen
            "#,
        )
        .bind(record.id.as_str())
        .bind(pubkey)
        .bind(host_pubkey)
        .bind(endpoint)
        .bind(via_agent)
        .bind(record.local_alias.as_ref().map(|a| a.as_str()))
        .bind(record.peer_asserted_alias.as_ref().map(|a| a.as_str()))
        .bind(record.trust_level.as_str())
        .bind(&record.tls_fingerprint)
        .bind(record.reputation)
        .bind(record.first_seen.unix_ms())
        .bind(record.last_seen.map(|t| t.unix_ms()))
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn upsert_observed(&self, record: &AgentRecord) -> Result<AliasOutcome> {
        // SERIALIZABLE so the collision-check SELECT and the INSERT see
        // a consistent snapshot. Postgres detects write-write conflicts
        // and aborts losing transactions; under READ COMMITTED two
        // concurrent observations of the same alias could both pass
        // the check and the second INSERT fails with a UNIQUE
        // violation. Raw BEGIN bypasses sqlx's txn-depth tracking, so
        // pair it with explicit COMMIT/ROLLBACK.
        let mut conn = self.pool.acquire().await?;
        sqlx::query("BEGIN ISOLATION LEVEL SERIALIZABLE")
            .execute(&mut *conn)
            .await?;

        let inner = self.upsert_observed_locked(&mut conn, record).await;

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

    async fn get(&self, id: &AgentId) -> Result<Option<AgentRecord>> {
        let row = sqlx::query(&select("WHERE id = $1", None))
            .bind(id.as_str())
            .fetch_optional(&self.pool)
            .await?;
        row.map(row_to_agent).transpose()
    }

    async fn get_by_local_alias(&self, alias: &AgentAlias) -> Result<Option<AgentRecord>> {
        let row = sqlx::query(&select("WHERE local_alias = $1", None))
            .bind(alias.as_str())
            .fetch_optional(&self.pool)
            .await?;
        row.map(row_to_agent).transpose()
    }

    async fn list(&self) -> Result<Vec<AgentRecord>> {
        let rows = sqlx::query(&select("", Some("local_alias, peer_asserted_alias, id")))
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter().map(row_to_agent).collect()
    }

    async fn list_federated(&self) -> Result<Vec<AgentRecord>> {
        let rows = sqlx::query(&select("WHERE endpoint IS NOT NULL", Some("id")))
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter().map(row_to_agent).collect()
    }

    async fn count_with_effective_alias(
        &self,
        alias: &hermod_core::AgentAlias,
        exclude: &AgentId,
    ) -> Result<u64> {
        let row = sqlx::query(
            r#"SELECT COUNT(*) AS n FROM agents
               WHERE id != $1
                 AND COALESCE(local_alias, peer_asserted_alias) = $2"#,
        )
        .bind(exclude.as_str())
        .bind(alias.as_str())
        .fetch_one(&self.pool)
        .await?;
        let n: i64 = row.try_get("n")?;
        Ok(n.max(0) as u64)
    }

    async fn set_trust(&self, id: &AgentId, trust: TrustLevel) -> Result<()> {
        sqlx::query(r#"UPDATE agents SET trust_level = $1 WHERE id = $2"#)
            .bind(trust.as_str())
            .bind(id.as_str())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn touch(&self, id: &AgentId, at: Timestamp) -> Result<()> {
        sqlx::query(r#"UPDATE agents SET last_seen = $1 WHERE id = $2"#)
            .bind(at.unix_ms())
            .bind(id.as_str())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn pin_or_match_tls_fingerprint(&self, id: &AgentId, observed: &str) -> Result<bool> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query(r#"SELECT tls_fingerprint FROM agents WHERE id = $1"#)
            .bind(id.as_str())
            .fetch_optional(&mut *tx)
            .await?;
        let stored: Option<String> = match row {
            None => return Ok(false),
            Some(r) => r.try_get("tls_fingerprint")?,
        };
        let outcome = match stored {
            Some(s) if s == observed => true,
            Some(_) => false,
            None => {
                sqlx::query(r#"UPDATE agents SET tls_fingerprint = $1 WHERE id = $2"#)
                    .bind(observed)
                    .bind(id.as_str())
                    .execute(&mut *tx)
                    .await?;
                true
            }
        };
        tx.commit().await?;
        Ok(outcome)
    }

    async fn replace_tls_fingerprint(
        &self,
        id: &AgentId,
        new: &str,
        require: TrustLevel,
    ) -> Result<RepinOutcome> {
        let mut conn = self.pool.acquire().await?;
        sqlx::query("BEGIN ISOLATION LEVEL SERIALIZABLE")
            .execute(&mut *conn)
            .await?;

        let inner = self
            .replace_tls_fingerprint_locked(&mut conn, id, new, require)
            .await;
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

    async fn forget_peer(&self, id: &AgentId) -> Result<ForgetOutcome> {
        let mut conn = self.pool.acquire().await?;
        sqlx::query("BEGIN ISOLATION LEVEL SERIALIZABLE")
            .execute(&mut *conn)
            .await?;

        let inner = self.forget_peer_locked(&mut conn, id).await;
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
}

const COLUMNS: &str = "id, pubkey, host_pubkey, endpoint, via_agent, local_alias, \
     peer_asserted_alias, trust_level, tls_fingerprint, reputation, first_seen, last_seen";

fn select(predicate: &str, order_by: Option<&str>) -> String {
    let order = order_by
        .map(|s| format!(" ORDER BY {s}"))
        .unwrap_or_default();
    format!("SELECT {COLUMNS} FROM agents {predicate}{order}")
}

fn row_to_agent(row: sqlx::postgres::PgRow) -> Result<AgentRecord> {
    let id_str: String = row.try_get("id")?;
    let id = AgentId::from_str(&id_str).map_err(StorageError::Core)?;

    let pubkey = decode_pubkey(row.try_get::<Vec<u8>, _>("pubkey")?, "pubkey")?;
    let host_pubkey: Option<Vec<u8>> = row.try_get("host_pubkey")?;
    let host_pubkey = host_pubkey
        .map(|b| decode_pubkey(b, "host_pubkey"))
        .transpose()?;

    let endpoint: Option<String> = row.try_get("endpoint")?;
    let endpoint = endpoint
        .map(|s| Endpoint::from_str(&s))
        .transpose()
        .map_err(StorageError::Core)?;

    let via_str: Option<String> = row.try_get("via_agent")?;
    let via_agent = via_str
        .map(|s| AgentId::from_str(&s))
        .transpose()
        .map_err(StorageError::Core)?;

    let local_alias = parse_alias(row.try_get("local_alias")?)?;
    let peer_asserted_alias = parse_alias(row.try_get("peer_asserted_alias")?)?;

    let trust_str: String = row.try_get("trust_level")?;
    let trust_level = TrustLevel::from_str(&trust_str).map_err(StorageError::Core)?;

    let tls_fingerprint: Option<String> = row.try_get("tls_fingerprint")?;
    let reputation: i64 = row.try_get("reputation")?;

    let first_seen_ms: i64 = row.try_get("first_seen")?;
    let first_seen = Timestamp::from_unix_ms(first_seen_ms).map_err(StorageError::Core)?;

    let last_seen_ms: Option<i64> = row.try_get("last_seen")?;
    let last_seen = last_seen_ms
        .map(Timestamp::from_unix_ms)
        .transpose()
        .map_err(StorageError::Core)?;

    Ok(AgentRecord {
        id,
        pubkey,
        host_pubkey,
        endpoint,
        via_agent,
        local_alias,
        peer_asserted_alias,
        trust_level,
        tls_fingerprint,
        reputation,
        first_seen,
        last_seen,
    })
}

fn decode_pubkey(bytes: Vec<u8>, column: &'static str) -> Result<PubkeyBytes> {
    if bytes.len() != PubkeyBytes::LEN {
        return Err(StorageError::decode(
            column,
            format!("expected {} bytes, got {}", PubkeyBytes::LEN, bytes.len()),
        ));
    }
    let mut arr = [0u8; PubkeyBytes::LEN];
    arr.copy_from_slice(&bytes);
    Ok(PubkeyBytes(arr))
}

fn parse_alias(raw: Option<String>) -> Result<Option<AgentAlias>> {
    raw.map(|s| AgentAlias::from_str(&s))
        .transpose()
        .map_err(StorageError::Core)
}
