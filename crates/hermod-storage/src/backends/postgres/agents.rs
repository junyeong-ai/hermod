//! PostgreSQL implementation of `AgentRepository`.
//!
//! Functional twin of `backends::sqlite::SqliteAgentRepository`.
//! Differences are dialect-only:
//!
//!   * `?` placeholders → `$N`
//!   * `BEGIN IMMEDIATE` → `BEGIN ISOLATION LEVEL SERIALIZABLE`
//!   * `sqlx::sqlite::SqliteRow` → `sqlx::postgres::PgRow`

use async_trait::async_trait;
use hermod_core::{AgentAlias, AgentId, PubkeyBytes, Timestamp, TrustLevel};
use sqlx::{PgPool, Row};
use std::str::FromStr;

use crate::error::{Result, StorageError};
use crate::repositories::agents::{AgentRecord, AgentRepository, AliasOutcome};

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

        let pubkey = record.pubkey.as_slice().to_vec();
        let host_id = record.host_id.as_ref().map(|h| h.as_str().to_string());
        let via_agent = record.via_agent.as_ref().map(|a| a.as_str().to_string());
        let peer_asserted_tags = encode_tag_set(&record.peer_asserted_tags)?;
        // See sqlite backend for the routing-ownership rationale.
        sqlx::query(
            r#"
            INSERT INTO agents
                (id, pubkey, host_id, via_agent, local_alias,
                 peer_asserted_alias, trust_level, reputation,
                 first_seen, last_seen, peer_asserted_tags)
            VALUES
                ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            ON CONFLICT(id) DO UPDATE SET
                pubkey              = EXCLUDED.pubkey,
                local_alias         = COALESCE(EXCLUDED.local_alias, agents.local_alias),
                peer_asserted_alias = COALESCE(EXCLUDED.peer_asserted_alias, agents.peer_asserted_alias),
                last_seen           = EXCLUDED.last_seen,
                peer_asserted_tags  = EXCLUDED.peer_asserted_tags
            "#,
        )
        .bind(record.id.as_str())
        .bind(pubkey)
        .bind(host_id)
        .bind(via_agent)
        .bind(effective_local.as_ref().map(|a| a.as_str()))
        .bind(record.peer_asserted_alias.as_ref().map(|a| a.as_str()))
        .bind(record.trust_level.as_str())
        .bind(record.reputation)
        .bind(record.first_seen.unix_ms())
        .bind(record.last_seen.map(|t| t.unix_ms()))
        .bind(peer_asserted_tags)
        .execute(&mut *conn)
        .await?;

        Ok(outcome)
    }
}

#[async_trait]
impl AgentRepository for PostgresAgentRepository {
    async fn upsert(&self, record: &AgentRecord) -> Result<()> {
        let pubkey = record.pubkey.as_slice().to_vec();
        let host_id = record.host_id.as_ref().map(|h| h.as_str().to_string());

        // Operator-managed columns intentionally NOT in the conflict
        // update list — see SqliteAgentRepository::upsert for rationale.
        let via_agent = record.via_agent.as_ref().map(|a| a.as_str().to_string());
        let peer_asserted_tags = encode_tag_set(&record.peer_asserted_tags)?;
        sqlx::query(
            r#"
            INSERT INTO agents
                (id, pubkey, host_id, via_agent, local_alias,
                 peer_asserted_alias, trust_level, reputation,
                 first_seen, last_seen, peer_asserted_tags)
            VALUES
                ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            ON CONFLICT(id) DO UPDATE SET
                pubkey              = EXCLUDED.pubkey,
                local_alias         = COALESCE(EXCLUDED.local_alias, agents.local_alias),
                peer_asserted_alias = COALESCE(EXCLUDED.peer_asserted_alias, agents.peer_asserted_alias),
                last_seen           = EXCLUDED.last_seen
            "#,
        )
        .bind(record.id.as_str())
        .bind(pubkey)
        .bind(host_id)
        .bind(via_agent)
        .bind(record.local_alias.as_ref().map(|a| a.as_str()))
        .bind(record.peer_asserted_alias.as_ref().map(|a| a.as_str()))
        .bind(record.trust_level.as_str())
        .bind(record.reputation)
        .bind(record.first_seen.unix_ms())
        .bind(record.last_seen.map(|t| t.unix_ms()))
        .bind(peer_asserted_tags)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn upsert_observed(&self, record: &AgentRecord) -> Result<AliasOutcome> {
        // SERIALIZABLE so the collision-check SELECT and the INSERT
        // see a consistent snapshot. Postgres detects write-write
        // conflicts and aborts losing transactions; under READ
        // COMMITTED two concurrent observations of the same alias
        // could both pass the check and the second INSERT would
        // fail with a UNIQUE violation. Raw BEGIN bypasses sqlx's
        // txn-depth tracking, so pair it with explicit
        // COMMIT/ROLLBACK.
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
        let rows = sqlx::query(&select(
            "WHERE (host_id IS NOT NULL OR via_agent IS NOT NULL) \
             AND id NOT IN (SELECT agent_id FROM local_agents)",
            Some("id"),
        ))
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

    async fn set_routing_direct(&self, id: &AgentId, host_id: &AgentId) -> Result<()> {
        sqlx::query(r#"UPDATE agents SET host_id = $1, via_agent = NULL WHERE id = $2"#)
            .bind(host_id.as_str())
            .bind(id.as_str())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn set_routing_brokered(&self, id: &AgentId, via_agent: &AgentId) -> Result<()> {
        sqlx::query(r#"UPDATE agents SET host_id = NULL, via_agent = $1 WHERE id = $2"#)
            .bind(via_agent.as_str())
            .bind(id.as_str())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn clear_routing(&self, id: &AgentId) -> Result<()> {
        sqlx::query(r#"UPDATE agents SET host_id = NULL, via_agent = NULL WHERE id = $1"#)
            .bind(id.as_str())
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

const COLUMNS: &str = "id, pubkey, host_id, via_agent, local_alias, \
     peer_asserted_alias, trust_level, reputation, first_seen, last_seen, \
     peer_asserted_tags";

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

    let host_id_str: Option<String> = row.try_get("host_id")?;
    let host_id = host_id_str
        .map(|s| AgentId::from_str(&s))
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

    let reputation: i64 = row.try_get("reputation")?;

    let first_seen_ms: i64 = row.try_get("first_seen")?;
    let first_seen = Timestamp::from_unix_ms(first_seen_ms).map_err(StorageError::Core)?;

    let last_seen_ms: Option<i64> = row.try_get("last_seen")?;
    let last_seen = last_seen_ms
        .map(Timestamp::from_unix_ms)
        .transpose()
        .map_err(StorageError::Core)?;

    let peer_asserted_tags = decode_tag_set(row.try_get::<String, _>("peer_asserted_tags")?)?;

    Ok(AgentRecord {
        id,
        pubkey,
        host_id,
        via_agent,
        local_alias,
        peer_asserted_alias,
        trust_level,
        reputation,
        first_seen,
        last_seen,
        peer_asserted_tags,
    })
}

/// Decode the JSON-encoded `peer_asserted_tags` column. Lossy
/// per-entry — same semantics as the sqlite backend.
fn decode_tag_set(json: String) -> Result<hermod_core::CapabilityTagSet> {
    let raw: Vec<String> = serde_json::from_str(&json)?;
    let (set, _dropped) = hermod_core::CapabilityTagSet::parse_lossy(raw);
    Ok(set)
}

/// Encode a `CapabilityTagSet` to the JSON array shape the
/// `peer_asserted_tags TEXT` column stores. Round-trips with
/// `decode_tag_set` (`into_strings()` ↔ `parse_lossy`).
fn encode_tag_set(tags: &hermod_core::CapabilityTagSet) -> Result<String> {
    let raw: Vec<String> = tags.clone().into_strings();
    Ok(serde_json::to_string(&raw)?)
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
