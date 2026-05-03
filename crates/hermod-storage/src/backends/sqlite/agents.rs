//! SQLite implementation of `AgentRepository`.

use async_trait::async_trait;
use hermod_core::{AgentAlias, AgentId, CapabilityTagSet, PubkeyBytes, Timestamp, TrustLevel};
use sqlx::{Row, SqlitePool};
use std::str::FromStr;

use crate::error::{Result, StorageError};
use crate::repositories::agents::{AgentRecord, AgentRepository, AliasOutcome};

#[derive(Debug, Clone)]
pub struct SqliteAgentRepository {
    pool: SqlitePool,
}

impl SqliteAgentRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    async fn upsert_observed_locked(
        &self,
        conn: &mut sqlx::SqliteConnection,
        record: &AgentRecord,
    ) -> Result<AliasOutcome> {
        let mut effective_local = record.local_alias.clone();
        let mut outcome = AliasOutcome::Accepted;
        if let Some(proposed) = &record.local_alias {
            let row =
                sqlx::query(r#"SELECT id FROM agents WHERE local_alias = ? AND id != ? LIMIT 1"#)
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
        // Routing fields (`host_id` / `via_agent`) are NOT touched
        // by upsert paths — they're owned by the explicit
        // `set_routing_direct` / `set_routing_brokered` /
        // `clear_routing` methods, which carry the operator's
        // (or peer.advertise's) intent in the method name. INSERT
        // still seeds them from the new record so first-contact rows
        // start with whatever routing the caller already knows.
        sqlx::query(
            r#"
            INSERT INTO agents
                (id, pubkey, host_id, via_agent, local_alias,
                 peer_asserted_alias, trust_level, reputation,
                 first_seen, last_seen, peer_asserted_tags)
            VALUES
                (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                pubkey              = excluded.pubkey,
                local_alias         = COALESCE(excluded.local_alias, agents.local_alias),
                peer_asserted_alias = COALESCE(excluded.peer_asserted_alias, agents.peer_asserted_alias),
                last_seen           = excluded.last_seen,
                peer_asserted_tags  = excluded.peer_asserted_tags
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
impl AgentRepository for SqliteAgentRepository {
    async fn upsert(&self, record: &AgentRecord) -> Result<()> {
        let pubkey = record.pubkey.as_slice().to_vec();
        let host_id = record.host_id.as_ref().map(|h| h.as_str().to_string());

        // Operator-managed columns are intentionally NOT in the conflict
        // update list:
        //   * `trust_level` — `set_trust` is the only path; re-observation
        //     must never silently demote.
        //   * `reputation` — adjusted by an explicit operator action.
        //   * `first_seen` — fixed by definition of "first".
        //   * `peer_asserted_tags` — owned by the peer; operator-driven
        //     upsert provides only the initial empty default and never
        //     overwrites a peer's most recent advertisement.
        let via_agent = record.via_agent.as_ref().map(|a| a.as_str().to_string());
        let peer_asserted_tags = encode_tag_set(&record.peer_asserted_tags)?;
        // Routing + peer-asserted fields stay outside the conflict
        // update list — see `upsert_observed_locked` for the full
        // ownership rationale. Operator re-runs of `peer add`
        // refresh routing through `set_routing_*`; tags through the
        // peer's next advertise.
        sqlx::query(
            r#"
            INSERT INTO agents
                (id, pubkey, host_id, via_agent, local_alias,
                 peer_asserted_alias, trust_level, reputation,
                 first_seen, last_seen, peer_asserted_tags)
            VALUES
                (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                pubkey              = excluded.pubkey,
                local_alias         = COALESCE(excluded.local_alias, agents.local_alias),
                peer_asserted_alias = COALESCE(excluded.peer_asserted_alias, agents.peer_asserted_alias),
                last_seen           = excluded.last_seen
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
        // BEGIN IMMEDIATE so the collision-check SELECT acquires the
        // write lock immediately. Under DEFERRED, two concurrent
        // observations of the same alias would both read a stale
        // snapshot, both see "no conflict", and the second INSERT
        // would fail with a UNIQUE violation. Raw BEGIN bypasses
        // sqlx's txn-depth tracking, so pair it with explicit
        // COMMIT/ROLLBACK.
        let mut conn = self.pool.acquire().await?;
        sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;

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
        let row = sqlx::query(&select("WHERE id = ?", None))
            .bind(id.as_str())
            .fetch_optional(&self.pool)
            .await?;
        row.map(row_to_agent).transpose()
    }

    async fn get_by_local_alias(&self, alias: &AgentAlias) -> Result<Option<AgentRecord>> {
        let row = sqlx::query(&select("WHERE local_alias = ?", None))
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
        // Remote agents only — exclude local_agents so a fan-out
        // sweep doesn't dispatch a daemon's own advertise back to
        // itself. Direct routing (host_id) XOR brokered (via_agent);
        // pure directory-only entries (both NULL) are intentionally
        // excluded.
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
        // Effective alias = COALESCE(local_alias, peer_asserted_alias).
        // Compare against the candidate; row that IS the exclude
        // never participates so its own alias isn't counted.
        let row = sqlx::query(
            r#"SELECT COUNT(*) AS n FROM agents
               WHERE id != ?
                 AND COALESCE(local_alias, peer_asserted_alias) = ?"#,
        )
        .bind(exclude.as_str())
        .bind(alias.as_str())
        .fetch_one(&self.pool)
        .await?;
        let n: i64 = row.try_get("n")?;
        Ok(n.max(0) as u64)
    }

    async fn set_trust(&self, id: &AgentId, trust: TrustLevel) -> Result<()> {
        sqlx::query(r#"UPDATE agents SET trust_level = ? WHERE id = ?"#)
            .bind(trust.as_str())
            .bind(id.as_str())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn touch(&self, id: &AgentId, at: Timestamp) -> Result<()> {
        sqlx::query(r#"UPDATE agents SET last_seen = ? WHERE id = ?"#)
            .bind(at.unix_ms())
            .bind(id.as_str())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn set_routing_direct(&self, id: &AgentId, host_id: &AgentId) -> Result<()> {
        sqlx::query(r#"UPDATE agents SET host_id = ?, via_agent = NULL WHERE id = ?"#)
            .bind(host_id.as_str())
            .bind(id.as_str())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn set_routing_brokered(&self, id: &AgentId, via_agent: &AgentId) -> Result<()> {
        sqlx::query(r#"UPDATE agents SET host_id = NULL, via_agent = ? WHERE id = ?"#)
            .bind(via_agent.as_str())
            .bind(id.as_str())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn clear_routing(&self, id: &AgentId) -> Result<()> {
        sqlx::query(r#"UPDATE agents SET host_id = NULL, via_agent = NULL WHERE id = ?"#)
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

fn row_to_agent(row: sqlx::sqlite::SqliteRow) -> Result<AgentRecord> {
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

/// Decode the JSON-encoded `peer_asserted_tags` column. Uses
/// `parse_lossy` so a row with corrupted / future-format entries
/// reads as a smaller set rather than failing the whole row read.
fn decode_tag_set(json: String) -> Result<CapabilityTagSet> {
    let raw: Vec<String> = serde_json::from_str(&json)?;
    let (set, _dropped) = CapabilityTagSet::parse_lossy(raw);
    Ok(set)
}

/// Encode a `CapabilityTagSet` to the JSON array shape the
/// `peer_asserted_tags TEXT` column stores. Round-trips with
/// `decode_tag_set` (`into_strings()` ↔ `parse_lossy`).
fn encode_tag_set(tags: &CapabilityTagSet) -> Result<String> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Database;
    use crate::backends::sqlite::SqliteDatabase;
    use crate::repositories::hosts::HostRecord;
    use hermod_core::Endpoint;

    async fn fresh_db() -> SqliteDatabase {
        let mut p = std::env::temp_dir();
        p.push(format!("hermod-agents-{}.sqlite", ulid::Ulid::new()));
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

    fn fake_agent(b: u8) -> AgentId {
        hermod_crypto::agent_id_from_pubkey(&PubkeyBytes([b; 32]))
    }

    fn record(id: AgentId, local: Option<&str>, peer: Option<&str>) -> AgentRecord {
        let now = Timestamp::now();
        AgentRecord {
            id,
            pubkey: PubkeyBytes([1u8; 32]),
            host_id: None,
            via_agent: None,
            local_alias: local.map(|s| AgentAlias::from_str(s).unwrap()),
            peer_asserted_alias: peer.map(|s| AgentAlias::from_str(s).unwrap()),
            trust_level: TrustLevel::Tofu,
            reputation: 0,
            first_seen: now,
            last_seen: Some(now),
            peer_asserted_tags: CapabilityTagSet::empty(),
        }
    }

    #[tokio::test]
    async fn upsert_observed_accepts_when_no_collision() {
        let db = fresh_db().await;
        let a = fake_agent(1);
        let outcome = db
            .agents()
            .upsert_observed(&record(a.clone(), Some("alice"), Some("alice")))
            .await
            .unwrap();
        assert_eq!(outcome, AliasOutcome::Accepted);
        let rec = db.agents().get(&a).await.unwrap().unwrap();
        assert_eq!(rec.local_alias.unwrap().as_str(), "alice");
        assert_eq!(rec.peer_asserted_alias.unwrap().as_str(), "alice");
    }

    #[tokio::test]
    async fn upsert_observed_drops_local_alias_on_collision() {
        let db = fresh_db().await;
        let alice = fake_agent(1);
        let mallory = fake_agent(2);

        db.agents()
            .upsert(&record(alice.clone(), Some("friend"), None))
            .await
            .unwrap();

        let outcome = db
            .agents()
            .upsert_observed(&record(mallory.clone(), Some("friend"), Some("friend")))
            .await
            .unwrap();
        assert!(matches!(
            outcome,
            AliasOutcome::LocalDropped { conflicting_id, .. } if conflicting_id == alice
        ));

        let alice_rec = db.agents().get(&alice).await.unwrap().unwrap();
        assert_eq!(alice_rec.local_alias.unwrap().as_str(), "friend");
        let mallory_rec = db.agents().get(&mallory).await.unwrap().unwrap();
        assert!(mallory_rec.local_alias.is_none());
        assert_eq!(mallory_rec.peer_asserted_alias.unwrap().as_str(), "friend");

        let by_alias = db
            .agents()
            .get_by_local_alias(&AgentAlias::from_str("friend").unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(by_alias.id, alice);
    }

    #[tokio::test]
    async fn upsert_observed_idempotent_on_same_id() {
        let db = fresh_db().await;
        let a = fake_agent(1);
        db.agents()
            .upsert(&record(a.clone(), Some("alice"), None))
            .await
            .unwrap();
        let outcome = db
            .agents()
            .upsert_observed(&record(a.clone(), Some("alice"), Some("alice")))
            .await
            .unwrap();
        assert_eq!(outcome, AliasOutcome::Accepted);
    }

    fn tags(items: &[&str]) -> CapabilityTagSet {
        let raw: Vec<String> = items.iter().map(|s| (*s).to_string()).collect();
        CapabilityTagSet::parse_lossy(raw).0
    }

    fn record_with_tags(id: AgentId, peer_tags: CapabilityTagSet) -> AgentRecord {
        let mut rec = record(id, None, None);
        rec.peer_asserted_tags = peer_tags;
        rec
    }

    /// `upsert_observed` is the persistence path for inbound
    /// `peer.advertise`. The latest advertise is authoritative for
    /// peer-side facets, so the column must round-trip verbatim and
    /// a follow-up advertise must overwrite (latest-wins).
    #[tokio::test]
    async fn upsert_observed_persists_and_overwrites_peer_asserted_tags() {
        let db = fresh_db().await;
        let a = fake_agent(1);

        db.agents()
            .upsert_observed(&record_with_tags(
                a.clone(),
                tags(&["language:rust", "framework:tokio"]),
            ))
            .await
            .unwrap();
        let rec = db.agents().get(&a).await.unwrap().unwrap();
        let got: Vec<String> = rec.peer_asserted_tags.clone().into_strings();
        assert_eq!(got, vec!["language:rust", "framework:tokio"]);

        db.agents()
            .upsert_observed(&record_with_tags(a.clone(), tags(&["role:reviewer"])))
            .await
            .unwrap();
        let rec = db.agents().get(&a).await.unwrap().unwrap();
        let got: Vec<String> = rec.peer_asserted_tags.into_strings();
        assert_eq!(got, vec!["role:reviewer"]);
    }

    /// Empty-set advertise must propagate — a peer dropping every
    /// label clears the column rather than retaining stale tags.
    #[tokio::test]
    async fn upsert_observed_empty_advertise_clears_peer_asserted_tags() {
        let db = fresh_db().await;
        let a = fake_agent(1);

        db.agents()
            .upsert_observed(&record_with_tags(a.clone(), tags(&["language:rust"])))
            .await
            .unwrap();
        db.agents()
            .upsert_observed(&record_with_tags(a.clone(), CapabilityTagSet::empty()))
            .await
            .unwrap();
        let rec = db.agents().get(&a).await.unwrap().unwrap();
        assert!(rec.peer_asserted_tags.is_empty());
    }

    /// `upsert` is operator-driven. It must never overwrite a
    /// peer-asserted column (the peer owns that facet); the
    /// existing value survives operator re-registration.
    #[tokio::test]
    async fn upsert_preserves_peer_asserted_tags_against_operator_writes() {
        let db = fresh_db().await;
        let a = fake_agent(1);

        db.agents()
            .upsert_observed(&record_with_tags(
                a.clone(),
                tags(&["language:rust", "role:author"]),
            ))
            .await
            .unwrap();
        // Operator re-asserts identity-shaped fields with no tags
        // (the empty default an operator-driven path supplies).
        db.agents()
            .upsert(&record_with_tags(a.clone(), CapabilityTagSet::empty()))
            .await
            .unwrap();
        let rec = db.agents().get(&a).await.unwrap().unwrap();
        let got: Vec<String> = rec.peer_asserted_tags.into_strings();
        assert_eq!(got, vec!["language:rust", "role:author"]);
    }

    /// `list_federated` includes agents with either a `host_id`
    /// (direct routing) or a `via_agent` (brokered routing). Pure
    /// directory-only entries (both NULL) are excluded.
    #[tokio::test]
    async fn list_federated_returns_routable_agents_only() {
        let db = fresh_db().await;
        let now = Timestamp::now();
        let host_pub = PubkeyBytes([7u8; 32]);
        let host = HostRecord {
            id: hermod_crypto::agent_id_from_pubkey(&host_pub),
            pubkey: host_pub,
            endpoint: Some(Endpoint::from_str("wss://bob:7823").unwrap()),
            tls_fingerprint: None,
            peer_asserted_alias: None,
            first_seen: now,
            last_seen: Some(now),
        };
        db.hosts().upsert(&host).await.unwrap();

        let bob = AgentRecord {
            id: fake_agent(8),
            pubkey: PubkeyBytes([8u8; 32]),
            host_id: None,
            via_agent: None,
            local_alias: Some(AgentAlias::from_str("bob").unwrap()),
            peer_asserted_alias: None,
            trust_level: TrustLevel::Tofu,
            reputation: 0,
            first_seen: now,
            last_seen: Some(now),
            peer_asserted_tags: CapabilityTagSet::empty(),
        };
        db.agents().upsert(&bob).await.unwrap();
        db.agents()
            .set_routing_direct(&bob.id, &host.id)
            .await
            .unwrap();

        // Directory-only orphan (no host, no broker) — must NOT
        // surface in list_federated.
        let orphan = record(fake_agent(9), Some("orphan"), None);
        db.agents().upsert(&orphan).await.unwrap();

        let federated = db.agents().list_federated().await.unwrap();
        let ids: Vec<String> = federated.iter().map(|r| r.id.to_string()).collect();
        assert_eq!(ids, vec![bob.id.to_string()]);
    }

    /// Routing field ownership: `upsert` does not touch `host_id`
    /// or `via_agent`. The dedicated `set_routing_*` methods are
    /// the only path. This regression locks in the post-PR-6
    /// invariant that prevents the `host_id XOR via_agent` CHECK
    /// from being violated by an upsert that "sort of" updates
    /// routing.
    #[tokio::test]
    async fn upsert_does_not_touch_routing_fields() {
        let db = fresh_db().await;
        let host_pk = PubkeyBytes([7u8; 32]);
        let host_id = hermod_crypto::agent_id_from_pubkey(&host_pk);
        let now = Timestamp::now();
        db.hosts()
            .upsert(&crate::repositories::hosts::HostRecord {
                id: host_id.clone(),
                pubkey: host_pk,
                endpoint: None,
                tls_fingerprint: None,
                peer_asserted_alias: None,
                first_seen: now,
                last_seen: Some(now),
            })
            .await
            .unwrap();

        let a = fake_agent(1);
        // First land the row with direct routing.
        db.agents()
            .upsert(&record(a.clone(), None, None))
            .await
            .unwrap();
        db.agents().set_routing_direct(&a, &host_id).await.unwrap();
        let got = db.agents().get(&a).await.unwrap().unwrap();
        assert_eq!(got.host_id.as_ref(), Some(&host_id));

        // Re-upsert with host_id=None — must NOT clear the prior
        // routing. (The new record carries identity-only intent.)
        db.agents()
            .upsert(&record(a.clone(), None, None))
            .await
            .unwrap();
        let got = db.agents().get(&a).await.unwrap().unwrap();
        assert_eq!(
            got.host_id.as_ref(),
            Some(&host_id),
            "routing must be preserved"
        );
    }

    #[tokio::test]
    async fn set_routing_brokered_clears_host_id() {
        let db = fresh_db().await;
        let host_pk = PubkeyBytes([7u8; 32]);
        let host_id = hermod_crypto::agent_id_from_pubkey(&host_pk);
        let now = Timestamp::now();
        db.hosts()
            .upsert(&crate::repositories::hosts::HostRecord {
                id: host_id.clone(),
                pubkey: host_pk,
                endpoint: None,
                tls_fingerprint: None,
                peer_asserted_alias: None,
                first_seen: now,
                last_seen: Some(now),
            })
            .await
            .unwrap();
        let a = fake_agent(1);
        let broker = fake_agent(2);
        db.agents()
            .upsert(&record(a.clone(), None, None))
            .await
            .unwrap();
        db.agents()
            .upsert(&record(broker.clone(), None, None))
            .await
            .unwrap();
        db.agents().set_routing_direct(&a, &host_id).await.unwrap();
        // Switch to brokered — must atomically swap host_id → NULL +
        // via_agent → broker, satisfying the XOR CHECK.
        db.agents().set_routing_brokered(&a, &broker).await.unwrap();
        let got = db.agents().get(&a).await.unwrap().unwrap();
        assert_eq!(got.host_id, None);
        assert_eq!(got.via_agent, Some(broker));
    }

    #[tokio::test]
    async fn clear_routing_drops_both_pointers() {
        let db = fresh_db().await;
        let host_pk = PubkeyBytes([7u8; 32]);
        let host_id = hermod_crypto::agent_id_from_pubkey(&host_pk);
        let now = Timestamp::now();
        db.hosts()
            .upsert(&crate::repositories::hosts::HostRecord {
                id: host_id.clone(),
                pubkey: host_pk,
                endpoint: None,
                tls_fingerprint: None,
                peer_asserted_alias: None,
                first_seen: now,
                last_seen: Some(now),
            })
            .await
            .unwrap();
        let a = fake_agent(1);
        db.agents()
            .upsert(&record(a.clone(), None, None))
            .await
            .unwrap();
        db.agents().set_routing_direct(&a, &host_id).await.unwrap();
        db.agents().clear_routing(&a).await.unwrap();
        let got = db.agents().get(&a).await.unwrap().unwrap();
        assert!(got.host_id.is_none());
        assert!(got.via_agent.is_none());
    }

    #[tokio::test]
    async fn effective_alias_prefers_local() {
        let r = record(fake_agent(1), Some("operator"), Some("self-claim"));
        assert_eq!(r.effective_alias().unwrap().as_str(), "operator");

        let r = record(fake_agent(2), None, Some("self-claim"));
        assert_eq!(r.effective_alias().unwrap().as_str(), "self-claim");

        let r = record(fake_agent(3), None, None);
        assert!(r.effective_alias().is_none());
    }
}
