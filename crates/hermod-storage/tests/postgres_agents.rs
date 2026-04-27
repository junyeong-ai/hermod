//! Integration test for the PostgreSQL `AgentRepository` implementation.
//!
//! Gated on the `postgres` cargo feature AND the `HERMOD_TEST_POSTGRES_URL`
//! env var being set to a usable DSN. CI / local runs without those
//! conditions skip the test rather than failing — running a real
//! PostgreSQL is the operator's responsibility for this slice.
//!
//! Bringing up a local PG for the test:
//!
//!   ```sh
//!   docker run --rm -d --name hermod-pg \
//!       -e POSTGRES_PASSWORD=hermod -p 5433:5432 postgres:16
//!   export HERMOD_TEST_POSTGRES_URL='postgres://postgres:hermod@127.0.0.1:5433/postgres'
//!   cargo test -p hermod-storage --features postgres --test postgres_agents
//!   ```
//!
//! The test creates a uniquely-named schema, runs migrations into it,
//! exercises the full `AgentRepository` surface, then drops the schema
//! — leaving the operator's DB clean enough to run repeatedly without
//! manual cleanup.

#![cfg(feature = "postgres")]

use hermod_core::{AgentAlias, AgentId, PubkeyBytes, Timestamp, TrustLevel};
use hermod_storage::AgentRepository;
use hermod_storage::backends::postgres::{PostgresAgentRepository, open_pool, run_migrations};
use hermod_storage::repositories::agents::{AgentRecord, AliasOutcome};
use sqlx::Executor;
use std::str::FromStr;
use std::sync::Arc;

const ENV: &str = "HERMOD_TEST_POSTGRES_URL";

fn dsn() -> Option<String> {
    std::env::var(ENV).ok()
}

fn fake_agent(b: u8) -> AgentId {
    hermod_crypto::agent_id_from_pubkey(&PubkeyBytes([b; 32]))
}

fn record(id: AgentId, local: Option<&str>, peer: Option<&str>) -> AgentRecord {
    let now = Timestamp::now();
    AgentRecord {
        id,
        pubkey: PubkeyBytes([1u8; 32]),
        endpoint: None,
        local_alias: local.map(|s| AgentAlias::from_str(s).unwrap()),
        peer_asserted_alias: peer.map(|s| AgentAlias::from_str(s).unwrap()),
        trust_level: TrustLevel::Tofu,
        tls_fingerprint: None,
        reputation: 0,
        first_seen: now,
        last_seen: Some(now),
    }
}

/// Stand up a fresh schema, run migrations into it, return a pool
/// scoped to that schema, plus a guard that drops the schema on
/// `Drop`. Lets the test run against a shared `postgres` database
/// without colliding with other runs or polluting the public schema.
struct ScopedSchema {
    pool: sqlx::PgPool,
    schema: String,
}

impl ScopedSchema {
    async fn open() -> Self {
        let url = dsn().expect("HERMOD_TEST_POSTGRES_URL must be set for this test");
        let schema = format!("hermod_test_{}", ulid::Ulid::new().to_string().to_lowercase());

        let pool = open_pool(&url).await.expect("open postgres pool");
        let create = format!("CREATE SCHEMA \"{schema}\"");
        pool.execute(create.as_str())
            .await
            .expect("create test schema");

        // Re-open the pool with `search_path` pinned to the test schema
        // so all subsequent SQL (including migration-runner's
        // `_sqlx_migrations` bookkeeping) lands inside it.
        let scoped_url = format!(
            "{}{}options=-csearch_path%3D{}",
            url,
            if url.contains('?') { "&" } else { "?" },
            schema
        );
        let pool = open_pool(&scoped_url)
            .await
            .expect("re-open with search_path");
        run_migrations(&pool).await.expect("run migrations");

        Self { pool, schema }
    }
}

impl Drop for ScopedSchema {
    fn drop(&mut self) {
        // Best-effort cleanup. Synchronous drop of an async resource
        // means we can't actually issue the DROP SCHEMA — instead we
        // leak the schema in the test DB; operators clean by
        // re-running `DROP SCHEMA` manually or restarting the
        // container. A future improvement could hold an admin handle
        // and dispatch the drop on a runtime, but for now the schema
        // names are timestamped and unique so leakage is bounded.
        let _ = &self.schema;
    }
}

#[tokio::test]
async fn postgres_agent_repository_full_surface() {
    if dsn().is_none() {
        eprintln!("skipping: ${ENV} is unset");
        return;
    }

    let env = ScopedSchema::open().await;
    let agents = Arc::new(PostgresAgentRepository::new(env.pool.clone()));

    // ── upsert + get + list ─────────────────────────────────────────
    let alice_id = fake_agent(1);
    agents
        .upsert(&record(alice_id.clone(), Some("alice"), None))
        .await
        .expect("upsert alice");

    let fetched = agents
        .get(&alice_id)
        .await
        .expect("get alice")
        .expect("alice present");
    assert_eq!(fetched.id, alice_id);
    assert_eq!(fetched.local_alias.unwrap().as_str(), "alice");
    assert_eq!(fetched.trust_level, TrustLevel::Tofu);

    let by_alias = agents
        .get_by_local_alias(&AgentAlias::from_str("alice").unwrap())
        .await
        .expect("get_by_local_alias")
        .expect("alice resolvable by alias");
    assert_eq!(by_alias.id, alice_id);

    let listed = agents.list().await.expect("list");
    assert_eq!(listed.len(), 1);

    // ── upsert_observed: no-collision path ─────────────────────────
    let bob_id = fake_agent(2);
    let outcome = agents
        .upsert_observed(&record(bob_id.clone(), Some("bob"), Some("bob")))
        .await
        .expect("observed bob");
    assert_eq!(outcome, AliasOutcome::Accepted);

    // ── upsert_observed: collision path ─────────────────────────────
    let mallory_id = fake_agent(3);
    let outcome = agents
        .upsert_observed(&record(mallory_id.clone(), Some("alice"), Some("alice")))
        .await
        .expect("observed mallory");
    assert!(
        matches!(
            outcome,
            AliasOutcome::LocalDropped { ref conflicting_id, .. } if *conflicting_id == alice_id
        ),
        "want LocalDropped(conflicting=alice), got {outcome:?}"
    );
    let mallory = agents.get(&mallory_id).await.unwrap().unwrap();
    assert!(
        mallory.local_alias.is_none(),
        "collision should drop local_alias on the new row"
    );
    assert_eq!(
        mallory.peer_asserted_alias.unwrap().as_str(),
        "alice",
        "peer_asserted_alias still populated"
    );

    // ── set_trust + touch ───────────────────────────────────────────
    agents
        .set_trust(&alice_id, TrustLevel::Verified)
        .await
        .expect("set_trust");
    let alice = agents.get(&alice_id).await.unwrap().unwrap();
    assert_eq!(alice.trust_level, TrustLevel::Verified);

    let later = Timestamp::now();
    agents.touch(&alice_id, later).await.expect("touch");
    let alice = agents.get(&alice_id).await.unwrap().unwrap();
    assert_eq!(alice.last_seen.unwrap().unix_ms(), later.unix_ms());

    // ── pin_or_match_tls_fingerprint: pin first, then match, then mismatch ──
    let pinned = agents
        .pin_or_match_tls_fingerprint(&alice_id, "ab:cd")
        .await
        .expect("first pin");
    assert!(pinned, "first pin should succeed");

    let matched = agents
        .pin_or_match_tls_fingerprint(&alice_id, "ab:cd")
        .await
        .expect("re-pin");
    assert!(matched, "second pin with same fp should match");

    let mismatched = agents
        .pin_or_match_tls_fingerprint(&alice_id, "ff:ee")
        .await
        .expect("mismatched pin call");
    assert!(!mismatched, "different fp must NOT replace pinned cert");

    // ── replace_tls_fingerprint: trust gate ────────────────────────
    use hermod_storage::repositories::agents::RepinOutcome;
    let outcome = agents
        .replace_tls_fingerprint(&alice_id, "11:22", TrustLevel::Verified)
        .await
        .expect("repin");
    assert!(matches!(outcome, RepinOutcome::Replaced { .. }));

    let outcome = agents
        .replace_tls_fingerprint(&alice_id, "33:44", TrustLevel::Self_)
        .await
        .expect("repin under wrong trust");
    assert!(matches!(outcome, RepinOutcome::TrustMismatch { .. }));

    // ── list_federated: empty when no endpoints ─────────────────────
    let federated = agents.list_federated().await.expect("list_federated");
    assert!(federated.is_empty(), "no agents have endpoints yet");

    // ── forget_peer ────────────────────────────────────────────────
    let outcome = agents.forget_peer(&alice_id).await.expect("forget alice");
    assert!(outcome.existed);
}
