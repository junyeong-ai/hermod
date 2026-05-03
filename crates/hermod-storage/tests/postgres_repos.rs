//! Integration tests for the second batch of PostgreSQL repository
//! implementations: `BriefRepository`, `RateLimitRepository`,
//! `AgentPresenceRepository`, `McpSessionRepository`.
//!
//! Same gating pattern as `postgres_agents.rs`:
//!
//!   ```sh
//!   docker run --rm -d --name hermod-pg \
//!       -e POSTGRES_PASSWORD=hermod -p 5433:5432 postgres:16
//!   export HERMOD_TEST_POSTGRES_URL='postgres://postgres:hermod@127.0.0.1:5433/postgres'
//!   cargo test -p hermod-storage --features postgres --test postgres_repos
//!   ```
//!
//! Each `#[tokio::test]` opens its own scoped schema so it can run in
//! parallel with siblings without contention.

#![cfg(feature = "postgres")]

use hermod_core::{
    AgentAlias, AgentId, McpSessionId, PresenceStatus, PubkeyBytes, Timestamp, TrustLevel,
};
use hermod_storage::AgentRepository;
use hermod_storage::backends::postgres::{
    PostgresAgentPresenceRepository, PostgresAgentRepository, PostgresBriefRepository,
    PostgresMcpSessionRepository, PostgresRateLimitRepository, open_pool, run_migrations,
};
use hermod_storage::repositories::agents::AgentRecord;
use hermod_storage::repositories::briefs::{BriefRecord, BriefRepository};
use hermod_storage::repositories::presence::{
    AgentPresenceRepository, AttachOutcome, AttachParams, McpSessionRepository, ObservedPresence,
};
use hermod_storage::repositories::rate_limit::RateLimitRepository;
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

/// Stand up a fresh schema, run migrations into it, return a pool
/// scoped to that schema.
async fn open_scoped() -> sqlx::PgPool {
    let url = dsn().expect("HERMOD_TEST_POSTGRES_URL must be set");
    let schema = format!(
        "hermod_test_{}",
        ulid::Ulid::new().to_string().to_lowercase()
    );

    let setup = open_pool(&url).await.expect("open pool for setup");
    let create = format!("CREATE SCHEMA \"{schema}\"");
    setup
        .execute(create.as_str())
        .await
        .expect("create test schema");

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
    pool
}

async fn seed_agent(pool: &sqlx::PgPool, id: AgentId) {
    let agents = PostgresAgentRepository::new(pool.clone());
    let now = Timestamp::now();
    agents
        .upsert(&AgentRecord {
            id,
            pubkey: PubkeyBytes([1u8; 32]),
            endpoint: None,
            via_agent: None,
            local_alias: None,
            peer_asserted_alias: None,
            trust_level: TrustLevel::Tofu,
            reputation: 0,
            first_seen: now,
            last_seen: Some(now),
        })
        .await
        .expect("seed agent");
}

// ── briefs ──────────────────────────────────────────────────────────

#[tokio::test]
async fn briefs_upsert_replaces_within_topic_and_latest_picks_freshest() {
    if dsn().is_none() {
        eprintln!("skipping: ${ENV} unset");
        return;
    }
    let pool = open_scoped().await;
    let agent = fake_agent(10);
    seed_agent(&pool, agent.clone()).await;

    let briefs = PostgresBriefRepository::new(pool.clone());
    let now = Timestamp::now();

    // Default topic (NULL).
    briefs
        .upsert(&BriefRecord {
            agent_id: agent.clone(),
            topic: None,
            summary: "first".into(),
            published_at: now,
            expires_at: None,
        })
        .await
        .expect("insert default brief");
    briefs
        .upsert(&BriefRecord {
            agent_id: agent.clone(),
            topic: None,
            summary: "second (overwrites)".into(),
            published_at: now,
            expires_at: None,
        })
        .await
        .expect("upsert default brief");

    // Distinct topic.
    briefs
        .upsert(&BriefRecord {
            agent_id: agent.clone(),
            topic: Some("status".into()),
            summary: "topic-status".into(),
            published_at: now,
            expires_at: None,
        })
        .await
        .expect("insert topic brief");

    let latest_default = briefs
        .latest(&agent, None, now.unix_ms())
        .await
        .expect("latest default")
        .expect("present");
    assert_eq!(latest_default.summary, "second (overwrites)");

    let latest_status = briefs
        .latest(&agent, Some("status"), now.unix_ms())
        .await
        .expect("latest topic=status")
        .expect("present");
    assert_eq!(latest_status.summary, "topic-status");
}

#[tokio::test]
async fn briefs_prune_expired_only_drops_past_their_ttl() {
    if dsn().is_none() {
        return;
    }
    let pool = open_scoped().await;
    let agent = fake_agent(11);
    seed_agent(&pool, agent.clone()).await;

    let briefs = PostgresBriefRepository::new(pool.clone());
    let t0 = Timestamp::now();
    let expired_at = Timestamp::from_unix_ms(t0.unix_ms() - 1).unwrap();
    let future = Timestamp::from_unix_ms(t0.unix_ms() + 60_000).unwrap();

    briefs
        .upsert(&BriefRecord {
            agent_id: agent.clone(),
            topic: Some("expiring".into()),
            summary: "old".into(),
            published_at: t0,
            expires_at: Some(expired_at),
        })
        .await
        .expect("upsert expiring");
    briefs
        .upsert(&BriefRecord {
            agent_id: agent.clone(),
            topic: Some("fresh".into()),
            summary: "still here".into(),
            published_at: t0,
            expires_at: Some(future),
        })
        .await
        .expect("upsert fresh");

    let pruned = briefs.prune_expired(t0.unix_ms()).await.unwrap();
    assert_eq!(pruned, 1);

    assert!(
        briefs
            .latest(&agent, Some("expiring"), t0.unix_ms())
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        briefs
            .latest(&agent, Some("fresh"), t0.unix_ms())
            .await
            .unwrap()
            .is_some()
    );
}

// ── rate_limit ──────────────────────────────────────────────────────

#[tokio::test]
async fn rate_limit_bucket_drains_and_refills() {
    if dsn().is_none() {
        return;
    }
    let pool = open_scoped().await;
    let rl = PostgresRateLimitRepository::new(pool.clone());
    let now = Timestamp::now();

    assert!(rl.try_consume_one("a|b", 2, 60, now).await.unwrap());
    assert!(rl.try_consume_one("a|b", 2, 60, now).await.unwrap());
    assert!(!rl.try_consume_one("a|b", 2, 60, now).await.unwrap());

    // 60 tokens/min → 1/sec; 2s later we should be back to 1 token.
    let later = Timestamp::from_unix_ms(now.unix_ms() + 2_000).unwrap();
    assert!(rl.try_consume_one("a|b", 2, 60, later).await.unwrap());
}

#[tokio::test]
async fn rate_limit_concurrent_consumers_never_over_deliver() {
    if dsn().is_none() {
        return;
    }
    let pool = open_scoped().await;
    let rl = Arc::new(PostgresRateLimitRepository::new(pool.clone()));
    let now = Timestamp::now();

    // capacity=4, refill=0 — exactly 4 grants total under the race.
    // The repo internally retries on SERIALIZABLE conflict
    // (Postgres-specific) so the trait contract is preserved
    // unchanged from SQLite: each call returns true (granted) or
    // false (denied), never a serialisation error.
    let mut handles = Vec::new();
    for _ in 0..16u32 {
        let rl = rl.clone();
        handles.push(tokio::spawn(async move {
            rl.try_consume_one("racer|target", 4, 0, now).await.unwrap()
        }));
    }
    let mut granted = 0u32;
    for h in handles {
        if h.await.unwrap() {
            granted += 1;
        }
    }
    assert_eq!(
        granted, 4,
        "exactly capacity must be granted under race; got {granted}"
    );
}

// ── presence ────────────────────────────────────────────────────────

#[tokio::test]
async fn presence_set_and_clear_manual_status_roundtrips() {
    if dsn().is_none() {
        return;
    }
    let pool = open_scoped().await;
    let agent = fake_agent(20);
    seed_agent(&pool, agent.clone()).await;

    let presence = PostgresAgentPresenceRepository::new(pool.clone());
    let t0 = Timestamp::now();
    let exp = Timestamp::from_unix_ms(t0.unix_ms() + 60_000).unwrap();

    presence
        .set_manual(&agent, PresenceStatus::Busy, t0, Some(exp))
        .await
        .expect("set busy");
    let rec = presence.get(&agent).await.expect("get").expect("present");
    assert_eq!(rec.manual_status, Some(PresenceStatus::Busy));
    assert_eq!(
        rec.manual_status_expires_at.unwrap().unix_ms(),
        exp.unix_ms()
    );

    presence.clear_manual(&agent).await.expect("clear");
    let rec = presence.get(&agent).await.unwrap().unwrap();
    assert!(rec.manual_status.is_none());
    assert!(rec.manual_status_set_at.is_none());
}

#[tokio::test]
async fn presence_observe_peer_persists_live_flag() {
    if dsn().is_none() {
        return;
    }
    let pool = open_scoped().await;
    let peer = fake_agent(21);
    seed_agent(&pool, peer.clone()).await;

    let presence = PostgresAgentPresenceRepository::new(pool.clone());
    let t0 = Timestamp::now();
    let exp = Timestamp::from_unix_ms(t0.unix_ms() + 60_000).unwrap();

    presence
        .observe_peer(
            &peer,
            ObservedPresence {
                manual_status: Some(PresenceStatus::Idle),
                live: true,
                observed_at: t0,
                expires_at: exp,
            },
        )
        .await
        .expect("observe peer");

    let rec = presence.get(&peer).await.unwrap().unwrap();
    assert_eq!(rec.manual_status, Some(PresenceStatus::Idle));
    assert_eq!(rec.peer_live, Some(true));
    assert_eq!(rec.peer_live_expires_at.unwrap().unix_ms(), exp.unix_ms());

    // Re-observe with live=false flips the cache.
    presence
        .observe_peer(
            &peer,
            ObservedPresence {
                manual_status: None,
                live: false,
                observed_at: t0,
                expires_at: exp,
            },
        )
        .await
        .expect("re-observe");
    let rec = presence.get(&peer).await.unwrap().unwrap();
    assert_eq!(rec.peer_live, Some(false));
}

// ── mcp_sessions ────────────────────────────────────────────────────

#[tokio::test]
async fn mcp_attach_detach_track_liveness_correctly() {
    if dsn().is_none() {
        return;
    }
    let pool = open_scoped().await;
    let mcp = PostgresMcpSessionRepository::new(pool.clone());

    let now = Timestamp::now();
    let ttl_ms: i64 = 60_000;

    // mcp_sessions FKs to agents — seed an agent before attaching.
    let agent = fake_agent(20);
    seed_agent(&pool, agent.clone()).await;

    let p1 = AttachParams {
        session_id: McpSessionId::from_raw("sess-1".into()),
        agent_id: agent.clone(),
        session_label: None,
        attached_at: now,
        client_name: Some("claude".into()),
        client_version: Some("0.1".into()),
        ttl_ms,
    };
    let p2 = AttachParams {
        session_id: McpSessionId::from_raw("sess-2".into()),
        ..p1.clone()
    };

    let outcome_first = mcp.attach(p1).await.unwrap();
    let was_live_before_first = matches!(
        outcome_first,
        AttachOutcome::Inserted {
            was_live: false,
            ..
        }
    );
    assert!(was_live_before_first, "no sessions before first attach");
    let outcome_second = mcp.attach(p2).await.unwrap();
    let was_live_before_second = matches!(
        outcome_second,
        AttachOutcome::Inserted { was_live: true, .. }
    );
    assert!(
        was_live_before_second,
        "first session is live when second attaches"
    );

    assert_eq!(mcp.count_live(now, ttl_ms).await.unwrap(), 2);
    assert_eq!(mcp.count_live_for(&agent, now, ttl_ms).await.unwrap(), 2);
    let other = fake_agent(21);
    seed_agent(&pool, other.clone()).await;
    assert_eq!(
        mcp.count_live_for(&other, now, ttl_ms).await.unwrap(),
        0,
        "agent without sessions reads as not-live regardless of host activity"
    );

    // Heartbeat keeps the session live.
    let later = Timestamp::from_unix_ms(now.unix_ms() + 30_000).unwrap();
    let sess1 = McpSessionId::from_raw("sess-1".into());
    let sess2 = McpSessionId::from_raw("sess-2".into());
    assert!(mcp.heartbeat(&sess1, later).await.unwrap());

    // Detach one — should still be live (the other is fresh).
    let outcome = mcp.detach_atomic(&sess1, later, ttl_ms).await.unwrap();
    assert!(outcome.was_live);
    assert!(outcome.is_live);

    // Detach the other — last live session goes away.
    let outcome = mcp.detach_atomic(&sess2, later, ttl_ms).await.unwrap();
    assert!(outcome.was_live);
    assert!(!outcome.is_live);
}

#[tokio::test]
async fn mcp_prune_with_transition_drops_stale_and_reports_was_live_correctly() {
    if dsn().is_none() {
        return;
    }
    let pool = open_scoped().await;
    let mcp = PostgresMcpSessionRepository::new(pool.clone());

    let attached = Timestamp::now();
    let ttl_ms: i64 = 60_000;
    let agent = fake_agent(22);
    seed_agent(&pool, agent.clone()).await;

    mcp.attach(AttachParams {
        session_id: McpSessionId::from_raw("stale".into()),
        agent_id: agent,
        session_label: None,
        attached_at: attached,
        client_name: None,
        client_version: None,
        ttl_ms,
    })
    .await
    .unwrap();

    // Fast-forward way past the TTL so the session is stale.
    let now = Timestamp::from_unix_ms(attached.unix_ms() + ttl_ms + 1_000).unwrap();
    let outcome = mcp.prune_with_transition(now, ttl_ms).await.unwrap();
    assert_eq!(outcome.pruned, 1);
    assert!(!outcome.was_live, "stale session counted as not-live");
    assert!(!outcome.is_live);
}

// ── alias resolution test re-uses Phase 6.1's PostgresAgentRepository to keep
// the integration test suite cross-checking trait surface coverage ──

#[tokio::test]
async fn briefs_test_uses_real_agents_repo_so_agent_id_fk_resolves() {
    if dsn().is_none() {
        return;
    }
    // Demonstrates that BriefRepository's agent_id FK is honoured —
    // upsert without seeding fails.
    let pool = open_scoped().await;
    let briefs = PostgresBriefRepository::new(pool.clone());
    let agent = fake_agent(99);
    let now = Timestamp::now();
    let result = briefs
        .upsert(&BriefRecord {
            agent_id: agent.clone(),
            topic: None,
            summary: "no agent yet".into(),
            published_at: now,
            expires_at: None,
        })
        .await;
    assert!(
        result.is_err(),
        "FK to agents must reject upsert when agent absent"
    );

    // Then with the agent seeded, it works.
    seed_agent(&pool, agent.clone()).await;
    briefs
        .upsert(&BriefRecord {
            agent_id: agent,
            topic: None,
            summary: "now ok".into(),
            published_at: now,
            expires_at: None,
        })
        .await
        .expect("upsert with seeded agent");

    // Touch the alias type so the import isn't dead — preserves
    // single-source-of-truth in the imports list.
    let _ = AgentAlias::from_str("ignored").ok();
}
