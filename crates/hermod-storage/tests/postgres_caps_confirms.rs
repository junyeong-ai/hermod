//! Integration tests for the third batch of PostgreSQL repository
//! implementations: `CapabilityRepository` + `ConfirmationRepository`.
//!
//! Same gating + scoped-schema pattern as the prior Postgres test
//! files. Each test runs against a fresh schema.

#![cfg(feature = "postgres")]

use hermod_core::{AgentId, MessageId, PubkeyBytes, Timestamp, TrustLevel};
use hermod_storage::AgentRepository;
use hermod_storage::backends::postgres::{
    PostgresAgentRepository, PostgresCapabilityRepository, PostgresConfirmationRepository,
    open_pool, run_migrations,
};
use hermod_storage::repositories::agents::AgentRecord;
use hermod_storage::repositories::capabilities::{
    CapabilityFilter, CapabilityRecord, CapabilityRepository,
};
use hermod_storage::repositories::confirmations::{
    ConfirmationRepository, ConfirmationStatus, HoldRequest, HoldedIntent,
};
use sqlx::Executor;
use std::sync::Arc;

const ENV: &str = "HERMOD_TEST_POSTGRES_URL";

fn dsn() -> Option<String> {
    std::env::var(ENV).ok()
}

fn fake_agent(b: u8) -> AgentId {
    hermod_crypto::agent_id_from_pubkey(&PubkeyBytes([b; 32]))
}

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
        .expect("seed agent");
}

fn cap_record(id: &str, issuer: AgentId, scope: &str) -> CapabilityRecord {
    CapabilityRecord {
        id: id.into(),
        issuer,
        audience: None,
        scope: scope.into(),
        target: None,
        expires_at: None,
        revoked_at: None,
        raw_token: vec![0xab, 0xcd],
    }
}

// ── capabilities ────────────────────────────────────────────────────

#[tokio::test]
async fn caps_upsert_revoke_is_revoked_roundtrip() {
    if dsn().is_none() {
        return;
    }
    let pool = open_scoped().await;
    let issuer = fake_agent(1);
    seed_agent(&pool, issuer.clone()).await;

    let caps = PostgresCapabilityRepository::new(pool.clone());
    let cap = cap_record("cap-1", issuer.clone(), "message:send");
    caps.upsert(&cap).await.expect("upsert");

    assert!(!caps.is_revoked("cap-1").await.unwrap());
    let revoked = caps.revoke("cap-1", Timestamp::now()).await.unwrap();
    assert!(revoked, "first revoke succeeds");
    assert!(caps.is_revoked("cap-1").await.unwrap());

    // Idempotent: second revoke on already-revoked returns false.
    let again = caps.revoke("cap-1", Timestamp::now()).await.unwrap();
    assert!(!again);
}

#[tokio::test]
async fn caps_active_audiences_filters_revoked_and_expired() {
    if dsn().is_none() {
        return;
    }
    let pool = open_scoped().await;
    let issuer = fake_agent(2);
    seed_agent(&pool, issuer.clone()).await;
    let alice = fake_agent(10);
    let bob = fake_agent(11);
    let carol = fake_agent(12);
    for a in [&alice, &bob, &carol] {
        seed_agent(&pool, a.clone()).await;
    }

    let caps = PostgresCapabilityRepository::new(pool.clone());
    let now = Timestamp::now();

    let mut active = cap_record("cap-active", issuer.clone(), "channel:advertise");
    active.audience = Some(alice.clone());
    caps.upsert(&active).await.unwrap();

    let mut revoked = cap_record("cap-revoked", issuer.clone(), "channel:advertise");
    revoked.audience = Some(bob.clone());
    caps.upsert(&revoked).await.unwrap();
    caps.revoke("cap-revoked", now).await.unwrap();

    let mut expired = cap_record("cap-expired", issuer.clone(), "channel:advertise");
    expired.audience = Some(carol.clone());
    expired.expires_at = Some(Timestamp::from_unix_ms(now.unix_ms() - 1).unwrap());
    caps.upsert(&expired).await.unwrap();

    let active_audiences = caps
        .active_audiences_for_scope(&issuer, "channel:advertise", now.unix_ms())
        .await
        .unwrap();
    assert_eq!(active_audiences.len(), 1);
    assert_eq!(active_audiences[0], alice);
}

#[tokio::test]
async fn caps_list_dynamic_filters_apply_correctly() {
    if dsn().is_none() {
        return;
    }
    let pool = open_scoped().await;
    let issuer = fake_agent(3);
    seed_agent(&pool, issuer.clone()).await;

    let caps = PostgresCapabilityRepository::new(pool.clone());
    let now = Timestamp::now();

    // Three rows: active, expired, revoked.
    caps.upsert(&cap_record("a", issuer.clone(), "x"))
        .await
        .unwrap();
    let mut e = cap_record("b", issuer.clone(), "x");
    e.expires_at = Some(Timestamp::from_unix_ms(now.unix_ms() - 1).unwrap());
    caps.upsert(&e).await.unwrap();
    caps.upsert(&cap_record("c", issuer.clone(), "x"))
        .await
        .unwrap();
    caps.revoke("c", now).await.unwrap();

    // Default filter: include_revoked=false, include_expired=false
    let listed = caps
        .list(
            &issuer,
            now.unix_ms(),
            &CapabilityFilter {
                include_revoked: false,
                include_expired: false,
                limit: None,
                after_id: None,
                direction: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(listed.len(), 1, "only active row should appear");
    assert_eq!(listed[0].id, "a");

    // include_revoked + include_expired returns all three.
    let all = caps
        .list(
            &issuer,
            now.unix_ms(),
            &CapabilityFilter {
                include_revoked: true,
                include_expired: true,
                limit: None,
                after_id: None,
                direction: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(all.len(), 3);

    // Cursor + limit: skip past `a`, take 1 → expect `b` (next by id ASC).
    let page = caps
        .list(
            &issuer,
            now.unix_ms(),
            &CapabilityFilter {
                include_revoked: true,
                include_expired: true,
                limit: Some(1),
                after_id: Some("a".into()),
                direction: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].id, "b");
}

#[tokio::test]
async fn caps_prune_terminal_drops_only_expired() {
    if dsn().is_none() {
        return;
    }
    let pool = open_scoped().await;
    let issuer = fake_agent(4);
    seed_agent(&pool, issuer.clone()).await;

    let caps = PostgresCapabilityRepository::new(pool.clone());
    let now = Timestamp::now();

    let mut expired = cap_record("old", issuer.clone(), "x");
    expired.expires_at = Some(Timestamp::from_unix_ms(now.unix_ms() - 1).unwrap());
    caps.upsert(&expired).await.unwrap();

    let mut future = cap_record("new", issuer.clone(), "x");
    future.expires_at = Some(Timestamp::from_unix_ms(now.unix_ms() + 60_000).unwrap());
    caps.upsert(&future).await.unwrap();

    caps.upsert(&cap_record("forever", issuer.clone(), "x"))
        .await
        .unwrap();

    let pruned = caps.prune_terminal(now.unix_ms()).await.unwrap();
    assert_eq!(pruned, 1);

    let listed = caps
        .list(
            &issuer,
            now.unix_ms(),
            &CapabilityFilter {
                include_revoked: true,
                include_expired: true,
                limit: None,
                after_id: None,
                direction: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(listed.len(), 2);
}

// ── confirmations ───────────────────────────────────────────────────

#[tokio::test]
async fn confirmations_dedupe_pending_envelope_under_partial_index() {
    if dsn().is_none() {
        return;
    }
    let pool = open_scoped().await;
    let actor = fake_agent(20);
    seed_agent(&pool, actor.clone()).await;

    let conf = PostgresConfirmationRepository::new(pool.clone());
    let env_id = MessageId::new();
    let req = |summary: &'static str| HoldRequest {
        envelope_id: &env_id,
        actor: &actor,
        intent: HoldedIntent::DirectMessage,
        sensitivity: "review",
        trust_level: TrustLevel::Tofu,
        summary,
        envelope_cbor: b"\x00",
    };

    let first = conf.enqueue(req("first")).await.unwrap();
    let second = conf.enqueue(req("retry")).await.unwrap();
    assert!(first.is_some(), "first must insert");
    assert!(second.is_none(), "duplicate envelope must dedupe to None");

    let pending = conf.list_pending(10, None).await.unwrap();
    assert_eq!(pending.len(), 1);

    // After the first row is decided, a fresh enqueue for the same
    // envelope_id should succeed — the partial unique index only
    // constrains pending rows.
    conf.decide(
        &first.unwrap(),
        ConfirmationStatus::Rejected,
        &actor,
        Timestamp::now(),
    )
    .await
    .unwrap();
    let third = conf.enqueue(req("third")).await.unwrap();
    assert!(third.is_some(), "after decide, re-enqueue must succeed");
}

#[tokio::test]
async fn confirmations_quota_check_under_concurrent_enqueue() {
    if dsn().is_none() {
        return;
    }
    let pool = open_scoped().await;
    let actor = fake_agent(21);
    seed_agent(&pool, actor.clone()).await;

    let conf = Arc::new(PostgresConfirmationRepository::new(pool.clone()));
    use hermod_storage::MAX_PENDING_PER_ACTOR;

    // Spawn 2*MAX concurrent enqueues for distinct envelopes; the
    // advisory lock should serialise the quota check + insert so the
    // total accepted equals exactly MAX. Excess attempts surface as
    // QuotaExceeded errors that we count separately.
    let n = (MAX_PENDING_PER_ACTOR * 2) as u32;
    let mut handles = Vec::new();
    for _ in 0..n {
        let conf = conf.clone();
        let actor = actor.clone();
        handles.push(tokio::spawn(async move {
            // Each task uses a distinct envelope_id so they don't dedupe.
            let env_id = MessageId::new();
            let req = HoldRequest {
                envelope_id: &env_id,
                actor: &actor,
                intent: HoldedIntent::DirectMessage,
                sensitivity: "review",
                trust_level: TrustLevel::Tofu,
                summary: "concurrent",
                envelope_cbor: b"\x00",
            };
            conf.enqueue(req).await
        }));
    }
    let mut accepted = 0u64;
    let mut quota_errors = 0u64;
    let mut other_errors = 0u64;
    for h in handles {
        match h.await.unwrap() {
            Ok(Some(_)) => accepted += 1,
            Ok(None) => other_errors += 1, // shouldn't happen: distinct envelopes can't dedupe
            Err(hermod_storage::StorageError::QuotaExceeded(_)) => quota_errors += 1,
            Err(other) => panic!("unexpected error: {other:?}"),
        }
    }
    assert_eq!(
        accepted, MAX_PENDING_PER_ACTOR,
        "exactly the quota must be admitted; got {accepted}"
    );
    assert_eq!(
        quota_errors,
        n as u64 - MAX_PENDING_PER_ACTOR,
        "the rest must be quota-rejected"
    );
    assert_eq!(other_errors, 0);
}

#[tokio::test]
async fn confirmations_decide_is_idempotent() {
    if dsn().is_none() {
        return;
    }
    let pool = open_scoped().await;
    let actor = fake_agent(22);
    seed_agent(&pool, actor.clone()).await;

    let conf = PostgresConfirmationRepository::new(pool.clone());
    let env_id = MessageId::new();
    let id = conf
        .enqueue(HoldRequest {
            envelope_id: &env_id,
            actor: &actor,
            intent: HoldedIntent::DirectMessage,
            sensitivity: "review",
            trust_level: TrustLevel::Tofu,
            summary: "decide-test",
            envelope_cbor: b"\x00",
        })
        .await
        .unwrap()
        .unwrap();

    let first = conf
        .decide(&id, ConfirmationStatus::Accepted, &actor, Timestamp::now())
        .await
        .unwrap();
    assert!(first, "first decide transitions");

    let second = conf
        .decide(&id, ConfirmationStatus::Accepted, &actor, Timestamp::now())
        .await
        .unwrap();
    assert!(!second, "second decide is a no-op (idempotent)");
}

#[tokio::test]
async fn confirmations_expire_pending_older_than_cutoff() {
    if dsn().is_none() {
        return;
    }
    let pool = open_scoped().await;
    let actor = fake_agent(23);
    seed_agent(&pool, actor.clone()).await;

    let conf = PostgresConfirmationRepository::new(pool.clone());
    let env1 = MessageId::new();
    let env2 = MessageId::new();
    conf.enqueue(HoldRequest {
        envelope_id: &env1,
        actor: &actor,
        intent: HoldedIntent::DirectMessage,
        sensitivity: "review",
        trust_level: TrustLevel::Tofu,
        summary: "old",
        envelope_cbor: b"\x00",
    })
    .await
    .unwrap();
    // Bump time so the second row is fresh.
    tokio::time::sleep(std::time::Duration::from_millis(15)).await;
    let mid_ms = Timestamp::now().unix_ms();
    tokio::time::sleep(std::time::Duration::from_millis(15)).await;
    conf.enqueue(HoldRequest {
        envelope_id: &env2,
        actor: &actor,
        intent: HoldedIntent::DirectMessage,
        sensitivity: "review",
        trust_level: TrustLevel::Tofu,
        summary: "fresh",
        envelope_cbor: b"\x00",
    })
    .await
    .unwrap();

    let expired = conf.expire_pending_older_than(mid_ms).await.unwrap();
    assert_eq!(expired, 1);
    let pending = conf.list_pending(10, None).await.unwrap();
    assert_eq!(pending.len(), 1, "fresh row remains pending");
}
