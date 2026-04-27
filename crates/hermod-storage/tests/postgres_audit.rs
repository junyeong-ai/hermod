//! Integration tests for the PostgreSQL `AuditRepository` and the
//! end-to-end `connect("postgres://…")` factory path.
//!
//! Same gating + scoped-schema pattern as the prior Postgres test
//! files. The headline test exercises hash-chain integrity under
//! 16-way concurrent appends — the global advisory lock keyed on
//! `hashtext('audit_log')` is what makes this safe on Postgres.

#![cfg(feature = "postgres")]
// Tests exercise `AuditRepository::append` directly to validate the
// hash-chain implementation; production code goes through
// `AuditSink`, but the storage-layer test suite has to call into
// the repo to assert chain semantics.
#![allow(clippy::disallowed_methods)]

use hermod_core::{AgentId, PubkeyBytes, Timestamp};
use hermod_crypto::{Keypair, LocalKeySigner, Signer};
use hermod_storage::backends::postgres::{PostgresAuditRepository, open_pool, run_migrations};
use hermod_storage::repositories::audit::{AuditEntry, AuditRepository, ChainVerification};
use sqlx::Executor;
use std::sync::Arc;

const ENV: &str = "HERMOD_TEST_POSTGRES_URL";

fn dsn() -> Option<String> {
    std::env::var(ENV).ok()
}

fn fake_actor() -> AgentId {
    hermod_crypto::agent_id_from_pubkey(&PubkeyBytes([1u8; 32]))
}

fn fake_signer() -> Arc<dyn Signer> {
    Arc::new(LocalKeySigner::new(Arc::new(Keypair::generate())))
}

async fn open_scoped() -> (sqlx::PgPool, String) {
    let url = dsn().expect("HERMOD_TEST_POSTGRES_URL must be set");
    let schema = format!("hermod_test_{}", ulid::Ulid::new().to_string().to_lowercase());

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
    (pool, scoped_url)
}

#[tokio::test]
async fn signed_chain_verifies() {
    if dsn().is_none() {
        return;
    }
    let (pool, _url) = open_scoped().await;
    let signer = fake_signer();
    let audit = PostgresAuditRepository::new(pool.clone(), signer);
    let actor = fake_actor();

    for i in 0..5 {
        audit
            .append(&AuditEntry {
                id: None,
                ts: Timestamp::now(),
                actor: actor.clone(),
                action: format!("test.{i}"),
                target: Some(format!("t{i}")),
                details: Some(serde_json::json!({"i": i})),
                federation: hermod_storage::AuditFederationPolicy::Default,
            })
            .await
            .unwrap();
    }
    let v = audit.verify_chain().await.unwrap();
    assert_eq!(v, ChainVerification::Ok { rows: 5 });
}

#[tokio::test]
async fn tamper_detected_as_hash_mismatch() {
    if dsn().is_none() {
        return;
    }
    let (pool, _url) = open_scoped().await;
    let signer = fake_signer();
    let audit = PostgresAuditRepository::new(pool.clone(), signer);
    let actor = fake_actor();

    let id = audit
        .append(&AuditEntry {
            id: None,
            ts: Timestamp::now(),
            actor: actor.clone(),
            action: "honest".into(),
            target: None,
            details: None,
            federation: hermod_storage::AuditFederationPolicy::Default,
        })
        .await
        .unwrap();

    sqlx::query("UPDATE audit_log SET action = 'tampered' WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();

    let v = audit.verify_chain().await.unwrap();
    assert_eq!(v, ChainVerification::HashMismatch { row_id: id });
}

#[tokio::test]
async fn missing_link_detected() {
    if dsn().is_none() {
        return;
    }
    let (pool, _url) = open_scoped().await;
    let signer = fake_signer();
    let audit = PostgresAuditRepository::new(pool.clone(), signer);
    let actor = fake_actor();

    let mut ids = Vec::new();
    for i in 0..3 {
        ids.push(
            audit
                .append(&AuditEntry {
                    id: None,
                    ts: Timestamp::now(),
                    actor: actor.clone(),
                    action: format!("step.{i}"),
                    target: None,
                    details: None,
                    federation: hermod_storage::AuditFederationPolicy::Default,
                })
                .await
                .unwrap(),
        );
    }

    // Surgically delete the middle row.
    sqlx::query("DELETE FROM audit_log WHERE id = $1")
        .bind(ids[1])
        .execute(&pool)
        .await
        .unwrap();

    let v = audit.verify_chain().await.unwrap();
    assert_eq!(v, ChainVerification::BrokenLink { row_id: ids[2] });
}

#[tokio::test]
async fn concurrent_appends_chain_correctly() {
    if dsn().is_none() {
        return;
    }
    let (pool, _url) = open_scoped().await;
    let signer = fake_signer();
    let audit = Arc::new(PostgresAuditRepository::new(pool.clone(), signer));
    let actor = fake_actor();

    let mut handles = Vec::new();
    for i in 0..16u32 {
        let audit = audit.clone();
        let actor = actor.clone();
        handles.push(tokio::spawn(async move {
            audit
                .append(&AuditEntry {
                    id: None,
                    ts: Timestamp::now(),
                    actor,
                    action: format!("race.{i}"),
                    target: None,
                    details: None,
                    federation: hermod_storage::AuditFederationPolicy::Default,
                })
                .await
                .expect("append must succeed under contention")
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
    // The advisory-lock is what makes this work: every append takes
    // the same lock keyed on hashtext('audit_log'), so they queue and
    // each links against the previous winner's row.
    let v = audit.verify_chain().await.unwrap();
    assert_eq!(v, ChainVerification::Ok { rows: 16 });
}

#[tokio::test]
async fn query_filters_actor_and_action_with_dynamic_placeholders() {
    if dsn().is_none() {
        return;
    }
    let (pool, _url) = open_scoped().await;
    let signer = fake_signer();
    let audit = PostgresAuditRepository::new(pool.clone(), signer);
    let actor = fake_actor();
    let other = hermod_crypto::agent_id_from_pubkey(&PubkeyBytes([2u8; 32]));

    audit
        .append(&AuditEntry {
            id: None,
            ts: Timestamp::now(),
            actor: actor.clone(),
            action: "alpha".into(),
            target: None,
            details: None,
            federation: hermod_storage::AuditFederationPolicy::Default,
        })
        .await
        .unwrap();
    audit
        .append(&AuditEntry {
            id: None,
            ts: Timestamp::now(),
            actor: actor.clone(),
            action: "beta".into(),
            target: None,
            details: None,
            federation: hermod_storage::AuditFederationPolicy::Default,
        })
        .await
        .unwrap();
    audit
        .append(&AuditEntry {
            id: None,
            ts: Timestamp::now(),
            actor: other.clone(),
            action: "alpha".into(),
            target: None,
            details: None,
            federation: hermod_storage::AuditFederationPolicy::Default,
        })
        .await
        .unwrap();

    // No filter — all 3.
    let all = audit.query(None, None, None, 100).await.unwrap();
    assert_eq!(all.len(), 3);

    // Filter by actor only.
    let by_actor = audit.query(Some(&actor), None, None, 100).await.unwrap();
    assert_eq!(by_actor.len(), 2);

    // Filter by action only.
    let by_action = audit.query(None, Some("alpha"), None, 100).await.unwrap();
    assert_eq!(by_action.len(), 2);

    // Both filters — the placeholder builder must keep $N in lock-step.
    let both = audit
        .query(Some(&actor), Some("alpha"), None, 100)
        .await
        .unwrap();
    assert_eq!(both.len(), 1);
    assert_eq!(both[0].action, "alpha");
    assert_eq!(both[0].actor, actor);
}

#[tokio::test]
async fn earliest_ts_returns_min_or_none() {
    if dsn().is_none() {
        return;
    }
    let (pool, _url) = open_scoped().await;
    let signer = fake_signer();
    let audit = PostgresAuditRepository::new(pool.clone(), signer);

    assert_eq!(audit.earliest_ts().await.unwrap(), None);

    let actor = fake_actor();
    let t1 = Timestamp::from_unix_ms(1_700_000_000_000).unwrap();
    let t2 = Timestamp::from_unix_ms(1_700_000_001_000).unwrap();
    audit
        .append(&AuditEntry {
            id: None,
            ts: t2,
            actor: actor.clone(),
            action: "later".into(),
            target: None,
            details: None,
            federation: hermod_storage::AuditFederationPolicy::Default,
        })
        .await
        .unwrap();
    audit
        .append(&AuditEntry {
            id: None,
            ts: t1,
            actor,
            action: "earlier".into(),
            target: None,
            details: None,
            federation: hermod_storage::AuditFederationPolicy::Default,
        })
        .await
        .unwrap();

    assert_eq!(audit.earliest_ts().await.unwrap(), Some(t1.unix_ms()));
}

#[tokio::test]
async fn archive_day_then_verify_archive_roundtrip() {
    if dsn().is_none() {
        return;
    }
    let (pool, _url) = open_scoped().await;
    let signer = fake_signer();
    let audit = PostgresAuditRepository::new(pool.clone(), signer);
    let actor = fake_actor();
    let blobs = Arc::new(hermod_storage::MemoryBlobStore::new());

    // Seed rows inside a fixed UTC day.
    let day_start: i64 = 1_700_006_400_000; // 2023-11-15 00:00:00 UTC
    let day_end = day_start + 24 * 3600 * 1000;
    for i in 0..5 {
        let ts = Timestamp::from_unix_ms(day_start + (i as i64) * 1000).unwrap();
        audit
            .append(&AuditEntry {
                id: None,
                ts,
                actor: actor.clone(),
                action: format!("day.{i}"),
                target: Some(format!("t{i}")),
                details: Some(serde_json::json!({"i": i})),
                federation: hermod_storage::AuditFederationPolicy::Default,
            })
            .await
            .unwrap();
    }

    let summary = audit
        .archive_day(blobs.as_ref(), day_start, day_end)
        .await
        .unwrap()
        .expect("archive produced");
    assert_eq!(summary.row_count, 5);
    assert_eq!(summary.deleted_rows, 5);

    // Live audit_log should be empty for that day now.
    let live: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_log")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(live, 0);

    let archives = audit.list_archives(10).await.unwrap();
    assert_eq!(archives.len(), 1);
    assert_eq!(archives[0].epoch_start_ms, day_start);

    let verification = audit
        .verify_archive(blobs.as_ref(), day_start)
        .await
        .unwrap();
    use hermod_storage::ArchiveVerification;
    assert!(
        matches!(verification, ArchiveVerification::Ok { rows: 5 }),
        "got {verification:?}"
    );

    // verify_chain spans the archive index + (empty) live tail.
    let v = audit.verify_chain().await.unwrap();
    assert_eq!(v, ChainVerification::Ok { rows: 5 });
}

#[tokio::test]
async fn connect_postgres_returns_full_database_trait_object() {
    if dsn().is_none() {
        return;
    }
    let (_pool, url) = open_scoped().await;

    // The headline assertion of all of Phase 6: the public
    // `connect()` factory accepts a `postgres://` URL and returns
    // the daemon's standard `Arc<dyn Database>`. After this, the
    // daemon doesn't need to know which backend is in use.
    let db = hermod_storage::connect(
        &url,
        fake_signer(),
        Arc::new(hermod_storage::MemoryBlobStore::new()),
    )
    .await
    .expect("connect via postgres scheme");

    db.ping().await.expect("ping");
    let snap = db.metrics_snapshot(Timestamp::now().unix_ms()).await.unwrap();
    assert_eq!(snap.audit_rows_total, 0);
    assert_eq!(snap.workspaces_total, 0);

    // Touch a couple of repositories to confirm the trait object's
    // accessors return live impls (not panicking stubs).
    db.audit()
        .append(&AuditEntry {
            id: None,
            ts: Timestamp::now(),
            actor: fake_actor(),
            action: "connected".into(),
            target: None,
            details: None,
            federation: hermod_storage::AuditFederationPolicy::Default,
        })
        .await
        .expect("audit append");
    let v = db.audit().verify_chain().await.unwrap();
    assert_eq!(v, ChainVerification::Ok { rows: 1 });

    db.shutdown().await;
}
