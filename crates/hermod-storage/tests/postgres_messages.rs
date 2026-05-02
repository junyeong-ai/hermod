//! Integration tests for the PostgreSQL `MessageRepository`.
//!
//! Same gating + scoped-schema pattern as the prior Postgres test
//! files. The headline test exercises the outbox claim race that
//! motivated the `FOR UPDATE SKIP LOCKED` translation: many concurrent
//! workers must collectively claim each row exactly once, with no
//! row left unclaimed and no row claimed twice.

#![cfg(feature = "postgres")]

use hermod_core::{
    AgentId, Endpoint, MessageBody, MessageId, MessageKind, MessagePriority, MessageStatus,
    PubkeyBytes, Timestamp, TrustLevel,
};
use hermod_storage::AgentRepository;
use hermod_storage::backends::postgres::{
    PostgresAgentRepository, PostgresMessageRepository, open_pool, run_migrations,
};
use hermod_storage::repositories::agents::AgentRecord;
use hermod_storage::repositories::messages::{
    InboxFilter, MessageRecord, MessageRepository, TransitionOutcome,
};
use sqlx::Executor;
use std::collections::HashSet;
use std::str::FromStr;
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

async fn seed_local_agent(pool: &sqlx::PgPool, id: AgentId) {
    let agents = PostgresAgentRepository::new(pool.clone());
    let now = Timestamp::now();
    agents
        .upsert(&AgentRecord {
            id,
            pubkey: PubkeyBytes([1u8; 32]),
            host_pubkey: None,
            endpoint: None,
            via_agent_id: None,
            local_alias: None,
            peer_asserted_alias: None,
            trust_level: TrustLevel::Local,
            tls_fingerprint: None,
            reputation: 0,
            first_seen: now,
            last_seen: Some(now),
        })
        .await
        .expect("seed local agent");
}

async fn seed_remote_agent(pool: &sqlx::PgPool, id: AgentId) {
    let agents = PostgresAgentRepository::new(pool.clone());
    let now = Timestamp::now();
    let endpoint = Endpoint::from_str("wss://peer.example:7823").expect("parse endpoint");
    agents
        .upsert(&AgentRecord {
            id,
            pubkey: PubkeyBytes([1u8; 32]),
            host_pubkey: None,
            endpoint: Some(endpoint),
            via_agent_id: None,
            local_alias: None,
            peer_asserted_alias: None,
            trust_level: TrustLevel::Verified,
            tls_fingerprint: None,
            reputation: 0,
            first_seen: now,
            last_seen: Some(now),
        })
        .await
        .expect("seed remote agent");
}

fn pending_record(
    id: MessageId,
    from: AgentId,
    to: AgentId,
    priority: MessagePriority,
) -> MessageRecord {
    let now = Timestamp::now();
    MessageRecord {
        id,
        thread_id: None,
        from_agent: from,
        to_agent: to,
        kind: MessageKind::Direct,
        priority,
        body: MessageBody::Direct {
            text: "hello".into(),
        },
        envelope_cbor: vec![0x00],
        status: MessageStatus::Pending,
        created_at: now,
        delivered_at: None,
        read_at: None,
        expires_at: None,
        attempts: 0,
        next_attempt_at: None,
        file_blob_location: None,
        file_size: None,
        delivery_endpoint: None,
    }
}

#[tokio::test]
async fn enqueue_get_roundtrip() {
    if dsn().is_none() {
        return;
    }
    let pool = open_scoped().await;
    let me = fake_agent(1);
    let peer = fake_agent(2);
    seed_local_agent(&pool, me.clone()).await;
    seed_remote_agent(&pool, peer.clone()).await;

    let messages = PostgresMessageRepository::new(pool.clone());
    let id = MessageId::new();
    messages
        .enqueue(&pending_record(
            id,
            me.clone(),
            peer.clone(),
            MessagePriority::Normal,
        ))
        .await
        .expect("enqueue");

    let got = messages.get(&id).await.unwrap().expect("present");
    assert_eq!(got.id, id);
    assert_eq!(got.from_agent, me);
    assert_eq!(got.to_agent, peer);
    assert_eq!(got.status, MessageStatus::Pending);
}

#[tokio::test]
async fn list_inbox_filters_status_and_priority_with_dynamic_placeholders() {
    if dsn().is_none() {
        return;
    }
    let pool = open_scoped().await;
    let me = fake_agent(3);
    let peer = fake_agent(4);
    seed_local_agent(&pool, me.clone()).await;
    seed_remote_agent(&pool, peer.clone()).await;

    let messages = PostgresMessageRepository::new(pool.clone());
    let prios = [
        MessagePriority::Low,
        MessagePriority::Normal,
        MessagePriority::High,
        MessagePriority::Urgent,
    ];
    for p in prios {
        let rec = pending_record(MessageId::new(), peer.clone(), me.clone(), p);
        messages.enqueue(&rec).await.unwrap();
    }

    // No filter — all 4 returned.
    let all = messages
        .list_inbox(
            &me,
            &InboxFilter {
                statuses: None,
                priority_min: None,
                limit: None,
                after_id: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(all.len(), 4);

    // priority_min = High keeps only High + Urgent.
    let high_plus = messages
        .list_inbox(
            &me,
            &InboxFilter {
                statuses: None,
                priority_min: Some(MessagePriority::High),
                limit: None,
                after_id: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(high_plus.len(), 2);
    for m in &high_plus {
        assert!(m.priority >= MessagePriority::High);
    }

    // Limit 2 with cursor: skip past the smallest id.
    let first_two = messages
        .list_inbox(
            &me,
            &InboxFilter {
                statuses: None,
                priority_min: None,
                limit: Some(2),
                after_id: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(first_two.len(), 2);
    let after_first = messages
        .list_inbox(
            &me,
            &InboxFilter {
                statuses: None,
                priority_min: None,
                limit: Some(10),
                after_id: Some(first_two[0].id),
            },
        )
        .await
        .unwrap();
    assert_eq!(after_first.len(), 3);
}

#[tokio::test]
async fn try_deliver_pending_and_ack_transitions() {
    if dsn().is_none() {
        return;
    }
    let pool = open_scoped().await;
    let me = fake_agent(5);
    let peer = fake_agent(6);
    seed_local_agent(&pool, me.clone()).await;
    seed_remote_agent(&pool, peer.clone()).await;

    let messages = PostgresMessageRepository::new(pool.clone());
    let id = MessageId::new();
    messages
        .enqueue(&pending_record(
            id,
            peer.clone(),
            me.clone(),
            MessagePriority::Normal,
        ))
        .await
        .unwrap();

    let outcome = messages
        .try_deliver_pending(&id, Timestamp::now())
        .await
        .unwrap();
    assert!(matches!(outcome, TransitionOutcome::Applied));
    let rec = messages.get(&id).await.unwrap().unwrap();
    assert_eq!(rec.status, MessageStatus::Delivered);

    // Second attempt is a no-op.
    let outcome = messages
        .try_deliver_pending(&id, Timestamp::now())
        .await
        .unwrap();
    assert!(matches!(outcome, TransitionOutcome::NoOp));

    // Ack moves to read.
    let acked = messages.ack(&id, &me, Timestamp::now()).await.unwrap();
    assert!(acked);
    let rec = messages.get(&id).await.unwrap().unwrap();
    assert_eq!(rec.status, MessageStatus::Read);
}

#[tokio::test]
async fn fail_pending_to_recipient_marks_all_in_flight_failed() {
    if dsn().is_none() {
        return;
    }
    let pool = open_scoped().await;
    let me = fake_agent(7);
    let peer = fake_agent(8);
    seed_local_agent(&pool, me.clone()).await;
    seed_remote_agent(&pool, peer.clone()).await;

    let messages = PostgresMessageRepository::new(pool.clone());
    for _ in 0..3 {
        messages
            .enqueue(&pending_record(
                MessageId::new(),
                me.clone(),
                peer.clone(),
                MessagePriority::Normal,
            ))
            .await
            .unwrap();
    }
    let n = messages.fail_pending_to(&peer).await.unwrap();
    assert_eq!(n, 3);
    let pending_count = messages.count_pending_to(&peer).await.unwrap();
    assert_eq!(pending_count, 0);
}

#[tokio::test]
async fn prune_expired_returns_blob_locations() {
    if dsn().is_none() {
        return;
    }
    let pool = open_scoped().await;
    let me = fake_agent(9);
    let peer = fake_agent(10);
    seed_local_agent(&pool, me.clone()).await;
    seed_remote_agent(&pool, peer.clone()).await;

    let messages = PostgresMessageRepository::new(pool.clone());
    let now = Timestamp::now();

    // Two expired rows; one with a blob location, one without.
    let mut expired_with_blob = pending_record(
        MessageId::new(),
        me.clone(),
        peer.clone(),
        MessagePriority::Normal,
    );
    expired_with_blob.expires_at = Some(Timestamp::from_unix_ms(now.unix_ms() - 1).unwrap());
    expired_with_blob.file_blob_location = Some("files/abc".into());
    messages.enqueue(&expired_with_blob).await.unwrap();

    let mut expired_no_blob = pending_record(
        MessageId::new(),
        me.clone(),
        peer.clone(),
        MessagePriority::Normal,
    );
    expired_no_blob.expires_at = Some(Timestamp::from_unix_ms(now.unix_ms() - 1).unwrap());
    messages.enqueue(&expired_no_blob).await.unwrap();

    // One live row that survives.
    let mut live = pending_record(
        MessageId::new(),
        me.clone(),
        peer.clone(),
        MessagePriority::Normal,
    );
    live.expires_at = Some(Timestamp::from_unix_ms(now.unix_ms() + 60_000).unwrap());
    messages.enqueue(&live).await.unwrap();

    let outcome = messages.prune_expired(now.unix_ms()).await.unwrap();
    assert_eq!(outcome.rows, 2);
    assert_eq!(outcome.blob_locations, vec!["files/abc"]);
    assert!(messages.get(&live.id).await.unwrap().is_some());
}

#[tokio::test]
async fn outbox_claim_race_each_row_claimed_exactly_once() {
    if dsn().is_none() {
        return;
    }
    let pool = open_scoped().await;
    let me = fake_agent(11);
    let peer = fake_agent(12);
    seed_local_agent(&pool, me.clone()).await;
    seed_remote_agent(&pool, peer.clone()).await;

    let messages = Arc::new(PostgresMessageRepository::new(pool.clone()));

    // Enqueue N pending rows.
    let n = 64usize;
    let mut all_ids: HashSet<MessageId> = HashSet::with_capacity(n);
    for _ in 0..n {
        let id = MessageId::new();
        all_ids.insert(id);
        messages
            .enqueue(&pending_record(
                id,
                me.clone(),
                peer.clone(),
                MessagePriority::Normal,
            ))
            .await
            .unwrap();
    }

    // 8 concurrent workers each repeatedly claim batches of 16 until
    // the row pool is empty. Without `FOR UPDATE SKIP LOCKED`,
    // multiple workers' SELECTs would see the same rows and the
    // outer UPDATEs would race; with it, each claim sees only the
    // unlocked subset, so no row is claimed twice.
    //
    // Workers must NOT exit on the first empty batch — under a
    // parallel race, a worker can momentarily see "empty" because
    // every remaining row is row-locked by a sibling's in-flight
    // UPDATE that hasn't committed yet. Production outbox workers
    // poll on a timer for the same reason. We back off briefly and
    // require N consecutive empty batches before declaring done.
    let workers = 8;
    let mut handles = Vec::with_capacity(workers);
    for w in 0..workers {
        let messages = messages.clone();
        handles.push(tokio::spawn(async move {
            let worker_id = format!("worker-{w}");
            let mut claimed: Vec<MessageId> = Vec::new();
            let mut consecutive_empty = 0u32;
            const REQUIRED_EMPTY_PASSES: u32 = 3;
            loop {
                let batch = messages
                    .claim_pending_remote(&worker_id, Timestamp::now(), 60_000, 16)
                    .await
                    .expect("claim");
                if batch.is_empty() {
                    consecutive_empty += 1;
                    if consecutive_empty >= REQUIRED_EMPTY_PASSES {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                    continue;
                }
                consecutive_empty = 0;
                for rec in batch {
                    claimed.push(rec.id);
                }
            }
            claimed
        }));
    }

    let mut union: HashSet<MessageId> = HashSet::with_capacity(n);
    let mut total = 0usize;
    for h in handles {
        let claims = h.await.unwrap();
        total += claims.len();
        for id in claims {
            assert!(
                union.insert(id),
                "row {id} was claimed by more than one worker"
            );
        }
    }

    assert_eq!(total, n, "every row must be claimed exactly once");
    assert_eq!(union, all_ids, "claimed set must equal seeded set");
}

#[tokio::test]
async fn release_claim_returns_row_to_pool() {
    if dsn().is_none() {
        return;
    }
    let pool = open_scoped().await;
    let me = fake_agent(13);
    let peer = fake_agent(14);
    seed_local_agent(&pool, me.clone()).await;
    seed_remote_agent(&pool, peer.clone()).await;

    let messages = PostgresMessageRepository::new(pool.clone());
    let id = MessageId::new();
    messages
        .enqueue(&pending_record(
            id,
            me.clone(),
            peer.clone(),
            MessagePriority::Normal,
        ))
        .await
        .unwrap();

    let claimed = messages
        .claim_pending_remote("solo", Timestamp::now(), 60_000, 8)
        .await
        .unwrap();
    assert_eq!(claimed.len(), 1);

    // Same worker re-claiming sees nothing — the row is owned.
    let again = messages
        .claim_pending_remote("solo2", Timestamp::now(), 60_000, 8)
        .await
        .unwrap();
    assert_eq!(again.len(), 0);

    messages.release_claim(&id).await.unwrap();

    // After release, a fresh claim picks it back up.
    let after_release = messages
        .claim_pending_remote("solo3", Timestamp::now(), 60_000, 8)
        .await
        .unwrap();
    assert_eq!(after_release.len(), 1);
}

#[tokio::test]
async fn try_fail_pending_or_delivered_idempotent() {
    if dsn().is_none() {
        return;
    }
    let pool = open_scoped().await;
    let me = fake_agent(15);
    let peer = fake_agent(16);
    seed_local_agent(&pool, me.clone()).await;
    seed_remote_agent(&pool, peer.clone()).await;

    let messages = PostgresMessageRepository::new(pool.clone());
    let id = MessageId::new();
    messages
        .enqueue(&pending_record(
            id,
            me.clone(),
            peer.clone(),
            MessagePriority::Normal,
        ))
        .await
        .unwrap();

    let first = messages.try_fail_pending_or_delivered(&id).await.unwrap();
    assert!(matches!(first, TransitionOutcome::Applied));
    let second = messages.try_fail_pending_or_delivered(&id).await.unwrap();
    assert!(matches!(second, TransitionOutcome::NoOp));
}
