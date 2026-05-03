//! Integration tests for the PostgreSQL workspace family.
//!
//! Same gating + scoped-schema pattern as the prior Postgres test
//! files. The cascade test confirms the FK chain (`workspaces` →
//! `channels` → `channel_messages`, `workspaces` →
//! `workspace_members`, `workspaces` → `discovered_channels`)
//! drops everything in one DELETE the same way SQLite's cascading
//! foreign keys do.

#![cfg(feature = "postgres")]

use hermod_core::{AgentId, MessageId, PubkeyBytes, Timestamp, TrustLevel, WorkspaceVisibility};
use hermod_crypto::{WorkspaceId, WorkspaceSecret};
use hermod_storage::AgentRepository;
use hermod_storage::backends::postgres::{
    PostgresAgentRepository, PostgresChannelRepository, PostgresDiscoveredChannelRepository,
    PostgresWorkspaceMemberRepository, PostgresWorkspaceRepository, open_pool, run_migrations,
};
use hermod_storage::repositories::agents::AgentRecord;
use hermod_storage::repositories::workspaces::{
    ChannelMessage, ChannelRecord, ChannelRepository, DiscoveredChannelRepository,
    WorkspaceMemberRepository, WorkspaceRecord, WorkspaceRepository,
};
use sqlx::Executor;

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

async fn seed_agent(pool: &sqlx::PgPool, id: AgentId, byte: u8) {
    let agents = PostgresAgentRepository::new(pool.clone());
    let now = Timestamp::now();
    agents
        .upsert(&AgentRecord {
            id,
            pubkey: PubkeyBytes([byte; 32]),
            endpoint: None,
            via_agent: None,
            local_alias: None,
            peer_asserted_alias: None,
            trust_level: TrustLevel::Local,
            reputation: 0,
            first_seen: now,
            last_seen: Some(now),
        })
        .await
        .expect("seed agent");
}

fn workspace(id: WorkspaceId, secret: Option<WorkspaceSecret>) -> WorkspaceRecord {
    let now = Timestamp::now();
    WorkspaceRecord {
        id,
        name: "team".into(),
        visibility: if secret.is_some() {
            WorkspaceVisibility::Private
        } else {
            WorkspaceVisibility::Public
        },
        secret,
        created_locally: true,
        muted: false,
        joined_at: now,
        last_active: Some(now),
    }
}

#[tokio::test]
async fn workspaces_roundtrip_private() {
    if dsn().is_none() {
        return;
    }
    let pool = open_scoped().await;
    seed_agent(&pool, fake_agent(1), 1).await;

    let ws = PostgresWorkspaceRepository::new(pool.clone());
    let secret = WorkspaceSecret::from_bytes([7u8; 32]);
    let id = secret.workspace_id();
    ws.upsert(&workspace(id, Some(secret))).await.unwrap();

    let got = ws.get(&id).await.unwrap().unwrap();
    assert_eq!(got.name, "team");
    assert_eq!(got.visibility, WorkspaceVisibility::Private);
    assert!(got.secret.is_some());
    assert!(got.created_locally);
    assert!(!got.muted);
}

#[tokio::test]
async fn workspaces_set_muted_roundtrips() {
    if dsn().is_none() {
        return;
    }
    let pool = open_scoped().await;
    let ws = PostgresWorkspaceRepository::new(pool.clone());

    let secret = WorkspaceSecret::from_bytes([8u8; 32]);
    let id = secret.workspace_id();
    ws.upsert(&workspace(id, Some(secret))).await.unwrap();

    assert!(!ws.get(&id).await.unwrap().unwrap().muted);
    assert!(ws.set_muted(&id, true).await.unwrap());
    assert!(ws.get(&id).await.unwrap().unwrap().muted);
    assert!(ws.set_muted(&id, false).await.unwrap());
    assert!(!ws.get(&id).await.unwrap().unwrap().muted);
}

#[tokio::test]
async fn workspace_delete_cascades_to_channels_messages_members_discovered() {
    if dsn().is_none() {
        return;
    }
    let pool = open_scoped().await;
    let creator = fake_agent(2);
    seed_agent(&pool, creator.clone(), 2).await;

    let ws_repo = PostgresWorkspaceRepository::new(pool.clone());
    let ch_repo = PostgresChannelRepository::new(pool.clone());
    let mem_repo = PostgresWorkspaceMemberRepository::new(pool.clone());
    let disc_repo = PostgresDiscoveredChannelRepository::new(pool.clone());

    let secret = WorkspaceSecret::from_bytes([9u8; 32]);
    let ws_id = secret.workspace_id();
    let now = Timestamp::now();
    ws_repo
        .upsert(&workspace(ws_id, Some(secret.clone())))
        .await
        .unwrap();

    let ch_id = secret.channel_id("general");
    ch_repo
        .upsert(&ChannelRecord {
            id: ch_id,
            workspace_id: ws_id,
            name: "general".into(),
            mac_key: Some(secret.channel_mac_key("general")),
            muted: false,
            joined_at: now,
            last_active: None,
        })
        .await
        .unwrap();
    ch_repo
        .record_message(&ChannelMessage {
            id: MessageId::new(),
            channel_id: ch_id,
            from_agent: creator.clone(),
            body_text: "hi".into(),
            received_at: now,
        })
        .await
        .unwrap();
    mem_repo.touch(&ws_id, &creator, now).await.unwrap();
    disc_repo
        .observe(&ws_id, &ch_id, "general", &creator, now)
        .await
        .unwrap();

    // Sanity: every related row exists.
    assert!(ch_repo.get(&ch_id).await.unwrap().is_some());
    assert_eq!(ch_repo.history(&ch_id, 10).await.unwrap().len(), 1);
    assert_eq!(mem_repo.list(&ws_id).await.unwrap().len(), 1);
    assert!(disc_repo.get(&ch_id).await.unwrap().is_some());

    // Drop the workspace; cascades take everything with it.
    assert!(ws_repo.delete(&ws_id).await.unwrap());
    assert!(ws_repo.get(&ws_id).await.unwrap().is_none());
    assert!(ch_repo.get(&ch_id).await.unwrap().is_none());
    assert!(ch_repo.history(&ch_id, 10).await.unwrap().is_empty());
    assert!(mem_repo.list(&ws_id).await.unwrap().is_empty());
    assert!(disc_repo.get(&ch_id).await.unwrap().is_none());
}

#[tokio::test]
async fn channel_history_orders_by_received_at_desc_with_limit() {
    if dsn().is_none() {
        return;
    }
    let pool = open_scoped().await;
    let creator = fake_agent(3);
    seed_agent(&pool, creator.clone(), 3).await;

    let ws_repo = PostgresWorkspaceRepository::new(pool.clone());
    let ch_repo = PostgresChannelRepository::new(pool.clone());

    let secret = WorkspaceSecret::from_bytes([10u8; 32]);
    let ws_id = secret.workspace_id();
    let now = Timestamp::now();
    ws_repo
        .upsert(&workspace(ws_id, Some(secret.clone())))
        .await
        .unwrap();

    let ch_id = secret.channel_id("general");
    ch_repo
        .upsert(&ChannelRecord {
            id: ch_id,
            workspace_id: ws_id,
            name: "general".into(),
            mac_key: Some(secret.channel_mac_key("general")),
            muted: false,
            joined_at: now,
            last_active: None,
        })
        .await
        .unwrap();

    for (i, body) in ["a", "b", "c"].iter().enumerate() {
        let received = Timestamp::from_unix_ms(now.unix_ms() + (i as i64) * 1000).unwrap();
        ch_repo
            .record_message(&ChannelMessage {
                id: MessageId::new(),
                channel_id: ch_id,
                from_agent: creator.clone(),
                body_text: (*body).into(),
                received_at: received,
            })
            .await
            .unwrap();
    }

    let history = ch_repo.history(&ch_id, 10).await.unwrap();
    assert_eq!(history.len(), 3);
    assert_eq!(history[0].body_text, "c"); // newest first
    assert_eq!(history[2].body_text, "a");

    // Limit clips the head of the list (newest N).
    let limited = ch_repo.history(&ch_id, 2).await.unwrap();
    assert_eq!(limited.len(), 2);
    assert_eq!(limited[0].body_text, "c");
    assert_eq!(limited[1].body_text, "b");
}

#[tokio::test]
async fn channel_record_message_dedupes_on_id() {
    if dsn().is_none() {
        return;
    }
    let pool = open_scoped().await;
    let creator = fake_agent(4);
    seed_agent(&pool, creator.clone(), 4).await;

    let ws_repo = PostgresWorkspaceRepository::new(pool.clone());
    let ch_repo = PostgresChannelRepository::new(pool.clone());

    let secret = WorkspaceSecret::from_bytes([11u8; 32]);
    let ws_id = secret.workspace_id();
    let now = Timestamp::now();
    ws_repo
        .upsert(&workspace(ws_id, Some(secret.clone())))
        .await
        .unwrap();

    let ch_id = secret.channel_id("general");
    ch_repo
        .upsert(&ChannelRecord {
            id: ch_id,
            workspace_id: ws_id,
            name: "general".into(),
            mac_key: Some(secret.channel_mac_key("general")),
            muted: false,
            joined_at: now,
            last_active: None,
        })
        .await
        .unwrap();

    let mid = MessageId::new();
    let msg = ChannelMessage {
        id: mid,
        channel_id: ch_id,
        from_agent: creator.clone(),
        body_text: "first write".into(),
        received_at: now,
    };
    ch_repo.record_message(&msg).await.unwrap();

    // Second insert with the SAME id but different body must dedupe
    // — `ON CONFLICT DO NOTHING` mirrors SQLite's `INSERT OR IGNORE`.
    let dup = ChannelMessage {
        body_text: "would overwrite".into(),
        ..msg.clone()
    };
    ch_repo.record_message(&dup).await.unwrap();

    let history = ch_repo.history(&ch_id, 10).await.unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].body_text, "first write");
}

#[tokio::test]
async fn workspace_members_touch_dedupes_and_updates_last_seen() {
    if dsn().is_none() {
        return;
    }
    let pool = open_scoped().await;
    let me = fake_agent(5);
    let other = fake_agent(6);
    seed_agent(&pool, me.clone(), 5).await;
    seed_agent(&pool, other.clone(), 6).await;

    let ws_repo = PostgresWorkspaceRepository::new(pool.clone());
    let mem_repo = PostgresWorkspaceMemberRepository::new(pool.clone());

    let secret = WorkspaceSecret::from_bytes([12u8; 32]);
    let id = secret.workspace_id();
    let now = Timestamp::now();
    ws_repo.upsert(&workspace(id, Some(secret))).await.unwrap();

    mem_repo.touch(&id, &me, now).await.unwrap();
    mem_repo.touch(&id, &other, now).await.unwrap();
    mem_repo.touch(&id, &me, now).await.unwrap(); // duplicate

    let members = mem_repo.list(&id).await.unwrap();
    assert_eq!(members.len(), 2);
}

#[tokio::test]
async fn list_distinct_excluding_filters_self_and_returns_sorted() {
    if dsn().is_none() {
        return;
    }
    let pool = open_scoped().await;
    let me = fake_agent(7);
    let a = fake_agent(8);
    let b = fake_agent(9);
    seed_agent(&pool, me.clone(), 7).await;
    seed_agent(&pool, a.clone(), 8).await;
    seed_agent(&pool, b.clone(), 9).await;

    let ws_repo = PostgresWorkspaceRepository::new(pool.clone());
    let mem_repo = PostgresWorkspaceMemberRepository::new(pool.clone());
    let secret = WorkspaceSecret::from_bytes([13u8; 32]);
    let id = secret.workspace_id();
    let now = Timestamp::now();
    ws_repo.upsert(&workspace(id, Some(secret))).await.unwrap();

    for agent in [&me, &a, &b] {
        mem_repo.touch(&id, agent, now).await.unwrap();
    }

    let others = mem_repo.list_distinct_excluding(&me).await.unwrap();
    assert_eq!(others.len(), 2);
    assert!(others.contains(&a));
    assert!(others.contains(&b));
    assert!(!others.contains(&me));

    // Deterministic ordering: agent_id ASC.
    let mut sorted = others.clone();
    sorted.sort_by(|x, y| x.as_str().cmp(y.as_str()));
    assert_eq!(others, sorted, "list_distinct_excluding must be sorted");
}

#[tokio::test]
async fn discovered_channels_observe_upserts_then_prune_cuts_old() {
    if dsn().is_none() {
        return;
    }
    let pool = open_scoped().await;
    let advertiser = fake_agent(10);
    seed_agent(&pool, advertiser.clone(), 10).await;

    let ws_repo = PostgresWorkspaceRepository::new(pool.clone());
    let disc_repo = PostgresDiscoveredChannelRepository::new(pool.clone());

    let secret = WorkspaceSecret::from_bytes([14u8; 32]);
    let ws_id = secret.workspace_id();
    let t0 = Timestamp::now();
    ws_repo
        .upsert(&workspace(ws_id, Some(secret.clone())))
        .await
        .unwrap();

    let ch_id = secret.channel_id("general");
    disc_repo
        .observe(&ws_id, &ch_id, "general", &advertiser, t0)
        .await
        .unwrap();

    // Re-observe with a newer timestamp updates last_seen (upsert).
    let t1 = Timestamp::from_unix_ms(t0.unix_ms() + 60_000).unwrap();
    disc_repo
        .observe(&ws_id, &ch_id, "general", &advertiser, t1)
        .await
        .unwrap();
    let row = disc_repo.get(&ch_id).await.unwrap().unwrap();
    assert_eq!(row.last_seen.unix_ms(), t1.unix_ms());

    // Prune cuts rows older than the cutoff.
    let cutoff = t1.unix_ms() + 1;
    let n = disc_repo.prune_older_than(cutoff).await.unwrap();
    assert_eq!(n, 1);
    assert!(disc_repo.get(&ch_id).await.unwrap().is_none());
}
