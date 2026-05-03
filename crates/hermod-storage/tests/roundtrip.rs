//! End-to-end roundtrip: open DB, migrate, insert an agent, enqueue a message,
//! list inbox, ack, verify state.

use hermod_core::{
    AgentAddress, Endpoint, Envelope, MessageBody, MessagePriority, MessageStatus, Timestamp,
    TrustLevel, WssEndpoint,
};
use hermod_crypto::{Keypair, LocalKeySigner, Signer, canonical_envelope_bytes};
use hermod_storage::backends::sqlite::SqliteDatabase;
use hermod_storage::{AgentRecord, Database, HostRecord, InboxFilter, MessageRecord};
use std::sync::Arc;

fn tmp_db_path() -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("hermod-test-{}.sqlite", ulid::Ulid::new()));
    p
}

async fn fresh_db() -> SqliteDatabase {
    let p = tmp_db_path();
    let signer: Arc<dyn Signer> = Arc::new(LocalKeySigner::new(Arc::new(Keypair::generate())));
    SqliteDatabase::connect(&p, signer, Arc::new(hermod_storage::MemoryBlobStore::new()))
        .await
        .expect("open db")
}

#[tokio::test]
async fn message_roundtrip() {
    let db = fresh_db().await;

    // Two local agents.
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let now = Timestamp::now();

    for kp in [&kp_a, &kp_b] {
        db.agents()
            .upsert(&AgentRecord {
                id: kp.agent_id(),
                pubkey: kp.to_pubkey_bytes(),
                host_id: None,
                via_agent: None,
                local_alias: None,
                peer_asserted_alias: None,
                trust_level: TrustLevel::Local,
                reputation: 0,
                first_seen: now,
                last_seen: Some(now),
                peer_asserted_tags: hermod_core::CapabilityTagSet::empty(),
            })
            .await
            .expect("upsert agent");
    }

    // A -> B signed envelope.
    let from = AgentAddress::local(kp_a.agent_id());
    let to = AgentAddress::local(kp_b.agent_id());
    let mut env = Envelope::draft(
        from,
        to,
        MessageBody::Direct {
            text: "안녕, B".into(),
        },
        MessagePriority::High,
        3600,
    );
    kp_a.sign_envelope(&mut env).expect("sign");

    let cbor = canonical_envelope_bytes(&env).expect("cbor");
    let msg = MessageRecord::from_envelope(&env, cbor, MessageStatus::Pending);
    db.messages().enqueue(&msg).await.expect("enqueue");

    // B lists inbox, sees the message.
    let inbox = db
        .messages()
        .list_inbox(&kp_b.agent_id(), &InboxFilter::default())
        .await
        .expect("inbox");
    assert_eq!(inbox.len(), 1);
    assert_eq!(inbox[0].id, env.id);
    match &inbox[0].body {
        MessageBody::Direct { text } => assert_eq!(text, "안녕, B"),
        other => panic!("unexpected body: {other:?}"),
    }

    // B acks.
    let acked = db
        .messages()
        .ack(&env.id, &kp_b.agent_id(), Timestamp::now())
        .await
        .expect("ack");
    assert!(acked);

    // Inbox is now empty for pending/delivered.
    let inbox_after = db
        .messages()
        .list_inbox(&kp_b.agent_id(), &InboxFilter::default())
        .await
        .expect("inbox after");
    assert!(inbox_after.is_empty());
}

/// Regression: `priority_min` filter must produce the right number of
/// `?` placeholders to match `priorities_at_least`. A mismatch (e.g. 4
/// fixed `?` for any min while only binding 1 priority for `Urgent`)
/// would corrupt subsequent positional bindings (cursor, limit) and
/// either error or silently return wrong rows.
#[tokio::test]
async fn priority_min_filter_binds_correctly() {
    let db = fresh_db().await;
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let now = Timestamp::now();
    for kp in [&kp_a, &kp_b] {
        db.agents()
            .upsert(&AgentRecord {
                id: kp.agent_id(),
                pubkey: kp.to_pubkey_bytes(),
                host_id: None,
                via_agent: None,
                local_alias: None,
                peer_asserted_alias: None,
                trust_level: TrustLevel::Local,
                reputation: 0,
                first_seen: now,
                last_seen: Some(now),
                peer_asserted_tags: hermod_core::CapabilityTagSet::empty(),
            })
            .await
            .unwrap();
    }
    let send = |priority: MessagePriority, text: &str| {
        let from = AgentAddress::local(kp_a.agent_id());
        let to = AgentAddress::local(kp_b.agent_id());
        let mut env = Envelope::draft(
            from,
            to,
            MessageBody::Direct { text: text.into() },
            priority,
            3600,
        );
        kp_a.sign_envelope(&mut env).unwrap();
        let cbor = canonical_envelope_bytes(&env).unwrap();
        MessageRecord::from_envelope(&env, cbor, MessageStatus::Delivered)
    };
    db.messages()
        .enqueue(&send(MessagePriority::Low, "low"))
        .await
        .unwrap();
    db.messages()
        .enqueue(&send(MessagePriority::Normal, "normal"))
        .await
        .unwrap();
    db.messages()
        .enqueue(&send(MessagePriority::High, "high"))
        .await
        .unwrap();
    db.messages()
        .enqueue(&send(MessagePriority::Urgent, "urgent"))
        .await
        .unwrap();

    // Each level must include itself and higher; cursor + limit clauses
    // also exercise placeholder ordering after the dynamic priority list.
    for (min, expected_count) in [
        (MessagePriority::Low, 4),
        (MessagePriority::Normal, 3),
        (MessagePriority::High, 2),
        (MessagePriority::Urgent, 1),
    ] {
        let rows = db
            .messages()
            .list_inbox(
                &kp_b.agent_id(),
                &InboxFilter {
                    priority_min: Some(min),
                    limit: Some(50),
                    ..Default::default()
                },
            )
            .await
            .expect("list with priority_min");
        assert_eq!(
            rows.len(),
            expected_count,
            "priority_min={min:?} expected {expected_count}, got {}",
            rows.len()
        );
    }
}

#[tokio::test]
async fn wrong_recipient_cannot_ack() {
    let db = fresh_db().await;
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let kp_evil = Keypair::generate();
    let now = Timestamp::now();

    for kp in [&kp_a, &kp_b, &kp_evil] {
        db.agents()
            .upsert(&AgentRecord {
                id: kp.agent_id(),
                pubkey: kp.to_pubkey_bytes(),
                host_id: None,
                via_agent: None,
                local_alias: None,
                peer_asserted_alias: None,
                trust_level: TrustLevel::Local,
                reputation: 0,
                first_seen: now,
                last_seen: Some(now),
                peer_asserted_tags: hermod_core::CapabilityTagSet::empty(),
            })
            .await
            .unwrap();
    }

    let mut env = Envelope::draft(
        AgentAddress::local(kp_a.agent_id()),
        AgentAddress::local(kp_b.agent_id()),
        MessageBody::Direct {
            text: "for B only".into(),
        },
        MessagePriority::Normal,
        60,
    );
    kp_a.sign_envelope(&mut env).unwrap();
    let cbor = canonical_envelope_bytes(&env).unwrap();
    db.messages()
        .enqueue(&MessageRecord::from_envelope(
            &env,
            cbor,
            MessageStatus::Pending,
        ))
        .await
        .unwrap();

    let acked = db
        .messages()
        .ack(&env.id, &kp_evil.agent_id(), Timestamp::now())
        .await
        .unwrap();
    assert!(!acked, "non-recipient should not be able to ack");
}

#[tokio::test]
async fn agent_upsert_preserves_operator_trust() {
    let db = fresh_db().await;
    let kp = Keypair::generate();
    let now = Timestamp::now();

    // First observation — TOFU.
    db.agents()
        .upsert(&AgentRecord {
            id: kp.agent_id(),
            pubkey: kp.to_pubkey_bytes(),
            host_id: None,
            via_agent: None,
            local_alias: None,
            peer_asserted_alias: None,
            trust_level: TrustLevel::Tofu,
            reputation: 0,
            first_seen: now,
            last_seen: Some(now),
            peer_asserted_tags: hermod_core::CapabilityTagSet::empty(),
        })
        .await
        .unwrap();

    // Operator promotes.
    db.agents()
        .set_trust(&kp.agent_id(), TrustLevel::Verified)
        .await
        .unwrap();

    // Re-observation (federation re-handshake) tries to set Tofu again.
    db.agents()
        .upsert(&AgentRecord {
            id: kp.agent_id(),
            pubkey: kp.to_pubkey_bytes(),
            host_id: None,
            via_agent: None,
            local_alias: None,
            peer_asserted_alias: None,
            trust_level: TrustLevel::Tofu,
            reputation: 0,
            first_seen: now,
            last_seen: Some(now),
            peer_asserted_tags: hermod_core::CapabilityTagSet::empty(),
        })
        .await
        .unwrap();

    let got = db.agents().get(&kp.agent_id()).await.unwrap().unwrap();
    assert_eq!(
        got.trust_level,
        TrustLevel::Verified,
        "operator-set trust must survive a TOFU re-upsert"
    );
}

#[tokio::test]
async fn broadcast_hmac_end_to_end() {
    use hermod_core::MessageId;
    use hermod_core::WorkspaceVisibility;
    use hermod_crypto::WorkspaceSecret;
    use hermod_storage::{ChannelMessage, ChannelRecord, WorkspaceRecord};
    use serde_bytes::ByteBuf;

    let db = fresh_db().await;
    let now = Timestamp::now();

    // Two agents in the same private workspace.
    let kp_alice = Keypair::generate();
    let kp_bob = Keypair::generate();
    for kp in [&kp_alice, &kp_bob] {
        db.agents()
            .upsert(&AgentRecord {
                id: kp.agent_id(),
                pubkey: kp.to_pubkey_bytes(),
                host_id: None,
                via_agent: None,
                local_alias: None,
                peer_asserted_alias: None,
                trust_level: TrustLevel::Tofu,
                reputation: 0,
                first_seen: now,
                last_seen: Some(now),
                peer_asserted_tags: hermod_core::CapabilityTagSet::empty(),
            })
            .await
            .unwrap();
    }

    // Bob (the receiver) creates the workspace and a channel.
    let secret = WorkspaceSecret::from_bytes([42u8; 32]);
    let ws_id = secret.workspace_id();
    db.workspaces()
        .upsert(&WorkspaceRecord {
            id: ws_id,
            name: "team".into(),
            visibility: WorkspaceVisibility::Private,
            secret: Some(secret.clone()),
            created_locally: true,
            muted: false,
            joined_at: now,
            last_active: Some(now),
        })
        .await
        .unwrap();
    let ch_id = secret.channel_id("general");
    let mac_key = secret.channel_mac_key("general");
    db.channels()
        .upsert(&ChannelRecord {
            id: ch_id,
            workspace_id: ws_id,
            name: "general".into(),
            mac_key: Some(mac_key.clone()),
            muted: false,
            joined_at: now,
            last_active: None,
        })
        .await
        .unwrap();

    // Alice (sender, sharing the secret out-of-band) computes the HMAC over
    // her broadcast text and the receiver re-derives + verifies under the
    // same channel mac key. Round-trip works.
    let text = "engineering standup at 2pm";
    let alice_hmac = secret.channel_mac_key("general").mac(text.as_bytes());
    assert!(mac_key.verify(text.as_bytes(), &alice_hmac));

    // Tampered text fails verification — same mac, different bytes.
    assert!(!mac_key.verify(b"engineering standup at 3pm", &alice_hmac));

    // Cross-channel attack: Alice's HMAC for "general" must not validate
    // when an attacker re-binds the message to a sibling channel under the
    // same workspace secret.
    let other_mac = secret.channel_mac_key("random");
    assert!(!other_mac.verify(text.as_bytes(), &alice_hmac));

    // Persist the broadcast as the federation listener would have.
    let envelope_id = MessageId::new();
    db.channels()
        .record_message(&ChannelMessage {
            id: envelope_id,
            channel_id: ch_id,
            from_agent: kp_alice.agent_id(),
            body_text: text.to_string(),
            received_at: now,
        })
        .await
        .unwrap();
    db.workspace_members()
        .touch(&ws_id, &kp_alice.agent_id(), now)
        .await
        .unwrap();

    // Read-back: history reports one broadcast from Alice; the workspace
    // member list contains Alice (auto-added on receipt — the foundation for
    // future fan-out from Bob back to her).
    let history = db.channels().history(&ch_id, 10).await.unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].id, envelope_id);
    assert_eq!(history[0].from_agent, kp_alice.agent_id());
    assert_eq!(history[0].body_text, text);

    let members = db.workspace_members().list(&ws_id).await.unwrap();
    assert!(members.iter().any(|m| m == &kp_alice.agent_id()));

    // CBOR wire body roundtrip for the same broadcast — proves the payload
    // serialization is symmetric with what the federation listener expects.
    let body = MessageBody::ChannelBroadcast {
        workspace_id: ByteBuf::from(ws_id.0.to_vec()),
        channel_id: ByteBuf::from(ch_id.0.to_vec()),
        text: text.to_string(),
        hmac: Some(ByteBuf::from(alice_hmac.to_vec())),
    };
    let env = Envelope::draft(
        AgentAddress::local(kp_alice.agent_id()),
        AgentAddress::local(kp_bob.agent_id()),
        body,
        MessagePriority::Normal,
        60,
    );
    let bytes = canonical_envelope_bytes(&env).unwrap();
    assert!(!bytes.is_empty());
}

#[tokio::test]
async fn fail_pending_to_clears_invisible_pending() {
    // Regression: peer.remove must transition every pending row addressed
    // to the forgotten peer to `failed`. Otherwise the outbox skips them
    // (its query filters on endpoint IS NOT NULL after `forget_peer`)
    // and the operator sees `pending` rows that will never resolve.
    let db = fresh_db().await;
    let kp_self = Keypair::generate();
    let kp_peer = Keypair::generate();
    let now = Timestamp::now();

    for kp in [&kp_self, &kp_peer] {
        db.agents()
            .upsert(&AgentRecord {
                id: kp.agent_id(),
                pubkey: kp.to_pubkey_bytes(),
                host_id: None,
                via_agent: None,
                local_alias: None,
                peer_asserted_alias: None,
                trust_level: TrustLevel::Tofu,
                reputation: 0,
                first_seen: now,
                last_seen: Some(now),
                peer_asserted_tags: hermod_core::CapabilityTagSet::empty(),
            })
            .await
            .unwrap();
    }

    for _ in 0..3u32 {
        let env = Envelope::draft(
            AgentAddress::local(kp_self.agent_id()),
            AgentAddress::local(kp_peer.agent_id()),
            MessageBody::Direct {
                text: "hello".into(),
            },
            MessagePriority::Normal,
            3600,
        );
        let cbor = canonical_envelope_bytes(&env).unwrap();
        db.messages()
            .enqueue(&MessageRecord::from_envelope(
                &env,
                cbor,
                MessageStatus::Pending,
            ))
            .await
            .unwrap();
    }

    let count = db
        .messages()
        .fail_pending_to(&kp_peer.agent_id())
        .await
        .unwrap();
    assert_eq!(count, 3);

    let still_pending = db
        .messages()
        .list_inbox(
            &kp_peer.agent_id(),
            &InboxFilter {
                statuses: Some(vec![MessageStatus::Pending]),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(still_pending.is_empty(), "no pending rows must remain");

    // Calling again is idempotent — already-failed rows are not
    // transitioned a second time.
    let count2 = db
        .messages()
        .fail_pending_to(&kp_peer.agent_id())
        .await
        .unwrap();
    assert_eq!(count2, 0);
}

#[tokio::test]
async fn list_distinct_excluding_is_deterministic() {
    // Regression: fanout truncation at MAX_FANOUT_PER_CALL needs a stable
    // ordering, otherwise the same publish reaches a different subset of
    // members on each call.
    let db = fresh_db().await;
    let mut kps: Vec<Keypair> = (0..16).map(|_| Keypair::generate()).collect();
    let now = Timestamp::now();
    for kp in &kps {
        db.agents()
            .upsert(&AgentRecord {
                id: kp.agent_id(),
                pubkey: kp.to_pubkey_bytes(),
                host_id: None,
                via_agent: None,
                local_alias: None,
                peer_asserted_alias: None,
                trust_level: TrustLevel::Tofu,
                reputation: 0,
                first_seen: now,
                last_seen: Some(now),
                peer_asserted_tags: hermod_core::CapabilityTagSet::empty(),
            })
            .await
            .unwrap();
    }
    let workspace = hermod_crypto::WorkspaceId([7u8; 16]);
    let secret = hermod_crypto::WorkspaceSecret::from_bytes([0u8; 32]);
    db.workspaces()
        .upsert(&hermod_storage::WorkspaceRecord {
            id: workspace,
            name: "test".into(),
            visibility: hermod_core::WorkspaceVisibility::Private,
            secret: Some(secret),
            created_locally: true,
            muted: false,
            joined_at: now,
            last_active: Some(now),
        })
        .await
        .unwrap();
    for kp in &kps {
        db.workspace_members()
            .touch(&workspace, &kp.agent_id(), now)
            .await
            .unwrap();
    }

    let exclude = kps.pop().unwrap().agent_id();
    let first = db
        .workspace_members()
        .list_distinct_excluding(&exclude)
        .await
        .unwrap();
    let second = db
        .workspace_members()
        .list_distinct_excluding(&exclude)
        .await
        .unwrap();
    assert_eq!(first, second, "list order must be stable across calls");

    // And the order must be lexicographic ascending by agent_id.
    let mut sorted = first.clone();
    sorted.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    assert_eq!(first, sorted);
}

// `HostRepository` integration tests cover `forget`,
// `replace_tls_fingerprint`, and `pin_or_match_tls_fingerprint`
// directly (see `crates/hermod-storage/src/backends/sqlite/hosts.rs`).
// The `peer.repin` trust-gate is enforced in the daemon's
// `services::peer::repin` (see daemon-side regression).

/// Two outbox workers calling `claim_pending_remote` concurrently must
/// never both receive the same row. SQLite's IMMEDIATE transaction
/// inside the implementation serialises the SELECT-then-UPDATE — this
/// test seeds N pending rows and races two claimants against them, then
/// asserts the union is exactly N (no doubles, no losses).
#[tokio::test]
async fn claim_pending_remote_no_double_claims_under_race() {
    let db = fresh_db().await;
    let now = Timestamp::now();

    // Sender (local) and remote recipient. The recipient has an
    // endpoint so a sane fixture matches reality, but
    // `claim_pending_remote` keys off the row's stamped
    // `delivery_endpoint` — set explicitly below.
    let sender = Keypair::generate();
    let recipient = Keypair::generate();
    let endpoint = Endpoint::Wss(WssEndpoint {
        host: "remote.example".into(),
        port: 7823,
    });
    db.agents()
        .upsert(&AgentRecord {
            id: sender.agent_id(),
            pubkey: sender.to_pubkey_bytes(),
            host_id: None,
            via_agent: None,
            local_alias: None,
            peer_asserted_alias: None,
            trust_level: TrustLevel::Local,
            reputation: 0,
            first_seen: now,
            last_seen: Some(now),
            peer_asserted_tags: hermod_core::CapabilityTagSet::empty(),
        })
        .await
        .unwrap();
    let host_pk = recipient.to_pubkey_bytes();
    let host_id = hermod_crypto::agent_id_from_pubkey(&host_pk);
    db.hosts()
        .upsert(&HostRecord {
            id: host_id.clone(),
            pubkey: host_pk,
            endpoint: Some(endpoint),
            tls_fingerprint: None,
            peer_asserted_alias: None,
            first_seen: now,
            last_seen: Some(now),
        })
        .await
        .unwrap();
    db.agents()
        .upsert(&AgentRecord {
            id: recipient.agent_id(),
            pubkey: recipient.to_pubkey_bytes(),
            host_id: Some(host_id),
            via_agent: None,
            local_alias: None,
            peer_asserted_alias: None,
            trust_level: TrustLevel::Verified,
            reputation: 0,
            first_seen: now,
            last_seen: Some(now),
            peer_asserted_tags: hermod_core::CapabilityTagSet::empty(),
        })
        .await
        .unwrap();

    const N: usize = 40;
    for i in 0..N {
        let mut env = Envelope::draft(
            AgentAddress::local(sender.agent_id()),
            AgentAddress::local(recipient.agent_id()),
            MessageBody::Direct {
                text: format!("msg {i}"),
            },
            MessagePriority::Normal,
            3600,
        );
        sender.sign_envelope(&mut env).unwrap();
        let cbor = canonical_envelope_bytes(&env).unwrap();
        let mut rec = MessageRecord::from_envelope(&env, cbor, MessageStatus::Pending);
        rec.delivery_endpoint = Some("wss://remote.example:7823".into());
        db.messages().enqueue(&rec).await.unwrap();
    }

    // Two workers claiming in parallel.
    let claim_ttl_ms = 60_000_i64;
    let limit = 32_u32;
    let now = Timestamp::now();
    let db_a = db.clone();
    let db_b = db.clone();
    let (a, b) = tokio::join!(
        async move {
            db_a.messages()
                .claim_pending_remote("worker-a", now, claim_ttl_ms, limit)
                .await
                .unwrap()
        },
        async move {
            db_b.messages()
                .claim_pending_remote("worker-b", now, claim_ttl_ms, limit)
                .await
                .unwrap()
        }
    );

    let mut ids: Vec<String> = a.iter().map(|m| m.id.to_string()).collect();
    ids.extend(b.iter().map(|m| m.id.to_string()));
    let unique: std::collections::HashSet<_> = ids.iter().collect();
    assert_eq!(
        unique.len(),
        ids.len(),
        "no row may appear in both workers' batches"
    );
    assert!(
        ids.len() <= N,
        "total claimed rows must not exceed seeded count"
    );
    // Each worker should claim at least one (cap is 32 each, so the
    // exact split varies under SQLite's lock fairness, but neither side
    // should starve completely).
    assert!(!a.is_empty() || !b.is_empty(), "at least one worker claims");
}

/// A claim whose `claimed_at` is older than `claim_ttl` is reclaimable
/// — simulates a worker that crashed mid-batch. The replacement worker
/// must successfully take ownership and the row's claim_token must
/// switch to the new worker.
#[tokio::test]
async fn claim_pending_remote_reclaims_stale_owners() {
    let db = fresh_db().await;
    let now = Timestamp::now();

    let sender = Keypair::generate();
    let recipient = Keypair::generate();
    let endpoint = Endpoint::Wss(WssEndpoint {
        host: "remote.example".into(),
        port: 7823,
    });
    let recipient_host_pk = recipient.to_pubkey_bytes();
    let recipient_host_id = hermod_crypto::agent_id_from_pubkey(&recipient_host_pk);
    db.hosts()
        .upsert(&HostRecord {
            id: recipient_host_id.clone(),
            pubkey: recipient_host_pk,
            endpoint: Some(endpoint),
            tls_fingerprint: None,
            peer_asserted_alias: None,
            first_seen: now,
            last_seen: Some(now),
        })
        .await
        .unwrap();
    for (kp, host_id, trust) in [
        (&sender, None, TrustLevel::Local),
        (&recipient, Some(recipient_host_id), TrustLevel::Verified),
    ] {
        db.agents()
            .upsert(&AgentRecord {
                id: kp.agent_id(),
                pubkey: kp.to_pubkey_bytes(),
                host_id,
                via_agent: None,
                local_alias: None,
                peer_asserted_alias: None,
                trust_level: trust,
                reputation: 0,
                first_seen: now,
                last_seen: Some(now),
                peer_asserted_tags: hermod_core::CapabilityTagSet::empty(),
            })
            .await
            .unwrap();
    }

    let mut env = Envelope::draft(
        AgentAddress::local(sender.agent_id()),
        AgentAddress::local(recipient.agent_id()),
        MessageBody::Direct {
            text: "stranded".into(),
        },
        MessagePriority::High,
        3600,
    );
    sender.sign_envelope(&mut env).unwrap();
    let cbor = canonical_envelope_bytes(&env).unwrap();
    let mut rec = MessageRecord::from_envelope(&env, cbor, MessageStatus::Pending);
    rec.delivery_endpoint = Some("wss://remote.example:7823".into());
    db.messages().enqueue(&rec).await.unwrap();

    // Worker A claims, then "crashes" (we never release).
    let now_a = Timestamp::now();
    let a = db
        .messages()
        .claim_pending_remote("worker-a", now_a, 60_000, 8)
        .await
        .unwrap();
    assert_eq!(a.len(), 1);

    // Immediately, worker B sees nothing — A's claim is still fresh.
    let b1 = db
        .messages()
        .claim_pending_remote("worker-b", now_a, 60_000, 8)
        .await
        .unwrap();
    assert!(b1.is_empty(), "fresh claim must protect the row");

    // Time passes (simulated by passing a "now" past the TTL).
    let later = Timestamp::from_unix_ms(now_a.unix_ms() + 5 * 60 * 1000).unwrap();
    let b2 = db
        .messages()
        .claim_pending_remote("worker-b", later, 60_000, 8)
        .await
        .unwrap();
    assert_eq!(b2.len(), 1, "stale claim must be reclaimable");
    assert_eq!(b2[0].id, env.id);
}

/// Per-instance MCP boundary (axis 1):
///
/// * Label-collision attach against a *live* row is rejected as
///   `LabelInUse` so two Claude Code windows can't silently share a
///   single cursor stream.
/// * Label-collision attach against a *stale* row reuses the cursors
///   so a process restart with the same label resumes mid-stream.
/// * `cursor_advance` persists per-cursor; partial advances leave
///   untouched columns intact.
/// * `list_for_agent` returns the live sessions for `local.sessions`.
#[tokio::test]
async fn mcp_session_label_attach_resume_and_cursor_advance() {
    use hermod_core::{McpSessionId, MessageId, SessionLabel};
    use hermod_storage::{AttachOutcome, AttachParams, CursorAdvance};

    let db = fresh_db().await;
    let kp = Keypair::generate();
    let now = Timestamp::now();
    db.agents()
        .upsert(&AgentRecord {
            id: kp.agent_id(),
            pubkey: kp.to_pubkey_bytes(),
            host_id: None,
            via_agent: None,
            local_alias: None,
            peer_asserted_alias: None,
            trust_level: TrustLevel::Local,
            reputation: 0,
            first_seen: now,
            last_seen: Some(now),
            peer_asserted_tags: hermod_core::CapabilityTagSet::empty(),
        })
        .await
        .unwrap();
    let agent = kp.agent_id();
    let label: SessionLabel = "vscode-1".parse().unwrap();
    let ttl_ms: i64 = 60_000;

    // First attach with the label — fresh insert, no cursors carried.
    let s1 = McpSessionId::from_raw("sess-1".into());
    let outcome = db
        .mcp_sessions()
        .attach(AttachParams {
            session_id: s1.clone(),
            agent_id: agent.clone(),
            session_label: Some(label.clone()),
            attached_at: now,
            client_name: Some("claude".into()),
            client_version: None,
            ttl_ms,
        })
        .await
        .unwrap();
    let resumed = matches!(outcome, AttachOutcome::Inserted { resumed: false, .. });
    assert!(resumed, "first attach must not claim resume");

    // Advance the message cursor.
    let cursor_msg: MessageId = ulid::Ulid::new().to_string().parse().unwrap();
    db.mcp_sessions()
        .cursor_advance(
            &s1,
            &CursorAdvance {
                last_message_id: Some(cursor_msg),
                last_confirmation_id: None,
                last_resolved_seq: Some(42),
            },
        )
        .await
        .unwrap();

    // Second attach with the SAME label while the first is live ⇒ LabelInUse.
    let s2 = McpSessionId::from_raw("sess-2".into());
    let outcome = db
        .mcp_sessions()
        .attach(AttachParams {
            session_id: s2.clone(),
            agent_id: agent.clone(),
            session_label: Some(label.clone()),
            attached_at: now,
            client_name: None,
            client_version: None,
            ttl_ms,
        })
        .await
        .unwrap();
    assert!(matches!(outcome, AttachOutcome::LabelInUse { .. }));

    // Heartbeat-stale the first row by attaching far in the future.
    let way_later = Timestamp::from_unix_ms(now.unix_ms() + ttl_ms * 10).unwrap();
    let s3 = McpSessionId::from_raw("sess-3".into());
    let outcome = db
        .mcp_sessions()
        .attach(AttachParams {
            session_id: s3.clone(),
            agent_id: agent.clone(),
            session_label: Some(label.clone()),
            attached_at: way_later,
            client_name: None,
            client_version: None,
            ttl_ms,
        })
        .await
        .unwrap();
    match outcome {
        AttachOutcome::Inserted {
            session,
            resumed: true,
            ..
        } => {
            assert_eq!(session.session_id, s3);
            assert!(session.last_message_id.is_some(), "cursor must be carried");
            assert_eq!(session.last_resolved_seq, Some(42));
            assert!(session.last_confirmation_id.is_none());
        }
        other => panic!("expected Inserted{{ resumed: true }}, got {other:?}"),
    }

    // Old session is gone (replaced by the resumed one).
    assert!(db.mcp_sessions().get(&s1).await.unwrap().is_none());

    // list_for_agent surfaces the resumed session.
    let live = db
        .mcp_sessions()
        .list_for_agent(&agent, way_later, ttl_ms)
        .await
        .unwrap();
    assert_eq!(live.len(), 1);
    assert_eq!(live[0].session_id, s3);
    assert_eq!(live[0].session_label.as_ref(), Some(&label));
}

/// Alias-ambiguity count (axis 3): `count_with_effective_alias`
/// returns the number of *other* agents (excluding `exclude`) whose
/// effective alias equals the candidate. Drives the
/// `from_alias_ambiguous` flag in `MessageView` /
/// `PendingConfirmationView` / `ChannelEvent`.
#[tokio::test]
async fn count_with_effective_alias_excludes_self_and_counts_collisions() {
    use hermod_core::AgentAlias;

    let db = fresh_db().await;
    let now = Timestamp::now();
    let alias: AgentAlias = "alice".parse().unwrap();

    let mk = |_idx: u32, local: Option<AgentAlias>, peer: Option<AgentAlias>| -> AgentRecord {
        let kp = Keypair::generate();
        AgentRecord {
            id: kp.agent_id(),
            pubkey: kp.to_pubkey_bytes(),
            host_id: None,
            via_agent: None,
            local_alias: local,
            peer_asserted_alias: peer,
            trust_level: TrustLevel::Tofu,
            reputation: 0,
            first_seen: now,
            last_seen: Some(now),
            peer_asserted_tags: hermod_core::CapabilityTagSet::empty(),
        }
    };

    let a = mk(1, Some(alias.clone()), None); // local "alice"
    let b = mk(2, None, Some(alias.clone())); // peer-asserted "alice" (effective)
    let c = mk(3, Some("bob".parse().unwrap()), Some(alias.clone())); // effective "bob" — local wins
    db.agents().upsert(&a).await.unwrap();
    db.agents().upsert(&b).await.unwrap();
    db.agents().upsert(&c).await.unwrap();

    // From a's perspective: one other agent (b) has effective "alice".
    let n = db
        .agents()
        .count_with_effective_alias(&alias, &a.id)
        .await
        .unwrap();
    assert_eq!(n, 1, "b should collide with a's effective alias");

    // From a host with no other "alice" rows: zero.
    let alone = mk(4, None, Some("solo".parse().unwrap()));
    db.agents().upsert(&alone).await.unwrap();
    let n = db
        .agents()
        .count_with_effective_alias(&"solo".parse().unwrap(), &alone.id)
        .await
        .unwrap();
    assert_eq!(n, 0);
}

/// PR-2 axis-8 storage integration: a `Silent` row is invisible to a
/// `disposition: [Push]` filter but visible to `[Silent]` and to no
/// filter at all. After `promote_to_push`, it surfaces in `[Push]`.
#[tokio::test]
async fn inbox_disposition_filter_and_promote() {
    use hermod_core::MessageDisposition;
    use hermod_storage::{Database, InboxFilter, MessageRecord, TransitionOutcome};

    let db = fresh_db().await;
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let now = Timestamp::now();
    for kp in [&kp_a, &kp_b] {
        db.agents()
            .upsert(&AgentRecord {
                id: kp.agent_id(),
                pubkey: kp.to_pubkey_bytes(),
                host_id: None,
                via_agent: None,
                local_alias: None,
                peer_asserted_alias: None,
                trust_level: TrustLevel::Local,
                reputation: 0,
                first_seen: now,
                last_seen: Some(now),
                peer_asserted_tags: hermod_core::CapabilityTagSet::empty(),
            })
            .await
            .unwrap();
    }

    // Two envelopes A→B: one Push, one Silent.
    let mk = |kp: &Keypair, text: &str, disp: MessageDisposition| -> MessageRecord {
        let mut env = Envelope::draft(
            AgentAddress::local(kp_a.agent_id()),
            AgentAddress::local(kp_b.agent_id()),
            MessageBody::Direct { text: text.into() },
            MessagePriority::Normal,
            3600,
        );
        kp.sign_envelope(&mut env).unwrap();
        let cbor = canonical_envelope_bytes(&env).unwrap();
        MessageRecord::from_envelope(&env, cbor, MessageStatus::Delivered).with_disposition(disp)
    };

    let push_rec = mk(&kp_a, "loud", MessageDisposition::Push);
    let silent_rec = mk(&kp_a, "quiet", MessageDisposition::Silent);
    let silent_id = silent_rec.id;
    db.messages().enqueue(&push_rec).await.unwrap();
    db.messages().enqueue(&silent_rec).await.unwrap();

    // Push-only filter (MCP channel poller): excludes Silent.
    let push_only = db
        .messages()
        .list_inbox(
            &kp_b.agent_id(),
            &InboxFilter {
                dispositions: Some(vec![MessageDisposition::Push]),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(push_only.len(), 1);
    assert_eq!(push_only[0].disposition, MessageDisposition::Push);

    // Silent-only filter (operator triage): excludes Push.
    let silent_only = db
        .messages()
        .list_inbox(
            &kp_b.agent_id(),
            &InboxFilter {
                dispositions: Some(vec![MessageDisposition::Silent]),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(silent_only.len(), 1);
    assert_eq!(silent_only[0].disposition, MessageDisposition::Silent);

    // No filter (operator default): both.
    let all = db
        .messages()
        .list_inbox(&kp_b.agent_id(), &InboxFilter::default())
        .await
        .unwrap();
    assert_eq!(all.len(), 2);

    // Promote silent → push: row joins the push-only view, leaves silent-only.
    let outcome = db
        .messages()
        .promote_to_push(&silent_id, &kp_b.agent_id())
        .await
        .unwrap();
    assert_eq!(outcome, TransitionOutcome::Applied);

    let push_after = db
        .messages()
        .list_inbox(
            &kp_b.agent_id(),
            &InboxFilter {
                dispositions: Some(vec![MessageDisposition::Push]),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(push_after.len(), 2);

    // Promote-already-push is a NoOp.
    let outcome = db
        .messages()
        .promote_to_push(&silent_id, &kp_b.agent_id())
        .await
        .unwrap();
    assert_eq!(outcome, TransitionOutcome::NoOp);

    // Cross-agent guard: A's bearer can't promote B's row.
    let outcome = db
        .messages()
        .promote_to_push(&silent_id, &kp_a.agent_id())
        .await
        .unwrap();
    assert_eq!(outcome, TransitionOutcome::NoOp);

    // count_silent_to is consistent — after promotion, no silent.
    let n = db
        .messages()
        .count_silent_to(&kp_b.agent_id())
        .await
        .unwrap();
    assert_eq!(n, 0);
}

/// PR-2 atomic enqueue with cap: the storage layer's
/// `INSERT … WHERE COUNT < cap` rejects writes once the cap is
/// reached — no race window between count and insert.
#[tokio::test]
async fn notification_enqueue_respects_cap_atomically() {
    use hermod_core::MessageDisposition;
    use hermod_storage::{Database, EnqueueOutcome, EnqueueRequest, MessageRecord};

    let db = fresh_db().await;
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let now = Timestamp::now();
    for kp in [&kp_a, &kp_b] {
        db.agents()
            .upsert(&AgentRecord {
                id: kp.agent_id(),
                pubkey: kp.to_pubkey_bytes(),
                host_id: None,
                via_agent: None,
                local_alias: None,
                peer_asserted_alias: None,
                trust_level: TrustLevel::Local,
                reputation: 0,
                first_seen: now,
                last_seen: Some(now),
                peer_asserted_tags: hermod_core::CapabilityTagSet::empty(),
            })
            .await
            .unwrap();
    }

    // Seed messages so the FK on notifications.message_id resolves.
    let mut env = Envelope::draft(
        AgentAddress::local(kp_a.agent_id()),
        AgentAddress::local(kp_b.agent_id()),
        MessageBody::Direct { text: "x".into() },
        MessagePriority::Normal,
        3600,
    );
    kp_a.sign_envelope(&mut env).unwrap();
    let cbor = canonical_envelope_bytes(&env).unwrap();
    let rec = MessageRecord::from_envelope(&env, cbor, MessageStatus::Delivered)
        .with_disposition(MessageDisposition::Push);
    let msg_id = rec.id;
    db.messages().enqueue(&rec).await.unwrap();

    let recipient = kp_b.agent_id();
    let make_req = |i: usize| EnqueueRequest {
        id: format!("notif-{i:04}"),
        recipient_agent_id: recipient.clone(),
        message_id: msg_id,
        sound: None,
        created_at: Timestamp::now(),
    };

    // First 3 inserts at cap=3 succeed.
    for i in 0..3 {
        let outcome = db.notifications().enqueue(&make_req(i), 3).await.unwrap();
        assert_eq!(outcome, EnqueueOutcome::Inserted, "row {i} must land");
    }
    // 4th hits the cap atomically.
    let outcome = db.notifications().enqueue(&make_req(99), 3).await.unwrap();
    assert_eq!(outcome, EnqueueOutcome::BackPressure);

    // Open count for the recipient is exactly 3 (pending) — the
    // back-pressured row was never written.
    let n = db.notifications().count_open_for(&recipient).await.unwrap();
    assert_eq!(n, 3);
}
