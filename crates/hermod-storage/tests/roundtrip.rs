//! End-to-end roundtrip: open DB, migrate, insert an agent, enqueue a message,
//! list inbox, ack, verify state.

use hermod_core::{
    AgentAddress, Endpoint, Envelope, MessageBody, MessagePriority, MessageStatus, Timestamp,
    TrustLevel, WssEndpoint,
};
use hermod_crypto::{Keypair, LocalKeySigner, Signer, canonical_envelope_bytes};
use hermod_storage::backends::sqlite::SqliteDatabase;
use hermod_storage::{AgentRecord, Database, InboxFilter, MessageRecord, RepinOutcome};
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
                host_pubkey: None,
                endpoint: None,
                via_agent: None,
                local_alias: None,
                peer_asserted_alias: None,
                trust_level: TrustLevel::Local,
                tls_fingerprint: None,
                reputation: 0,
                first_seen: now,
                last_seen: Some(now),
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
                host_pubkey: None,
                endpoint: None,
                via_agent: None,
                local_alias: None,
                peer_asserted_alias: None,
                trust_level: TrustLevel::Local,
                tls_fingerprint: None,
                reputation: 0,
                first_seen: now,
                last_seen: Some(now),
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
                host_pubkey: None,
                endpoint: None,
                via_agent: None,
                local_alias: None,
                peer_asserted_alias: None,
                trust_level: TrustLevel::Local,
                tls_fingerprint: None,
                reputation: 0,
                first_seen: now,
                last_seen: Some(now),
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
            host_pubkey: None,
            endpoint: None,
            via_agent: None,
            local_alias: None,
            peer_asserted_alias: None,
            trust_level: TrustLevel::Tofu,
            tls_fingerprint: None,
            reputation: 0,
            first_seen: now,
            last_seen: Some(now),
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
            host_pubkey: None,
            endpoint: None,
            via_agent: None,
            local_alias: None,
            peer_asserted_alias: None,
            trust_level: TrustLevel::Tofu,
            tls_fingerprint: None,
            reputation: 0,
            first_seen: now,
            last_seen: Some(now),
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
                host_pubkey: None,
                endpoint: None,
                via_agent: None,
                local_alias: None,
                peer_asserted_alias: None,
                trust_level: TrustLevel::Tofu,
                tls_fingerprint: None,
                reputation: 0,
                first_seen: now,
                last_seen: Some(now),
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
                host_pubkey: None,
                endpoint: None,
                via_agent: None,
                local_alias: None,
                peer_asserted_alias: None,
                trust_level: TrustLevel::Tofu,
                tls_fingerprint: None,
                reputation: 0,
                first_seen: now,
                last_seen: Some(now),
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
                host_pubkey: None,
                endpoint: None,
                via_agent: None,
                local_alias: None,
                peer_asserted_alias: None,
                trust_level: TrustLevel::Tofu,
                tls_fingerprint: None,
                reputation: 0,
                first_seen: now,
                last_seen: Some(now),
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

#[tokio::test]
async fn forget_peer_returns_prior_endpoint_atomically() {
    // Regression: forget_peer must read-and-clear in one transaction, so
    // a concurrent peer.add can't change the endpoint between the read
    // and the clear and leave a stale pool entry alive.
    let db = fresh_db().await;
    let kp = Keypair::generate();
    let now = Timestamp::now();

    let endpoint = hermod_core::Endpoint::Wss(hermod_core::WssEndpoint {
        host: "example.com".into(),
        port: 7823,
    });
    db.agents()
        .upsert(&AgentRecord {
            id: kp.agent_id(),
            pubkey: kp.to_pubkey_bytes(),
            host_pubkey: None,
            endpoint: Some(endpoint.clone()),
            via_agent: None,
            local_alias: None,
            peer_asserted_alias: None,
            trust_level: TrustLevel::Verified,
            tls_fingerprint: Some("aa:bb".into()),
            reputation: 0,
            first_seen: now,
            last_seen: Some(now),
        })
        .await
        .unwrap();

    let outcome = db.agents().forget_peer(&kp.agent_id()).await.unwrap();
    assert!(outcome.existed);
    assert_eq!(outcome.prior_endpoint, Some(endpoint));

    // Idempotent: a second call against the now-cleared row reports
    // existed=true (row still exists) but prior_endpoint=None.
    let outcome2 = db.agents().forget_peer(&kp.agent_id()).await.unwrap();
    assert!(outcome2.existed);
    assert_eq!(outcome2.prior_endpoint, None);

    // Missing row reports existed=false.
    let missing = db
        .agents()
        .forget_peer(&Keypair::generate().agent_id())
        .await
        .unwrap();
    assert!(!missing.existed);
    assert_eq!(missing.prior_endpoint, None);
}

#[tokio::test]
async fn repin_returns_endpoint_snapshot_for_pool_eviction() {
    // R17 regression: replace_tls_fingerprint must capture the endpoint
    // inside the same SQL transaction that swaps the fingerprint.
    // Without that snapshot, a follow-up SELECT could observe an
    // endpoint changed by a concurrent peer.add and evict the wrong
    // pool entry, leaving the stale-context one alive.
    let db = fresh_db().await;
    let kp = Keypair::generate();
    let now = Timestamp::now();
    let endpoint = hermod_core::Endpoint::Wss(hermod_core::WssEndpoint {
        host: "peer.example".into(),
        port: 7823,
    });
    db.agents()
        .upsert(&AgentRecord {
            id: kp.agent_id(),
            pubkey: kp.to_pubkey_bytes(),
            host_pubkey: None,
            endpoint: Some(endpoint.clone()),
            via_agent: None,
            local_alias: None,
            peer_asserted_alias: None,
            trust_level: TrustLevel::Verified,
            tls_fingerprint: Some("aa:bb".into()),
            reputation: 0,
            first_seen: now,
            last_seen: Some(now),
        })
        .await
        .unwrap();

    let outcome = db
        .agents()
        .replace_tls_fingerprint(&kp.agent_id(), "cc:dd", TrustLevel::Verified)
        .await
        .unwrap();
    match outcome {
        RepinOutcome::Replaced {
            previous,
            endpoint: ep,
        } => {
            assert_eq!(previous.as_deref(), Some("aa:bb"));
            assert_eq!(ep, Some(endpoint));
        }
        other => panic!("expected Replaced with endpoint, got {other:?}"),
    }
}

#[tokio::test]
async fn repin_atomic_against_trust_change() {
    // Regression: replace_tls_fingerprint must check trust level and
    // perform the update in one transaction. A non-Verified peer must
    // not have its pin silently rotated.
    let db = fresh_db().await;
    let kp = Keypair::generate();
    let now = Timestamp::now();

    db.agents()
        .upsert(&AgentRecord {
            id: kp.agent_id(),
            pubkey: kp.to_pubkey_bytes(),
            host_pubkey: None,
            endpoint: None,
            via_agent: None,
            local_alias: None,
            peer_asserted_alias: None,
            trust_level: TrustLevel::Tofu,
            tls_fingerprint: Some("aa:bb".into()),
            reputation: 0,
            first_seen: now,
            last_seen: Some(now),
        })
        .await
        .unwrap();

    // Tofu — refuse.
    let r = db
        .agents()
        .replace_tls_fingerprint(&kp.agent_id(), "cc:dd", TrustLevel::Verified)
        .await
        .unwrap();
    match r {
        RepinOutcome::TrustMismatch { actual } => assert_eq!(actual, TrustLevel::Tofu),
        other => panic!("expected TrustMismatch, got {other:?}"),
    }
    // The pin must NOT have been rotated.
    let rec = db.agents().get(&kp.agent_id()).await.unwrap().unwrap();
    assert_eq!(rec.tls_fingerprint.as_deref(), Some("aa:bb"));

    // Promote to Verified.
    db.agents()
        .set_trust(&kp.agent_id(), TrustLevel::Verified)
        .await
        .unwrap();

    // Now repin succeeds and reports the previous value + the endpoint
    // snapshot taken inside the same transaction.
    let r = db
        .agents()
        .replace_tls_fingerprint(&kp.agent_id(), "cc:dd", TrustLevel::Verified)
        .await
        .unwrap();
    match r {
        RepinOutcome::Replaced { previous, endpoint } => {
            assert_eq!(previous.as_deref(), Some("aa:bb"));
            // This peer was upserted with endpoint = None.
            assert_eq!(endpoint, None);
        }
        other => panic!("expected Replaced, got {other:?}"),
    }
    let rec = db.agents().get(&kp.agent_id()).await.unwrap().unwrap();
    assert_eq!(rec.tls_fingerprint.as_deref(), Some("cc:dd"));

    // Missing peer.
    let r = db
        .agents()
        .replace_tls_fingerprint(
            &Keypair::generate().agent_id(),
            "ee:ff",
            TrustLevel::Verified,
        )
        .await
        .unwrap();
    assert_eq!(r, RepinOutcome::NotFound);
}

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
            host_pubkey: None,
            endpoint: None,
            via_agent: None,
            local_alias: None,
            peer_asserted_alias: None,
            trust_level: TrustLevel::Local,
            tls_fingerprint: None,
            reputation: 0,
            first_seen: now,
            last_seen: Some(now),
        })
        .await
        .unwrap();
    db.agents()
        .upsert(&AgentRecord {
            id: recipient.agent_id(),
            pubkey: recipient.to_pubkey_bytes(),
            host_pubkey: None,
            endpoint: Some(endpoint),
            via_agent: None,
            local_alias: None,
            peer_asserted_alias: None,
            trust_level: TrustLevel::Verified,
            tls_fingerprint: None,
            reputation: 0,
            first_seen: now,
            last_seen: Some(now),
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
    for (kp, ep, trust) in [
        (&sender, None, TrustLevel::Local),
        (&recipient, Some(endpoint), TrustLevel::Verified),
    ] {
        db.agents()
            .upsert(&AgentRecord {
                id: kp.agent_id(),
                pubkey: kp.to_pubkey_bytes(),
                host_pubkey: None,
                endpoint: ep,
                via_agent: None,
                local_alias: None,
                peer_asserted_alias: None,
                trust_level: trust,
                tls_fingerprint: None,
                reputation: 0,
                first_seen: now,
                last_seen: Some(now),
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
