//! Property-based test for the message state machine.
//!
//! Generates random sequences of transitions (`Deliver`, `Ack`, `Fail`,
//! `Prune`) over a synthetic message and asserts the invariants the
//! production code is supposed to honour:
//!
//!   1. A row in a terminal state (`read`, `failed`) never moves back to
//!      `pending` or `delivered`.
//!   2. `delivered_at` (when set) is no later than `read_at` (when set).
//!   3. `try_deliver_pending` after the row is past `pending` is a NoOp.
//!   4. `try_fail_pending_or_delivered` against a terminal row is a NoOp.

use hermod_core::{
    AgentAddress, AgentId, Envelope, HermodError, MessageBody, MessagePriority, MessageStatus,
    PubkeyBytes, Timestamp,
};
use hermod_crypto::{Keypair, agent_id_from_pubkey};
use hermod_storage::backends::sqlite::SqliteDatabase;
use hermod_storage::{AgentRecord, Database, MessageRecord, TransitionOutcome};
use proptest::prelude::*;
use std::sync::Arc;
use tokio::runtime::Runtime;

#[derive(Debug, Clone, Copy)]
enum Op {
    Deliver,
    Ack,
    Fail,
    Touch, // re-enqueue (no-op when row exists; tests idempotency of insert)
}

fn op_strategy() -> impl Strategy<Value = Op> {
    prop_oneof![
        Just(Op::Deliver),
        Just(Op::Ack),
        Just(Op::Fail),
        Just(Op::Touch),
    ]
}

async fn fresh_db() -> SqliteDatabase {
    let mut p = std::env::temp_dir();
    p.push(format!("hermod-proptest-{}.sqlite", ulid::Ulid::new()));
    SqliteDatabase::connect(
        &p,
        Arc::new(hermod_crypto::LocalKeySigner::new(Arc::new(
            Keypair::generate(),
        ))) as Arc<dyn hermod_crypto::Signer>,
        Arc::new(hermod_storage::MemoryBlobStore::new()),
    )
    .await
    .unwrap()
}

async fn seed_agents(repo: &dyn hermod_storage::AgentRepository, from: &AgentId, to: &AgentId) {
    let now = Timestamp::now();
    let pk_bytes = |seed: u8| PubkeyBytes([seed; 32]);
    for (id, seed) in [(from, 1u8), (to, 2u8)] {
        repo.upsert(&AgentRecord {
            id: id.clone(),
            pubkey: pk_bytes(seed),
            endpoint: None,
            local_alias: None,
            peer_asserted_alias: None,
            trust_level: hermod_core::TrustLevel::Tofu,
            tls_fingerprint: None,
            reputation: 0,
            first_seen: now,
            last_seen: Some(now),
        })
        .await
        .unwrap();
    }
}

fn make_envelope(from: AgentId, to: AgentId) -> Result<Envelope, HermodError> {
    Ok(Envelope::draft(
        AgentAddress::local(from),
        AgentAddress::local(to),
        MessageBody::Direct {
            text: "proptest".into(),
        },
        MessagePriority::Normal,
        3600,
    ))
}

async fn run_sequence(ops: Vec<Op>) {
    let db = fresh_db().await;
    let from = agent_id_from_pubkey(&PubkeyBytes([1; 32]));
    let to = agent_id_from_pubkey(&PubkeyBytes([2; 32]));
    seed_agents(db.agents(), &from, &to).await;

    let env = make_envelope(from.clone(), to.clone()).unwrap();
    let id = env.id;
    let cbor = vec![0xff];
    let messages = db.messages();
    messages
        .enqueue(&MessageRecord::from_envelope(
            &env,
            cbor.clone(),
            MessageStatus::Pending,
        ))
        .await
        .unwrap();

    for op in ops {
        match op {
            Op::Deliver => {
                let outcome = messages
                    .try_deliver_pending(&id, Timestamp::now())
                    .await
                    .unwrap();
                let row = messages.get(&id).await.unwrap().expect("row present");
                if outcome == TransitionOutcome::Applied {
                    assert_eq!(row.status, MessageStatus::Delivered);
                    assert!(row.delivered_at.is_some());
                } else {
                    // NoOp: row was not pending. Status must be terminal/delivered.
                    assert_ne!(row.status, MessageStatus::Pending);
                }
            }
            Op::Ack => {
                let _ = messages.ack(&id, &to, Timestamp::now()).await.unwrap();
                let row = messages.get(&id).await.unwrap().expect("row present");
                if row.status == MessageStatus::Read {
                    assert!(row.read_at.is_some());
                }
            }
            Op::Fail => {
                let outcome = messages.try_fail_pending_or_delivered(&id).await.unwrap();
                let row = messages.get(&id).await.unwrap().expect("row present");
                if outcome == TransitionOutcome::Applied {
                    assert_eq!(row.status, MessageStatus::Failed);
                } else {
                    assert!(matches!(
                        row.status,
                        MessageStatus::Read | MessageStatus::Failed
                    ));
                }
            }
            Op::Touch => {
                let row_before = messages.get(&id).await.unwrap().expect("row present");
                // Touching with the same record is an upsert no-op for status.
                messages
                    .enqueue(&MessageRecord::from_envelope(
                        &env,
                        cbor.clone(),
                        MessageStatus::Pending,
                    ))
                    .await
                    .unwrap();
                let row_after = messages.get(&id).await.unwrap().expect("row present");
                // Status must not regress: a `read` / `failed` row stays so.
                if matches!(
                    row_before.status,
                    MessageStatus::Read | MessageStatus::Failed
                ) {
                    assert_eq!(row_before.status, row_after.status);
                }
            }
        }
    }

    // Final invariants.
    let row = messages.get(&id).await.unwrap().expect("row present");
    if let (Some(d), Some(r)) = (row.delivered_at, row.read_at) {
        assert!(d.unix_ms() <= r.unix_ms(), "delivered_at <= read_at");
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]
    #[test]
    fn state_machine_invariants(ops in proptest::collection::vec(op_strategy(), 1..32)) {
        Runtime::new().unwrap().block_on(run_sequence(ops));
    }
}
