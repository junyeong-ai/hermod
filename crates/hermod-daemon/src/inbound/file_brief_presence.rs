//! Inbound acceptors for `MessageBody::{File, Brief, Presence}`.
//!
//! All three are "leaf" applications — they store-and-audit, no
//! follow-on services to dispatch into. Grouped together because each
//! is small, none cross-references the others, and the inbound module
//! tree benefits from one file per envelope-kind cluster rather than
//! a sprawling `mod.rs`.

use hermod_core::{Envelope, MessageStatus, Timestamp};
use hermod_protocol::envelope::serialize_envelope;
use hermod_storage::{AuditEntry, MessageRecord};

use super::InboundProcessor;
use super::scope::FederationRejection;
use crate::services::audit_or_warn;

impl InboundProcessor {
    pub(super) async fn accept_file(
        &self,
        envelope: &Envelope,
        name: &str,
        _mime: &str,
        hash: &serde_bytes::ByteBuf,
        data: &serde_bytes::ByteBuf,
    ) -> Result<(), FederationRejection> {
        let computed = blake3::hash(data.as_ref());
        if hash.as_ref() != computed.as_bytes() {
            return Err(FederationRejection::Invalid("file hash mismatch".into()));
        }

        let key = format!("{}-{name}", envelope.id);
        let location = self
            .db
            .blobs()
            .put(hermod_storage::bucket::FILES, &key, data.as_ref())
            .await
            .map_err(|e| FederationRejection::Storage(format!("blob put: {e}")))?;

        let cbor = serialize_envelope(envelope)
            .map_err(|e| FederationRejection::Invalid(format!("serialize: {e}")))?;
        let mut record = MessageRecord::from_envelope(envelope, cbor, MessageStatus::Delivered)
            .with_file_blob_location(location.clone());
        record.delivered_at = Some(Timestamp::now());
        if let Err(e) = self.db.messages().enqueue(&record).await {
            // Storage failed — release the blob to avoid orphaning.
            let _ = self.db.blobs().delete(&location).await;
            return Err(FederationRejection::Storage(e.to_string()));
        }

        audit_or_warn(
            &*self.audit_sink,
            AuditEntry {
                id: None,
                ts: Timestamp::now(),
                actor: envelope.from.id.clone(),
                action: "file.delivered".into(),
                target: Some(self.self_id.to_string()),
                details: Some(serde_json::json!({
                    "id": envelope.id.to_string(),
                    "name": name,
                    "size": data.len(),
                    "location": location,
                })),
                client_ip: None,
                federation: hermod_storage::AuditFederationPolicy::Default,
            },
        )
        .await;
        Ok(())
    }

    pub(super) async fn accept_brief(
        &self,
        envelope: &Envelope,
        summary: &str,
        topic: Option<&str>,
    ) -> Result<(), FederationRejection> {
        // Cap inbound ttl at the same bound `BriefService::publish` enforces
        // locally. A peer can't make us hold their brief forever.
        const MAX_INBOUND_BRIEF_TTL_SECS: u32 = 30 * 24 * 3600;
        let now = Timestamp::now();
        let ttl = envelope.ttl_secs.min(MAX_INBOUND_BRIEF_TTL_SECS);
        let expires_at = if ttl == 0 {
            None
        } else {
            Some(
                Timestamp::from_unix_ms(now.unix_ms() + (ttl as i64) * 1_000)
                    .expect("bounded ttl never overflows Timestamp"),
            )
        };
        self.db
            .briefs()
            .upsert(&hermod_storage::BriefRecord {
                agent_id: envelope.from.id.clone(),
                topic: topic.map(|s| s.to_string()),
                summary: summary.to_string(),
                published_at: envelope.ts,
                expires_at,
            })
            .await
            .map_err(|e| FederationRejection::Storage(e.to_string()))?;

        audit_or_warn(
            &*self.audit_sink,
            AuditEntry {
                id: None,
                ts: now,
                actor: envelope.from.id.clone(),
                action: "brief.observed".into(),
                target: Some(envelope.from.id.to_string()),
                details: Some(serde_json::json!({
                    "envelope_id": envelope.id.to_string(),
                    "topic": topic,
                    "len": summary.len(),
                })),
                client_ip: None,
                federation: hermod_storage::AuditFederationPolicy::Default,
            },
        )
        .await;
        Ok(())
    }

    pub(super) async fn accept_presence(
        &self,
        envelope: &Envelope,
        manual_status: Option<hermod_core::PresenceStatus>,
        live: bool,
    ) -> Result<(), FederationRejection> {
        // Freshness window: as advertised by the publisher in the envelope's
        // `ttl_secs`. If the publisher set a 1-hour fanout TTL we treat the
        // cached value as stale after 1 hour, even if no replacement
        // arrived (network partition, peer crashed, etc.).
        let observed_at = envelope.ts;
        let expires_at =
            Timestamp::from_unix_ms(observed_at.unix_ms() + (envelope.ttl_secs as i64) * 1_000)
                .map_err(|e| FederationRejection::Invalid(format!("ts overflow: {e}")))?;

        self.db
            .presences()
            .observe_peer(
                &envelope.from.id,
                hermod_storage::ObservedPresence {
                    manual_status,
                    live,
                    observed_at,
                    expires_at,
                },
            )
            .await
            .map_err(|e| FederationRejection::Storage(e.to_string()))?;

        audit_or_warn(
            &*self.audit_sink,
            AuditEntry {
                id: None,
                ts: Timestamp::now(),
                actor: envelope.from.id.clone(),
                action: "presence.observed".into(),
                target: Some(envelope.from.id.to_string()),
                details: Some(serde_json::json!({
                    "envelope_id": envelope.id.to_string(),
                    "manual_status": manual_status.map(|s| s.as_str()),
                    "live": live,
                })),
                client_ip: None,
                federation: hermod_storage::AuditFederationPolicy::Default,
            },
        )
        .await;
        Ok(())
    }
}
