//! Inbound acceptors for `MessageBody::CapabilityGrant` and
//! `MessageBody::AuditFederate`. Both are operator-meaningful
//! cross-daemon imports — capability tokens (issuer→audience) and
//! federated audit rows (sender→aggregator). Grouped together because
//! they share the "import a row from another daemon's authoritative
//! ledger" shape.

use hermod_core::{Envelope, Timestamp};
use hermod_storage::AuditEntry;

use super::InboundProcessor;
use super::scope::FederationRejection;
use crate::services::audit_or_warn;

impl InboundProcessor {
    pub(super) async fn accept_capability_grant(
        &self,
        envelope: &Envelope,
        token: &serde_bytes::ByteBuf,
        scope: &str,
    ) -> Result<(), FederationRejection> {
        // Verify the capability token using the issuer's pubkey
        // carried in the envelope itself — the binding check on the
        // accept_envelope path already proved
        // `agent_id == blake3(from_pubkey)[:26]`, so we can verify
        // independently of the directory.
        let pk = hermod_crypto::PublicKey::from_bytes(&envelope.from_pubkey)
            .map_err(|e| FederationRejection::Invalid(format!("issuer pubkey: {e}")))?;
        let claim = hermod_crypto::verify_capability(&pk, token.as_ref())
            .map_err(|e| FederationRejection::Invalid(format!("capability: {e}")))?;

        // Store on the audience side. Idempotent via INSERT OR IGNORE
        // on the jti primary key.
        let now = Timestamp::now();
        let exp_ts = claim.exp.and_then(|ms| Timestamp::from_unix_ms(ms).ok());
        self.db
            .capabilities()
            .upsert_received(&hermod_storage::CapabilityRecord {
                id: claim.jti.clone(),
                issuer: envelope.from.id.clone(),
                audience: claim.aud.clone(),
                scope: scope.to_string(),
                target: claim.target.clone(),
                expires_at: exp_ts,
                revoked_at: None,
                raw_token: token.to_vec(),
            })
            .await
            .map_err(|e| FederationRejection::Storage(e.to_string()))?;

        audit_or_warn(
            &*self.audit_sink,
            AuditEntry {
                id: None,
                ts: now,
                actor: envelope.from.id.clone(),
                action: "capability.observed".into(),
                target: Some(self.self_id.to_string()),
                details: Some(serde_json::json!({
                    "envelope_id": envelope.id.to_string(),
                    "scope": scope,
                    "jti": claim.jti,
                })),
                federation: hermod_storage::AuditFederationPolicy::Default,
            },
        )
        .await;
        Ok(())
    }

    /// Receive an `AuditFederate` envelope and write it into the local
    /// hash-chained log under `audit.federate.<original_action>`. The
    /// row's `actor` is the federation sender (so cross-daemon
    /// timelines reconstruct from `actor` alone), and `details`
    /// embeds the original target / details / timestamp so no
    /// information is lost across the bridge. Without operator opt-in
    /// (`[audit] accept_federation = true`) we reject — a peer can't
    /// pollute our audit log unilaterally.
    pub(super) async fn accept_audit_federate(
        &self,
        envelope: &Envelope,
        action: &str,
        target: Option<&str>,
        details: Option<&serde_json::Value>,
        original_ts_ms: i64,
    ) -> Result<(), FederationRejection> {
        if !self.accept_audit_federation {
            return Err(FederationRejection::Unauthorized("not an aggregator"));
        }
        // Reject already-federated rows. Without this guard, a buggy or
        // adversarial peer could ship `action = "audit.federate.foo"`,
        // and we would write `audit.federate.audit.federate.foo` to our
        // chain — harmless but ugly, and a foothold for action-string
        // collision games. The originating daemon emits the *primary*
        // action; only that primary is allowed across the wire.
        if action.starts_with("audit.federate.") {
            return Err(FederationRejection::Invalid(
                "nested audit.federate.* action".into(),
            ));
        }
        // Re-prefixing under `audit.federate.` makes the source obvious
        // when grepping the aggregator's log and prevents the row from
        // colliding with locally-emitted actions of the same name. The
        // original action is preserved verbatim in `details.action`.
        let folded_action = format!("audit.federate.{action}");
        let folded_details = serde_json::json!({
            "envelope_id": envelope.id.to_string(),
            "action": action,
            "target": target,
            "details": details,
            "original_ts_ms": original_ts_ms,
        });
        let now = Timestamp::now();
        let entry = AuditEntry {
            id: None,
            ts: now,
            actor: envelope.from.id.clone(),
            action: folded_action,
            target: target.map(|s| s.to_string()),
            details: Some(folded_details),
            // Aggregator-side echo. Federating it again would loop back
            // to the originator, which would loop back here, ad
            // infinitum. The originating daemon already committed the
            // pre-folded row to its own hash-chain.
            federation: hermod_storage::AuditFederationPolicy::Skip,
        };
        // Best-effort by `AuditSink` contract — a hash-chain failure
        // here MUST NOT bounce the envelope (the sender already
        // committed the row in their own chain; bouncing would
        // double-charge the sender for our backend hiccup).
        self.audit_sink.record(entry).await;
        // Receiver-side meta-row: separate from the federated row so
        // operators querying for `audit.federate.received` can see
        // the cross-daemon delivery rate independent of which actions
        // were shipped.
        audit_or_warn(
            &*self.audit_sink,
            AuditEntry {
                id: None,
                ts: now,
                actor: envelope.from.id.clone(),
                action: "audit.federate.received".into(),
                target: Some(self.self_id.to_string()),
                details: Some(serde_json::json!({
                    "envelope_id": envelope.id.to_string(),
                    "original_action": action,
                })),
                // Aggregator-local meta-row. Stays inside this daemon;
                // re-shipping it would just describe the description.
                federation: hermod_storage::AuditFederationPolicy::Skip,
            },
        )
        .await;
        Ok(())
    }
}
