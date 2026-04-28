use hermod_core::{AgentId, Timestamp};
use hermod_protocol::ipc::methods::{
    ConfirmationAcceptParams, ConfirmationAcceptResult, ConfirmationListParams,
    ConfirmationListResult, ConfirmationRejectParams, ConfirmationRejectResult,
    PendingConfirmationView,
};
use hermod_storage::{AuditEntry, AuditSink, ConfirmationStatus, Database};
use std::sync::Arc;

use crate::inbound::InboundProcessor;
use crate::services::{ServiceError, audit_or_warn};

const DEFAULT_LIST_LIMIT: u32 = 50;
const MAX_LIST_LIMIT: u32 = 500;

#[derive(Clone)]
pub struct ConfirmationService {
    db: Arc<dyn Database>,
    audit_sink: Arc<dyn AuditSink>,
    self_id: AgentId,
    /// Held envelopes replay through the post-gate apply path on accept.
    inbound: InboundProcessor,
}

impl std::fmt::Debug for ConfirmationService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfirmationService")
            .field("self_id", &self.self_id)
            .finish_non_exhaustive()
    }
}

impl ConfirmationService {
    pub fn new(
        db: Arc<dyn Database>,
        audit_sink: Arc<dyn AuditSink>,
        self_id: AgentId,
        inbound: InboundProcessor,
    ) -> Self {
        Self {
            db,
            audit_sink,
            self_id,
            inbound,
        }
    }

    pub async fn list(
        &self,
        params: ConfirmationListParams,
    ) -> Result<ConfirmationListResult, ServiceError> {
        let limit = params
            .limit
            .unwrap_or(DEFAULT_LIST_LIMIT)
            .min(MAX_LIST_LIMIT);
        let rows = self
            .db
            .confirmations()
            .list_pending(limit, params.after_id.as_deref())
            .await?;
        let mut alias_cache: std::collections::HashMap<
            hermod_core::AgentId,
            crate::services::message::AliasTriple,
        > = std::collections::HashMap::new();
        let mut confirmations = Vec::with_capacity(rows.len());
        for r in rows {
            let triple = match alias_cache.get(&r.actor) {
                Some(v) => v.clone(),
                None => {
                    let t = crate::services::message::AliasTriple::lookup(&self.db, &r.actor).await;
                    alias_cache.insert(r.actor.clone(), t.clone());
                    t
                }
            };
            confirmations.push(PendingConfirmationView {
                id: r.id,
                requested_at: r.requested_at,
                from: r.actor,
                from_local_alias: triple.local,
                from_peer_alias: triple.peer,
                from_alias: triple.effective,
                intent: r.intent.as_str().to_string(),
                sensitivity: r.sensitivity,
                trust_level: r.trust_level,
                summary: r.summary,
            });
        }
        Ok(ConfirmationListResult { confirmations })
    }

    pub async fn accept(
        &self,
        params: ConfirmationAcceptParams,
    ) -> Result<ConfirmationAcceptResult, ServiceError> {
        let row = self
            .db
            .confirmations()
            .get(&params.confirmation_id)
            .await?
            .ok_or(ServiceError::NotFound)?;
        if row.status != ConfirmationStatus::Pending {
            return Err(ServiceError::InvalidParam(format!(
                "confirmation {} is already {}",
                row.id,
                row.status.as_str()
            )));
        }
        // Apply the held envelope. If application fails (e.g. an unknown
        // channel after the workspace was deleted while the row was held),
        // surface the error instead of marking accepted, so the operator can
        // re-decide.
        self.inbound
            .apply_held(&row.envelope_cbor)
            .await
            .map_err(|e| ServiceError::InvalidParam(format!("replay: {e}")))?;

        let now = Timestamp::now();
        let updated = self
            .db
            .confirmations()
            .decide(
                &params.confirmation_id,
                ConfirmationStatus::Accepted,
                &self.self_id,
                now,
            )
            .await?;
        if !updated {
            // Race: another caller decided concurrently. The replay already
            // happened above — that's idempotent for our uses (envelope ids
            // dedupe at the messages / channel_messages tables).
        }

        audit_or_warn(
            &*self.audit_sink,
            AuditEntry {
                id: None,
                ts: now,
                actor: self.self_id.clone(),
                action: "confirmation.accept".into(),
                target: Some(row.id.clone()),
                details: Some(serde_json::json!({
                    "from": row.actor.to_string(),
                    "held_intent": row.intent.as_str(),
                })),
                federation: hermod_storage::AuditFederationPolicy::Default,
            },
        )
        .await;

        Ok(ConfirmationAcceptResult {
            id: params.confirmation_id,
        })
    }

    pub async fn reject(
        &self,
        params: ConfirmationRejectParams,
    ) -> Result<ConfirmationRejectResult, ServiceError> {
        let now = Timestamp::now();
        let row = self
            .db
            .confirmations()
            .get(&params.confirmation_id)
            .await?
            .ok_or(ServiceError::NotFound)?;
        if row.status != ConfirmationStatus::Pending {
            return Err(ServiceError::InvalidParam(format!(
                "confirmation {} is already {}",
                row.id,
                row.status.as_str()
            )));
        }
        self.db
            .confirmations()
            .decide(
                &params.confirmation_id,
                ConfirmationStatus::Rejected,
                &self.self_id,
                now,
            )
            .await?;
        audit_or_warn(
            &*self.audit_sink,
            AuditEntry {
                id: None,
                ts: now,
                actor: self.self_id.clone(),
                action: "confirmation.reject".into(),
                target: Some(row.id.clone()),
                details: Some(serde_json::json!({
                    "from": row.actor.to_string(),
                    "held_intent": row.intent.as_str(),
                })),
                federation: hermod_storage::AuditFederationPolicy::Default,
            },
        )
        .await;

        Ok(ConfirmationRejectResult {
            id: params.confirmation_id,
        })
    }
}
