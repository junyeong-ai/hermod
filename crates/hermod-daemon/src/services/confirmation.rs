use hermod_core::{AgentId, Timestamp};
use hermod_protocol::ipc::methods::{
    ConfirmationAcceptParams, ConfirmationAcceptResult, ConfirmationListParams,
    ConfirmationListResult, ConfirmationRejectParams, ConfirmationRejectResult,
    PendingConfirmationView,
};
use hermod_storage::{AuditEntry, AuditSink, ConfirmationStatus, Database};
use std::sync::Arc;

use crate::audit_context::current_caller_agent;
use crate::inbound::InboundProcessor;
use crate::services::{ServiceError, audit_or_warn};

const DEFAULT_LIST_LIMIT: u32 = 50;
const MAX_LIST_LIMIT: u32 = 500;

#[derive(Clone)]
pub struct ConfirmationService {
    db: Arc<dyn Database>,
    audit_sink: Arc<dyn AuditSink>,
    /// Audit fallback actor for emissions outside an IPC scope.
    /// `audit_or_warn` overlays the IPC caller's agent_id when one
    /// is in scope; this value is what lands in audit rows when no
    /// caller is present.
    host_actor: AgentId,
    /// Held envelopes replay through the post-gate apply path on accept.
    inbound: InboundProcessor,
}

impl std::fmt::Debug for ConfirmationService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfirmationService")
            .field("host_actor", &self.host_actor)
            .finish_non_exhaustive()
    }
}

impl ConfirmationService {
    pub fn new(
        db: Arc<dyn Database>,
        audit_sink: Arc<dyn AuditSink>,
        host_actor: AgentId,
        inbound: InboundProcessor,
    ) -> Self {
        Self {
            db,
            audit_sink,
            host_actor,
            inbound,
        }
    }

    /// Resolve the IPC caller. Confirmation decisions write a
    /// `decided_by` column verbatim, so a missing caller is a hard
    /// error here — falling back to host_actor would store the
    /// wrong identity in storage. Audit-only sites use the
    /// `audit_or_warn` overlay instead.
    fn caller(&self) -> Result<AgentId, ServiceError> {
        current_caller_agent().ok_or_else(|| {
            ServiceError::InvalidParam(
                "confirmation.* requires an IPC caller scope (no caller_agent in context)".into(),
            )
        })
    }

    pub async fn list(
        &self,
        params: ConfirmationListParams,
    ) -> Result<ConfirmationListResult, ServiceError> {
        // Per-agent isolation: only the recipient's own confirmation
        // queue is visible to a given IPC caller. Without this filter
        // bearer A could enumerate (and accept!) bearer B's held
        // envelopes — a privilege escalation in multi-tenant
        // deployments.
        let caller = self.caller()?;
        let limit = params
            .limit
            .unwrap_or(DEFAULT_LIST_LIMIT)
            .min(MAX_LIST_LIMIT);
        let rows = self
            .db
            .confirmations()
            .list_pending(Some(&caller), limit, params.after_id.as_deref())
            .await?;
        let mut sender_cache: std::collections::HashMap<
            hermod_core::AgentId,
            crate::services::message::SenderProjection,
        > = std::collections::HashMap::new();
        let mut confirmations = Vec::with_capacity(rows.len());
        for r in rows {
            let proj = match sender_cache.get(&r.actor) {
                Some(v) => v.clone(),
                None => {
                    let t = crate::services::message::SenderProjection::lookup(&self.db, &r.actor)
                        .await;
                    sender_cache.insert(r.actor.clone(), t.clone());
                    t
                }
            };
            confirmations.push(PendingConfirmationView {
                id: r.id,
                requested_at: r.requested_at,
                from: r.actor,
                from_local_alias: proj.local,
                from_peer_alias: proj.peer,
                from_alias: proj.effective,
                from_alias_ambiguous: proj.effective_ambiguous,
                from_host_pubkey: proj.host_pubkey_hex,
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
        let caller = self.caller()?;
        let row = self
            .db
            .confirmations()
            .get(&params.confirmation_id)
            .await?
            .ok_or(ServiceError::NotFound)?;
        // Multi-tenant isolation: the caller must be the held
        // envelope's recipient. NotFound (not Unauthorized) so
        // we don't leak the existence of another agent's queued
        // items.
        if row.recipient != caller {
            return Err(ServiceError::NotFound);
        }
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
                &caller,
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
                actor: self.host_actor.clone(),
                action: "confirmation.accept".into(),
                target: Some(row.id.clone()),
                details: Some(serde_json::json!({
                    "from": row.actor.to_string(),
                    "held_intent": row.intent.as_str(),
                })),
                client_ip: None,
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
        let caller = self.caller()?;
        let now = Timestamp::now();
        let row = self
            .db
            .confirmations()
            .get(&params.confirmation_id)
            .await?
            .ok_or(ServiceError::NotFound)?;
        if row.recipient != caller {
            return Err(ServiceError::NotFound);
        }
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
                &caller,
                now,
            )
            .await?;
        audit_or_warn(
            &*self.audit_sink,
            AuditEntry {
                id: None,
                ts: now,
                actor: self.host_actor.clone(),
                action: "confirmation.reject".into(),
                target: Some(row.id.clone()),
                details: Some(serde_json::json!({
                    "from": row.actor.to_string(),
                    "held_intent": row.intent.as_str(),
                })),
                client_ip: None,
                federation: hermod_storage::AuditFederationPolicy::Default,
            },
        )
        .await;

        Ok(ConfirmationRejectResult {
            id: params.confirmation_id,
        })
    }
}
