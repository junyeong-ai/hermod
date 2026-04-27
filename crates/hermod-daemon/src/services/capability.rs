use hermod_core::{AgentId, CapabilityToken, MessageBody, MessagePriority, Timestamp};
use hermod_crypto::{CAPABILITY_VERSION, CapabilityClaim, Signer};
use hermod_protocol::ipc::methods::{
    CapabilityDeliverParams, CapabilityDeliverResult, CapabilityIssueParams, CapabilityIssueResult,
    CapabilityListParams, CapabilityListResult, CapabilityRevokeParams, CapabilityRevokeResult,
    CapabilityView, MessageSendParams,
};
use hermod_storage::{AuditEntry, AuditSink, CapabilityFilter, CapabilityRecord, Database};
use serde_bytes::ByteBuf;
use std::sync::{Arc, OnceLock};

const DEFAULT_LIST_LIMIT: u32 = 100;
const MAX_LIST_LIMIT: u32 = 500;

use crate::services::{MessageService, ServiceError, audit_or_warn};

#[derive(Clone)]
pub struct CapabilityService {
    db: Arc<dyn Database>,
    audit_sink: Arc<dyn AuditSink>,
    signer: Arc<dyn Signer>,
    self_id: AgentId,
    /// Set once at daemon startup (after MessageService exists) so
    /// `deliver` can ship a `CapabilityGrant` envelope to the
    /// audience. `OnceLock` because the wiring is single-shot and
    /// must outlive every `CapabilityService::clone`.
    messages: Arc<OnceLock<MessageService>>,
}

impl std::fmt::Debug for CapabilityService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CapabilityService")
            .field("self_id", &self.self_id)
            .finish_non_exhaustive()
    }
}

impl CapabilityService {
    pub fn new(
        db: Arc<dyn Database>,
        audit_sink: Arc<dyn AuditSink>,
        signer: Arc<dyn Signer>,
    ) -> Self {
        let self_id = signer.agent_id();
        Self {
            db,
            audit_sink,
            signer,
            self_id,
            messages: Arc::new(OnceLock::new()),
        }
    }

    /// Wire the MessageService used by [`Self::deliver`]. Call once
    /// at daemon construction; later calls are silently no-op.
    pub fn set_message_service(&self, messages: MessageService) {
        let _ = self.messages.set(messages);
    }

    pub async fn issue(
        &self,
        params: CapabilityIssueParams,
    ) -> Result<CapabilityIssueResult, ServiceError> {
        let now_ms = Timestamp::now().unix_ms();
        let exp = params
            .expires_in_secs
            .map(|s| now_ms + (s as i64).saturating_mul(1000));
        let aud = params.audience;
        let jti = ulid::Ulid::new().to_string();
        let claim = CapabilityClaim {
            v: CAPABILITY_VERSION,
            iss: self.self_id.clone(),
            aud,
            scope: params.scope.clone(),
            target: params.target.clone(),
            iat: now_ms,
            exp,
            jti: jti.clone(),
        };
        let token_bytes = self
            .signer
            .sign_capability(&claim)
            .await
            .map_err(ServiceError::Crypto)?;

        let record = CapabilityRecord {
            id: jti.clone(),
            issuer: self.self_id.clone(),
            audience: claim.aud.clone(),
            scope: claim.scope.clone(),
            target: claim.target.clone(),
            expires_at: claim.exp.and_then(|ms| Timestamp::from_unix_ms(ms).ok()),
            revoked_at: None,
            raw_token: token_bytes.clone(),
        };
        self.db.capabilities().upsert(&record).await?;

        audit_or_warn(&*self.audit_sink,
            AuditEntry {
                id: None,
                ts: Timestamp::now(),
                actor: self.self_id.clone(),
                action: "capability.issue".into(),
                target: Some(jti.clone()),
                details: Some(serde_json::json!({
                    "scope": claim.scope,
                    "audience": claim.aud.as_ref().map(|a| a.to_string()),
                    "scope_target": claim.target,
                    "exp": claim.exp,
                })),
                federation: hermod_storage::AuditFederationPolicy::Default,
            },
        )
        .await;

        Ok(CapabilityIssueResult {
            token: CapabilityToken::from_bytes(token_bytes),
            id: jti,
        })
    }

    /// Issue a fresh capability and deliver it to the audience by
    /// envelope (`CapabilityGrant`). Combines `capability.issue` +
    /// `message.send` so the operator's CLI has a one-shot
    /// "delegate <agent>" flow.
    pub async fn deliver(
        &self,
        params: CapabilityDeliverParams,
    ) -> Result<CapabilityDeliverResult, ServiceError> {
        let messages = self
            .messages
            .get()
            .ok_or_else(|| {
                ServiceError::InvalidParam(
                    "capability deliver attempted before MessageService was wired".into(),
                )
            })?;

        // 1. Issue under the existing path so the audit + storage
        //    side-effects mirror a regular `capability.issue`.
        let issue_result = self
            .issue(CapabilityIssueParams {
                audience: Some(params.audience.id.clone()),
                scope: params.scope.clone(),
                target: params.scope_target.clone(),
                expires_in_secs: params.exp_secs.map(|s| s.max(0) as u64),
            })
            .await?;

        // 2. Wrap the token in a `CapabilityGrant` envelope and ship.
        let token_bytes = issue_result.token.as_bytes().to_vec();
        let send = messages
            .send(MessageSendParams {
                to: params.audience.clone(),
                body: MessageBody::CapabilityGrant {
                    token: ByteBuf::from(token_bytes),
                    scope: params.scope.clone(),
                },
                priority: Some(MessagePriority::High),
                thread: None,
                ttl_secs: Some(300),
                caps: None,
            })
            .await?;

        audit_or_warn(&*self.audit_sink,
            AuditEntry {
                id: None,
                ts: Timestamp::now(),
                actor: self.self_id.clone(),
                action: "capability.deliver".into(),
                target: Some(params.audience.id.to_string()),
                details: Some(serde_json::json!({
                    "scope": params.scope,
                    "jti": issue_result.id,
                    "envelope_id": send.id.to_string(),
                })),
                federation: hermod_storage::AuditFederationPolicy::Default,
            },
        )
        .await;

        Ok(CapabilityDeliverResult {
            jti: issue_result.id,
            envelope_id: send.id,
        })
    }

    pub async fn revoke(
        &self,
        params: CapabilityRevokeParams,
    ) -> Result<CapabilityRevokeResult, ServiceError> {
        let now = Timestamp::now();
        let revoked = self.db.capabilities().revoke(&params.token_id, now).await?;
        if revoked {
            audit_or_warn(&*self.audit_sink,
                AuditEntry {
                    id: None,
                    ts: now,
                    actor: self.self_id.clone(),
                    action: "capability.revoke".into(),
                    target: Some(params.token_id.clone()),
                    details: None,
                    federation: hermod_storage::AuditFederationPolicy::Default,
                },
            )
            .await;
        }
        Ok(CapabilityRevokeResult { revoked })
    }

    pub async fn list(
        &self,
        params: CapabilityListParams,
    ) -> Result<CapabilityListResult, ServiceError> {
        let limit = params
            .limit
            .unwrap_or(DEFAULT_LIST_LIMIT)
            .min(MAX_LIST_LIMIT);
        // Default direction is Issued — preserves the long-standing
        // "what did I grant?" view for unparam'd `capability list`.
        let direction = params
            .direction
            .unwrap_or(hermod_core::CapabilityDirection::Issued);
        let filter = CapabilityFilter {
            include_revoked: params.include_revoked,
            include_expired: params.include_expired,
            limit: Some(limit),
            after_id: params.after_id,
            direction: Some(direction),
        };
        let now_ms = Timestamp::now().unix_ms();
        let rows = self
            .db
            .capabilities()
            .list(&self.self_id, now_ms, &filter)
            .await?;
        let capabilities = rows
            .into_iter()
            .map(|r| CapabilityView {
                id: r.id,
                issuer: r.issuer,
                audience: r.audience,
                scope: r.scope,
                target: r.target,
                expires_at: r.expires_at,
                revoked_at: r.revoked_at,
            })
            .collect();
        Ok(CapabilityListResult {
            capabilities,
            direction,
        })
    }
}
