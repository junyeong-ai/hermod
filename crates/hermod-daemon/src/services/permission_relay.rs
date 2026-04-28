//! Production trait implementations for the permission relay
//! callbacks declared in [`crate::services::permission`].
//!
//! Two structs:
//!   * [`MessageRelayResponder`] — answers `RelayResponder::respond`
//!     by shipping a `PermissionResponse` envelope back to the
//!     federated originator. Pulls the issuer-granted
//!     `permission:respond` capability from the audience-side
//!     `capabilities` table so the outbound envelope passes the
//!     originator's strict-mode capability check.
//!   * [`CapabilityPromptForwarder`] — answers `PromptForwarder::forward`
//!     by reading the active `permission:respond` audience set from
//!     the issuer-side `capabilities` table and shipping one
//!     `PermissionPrompt` envelope per delegate. Transport failures to
//!     individual delegates are best-effort; the operator's local
//!     prompt remains live regardless.
//!
//! Both impls hold `Arc<dyn Database>` + a clone of `MessageService`,
//! which is what the closure-based callers held internally — the
//! refactor is type-shape only, behaviour is identical.

use async_trait::async_trait;
use hermod_core::{
    AgentAddress, AgentId, CapabilityToken, MessageBody, MessagePriority, Timestamp,
};
use hermod_protocol::ipc::methods::{MessageSendParams, PermissionBehavior};
use hermod_storage::Database;
use std::sync::Arc;

use crate::services::ServiceError;
use crate::services::message::MessageService;
use crate::services::permission::{PromptForwardPayload, PromptForwarder, RelayResponder};

/// Ships verdicts back to the originating peer via `MessageService`.
#[derive(Clone)]
pub struct MessageRelayResponder {
    db: Arc<dyn Database>,
    messages: MessageService,
}

impl std::fmt::Debug for MessageRelayResponder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MessageRelayResponder")
            .finish_non_exhaustive()
    }
}

impl MessageRelayResponder {
    pub fn new(db: Arc<dyn Database>, messages: MessageService) -> Self {
        Self { db, messages }
    }
}

#[async_trait]
impl RelayResponder for MessageRelayResponder {
    async fn respond(
        &self,
        to: AgentId,
        request_id: String,
        behavior: PermissionBehavior,
    ) -> Result<(), ServiceError> {
        let agent = self
            .db
            .agents()
            .get(&to)
            .await?
            .ok_or(ServiceError::NotFound)?;
        let to_addr = match agent.endpoint {
            Some(ep) => AgentAddress::with_endpoint(agent.id, ep),
            None => AgentAddress::local(agent.id),
        };

        // Pull the cap the originator granted us so the outbound
        // envelope passes their strict-mode capability check.
        // Missing-cap is a hard error — operator delegation never
        // happened.
        let cap_record = self
            .db
            .capabilities()
            .find_active_received(
                &to,
                hermod_routing::scope::PERMISSION_RESPOND,
                Timestamp::now().unix_ms(),
            )
            .await?
            .ok_or_else(|| {
                ServiceError::InvalidParam(format!(
                    "no active `permission:respond` capability from `{to}`; \
                     cannot ship verdict (was the delegation revoked or expired?)"
                ))
            })?;
        let cap_token = CapabilityToken::from_bytes(cap_record.raw_token);

        let params = MessageSendParams {
            to: to_addr,
            body: MessageBody::PermissionResponse {
                request_id,
                behavior: behavior.as_str().to_string(),
            },
            priority: Some(MessagePriority::High),
            thread: None,
            ttl_secs: Some(60),
            caps: Some(vec![cap_token]),
        };
        self.messages.send(params).await.map(|_| ())
    }
}

/// Fans a freshly-opened local prompt out to every active
/// `permission:respond` delegate.
#[derive(Clone)]
pub struct CapabilityPromptForwarder {
    db: Arc<dyn Database>,
    messages: MessageService,
    self_id: AgentId,
}

impl std::fmt::Debug for CapabilityPromptForwarder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CapabilityPromptForwarder")
            .field("self_id", &self.self_id)
            .finish_non_exhaustive()
    }
}

impl CapabilityPromptForwarder {
    pub fn new(db: Arc<dyn Database>, messages: MessageService, self_id: AgentId) -> Self {
        Self {
            db,
            messages,
            self_id,
        }
    }
}

#[async_trait]
impl PromptForwarder for CapabilityPromptForwarder {
    async fn forward(&self, payload: PromptForwardPayload) -> Result<u32, ServiceError> {
        let now_ms = Timestamp::now().unix_ms();
        let audience_ids = self
            .db
            .capabilities()
            .active_audiences_for_scope(
                &self.self_id,
                hermod_routing::scope::PERMISSION_RESPOND,
                now_ms,
            )
            .await?;
        let mut reach: u32 = 0;
        for audience_id in audience_ids {
            let agent = match self.db.agents().get(&audience_id).await {
                Ok(Some(a)) => a,
                _ => continue,
            };
            let to_addr = match agent.endpoint {
                Some(ep) => AgentAddress::with_endpoint(agent.id, ep),
                None => AgentAddress::local(agent.id),
            };
            let params = MessageSendParams {
                to: to_addr,
                body: MessageBody::PermissionPrompt {
                    request_id: payload.request_id.clone(),
                    tool_name: payload.tool_name.clone(),
                    description: payload.description.clone(),
                    input_preview: payload.input_preview.clone(),
                    expires_at: payload.expires_at,
                },
                priority: Some(MessagePriority::High),
                thread: None,
                ttl_secs: Some(60),
                caps: None,
            };
            if self.messages.send(params).await.is_ok() {
                reach = reach.saturating_add(1);
            }
        }
        Ok(reach)
    }
}
