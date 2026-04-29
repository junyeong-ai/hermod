//! Inbound acceptors for the federated permission relay:
//! `MessageBody::PermissionPrompt` (delegate side — operator approves
//! the prompt) and `MessageBody::PermissionResponse` (originator side
//! — the prompt's verdict travels back).

use hermod_core::{Envelope, Timestamp};
use hermod_storage::AuditEntry;

use super::InboundProcessor;
use super::scope::{FederationRejection, PermissionPromptFields};
use crate::services::audit_or_warn;

impl InboundProcessor {
    pub(super) async fn accept_permission_prompt(
        &self,
        envelope: &Envelope,
        prompt: PermissionPromptFields<'_>,
    ) -> Result<(), FederationRejection> {
        let PermissionPromptFields {
            request_id,
            tool_name,
            description,
            input_preview,
            expires_at,
        } = prompt;
        // Hand the prompt to the local PermissionService with origin
        // = Relayed. The operator's `hermod permission allow / deny
        // <id>` then runs through the same path as a local prompt; the
        // service's `respond` branches on origin and emits the
        // PermissionResponse back to `from` over federation.
        if let Some(svc) = &self.permission
            && let Err(e) = svc
                .receive_relayed(
                    envelope.from.id.clone(),
                    envelope.to.id.clone(),
                    request_id.to_string(),
                    tool_name.to_string(),
                    description.to_string(),
                    input_preview.to_string(),
                    expires_at,
                )
                .await
        {
            return Err(FederationRejection::Invalid(format!("relay receive: {e}")));
        }
        audit_or_warn(
            &*self.audit_sink,
            AuditEntry {
                id: None,
                ts: Timestamp::now(),
                actor: envelope.from.id.clone(),
                action: "permission.relay.observed".into(),
                target: Some(self.host_actor.to_string()),
                details: Some(serde_json::json!({
                    "envelope_id": envelope.id.to_string(),
                    "request_id": request_id,
                    "tool_name": tool_name,
                    "description": description,
                    "input_preview": input_preview,
                    "expires_at": expires_at,
                })),
                client_ip: None,
                federation: hermod_storage::AuditFederationPolicy::Default,
            },
        )
        .await;
        Ok(())
    }

    pub(super) async fn accept_permission_response(
        &self,
        envelope: &Envelope,
        request_id: &str,
        behavior: &str,
    ) -> Result<(), FederationRejection> {
        // Parse the wire `behavior` into the typed enum. An unknown
        // value is a malformed envelope from a non-cooperating sender;
        // reject so the operator's audit shows the rejection rather
        // than silently no-op'ing.
        let typed = match behavior {
            "allow" => hermod_protocol::ipc::methods::PermissionBehavior::Allow,
            "deny" => hermod_protocol::ipc::methods::PermissionBehavior::Deny,
            other => {
                return Err(FederationRejection::Invalid(format!(
                    "PermissionResponse.behavior `{other}` is not allow|deny"
                )));
            }
        };

        // Hand the verdict to the local PermissionService so the MCP
        // verdict cursor sees the resolution and emits the
        // `notifications/claude/channel/permission` frame back to
        // Claude Code. Idempotent — if the local operator already
        // answered (race), `matched=false` and the audit row notes the
        // late arrival.
        let matched = if let Some(svc) = &self.permission {
            svc.apply_relayed_verdict(request_id.to_string(), typed, envelope.from.id.clone())
                .await
                .map_err(|e| FederationRejection::Invalid(format!("relay verdict apply: {e}")))?
        } else {
            false
        };

        audit_or_warn(
            &*self.audit_sink,
            AuditEntry {
                id: None,
                ts: Timestamp::now(),
                actor: envelope.from.id.clone(),
                action: "permission.relay.responded".into(),
                target: Some(self.host_actor.to_string()),
                details: Some(serde_json::json!({
                    "envelope_id": envelope.id.to_string(),
                    "request_id": request_id,
                    "behavior": behavior,
                    "matched": matched,
                })),
                client_ip: None,
                federation: hermod_storage::AuditFederationPolicy::Default,
            },
        )
        .await;
        Ok(())
    }
}
