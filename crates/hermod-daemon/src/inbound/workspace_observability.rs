//! Inbound acceptors for the workspace-observability gossip RPCs:
//! `WorkspaceRosterRequest` / `WorkspaceRosterResponse` and the
//! channels equivalent. Both pairs run on the cryptographic gate of
//! the workspace MAC (private workspaces) or the local membership
//! table (public workspaces); the heavy lifting is in
//! [`crate::services::workspace_observability`] — these handlers just
//! authorise the inbound envelope and dispatch into that service.

use hermod_core::{AgentId, Envelope, Timestamp, TrustLevel};

use super::InboundProcessor;
use super::scope::{FederationRejection, workspace_id_from_bytes};

impl InboundProcessor {
    pub(super) async fn accept_workspace_roster_request(
        &self,
        envelope: &Envelope,
        workspace_id: &serde_bytes::ByteBuf,
        hmac: Option<&[u8]>,
    ) -> Result<(), FederationRejection> {
        let svc = self.observability.as_ref().ok_or_else(|| {
            FederationRejection::Storage("workspace observability not wired".into())
        })?;
        svc.authorise(
            &envelope.from.id,
            &workspace_id_from_bytes(workspace_id)?,
            workspace_id,
            hmac,
        )
        .await
        .map_err(FederationRejection::Unauthorized)?;
        svc.handle_roster_request(&envelope.from.id, envelope.id, workspace_id)
            .await
            .map_err(|e| FederationRejection::Storage(e.to_string()))
    }

    pub(super) async fn accept_workspace_roster_response(
        &self,
        envelope: &Envelope,
        request_id: &hermod_core::MessageId,
        workspace_id: &serde_bytes::ByteBuf,
        members: &[hermod_core::RosterMember],
        hmac: Option<&[u8]>,
    ) -> Result<(), FederationRejection> {
        let svc = self.observability.as_ref().ok_or_else(|| {
            FederationRejection::Storage("workspace observability not wired".into())
        })?;
        let ws_id = workspace_id_from_bytes(workspace_id)?;
        // Authorise by re-checking the workspace MAC over the response
        // payload (or member-table fallback for public).
        let workspace = self
            .db
            .workspaces()
            .get(&ws_id)
            .await
            .map_err(|e| FederationRejection::Storage(e.to_string()))?
            .ok_or(FederationRejection::Unauthorized("unknown workspace"))?;

        // Reject any entry whose pubkey does not bind to its
        // agent_id. The responder cannot lie about another member's
        // identity — `agent_id == blake3(pubkey)[:26]` is
        // self-certifying.
        for m in members {
            if hermod_crypto::agent_id_from_pubkey(&m.pubkey).as_str() != m.id.as_str() {
                return Err(FederationRejection::Unauthorized(
                    "roster entry id-pubkey binding violation",
                ));
            }
        }

        let mut sorted = members.to_vec();
        sorted.sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));
        if !crate::services::workspace_observability::verify_roster_response_mac(
            workspace.secret.as_ref(),
            workspace_id.as_ref(),
            &sorted,
            hmac,
        ) {
            // Public workspace: accept only if responder is a known member.
            if workspace.secret.is_none() {
                let known = self
                    .db
                    .workspace_members()
                    .list(&ws_id)
                    .await
                    .map_err(|e| FederationRejection::Storage(e.to_string()))?;
                if !known.iter().any(|m| m == &envelope.from.id) {
                    return Err(FederationRejection::Unauthorized(
                        "public workspace: unknown responder",
                    ));
                }
            } else {
                return Err(FederationRejection::Unauthorized("roster mac mismatch"));
            }
        }

        // Auto-upsert each member's pubkey into the local agents
        // directory. The receiver now learns the entire roster's
        // identities at once — no per-member out-of-band exchange.
        let now = Timestamp::now();
        for m in &sorted {
            if m.id.as_str() == self.self_id.as_str() {
                continue;
            }
            self.db
                .agents()
                .upsert_observed(&hermod_storage::AgentRecord {
                    id: m.id.clone(),
                    pubkey: m.pubkey,
                    host_pubkey: None,
                    endpoint: None,
                    local_alias: None,
                    peer_asserted_alias: None,
                    trust_level: TrustLevel::Tofu,
                    tls_fingerprint: None,
                    reputation: 0,
                    first_seen: now,
                    last_seen: Some(now),
                })
                .await
                .map_err(|e| FederationRejection::Storage(e.to_string()))?;
        }

        let ids: Vec<AgentId> = sorted.iter().map(|m| m.id.clone()).collect();
        svc.deliver_roster_response(envelope.from.id.clone(), *request_id, ids)
            .await;
        Ok(())
    }

    pub(super) async fn accept_workspace_channels_request(
        &self,
        envelope: &Envelope,
        workspace_id: &serde_bytes::ByteBuf,
        hmac: Option<&[u8]>,
    ) -> Result<(), FederationRejection> {
        let svc = self.observability.as_ref().ok_or_else(|| {
            FederationRejection::Storage("workspace observability not wired".into())
        })?;
        svc.authorise(
            &envelope.from.id,
            &workspace_id_from_bytes(workspace_id)?,
            workspace_id,
            hmac,
        )
        .await
        .map_err(FederationRejection::Unauthorized)?;
        svc.handle_channels_request(&envelope.from.id, envelope.id, workspace_id)
            .await
            .map_err(|e| FederationRejection::Storage(e.to_string()))
    }

    pub(super) async fn accept_workspace_channels_response(
        &self,
        envelope: &Envelope,
        request_id: &hermod_core::MessageId,
        workspace_id: &serde_bytes::ByteBuf,
        channels: &[hermod_core::WorkspaceChannelEntry],
        hmac: Option<&[u8]>,
    ) -> Result<(), FederationRejection> {
        let svc = self.observability.as_ref().ok_or_else(|| {
            FederationRejection::Storage("workspace observability not wired".into())
        })?;
        let ws_id = workspace_id_from_bytes(workspace_id)?;
        let workspace = self
            .db
            .workspaces()
            .get(&ws_id)
            .await
            .map_err(|e| FederationRejection::Storage(e.to_string()))?
            .ok_or(FederationRejection::Unauthorized("unknown workspace"))?;
        let mut sorted = channels.to_vec();
        sorted.sort_by(|a, b| a.channel_id.as_ref().cmp(b.channel_id.as_ref()));
        if !crate::services::workspace_observability::verify_channels_response_mac(
            workspace.secret.as_ref(),
            workspace_id.as_ref(),
            &sorted,
            hmac,
        ) {
            if workspace.secret.is_none() {
                let known = self
                    .db
                    .workspace_members()
                    .list(&ws_id)
                    .await
                    .map_err(|e| FederationRejection::Storage(e.to_string()))?;
                if !known.iter().any(|m| m == &envelope.from.id) {
                    return Err(FederationRejection::Unauthorized(
                        "public workspace: unknown responder",
                    ));
                }
            } else {
                return Err(FederationRejection::Unauthorized("channels mac mismatch"));
            }
        }
        svc.deliver_channels_response(envelope.from.id.clone(), *request_id, sorted)
            .await;
        Ok(())
    }
}
