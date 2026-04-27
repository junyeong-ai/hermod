//! Pure helpers for the inbound pipeline — kind→intent / kind→scope
//! mapping, body-size bounds, the `FederationRejection` error type,
//! and a few small parser helpers. Free of `&self` so callers can
//! reach for them without holding an `InboundProcessor` reference;
//! tested in isolation in `inbound::tests`.

use hermod_core::{Envelope, Timestamp};

// ── Body-size bounds ───────────────────────────────────────────────
//
// Tight per-kind caps for body fields. The WS frame ceiling (256 KiB
// at the transport layer) is the outermost guard; these per-kind
// bounds are defense-in-depth so a peer running a non-cooperating
// daemon can't force us to persist enormous rows.
const MAX_INBOUND_DIRECT_TEXT_BYTES: usize = 4096;
const MAX_INBOUND_BRIEF_SUMMARY_BYTES: usize = 4096;
const MAX_INBOUND_BRIEF_TOPIC_BYTES: usize = 64;
const MAX_INBOUND_BROADCAST_TEXT_BYTES: usize = 4096;
const MAX_INBOUND_CHANNEL_NAME_BYTES: usize = 64;
const MAX_INBOUND_WORKSPACE_NAME_BYTES: usize = 64;

#[derive(Debug, thiserror::Error)]
pub enum FederationRejection {
    #[error("envelope not addressed to this daemon")]
    NotForUs,

    #[error("envelope invalid: {0}")]
    Invalid(String),

    #[error("storage: {0}")]
    Storage(String),

    #[error("envelope timestamp outside replay window (skew: {skew_ms}ms)")]
    ReplayWindow { skew_ms: i64 },

    #[error("held envelope is too old to apply (age: {age_ms}ms)")]
    StaleHeldEnvelope { age_ms: i64 },

    #[error("unauthorized: {0}")]
    Unauthorized(&'static str),

    /// No path to the recipient: this daemon is not the addressee and
    /// no broker route is known. Distinct from `Unauthorized` (which
    /// implies a permission decision) so a caller can distinguish
    /// "you're not allowed" from "I don't know where to send this".
    #[error("no route: {0}")]
    Unroutable(&'static str),

    #[error("rate-limited: {0}")]
    RateLimited(String),
}

/// Bag of borrowed fields for `accept_permission_prompt`. Pulled out
/// to keep the function below clippy's 7-argument limit and to give
/// the parameter list a self-documenting name.
pub(super) struct PermissionPromptFields<'a> {
    pub request_id: &'a str,
    pub tool_name: &'a str,
    pub description: &'a str,
    pub input_preview: &'a str,
    pub expires_at: Timestamp,
}

pub(crate) fn workspace_id_from_bytes(
    bytes: &serde_bytes::ByteBuf,
) -> Result<hermod_crypto::WorkspaceId, FederationRejection> {
    let arr: [u8; 16] = bytes
        .as_ref()
        .try_into()
        .map_err(|_| FederationRejection::Invalid("workspace_id wrong length".into()))?;
    Ok(hermod_crypto::WorkspaceId(arr))
}

pub(crate) fn validate_inbound_body_size(
    body: &hermod_core::MessageBody,
    max_file_payload_bytes: usize,
) -> Result<(), FederationRejection> {
    use hermod_core::MessageBody as B;
    let bound = |label: &'static str, len: usize, cap: usize| {
        if len > cap {
            Err(FederationRejection::Invalid(format!(
                "{label} exceeds {cap} bytes (got {len})"
            )))
        } else {
            Ok(())
        }
    };
    match body {
        B::Direct { text } => bound("Direct.text", text.len(), MAX_INBOUND_DIRECT_TEXT_BYTES)?,
        B::Brief { summary, topic } => {
            bound(
                "Brief.summary",
                summary.len(),
                MAX_INBOUND_BRIEF_SUMMARY_BYTES,
            )?;
            if let Some(t) = topic {
                bound("Brief.topic", t.len(), MAX_INBOUND_BRIEF_TOPIC_BYTES)?;
            }
        }
        B::ChannelBroadcast { text, .. } => bound(
            "ChannelBroadcast.text",
            text.len(),
            MAX_INBOUND_BROADCAST_TEXT_BYTES,
        )?,
        B::ChannelAdvertise { channel_name, .. } => bound(
            "ChannelAdvertise.channel_name",
            channel_name.len(),
            MAX_INBOUND_CHANNEL_NAME_BYTES,
        )?,
        B::WorkspaceInvite { name, .. } => bound(
            "WorkspaceInvite.name",
            name.len(),
            MAX_INBOUND_WORKSPACE_NAME_BYTES,
        )?,
        B::Presence { .. } => {}
        B::File {
            name, mime, data, ..
        } => {
            bound("File.name", name.len(), 255)?;
            bound("File.mime", mime.len(), 255)?;
            bound("File.data", data.len(), max_file_payload_bytes)?;
        }
        B::PermissionPrompt {
            request_id,
            tool_name,
            description,
            input_preview,
            ..
        } => {
            bound("PermissionPrompt.request_id", request_id.len(), 16)?;
            bound("PermissionPrompt.tool_name", tool_name.len(), 128)?;
            bound("PermissionPrompt.description", description.len(), 4096)?;
            bound("PermissionPrompt.input_preview", input_preview.len(), 1024)?;
        }
        B::PermissionResponse {
            request_id,
            behavior,
        } => {
            bound("PermissionResponse.request_id", request_id.len(), 16)?;
            bound("PermissionResponse.behavior", behavior.len(), 16)?;
        }
        B::CapabilityGrant { token, scope } => {
            bound("CapabilityGrant.token", token.len(), 4096)?;
            bound("CapabilityGrant.scope", scope.len(), 128)?;
        }
        B::AuditFederate {
            action,
            target,
            details,
            ..
        } => {
            bound("AuditFederate.action", action.len(), 128)?;
            if let Some(t) = target {
                bound("AuditFederate.target", t.len(), 256)?;
            }
            if let Some(d) = details {
                // Re-encode to bound the JSON byte size against abuse
                // (an aggregator that accepts unlimited details could
                // be DoS'd on disk). 64 KiB matches the largest
                // `details` produced by any first-party action and
                // leaves headroom for operators with custom details.
                let encoded = serde_json::to_vec(d).map_err(|e| {
                    FederationRejection::Invalid(format!("AuditFederate.details encode: {e}"))
                })?;
                bound("AuditFederate.details", encoded.len(), 64 * 1024)?;
            }
        }
        B::WorkspaceRosterRequest { workspace_id, hmac } => {
            bound("WorkspaceRosterRequest.workspace_id", workspace_id.len(), 16)?;
            if let Some(h) = hmac {
                bound("WorkspaceRosterRequest.hmac", h.len(), 32)?;
            }
        }
        B::WorkspaceRosterResponse {
            workspace_id,
            members,
            hmac,
            ..
        } => {
            bound("WorkspaceRosterResponse.workspace_id", workspace_id.len(), 16)?;
            // Cap at MAX_WORKSPACE_MEMBERS_PER_RESPONSE so a malicious
            // peer can't return a giant list. 1024 is well above any
            // realistic team size; bigger workspaces should paginate
            // (future protocol extension).
            bound("WorkspaceRosterResponse.members", members.len(), 1024)?;
            if let Some(h) = hmac {
                bound("WorkspaceRosterResponse.hmac", h.len(), 32)?;
            }
        }
        B::WorkspaceChannelsRequest { workspace_id, hmac } => {
            bound(
                "WorkspaceChannelsRequest.workspace_id",
                workspace_id.len(),
                16,
            )?;
            if let Some(h) = hmac {
                bound("WorkspaceChannelsRequest.hmac", h.len(), 32)?;
            }
        }
        B::WorkspaceChannelsResponse {
            workspace_id,
            channels,
            hmac,
            ..
        } => {
            bound(
                "WorkspaceChannelsResponse.workspace_id",
                workspace_id.len(),
                16,
            )?;
            bound("WorkspaceChannelsResponse.channels", channels.len(), 1024)?;
            for entry in channels {
                bound(
                    "WorkspaceChannelsResponse.channels[i].channel_id",
                    entry.channel_id.len(),
                    16,
                )?;
                bound(
                    "WorkspaceChannelsResponse.channels[i].name",
                    entry.name.len(),
                    128,
                )?;
            }
            if let Some(h) = hmac {
                bound("WorkspaceChannelsResponse.hmac", h.len(), 32)?;
            }
        }
    }
    Ok(())
}

/// Map a `MessageKind` to the operator-facing intent label that the
/// confirmation gate stores in `pending_confirmations.intent`. Total
/// over `MessageKind` so adding a new kind requires updating the
/// match — the compiler enforces the catalogue.
pub(crate) fn intent_for(envelope: &Envelope) -> hermod_storage::HoldedIntent {
    use hermod_core::MessageKind;
    use hermod_storage::HoldedIntent;
    match envelope.kind {
        MessageKind::Direct => HoldedIntent::DirectMessage,
        MessageKind::Brief => HoldedIntent::BriefDeliver,
        MessageKind::ChannelBroadcast => HoldedIntent::ChannelBroadcast,
        MessageKind::WorkspaceInvite => HoldedIntent::WorkspaceInvite,
        MessageKind::ChannelAdvertise => HoldedIntent::ChannelAdvertise,
        MessageKind::Presence => HoldedIntent::PresenceUpdate,
        MessageKind::File => HoldedIntent::FileDeliver,
        MessageKind::PermissionPrompt => HoldedIntent::PermissionRelay,
        MessageKind::PermissionResponse => HoldedIntent::PermissionRelayResponse,
        MessageKind::CapabilityGrant => HoldedIntent::CapabilityDeliver,
        MessageKind::AuditFederate => HoldedIntent::AuditFederate,
        MessageKind::WorkspaceRosterRequest => HoldedIntent::WorkspaceRosterRequest,
        MessageKind::WorkspaceRosterResponse => HoldedIntent::WorkspaceRosterResponse,
        MessageKind::WorkspaceChannelsRequest => HoldedIntent::WorkspaceChannelsRequest,
        MessageKind::WorkspaceChannelsResponse => HoldedIntent::WorkspaceChannelsResponse,
    }
}

/// Some inbound kinds require a valid capability regardless of
/// `policy.require_capability` — they can't be safely accepted from a
/// peer that hasn't been explicitly delegated to.
pub(crate) fn always_requires_capability(kind: hermod_core::MessageKind) -> bool {
    matches!(kind, hermod_core::MessageKind::PermissionResponse)
}

/// Authorization scope an inbound envelope of `kind` is checked against
/// when `policy.require_capability = true`. Exhaustive — adding a new
/// `MessageKind` variant must add a scope here at compile time.
pub(crate) fn scope_for(kind: hermod_core::MessageKind) -> &'static str {
    use hermod_core::MessageKind;
    match kind {
        MessageKind::Direct => hermod_routing::scope::MESSAGE_SEND,
        MessageKind::Brief => hermod_routing::scope::BRIEF_PUBLISH,
        MessageKind::ChannelBroadcast => hermod_routing::scope::CHANNEL_BROADCAST,
        MessageKind::ChannelAdvertise => hermod_routing::scope::CHANNEL_ADVERTISE,
        MessageKind::WorkspaceInvite => hermod_routing::scope::WORKSPACE_INVITE,
        MessageKind::Presence => hermod_routing::scope::PRESENCE_SET,
        MessageKind::File => hermod_routing::scope::MESSAGE_SEND,
        // PermissionPrompt / CapabilityGrant flow through the trust
        // matrix; they don't require an explicit cap (capability-
        // gating PermissionPrompt would defeat the operator-can-set-
        // up-delegation flow). PermissionResponse always requires
        // `permission:respond` — see `always_requires_capability`.
        MessageKind::PermissionPrompt => hermod_routing::scope::MESSAGE_SEND,
        MessageKind::PermissionResponse => hermod_routing::scope::PERMISSION_RESPOND,
        MessageKind::CapabilityGrant => hermod_routing::scope::MESSAGE_SEND,
        MessageKind::AuditFederate => hermod_routing::scope::AUDIT_FEDERATE,
        // Workspace observability RPCs — the workspace MAC (private) /
        // membership table (public) is the cryptographic gate.
        // `policy.require_capability` is satisfied with the
        // workspace-scoped scope so a hardened deployment can still
        // demand explicit cap delegation on top.
        MessageKind::WorkspaceRosterRequest => hermod_routing::scope::WORKSPACE_ROSTER,
        MessageKind::WorkspaceRosterResponse => hermod_routing::scope::WORKSPACE_ROSTER,
        MessageKind::WorkspaceChannelsRequest => hermod_routing::scope::WORKSPACE_CHANNELS,
        MessageKind::WorkspaceChannelsResponse => hermod_routing::scope::WORKSPACE_CHANNELS,
    }
}
