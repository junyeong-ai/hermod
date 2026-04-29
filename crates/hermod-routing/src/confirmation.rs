//! Inbound confirmation gate.
//!
//! Inputs: peer trust level (already on `agents.trust_level`) + action
//! sensitivity (computed from the envelope body kind). Output: one of three
//! verdicts that the federation listener acts on.
//!
//! ```text
//!                     │ routine │ review  │ sensitive │
//! ────────────────────┼─────────┼─────────┼───────────┤
//!  Self               │ accept  │ accept  │ accept    │
//!  Verified           │ accept  │ accept  │ confirm   │
//!  Tofu               │ accept  │ confirm │ confirm   │
//!  Untrusted          │ accept  │ confirm │ reject    │
//! ```
//!
//! "Self" only applies on local-loopback paths; all federation traffic comes
//! from at most Verified.
//!
//! See `docs/confirmation.md` for the rationale per cell.

use hermod_core::{Envelope, MessageBody, TrustLevel};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Sensitivity {
    /// Informational — short signals that don't grant capabilities or write
    /// human-visible content into the inbox.
    Routine,
    /// Human-visible content (DMs). The operator should glance at it before
    /// it appears in their inbox feed.
    Review,
    /// Anything that imports authority or fresh secrets into our store —
    /// currently just `WorkspaceInvite`, which hands us a 32-byte channel
    /// secret granting full read/forge over the workspace's channels.
    Sensitive,
}

impl Sensitivity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Sensitivity::Routine => "routine",
            Sensitivity::Review => "review",
            Sensitivity::Sensitive => "sensitive",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Apply the action immediately.
    Accept,
    /// Park the envelope; surface to the operator for explicit accept/reject.
    Confirm,
    /// Drop the action without further processing.
    Reject,
}

/// Classify an envelope by content kind.
pub fn classify(envelope: &Envelope) -> Sensitivity {
    match &envelope.body {
        // Group MAC + workspace membership already gate this; landing in the
        // channel feed isn't more sensitive than a presence ping.
        MessageBody::ChannelBroadcast { .. } => Sensitivity::Routine,
        MessageBody::ChannelAdvertise { .. } => Sensitivity::Routine,
        MessageBody::Brief { .. } => Sensitivity::Routine,
        MessageBody::Presence { .. } => Sensitivity::Routine,
        // PermissionResponse is verdict traffic from a delegate the
        // operator already trusted (capability check is the real gate).
        // No need to surface to confirmation queue.
        MessageBody::PermissionResponse { .. } => Sensitivity::Routine,
        // DMs land in the operator's inbox in human-readable form. Hold for
        // review when trust is uncertain.
        MessageBody::Direct { .. } => Sensitivity::Review,
        // File payloads carry user-visible content (and bytes that a
        // sandbox might execute). Treat exactly like a DM under the
        // trust matrix — Verified+ accept, Tofu/Untrusted hold for
        // operator review.
        MessageBody::File { .. } => Sensitivity::Review,
        // PermissionPrompt forwarded by an originator we trust enough
        // to delegate. Trusted-peer prompts land in the operator's
        // queue immediately; TOFU/Untrusted prompts are held — a peer
        // we don't know yet shouldn't be able to spam our prompt UI.
        MessageBody::PermissionPrompt { .. } => Sensitivity::Review,
        // WorkspaceInvite always asks: accepting imports a fresh 32-byte
        // secret into our store, granting full read/forge over its channels.
        MessageBody::WorkspaceInvite { .. } => Sensitivity::Sensitive,
        // CapabilityGrant imports new authority into our local store —
        // same risk profile as WorkspaceInvite. Hold for unfamiliar
        // peers; trusted+ peers auto-import.
        MessageBody::CapabilityGrant { .. } => Sensitivity::Sensitive,
        // AuditFederate carries an audit-row payload the sender wants
        // mirrored into our hash-chained log. The trust gate is the
        // operator's `[audit] accept_federation` opt-in, not the
        // confirmation queue — a daemon that hasn't opted in rejects
        // the envelope outright (in inbound.rs). When opted in, audit
        // shipping is bulk traffic; per-envelope confirmation prompts
        // would be impractical and Verified+ peer signing already
        // bounds the abuse surface.
        MessageBody::AuditFederate { .. } => Sensitivity::Routine,
        // Workspace roster + channel-list RPCs. Auth gate is the
        // workspace MAC (private) or the responder's
        // `workspace_members` table (public) — verified at apply
        // time in inbound.rs. Per-envelope confirmation prompts on
        // members querying members would be infinite friction; the
        // membership proof is the trust gate.
        MessageBody::WorkspaceRosterRequest { .. } => Sensitivity::Routine,
        MessageBody::WorkspaceRosterResponse { .. } => Sensitivity::Routine,
        MessageBody::WorkspaceChannelsRequest { .. } => Sensitivity::Routine,
        MessageBody::WorkspaceChannelsResponse { .. } => Sensitivity::Routine,
    }
}

/// The 4 × 3 decision matrix. Pure function — no I/O.
pub fn decide(trust: TrustLevel, sensitivity: Sensitivity) -> Verdict {
    use Sensitivity::*;
    use TrustLevel::*;
    use Verdict::*;
    match (trust, sensitivity) {
        (Local, _) => Accept,
        (Verified, Sensitive) => Confirm,
        (Verified, _) => Accept,
        (Tofu, Routine) => Accept,
        (Tofu, _) => Confirm,
        (Untrusted, Routine) => Accept,
        (Untrusted, Review) => Confirm,
        (Untrusted, Sensitive) => Reject,
    }
}

/// Short human-readable summary for the confirmation queue listing.
pub fn summarize(envelope: &Envelope) -> String {
    match &envelope.body {
        MessageBody::Direct { text } => {
            let trimmed = truncate(text, 80);
            format!("DM from {}: {trimmed}", envelope.from.id)
        }
        MessageBody::Brief { summary, topic } => match topic {
            Some(t) => format!(
                "brief[{t}] from {}: {}",
                envelope.from.id,
                truncate(summary, 80)
            ),
            None => format!("brief from {}: {}", envelope.from.id, truncate(summary, 80)),
        },
        MessageBody::ChannelBroadcast { text, .. } => {
            format!(
                "broadcast from {}: {}",
                envelope.from.id,
                truncate(text, 80)
            )
        }
        MessageBody::ChannelAdvertise {
            channel_name,
            workspace_id,
            ..
        } => format!(
            "channel advertise from {}: {} in workspace {}",
            envelope.from.id,
            channel_name,
            hex::encode(workspace_id),
        ),
        MessageBody::WorkspaceInvite { name, .. } => format!(
            "workspace invite from {} to join {:?}",
            envelope.from.id, name
        ),
        MessageBody::Presence {
            manual_status,
            live,
        } => {
            let label = match (manual_status, live) {
                (Some(s), _) => s.as_str(),
                (None, true) => "online",
                (None, false) => "offline",
            };
            format!("presence update from {}: {label}", envelope.from.id)
        }
        MessageBody::File {
            name, mime, data, ..
        } => format!(
            "file from {}: {name} ({}, {} bytes)",
            envelope.from.id,
            if mime.is_empty() {
                "application/octet-stream"
            } else {
                mime.as_str()
            },
            data.len()
        ),
        MessageBody::PermissionPrompt {
            tool_name,
            description,
            ..
        } => format!(
            "permission relay from {}: {tool_name} — {description}",
            envelope.from.id
        ),
        MessageBody::PermissionResponse {
            request_id,
            behavior,
        } => format!(
            "permission verdict from {}: {behavior} {request_id}",
            envelope.from.id
        ),
        MessageBody::CapabilityGrant { scope, .. } => format!(
            "capability grant from {}: scope `{scope}`",
            envelope.from.id
        ),
        MessageBody::AuditFederate { action, .. } => {
            format!("audit federation from {}: {action}", envelope.from.id)
        }
        MessageBody::WorkspaceRosterRequest { workspace_id, .. } => format!(
            "workspace roster request from {}: workspace {}",
            envelope.from.id,
            hex::encode(workspace_id),
        ),
        MessageBody::WorkspaceRosterResponse {
            workspace_id,
            members,
            ..
        } => format!(
            "workspace roster response from {}: workspace {} ({} members)",
            envelope.from.id,
            hex::encode(workspace_id),
            members.len(),
        ),
        MessageBody::WorkspaceChannelsRequest { workspace_id, .. } => format!(
            "workspace channels request from {}: workspace {}",
            envelope.from.id,
            hex::encode(workspace_id),
        ),
        MessageBody::WorkspaceChannelsResponse {
            workspace_id,
            channels,
            ..
        } => format!(
            "workspace channels response from {}: workspace {} ({} channels)",
            envelope.from.id,
            hex::encode(workspace_id),
            channels.len(),
        ),
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        let mut end = max;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…", &s[..end])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matrix_is_total() {
        let trusts = [
            TrustLevel::Local,
            TrustLevel::Verified,
            TrustLevel::Tofu,
            TrustLevel::Untrusted,
        ];
        let sensitivities = [
            Sensitivity::Routine,
            Sensitivity::Review,
            Sensitivity::Sensitive,
        ];
        for t in trusts {
            for s in sensitivities {
                let _ = decide(t, s);
            }
        }
    }

    #[test]
    fn untrusted_sensitive_rejects() {
        assert_eq!(
            decide(TrustLevel::Untrusted, Sensitivity::Sensitive),
            Verdict::Reject
        );
    }

    #[test]
    fn local_always_accepts() {
        for s in [
            Sensitivity::Routine,
            Sensitivity::Review,
            Sensitivity::Sensitive,
        ] {
            assert_eq!(decide(TrustLevel::Local, s), Verdict::Accept);
        }
    }

    #[test]
    fn verified_routine_accepts_sensitive_confirms() {
        assert_eq!(
            decide(TrustLevel::Verified, Sensitivity::Routine),
            Verdict::Accept
        );
        assert_eq!(
            decide(TrustLevel::Verified, Sensitivity::Sensitive),
            Verdict::Confirm
        );
    }

    #[test]
    fn tofu_review_confirms() {
        assert_eq!(
            decide(TrustLevel::Tofu, Sensitivity::Review),
            Verdict::Confirm
        );
    }
}
