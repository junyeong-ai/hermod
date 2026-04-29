//! Operator confirmation queue contract.

use async_trait::async_trait;
use hermod_core::{AgentId, MessageId, Timestamp, TrustLevel};
use std::str::FromStr;

use crate::error::Result;

/// Soft cap on pending confirmations per actor — beyond this,
/// `enqueue` rejects so a single misbehaving peer can't fill the
/// operator's review queue and starve legitimate inbound.
pub const MAX_PENDING_PER_ACTOR: u64 = 100;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfirmationStatus {
    Pending,
    Accepted,
    Rejected,
    Expired,
}

impl ConfirmationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            ConfirmationStatus::Pending => "pending",
            ConfirmationStatus::Accepted => "accepted",
            ConfirmationStatus::Rejected => "rejected",
            ConfirmationStatus::Expired => "expired",
        }
    }
}

impl FromStr for ConfirmationStatus {
    type Err = hermod_core::HermodError;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "pending" => Ok(ConfirmationStatus::Pending),
            "accepted" => Ok(ConfirmationStatus::Accepted),
            "rejected" => Ok(ConfirmationStatus::Rejected),
            "expired" => Ok(ConfirmationStatus::Expired),
            other => Err(hermod_core::HermodError::InvalidEnvelope(format!(
                "unknown confirmation status {other:?}"
            ))),
        }
    }
}

/// What the operator would actually authorise by accepting a held
/// envelope. The pending-confirmations row stores this as a typed
/// label, not a free string — keeps the operator-facing label disjoint
/// from `audit_log.action` (which records *events*, not intents) and
/// guarantees every legal value is enumerated at compile time.
///
/// Rendered to its `as_str()` form on the wire (TOML config /
/// `hermod confirmation list` output / DB column); parsed back via
/// [`FromStr`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HoldedIntent {
    DirectMessage,
    BriefDeliver,
    ChannelBroadcast,
    ChannelAdvertise,
    WorkspaceInvite,
    PresenceUpdate,
    FileDeliver,
    PermissionRelay,
    PermissionRelayResponse,
    CapabilityDeliver,
    AuditFederate,
    WorkspaceRosterRequest,
    WorkspaceRosterResponse,
    WorkspaceChannelsRequest,
    WorkspaceChannelsResponse,
    PeerAdvertise,
}

impl HoldedIntent {
    pub fn as_str(&self) -> &'static str {
        match self {
            HoldedIntent::DirectMessage => "message.deliver",
            HoldedIntent::BriefDeliver => "brief.deliver",
            HoldedIntent::ChannelBroadcast => "broadcast.deliver",
            HoldedIntent::ChannelAdvertise => "channel.advertise",
            HoldedIntent::WorkspaceInvite => "workspace.invite",
            HoldedIntent::PresenceUpdate => "presence.deliver",
            HoldedIntent::FileDeliver => "file.deliver",
            HoldedIntent::PermissionRelay => "permission.relay",
            HoldedIntent::PermissionRelayResponse => "permission.relay.responded",
            HoldedIntent::CapabilityDeliver => "capability.deliver",
            HoldedIntent::AuditFederate => "audit.federate.received",
            HoldedIntent::WorkspaceRosterRequest => "workspace.roster.request",
            HoldedIntent::WorkspaceRosterResponse => "workspace.roster.response",
            HoldedIntent::WorkspaceChannelsRequest => "workspace.channels.request",
            HoldedIntent::WorkspaceChannelsResponse => "workspace.channels.response",
            HoldedIntent::PeerAdvertise => "peer.advertise",
        }
    }
}

impl FromStr for HoldedIntent {
    type Err = hermod_core::HermodError;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "message.deliver" => Ok(HoldedIntent::DirectMessage),
            "brief.deliver" => Ok(HoldedIntent::BriefDeliver),
            "broadcast.deliver" => Ok(HoldedIntent::ChannelBroadcast),
            "channel.advertise" => Ok(HoldedIntent::ChannelAdvertise),
            "workspace.invite" => Ok(HoldedIntent::WorkspaceInvite),
            "presence.deliver" => Ok(HoldedIntent::PresenceUpdate),
            "file.deliver" => Ok(HoldedIntent::FileDeliver),
            "permission.relay" => Ok(HoldedIntent::PermissionRelay),
            "permission.relay.responded" => Ok(HoldedIntent::PermissionRelayResponse),
            "capability.deliver" => Ok(HoldedIntent::CapabilityDeliver),
            "audit.federate.received" => Ok(HoldedIntent::AuditFederate),
            "workspace.roster.request" => Ok(HoldedIntent::WorkspaceRosterRequest),
            "workspace.roster.response" => Ok(HoldedIntent::WorkspaceRosterResponse),
            "workspace.channels.request" => Ok(HoldedIntent::WorkspaceChannelsRequest),
            "workspace.channels.response" => Ok(HoldedIntent::WorkspaceChannelsResponse),
            "peer.advertise" => Ok(HoldedIntent::PeerAdvertise),
            other => Err(hermod_core::HermodError::InvalidEnvelope(format!(
                "unknown holded intent {other:?}"
            ))),
        }
    }
}

impl std::fmt::Display for HoldedIntent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod intent_tests {
    use super::*;

    /// Every `HoldedIntent` variant. Maintained by hand because
    /// adding `strum` derive would push a transitive dep into the
    /// crate's public API; this list is short enough that a
    /// missed-variant test failure here is the canonical signal that
    /// `as_str` / `FromStr` need a new arm.
    const ALL: &[HoldedIntent] = &[
        HoldedIntent::DirectMessage,
        HoldedIntent::BriefDeliver,
        HoldedIntent::ChannelBroadcast,
        HoldedIntent::ChannelAdvertise,
        HoldedIntent::WorkspaceInvite,
        HoldedIntent::PresenceUpdate,
        HoldedIntent::FileDeliver,
        HoldedIntent::PermissionRelay,
        HoldedIntent::PermissionRelayResponse,
        HoldedIntent::CapabilityDeliver,
        HoldedIntent::AuditFederate,
        HoldedIntent::WorkspaceRosterRequest,
        HoldedIntent::WorkspaceRosterResponse,
        HoldedIntent::WorkspaceChannelsRequest,
        HoldedIntent::WorkspaceChannelsResponse,
        HoldedIntent::PeerAdvertise,
    ];

    #[test]
    fn intent_str_round_trips() {
        for &intent in ALL {
            let s = intent.as_str();
            let back = HoldedIntent::from_str(s).expect("FromStr must accept as_str()");
            assert_eq!(back, intent, "{intent:?} → {s:?} → roundtrip drift");
        }
    }

    #[test]
    fn intent_str_uniqueness() {
        // Two variants must never share an `as_str()` value — otherwise
        // a stored row's intent column would be ambiguous on read.
        let mut seen = std::collections::HashSet::new();
        for &intent in ALL {
            let s = intent.as_str();
            assert!(
                seen.insert(s),
                "duplicate as_str() representation for {intent:?}: {s:?}"
            );
        }
    }

    #[test]
    fn intent_str_shape_matches_naming_convention() {
        // Every intent is `<namespace>.<verb>` (2 components) or
        // `<namespace>.<verb>.<phase>` (3 components), all lowercase
        // snake_case. Same shape as audit actions — see
        // `docs/audit_actions.md`.
        for &intent in ALL {
            let s = intent.as_str();
            let parts: Vec<&str> = s.split('.').collect();
            assert!(
                (2..=3).contains(&parts.len()),
                "{s:?} has {} components, want 2 or 3",
                parts.len()
            );
            for p in &parts {
                assert!(
                    p.chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                    "{s:?} component {p:?} has non-snake_case chars"
                );
                assert!(!p.is_empty(), "{s:?} has an empty component");
            }
        }
    }

    #[test]
    fn intent_from_str_rejects_unknown() {
        for bad in [
            "",
            "nope",
            "message",
            ".",
            "MessageDeliver", // CamelCase is the Rust variant, not the wire form
            "message-deliver",
        ] {
            assert!(
                HoldedIntent::from_str(bad).is_err(),
                "FromStr should reject {bad:?} but accepted it"
            );
        }
    }
}

#[derive(Debug, Clone)]
pub struct PendingConfirmation {
    pub id: String,
    pub requested_at: Timestamp,
    pub actor: AgentId,
    /// Locally-hosted agent the held envelope was addressed to.
    /// Multi-tenant isolation: list/accept/reject all gate on
    /// `caller == recipient` so distinct hosted agents have
    /// independent confirmation queues.
    pub recipient: AgentId,
    pub intent: HoldedIntent,
    pub sensitivity: String,
    pub trust_level: TrustLevel,
    pub summary: String,
    pub envelope_cbor: Vec<u8>,
    pub status: ConfirmationStatus,
    pub decided_at: Option<Timestamp>,
    pub decided_by: Option<AgentId>,
}

/// Borrowed view of one envelope that the trust gate decided to hold.
#[derive(Debug, Clone, Copy)]
pub struct HoldRequest<'a> {
    pub envelope_id: &'a MessageId,
    pub actor: &'a AgentId,
    /// Locally-hosted agent the envelope was addressed to (`envelope.to.id`).
    pub recipient: &'a AgentId,
    pub intent: HoldedIntent,
    pub sensitivity: &'a str,
    pub trust_level: TrustLevel,
    pub summary: &'a str,
    pub envelope_cbor: &'a [u8],
}

#[async_trait]
pub trait ConfirmationRepository: Send + Sync + std::fmt::Debug {
    /// Hold an envelope. Returns `Some(row_id)` on a fresh insert,
    /// `None` if a previous still-pending row already covers the same
    /// envelope (sender retry — caller suppresses the duplicate audit).
    /// Returns `StorageError::QuotaExceeded` past `MAX_PENDING_PER_ACTOR`.
    async fn enqueue(&self, req: HoldRequest<'_>) -> Result<Option<String>>;

    /// `after_id` is a ULID cursor — only rows with `id > after_id`.
    /// `recipient = Some(...)` filters to one locally-hosted agent's
    /// queue (the multi-tenant isolation surface used by every IPC
    /// path); `None` returns the host-wide queue (used by janitor /
    /// `hermod doctor` + diagnostic tooling that cuts across agents).
    async fn list_pending(
        &self,
        recipient: Option<&AgentId>,
        limit: u32,
        after_id: Option<&str>,
    ) -> Result<Vec<PendingConfirmation>>;

    async fn get(&self, id: &str) -> Result<Option<PendingConfirmation>>;

    /// Mark every still-pending row whose `requested_at` is older than
    /// `cutoff_ms` as `expired`. Returns rows swept.
    async fn expire_pending_older_than(&self, cutoff_ms: i64) -> Result<u64>;

    /// Atomically transition a pending row to `new_status`. Returns true
    /// if the row was pending; false if already resolved (idempotent).
    async fn decide(
        &self,
        id: &str,
        new_status: ConfirmationStatus,
        decided_by: &AgentId,
        now: Timestamp,
    ) -> Result<bool>;
}
