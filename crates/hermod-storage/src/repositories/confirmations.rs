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
pub enum HeldIntent {
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

impl HeldIntent {
    pub fn as_str(&self) -> &'static str {
        match self {
            HeldIntent::DirectMessage => "message.deliver",
            HeldIntent::BriefDeliver => "brief.deliver",
            HeldIntent::ChannelBroadcast => "broadcast.deliver",
            HeldIntent::ChannelAdvertise => "channel.advertise",
            HeldIntent::WorkspaceInvite => "workspace.invite",
            HeldIntent::PresenceUpdate => "presence.deliver",
            HeldIntent::FileDeliver => "file.deliver",
            HeldIntent::PermissionRelay => "permission.relay",
            HeldIntent::PermissionRelayResponse => "permission.relay.responded",
            HeldIntent::CapabilityDeliver => "capability.deliver",
            HeldIntent::AuditFederate => "audit.federate.received",
            HeldIntent::WorkspaceRosterRequest => "workspace.roster.request",
            HeldIntent::WorkspaceRosterResponse => "workspace.roster.response",
            HeldIntent::WorkspaceChannelsRequest => "workspace.channels.request",
            HeldIntent::WorkspaceChannelsResponse => "workspace.channels.response",
            HeldIntent::PeerAdvertise => "peer.advertise",
        }
    }
}

impl FromStr for HeldIntent {
    type Err = hermod_core::HermodError;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "message.deliver" => Ok(HeldIntent::DirectMessage),
            "brief.deliver" => Ok(HeldIntent::BriefDeliver),
            "broadcast.deliver" => Ok(HeldIntent::ChannelBroadcast),
            "channel.advertise" => Ok(HeldIntent::ChannelAdvertise),
            "workspace.invite" => Ok(HeldIntent::WorkspaceInvite),
            "presence.deliver" => Ok(HeldIntent::PresenceUpdate),
            "file.deliver" => Ok(HeldIntent::FileDeliver),
            "permission.relay" => Ok(HeldIntent::PermissionRelay),
            "permission.relay.responded" => Ok(HeldIntent::PermissionRelayResponse),
            "capability.deliver" => Ok(HeldIntent::CapabilityDeliver),
            "audit.federate.received" => Ok(HeldIntent::AuditFederate),
            "workspace.roster.request" => Ok(HeldIntent::WorkspaceRosterRequest),
            "workspace.roster.response" => Ok(HeldIntent::WorkspaceRosterResponse),
            "workspace.channels.request" => Ok(HeldIntent::WorkspaceChannelsRequest),
            "workspace.channels.response" => Ok(HeldIntent::WorkspaceChannelsResponse),
            "peer.advertise" => Ok(HeldIntent::PeerAdvertise),
            other => Err(hermod_core::HermodError::InvalidEnvelope(format!(
                "unknown held intent {other:?}"
            ))),
        }
    }
}

impl std::fmt::Display for HeldIntent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod intent_tests {
    use super::*;

    /// Every `HeldIntent` variant. Maintained by hand because
    /// adding `strum` derive would push a transitive dep into the
    /// crate's public API; this list is short enough that a
    /// missed-variant test failure here is the canonical signal that
    /// `as_str` / `FromStr` need a new arm.
    const ALL: &[HeldIntent] = &[
        HeldIntent::DirectMessage,
        HeldIntent::BriefDeliver,
        HeldIntent::ChannelBroadcast,
        HeldIntent::ChannelAdvertise,
        HeldIntent::WorkspaceInvite,
        HeldIntent::PresenceUpdate,
        HeldIntent::FileDeliver,
        HeldIntent::PermissionRelay,
        HeldIntent::PermissionRelayResponse,
        HeldIntent::CapabilityDeliver,
        HeldIntent::AuditFederate,
        HeldIntent::WorkspaceRosterRequest,
        HeldIntent::WorkspaceRosterResponse,
        HeldIntent::WorkspaceChannelsRequest,
        HeldIntent::WorkspaceChannelsResponse,
        HeldIntent::PeerAdvertise,
    ];

    #[test]
    fn intent_str_round_trips() {
        for &intent in ALL {
            let s = intent.as_str();
            let back = HeldIntent::from_str(s).expect("FromStr must accept as_str()");
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
                HeldIntent::from_str(bad).is_err(),
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
    pub intent: HeldIntent,
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
    pub intent: HeldIntent,
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
