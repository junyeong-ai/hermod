use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use ulid::Ulid;

use crate::bytes::{PubkeyBytes, SignatureBytes};
use crate::capability::CapabilityToken;
use crate::error::HermodError;
use crate::identity::{AgentAddress, AgentAlias, AgentId};
use crate::time::Timestamp;
use serde_bytes::ByteBuf;

/// Hermod Wire Protocol major version embedded in every envelope.
pub const PROTOCOL_VERSION: u16 = 1;

/// Monotonic, sortable, per-sender unique message identifier (ULID).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct MessageId(pub Ulid);

impl MessageId {
    pub fn new() -> Self {
        Self(Ulid::new())
    }

    pub fn from_ulid(u: Ulid) -> Self {
        Self(u)
    }
}

impl Default for MessageId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MessageId({})", self.0)
    }
}

impl fmt::Display for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for MessageId {
    type Err = HermodError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ulid::from_string(s)
            .map(Self)
            .map_err(|e| HermodError::InvalidEnvelope(format!("bad ulid: {e}")))
    }
}

impl Serialize for MessageId {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for MessageId {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let s = String::deserialize(de)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Message kind, used for routing and indexing. Each kind has a corresponding
/// `MessageBody` variant — this 1:1 mapping is enforced by `validate_kind_body`
/// and by `MessageBody::kind()` returning the matching variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, strum::EnumIter)]
#[serde(rename_all = "snake_case")]
pub enum MessageKind {
    Direct,
    Brief,
    ChannelBroadcast,
    WorkspaceInvite,
    ChannelAdvertise,
    Presence,
    File,
    PermissionPrompt,
    PermissionResponse,
    CapabilityGrant,
    AuditFederate,
    WorkspaceRosterRequest,
    WorkspaceRosterResponse,
    WorkspaceChannelsRequest,
    WorkspaceChannelsResponse,
    /// Sender daemon enumerates the agents it hosts. Recipients
    /// upsert each advertised `(agent_id, pubkey, host_pubkey)`
    /// triple into their directory so cross-host reachability is
    /// known before the first envelope from that agent arrives.
    PeerAdvertise,
}

impl MessageKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            MessageKind::Direct => "direct",
            MessageKind::Brief => "brief",
            MessageKind::ChannelBroadcast => "channel_broadcast",
            MessageKind::WorkspaceInvite => "workspace_invite",
            MessageKind::ChannelAdvertise => "channel_advertise",
            MessageKind::Presence => "presence",
            MessageKind::File => "file",
            MessageKind::PermissionPrompt => "permission_prompt",
            MessageKind::PermissionResponse => "permission_response",
            MessageKind::CapabilityGrant => "capability_grant",
            MessageKind::AuditFederate => "audit_federate",
            MessageKind::WorkspaceRosterRequest => "workspace_roster_request",
            MessageKind::WorkspaceRosterResponse => "workspace_roster_response",
            MessageKind::WorkspaceChannelsRequest => "workspace_channels_request",
            MessageKind::WorkspaceChannelsResponse => "workspace_channels_response",
            MessageKind::PeerAdvertise => "peer_advertise",
        }
    }

    /// Human-readable variant name as it appears in source / docs (PascalCase).
    /// Used by the doc-coverage snapshot test in `hermod-routing`.
    pub fn variant_name(&self) -> &'static str {
        match self {
            MessageKind::Direct => "Direct",
            MessageKind::Brief => "Brief",
            MessageKind::ChannelBroadcast => "ChannelBroadcast",
            MessageKind::WorkspaceInvite => "WorkspaceInvite",
            MessageKind::ChannelAdvertise => "ChannelAdvertise",
            MessageKind::Presence => "Presence",
            MessageKind::File => "File",
            MessageKind::PermissionPrompt => "PermissionPrompt",
            MessageKind::PermissionResponse => "PermissionResponse",
            MessageKind::CapabilityGrant => "CapabilityGrant",
            MessageKind::AuditFederate => "AuditFederate",
            MessageKind::WorkspaceRosterRequest => "WorkspaceRosterRequest",
            MessageKind::WorkspaceRosterResponse => "WorkspaceRosterResponse",
            MessageKind::WorkspaceChannelsRequest => "WorkspaceChannelsRequest",
            MessageKind::WorkspaceChannelsResponse => "WorkspaceChannelsResponse",
            MessageKind::PeerAdvertise => "PeerAdvertise",
        }
    }

    /// `true` iff this kind lives in the `messages` table (carries a
    /// `disposition` column). Drives audit-truthfulness — for kinds
    /// without a column the dispatch decision is coerced to the
    /// kind-default (`Push`) when the audit row is emitted, so a
    /// rule that names e.g. `KindIn { kinds: [Brief] }` can't claim
    /// to have set a disposition that the storage layer dropped.
    pub fn has_disposition_column(&self) -> bool {
        matches!(self, MessageKind::Direct | MessageKind::File)
    }
}

/// Recipient-side delivery disposition. Decided per-envelope by the
/// `DispatchPolicy` immediately after the confirmation gate accepts
/// the inbound. Persisted on `messages.disposition` for kinds that
/// have a column (see [`MessageKind::has_disposition_column`]) and
/// gates whether the MCP channel emitter ever sees the row.
///
/// Two values, no `Default`. Every storage write supplies an
/// explicit choice — no global default that could quietly drift.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, strum::EnumIter)]
#[serde(rename_all = "snake_case")]
pub enum MessageDisposition {
    /// Push to the AI-agent channel (the standard delivery path).
    Push,
    /// Land in the inbox only — no `notifications/claude/channel`
    /// frame. Operator can promote later via `inbox.promote`.
    Silent,
}

impl MessageDisposition {
    pub fn as_str(&self) -> &'static str {
        match self {
            MessageDisposition::Push => "push",
            MessageDisposition::Silent => "silent",
        }
    }
}

impl FromStr for MessageDisposition {
    type Err = HermodError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "push" => Ok(MessageDisposition::Push),
            "silent" => Ok(MessageDisposition::Silent),
            other => Err(HermodError::InvalidEnvelope(format!(
                "unknown disposition `{other}`"
            ))),
        }
    }
}

/// Notification-queue row state. The OS-notification dispatcher claims
/// `Pending`, transitions to `Dispatched` on success or `Failed` on
/// terminal error; operators move rows to `Dismissed`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, strum::EnumIter)]
#[serde(rename_all = "snake_case")]
pub enum NotificationStatus {
    Pending,
    Dispatched,
    Failed,
    Dismissed,
}

impl NotificationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            NotificationStatus::Pending => "pending",
            NotificationStatus::Dispatched => "dispatched",
            NotificationStatus::Failed => "failed",
            NotificationStatus::Dismissed => "dismissed",
        }
    }
}

impl FromStr for NotificationStatus {
    type Err = HermodError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pending" => Ok(NotificationStatus::Pending),
            "dispatched" => Ok(NotificationStatus::Dispatched),
            "failed" => Ok(NotificationStatus::Failed),
            "dismissed" => Ok(NotificationStatus::Dismissed),
            other => Err(HermodError::InvalidEnvelope(format!(
                "unknown notification status `{other}`"
            ))),
        }
    }
}

/// Hard ceiling on a `MessageBody::File` payload, in bytes. The
/// daemon's `[policy]` config can lower this further; nothing on the
/// wire may exceed it. Set generously above the typical AI-agent file-
/// share size (snippets, logs, small screenshots, structured reports)
/// while keeping a single envelope's CBOR encode well under the
/// `tokio-tungstenite` default WS frame cap so a malformed sender
/// can't blow up the federation listener.
pub const MAX_FILE_PAYLOAD_BYTES: usize = 1024 * 1024; // 1 MiB

/// Maximum capability tokens attached to a single envelope.
///
/// Each entry is one ed25519 verify on the receiver side. An
/// unbounded `caps` Vec would let a peer amplify CPU cost by
/// stacking thousands of tokens — bounded by wire-frame size
/// (~64 caps fit in 256 KiB) but still enough to chew through
/// a slow CPU under sustained traffic.
///
/// Realistic envelopes carry 0-1 caps. `4` leaves headroom for
/// future schemes that bind multiple scopes (e.g. the operator
/// stacking a `permission:respond` cap with a `message:send`
/// cap on the same `PermissionResponse` envelope).
pub const MAX_CAPS_PER_ENVELOPE: usize = 4;

/// Validate a file name for inclusion in a `File` envelope. Rejects
/// path separators, control chars, and the empty string — all of which
/// would either escape the operator's blob root on the receiver or
/// confuse downstream tooling.
fn validate_file_name(name: &str) -> Result<(), HermodError> {
    if name.is_empty() {
        return Err(HermodError::InvalidEnvelope("file name is empty".into()));
    }
    if name.len() > 255 {
        return Err(HermodError::InvalidEnvelope(format!(
            "file name {} bytes exceeds 255-byte limit",
            name.len()
        )));
    }
    if name.contains('/') || name.contains('\\') || name.contains('\0') {
        return Err(HermodError::InvalidEnvelope(format!(
            "file name `{name}` contains a path separator or NUL"
        )));
    }
    if name.chars().any(|c| c.is_control()) {
        return Err(HermodError::InvalidEnvelope(format!(
            "file name `{name}` contains a control character"
        )));
    }
    Ok(())
}

/// Compute the 32-byte blake3 hash over `data`. Pulled into the core
/// envelope module so `draft_file` can compute hashes without taking
/// a dep on `hermod-crypto` (`hermod-core` is the lowest layer).
fn blake3_32(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

impl FromStr for MessageKind {
    type Err = HermodError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "direct" => Ok(MessageKind::Direct),
            "brief" => Ok(MessageKind::Brief),
            "channel_broadcast" => Ok(MessageKind::ChannelBroadcast),
            "workspace_invite" => Ok(MessageKind::WorkspaceInvite),
            "channel_advertise" => Ok(MessageKind::ChannelAdvertise),
            "presence" => Ok(MessageKind::Presence),
            "file" => Ok(MessageKind::File),
            "permission_prompt" => Ok(MessageKind::PermissionPrompt),
            "permission_response" => Ok(MessageKind::PermissionResponse),
            "capability_grant" => Ok(MessageKind::CapabilityGrant),
            "audit_federate" => Ok(MessageKind::AuditFederate),
            "workspace_roster_request" => Ok(MessageKind::WorkspaceRosterRequest),
            "workspace_roster_response" => Ok(MessageKind::WorkspaceRosterResponse),
            "workspace_channels_request" => Ok(MessageKind::WorkspaceChannelsRequest),
            "workspace_channels_response" => Ok(MessageKind::WorkspaceChannelsResponse),
            "peer_advertise" => Ok(MessageKind::PeerAdvertise),
            other => Err(HermodError::InvalidEnvelope(format!(
                "unknown message kind {other:?}"
            ))),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessagePriority {
    Low,
    Normal,
    High,
    Urgent,
}

impl MessagePriority {
    pub fn as_str(&self) -> &'static str {
        match self {
            MessagePriority::Low => "low",
            MessagePriority::Normal => "normal",
            MessagePriority::High => "high",
            MessagePriority::Urgent => "urgent",
        }
    }
}

impl FromStr for MessagePriority {
    type Err = HermodError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "low" => Ok(MessagePriority::Low),
            "normal" => Ok(MessagePriority::Normal),
            "high" => Ok(MessagePriority::High),
            "urgent" => Ok(MessagePriority::Urgent),
            other => Err(HermodError::InvalidEnvelope(format!(
                "unknown priority {other:?}"
            ))),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageStatus {
    Pending,
    Delivered,
    Read,
    Expired,
    Failed,
}

impl MessageStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            MessageStatus::Pending => "pending",
            MessageStatus::Delivered => "delivered",
            MessageStatus::Read => "read",
            MessageStatus::Expired => "expired",
            MessageStatus::Failed => "failed",
        }
    }
}

impl FromStr for MessageStatus {
    type Err = HermodError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pending" => Ok(MessageStatus::Pending),
            "delivered" => Ok(MessageStatus::Delivered),
            "read" => Ok(MessageStatus::Read),
            "expired" => Ok(MessageStatus::Expired),
            "failed" => Ok(MessageStatus::Failed),
            other => Err(HermodError::InvalidEnvelope(format!(
                "unknown status {other:?}"
            ))),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PresenceStatus {
    Online,
    Idle,
    Busy,
    Offline,
}

impl PresenceStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            PresenceStatus::Online => "online",
            PresenceStatus::Idle => "idle",
            PresenceStatus::Busy => "busy",
            PresenceStatus::Offline => "offline",
        }
    }
}

impl FromStr for PresenceStatus {
    type Err = HermodError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "online" => Ok(PresenceStatus::Online),
            "idle" => Ok(PresenceStatus::Idle),
            "busy" => Ok(PresenceStatus::Busy),
            "offline" => Ok(PresenceStatus::Offline),
            other => Err(HermodError::InvalidEnvelope(format!(
                "unknown presence status {other:?}"
            ))),
        }
    }
}

/// Kind-specific message payload.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MessageBody {
    Direct {
        text: String,
    },
    /// Operator-authored short summary of an agent's recent activity. The
    /// writer controls disclosure entirely — there is no model in the
    /// privacy-critical path.
    Brief {
        summary: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        topic: Option<String>,
    },
    /// Group-addressed message scoped to a channel within a workspace. The
    /// envelope's `to.id` carries the per-recipient fan-out target; the body
    /// carries the scope identifiers and (for private workspaces) a 32-byte
    /// blake3-MAC over `text` that the recipient verifies under the
    /// channel's MAC key.
    ChannelBroadcast {
        workspace_id: ByteBuf,
        channel_id: ByteBuf,
        text: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hmac: Option<ByteBuf>,
    },
    /// Direct invitation to join a private workspace. Sent peer-to-peer,
    /// always confirmation-gated as Sensitive — accepting it imports a
    /// 32-byte secret into the local store.
    WorkspaceInvite {
        workspace_id: ByteBuf,
        name: String,
        secret: ByteBuf,
    },
    /// Advertisement of a channel within a workspace I'm in. Recipients who
    /// are also in the workspace store this in `discovered_channels`.
    ChannelAdvertise {
        workspace_id: ByteBuf,
        channel_id: ByteBuf,
        channel_name: String,
    },
    /// Presence update. Publisher fans this out to workspace members so peers
    /// can answer "is this agent reachable?" without polling.
    ///
    /// Two facets:
    ///   * `manual_status` — operator/agent override (`busy`, `idle`, …).
    ///     `None` means the publisher hasn't asserted a hint right now.
    ///   * `live` — whether the publisher's daemon currently has at least
    ///     one MCP stdio session attached and heartbeating. This is the
    ///     "is anyone home to reply?" signal.
    ///
    /// Receivers cache both fields keyed by sender; envelope-level
    /// `ttl_secs` (set by the publisher) decides freshness.
    Presence {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        manual_status: Option<PresenceStatus>,
        live: bool,
    },

    /// Inline binary payload. Suitable for code snippets, log excerpts,
    /// small screenshots, structured reports — content where the
    /// receiver wants the bytes, not a URL. Larger payloads should be
    /// referenced from a `Direct` text body (URL / git ref).
    ///
    /// `hash` is `blake3(data)`. Receivers verify it on inbound; a
    /// mismatch is an envelope rejection (not silent corruption). The
    /// daemon enforces a payload cap from `[policy]
    /// max_file_payload_bytes` (compile-time ceiling
    /// [`MAX_FILE_PAYLOAD_BYTES`]) at signing and accept time.
    File {
        /// Display name. No path separators (rejected at signing).
        name: String,
        /// IANA media type. Empty deserialises as
        /// `application/octet-stream`.
        mime: String,
        /// 32-byte blake3 over `data`.
        hash: ByteBuf,
        data: ByteBuf,
    },

    /// Operator-approval prompt forwarded by an originating daemon to a
    /// holder of the `permission:respond` capability. The receiving
    /// daemon parks it in its `PermissionService` and surfaces it to
    /// the operator (`hermod permission allow / deny <id>`); the
    /// operator's verdict travels back as `PermissionResponse`.
    PermissionPrompt {
        /// Originator's local short id (5 chars `[a-km-z]`). Echoed
        /// in `PermissionResponse` so the originator can match
        /// verdicts to live prompts.
        request_id: String,
        tool_name: String,
        description: String,
        input_preview: String,
        /// Wall-clock instant the prompt is no longer answerable.
        /// Lifted from the originator so all delegates expire
        /// together.
        expires_at: Timestamp,
    },

    /// Verdict from a delegate, addressed back to the originator.
    /// Capability-gated: the inbound listener requires the sender to
    /// hold a valid `permission:respond` cap issued by us.
    PermissionResponse {
        request_id: String,
        /// `"allow"` or `"deny"` — wire form mirrors the Channels
        /// reference's `behavior` field.
        behavior: String,
    },

    /// Capability token delivered to the audience by the issuer over
    /// the wire. Receiving daemons import the token into their local
    /// `capabilities` table (audience side) so subsequent outbound
    /// envelopes can attach it via `caps[]`. Sensitive — accepting
    /// imports new authority into the local store, so the
    /// confirmation gate holds it for unfamiliar peers.
    CapabilityGrant {
        token: ByteBuf,
        scope: String,
    },

    /// Audit-row payload shipped from one daemon to a designated
    /// aggregator daemon. Sender's identity is in the envelope's `from`
    /// field (signed); the original audit row's metadata travels in the
    /// body. The aggregator opts in to ingestion via `[audit]
    /// accept_federation` and writes each received row into its local
    /// hash-chained log under `audit.federate.<original_action>`,
    /// preserving the sender as `actor` so the cross-daemon timeline is
    /// reconstructible. Sensitivity-classified as Routine because the
    /// aggregator's opt-in is the trust gate (a daemon that hasn't
    /// opted in rejects the envelope outright).
    AuditFederate {
        /// Original audit-row action name (e.g. `"workspace.create"`).
        action: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        target: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        details: Option<serde_json::Value>,
        /// Original audit-row timestamp in unix milliseconds. Differs
        /// from `envelope.ts` when the row was buffered before
        /// federating; the aggregator preserves this so cross-daemon
        /// audit timelines stay accurate even with shipping latency.
        original_ts_ms: i64,
    },

    /// Workspace roster query — "who is in this workspace?".
    ///
    /// Authorisation:
    ///   * Private workspace: `hmac` is the workspace MAC over
    ///     `workspace_id`. Possessing the workspace secret = membership
    ///     proof; non-members can't forge it.
    ///   * Public workspace: `hmac` is `None`. The responder gates on
    ///     its `workspace_members` table (sender must already be a
    ///     known member from a prior signed envelope).
    ///
    /// Sensitivity Routine — membership proof IS the trust gate.
    WorkspaceRosterRequest {
        workspace_id: ByteBuf,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hmac: Option<ByteBuf>,
    },

    /// Roster response — gossip view of "who I see as members of this
    /// workspace". Requester unions multiple responses for the
    /// canonical roster.
    ///
    /// `request_id` is the envelope id of the originating
    /// [`MessageBody::WorkspaceRosterRequest`] — requester correlates by
    /// this field. Each member entry carries both the agent_id and the
    /// pubkey, bound by `agent_id == blake3(pubkey)[:26]` so the
    /// receiver can verify and auto-upsert without separate
    /// out-of-band exchange. `hmac` (when present) is computed over
    /// the canonical `workspace_id || sorted-members-concatenated`
    /// byte string; proves the responder is also a workspace member.
    WorkspaceRosterResponse {
        request_id: MessageId,
        workspace_id: ByteBuf,
        members: Vec<RosterMember>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hmac: Option<ByteBuf>,
    },

    /// Channel listing query — "what channels exist in this workspace?".
    /// Same auth/sensitivity model as [`MessageBody::WorkspaceRosterRequest`].
    WorkspaceChannelsRequest {
        workspace_id: ByteBuf,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hmac: Option<ByteBuf>,
    },

    /// Channel listing response — gossip view of channels in this
    /// workspace. Each entry pairs a 16-byte channel id with its
    /// human-readable name. Members can derive the channel id locally
    /// from the secret + name; the response is mostly about
    /// surfacing names that the requester may not have seen
    /// advertised yet.
    WorkspaceChannelsResponse {
        request_id: MessageId,
        workspace_id: ByteBuf,
        channels: Vec<WorkspaceChannelEntry>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hmac: Option<ByteBuf>,
    },

    /// Sender daemon enumerates the agents it hosts. The receiver
    /// upserts each `(agent_id, pubkey)` triple into its directory
    /// keyed on `host_pubkey`. Authentication chain:
    ///   1. The standard envelope-signing path binds
    ///      `envelope.from_pubkey ↔ envelope.from.id` (self-cert).
    ///   2. The acceptor verifies that `envelope.from.id` appears in
    ///      `agents` (so the sender claims authority over its own
    ///      agent_id, not someone else's).
    ///   3. The acceptor verifies `host_pubkey` matches the sender's
    ///      already-known host binding (or pins on first contact).
    ///   4. Each `AdvertisedAgent` is self-cert-checked
    ///      (`id == blake3(pubkey)[:26]`); existing rows are
    ///      upserted (operator-set fields preserved), new rows land
    ///      with `TrustLevel::Tofu`.
    PeerAdvertise {
        /// Sender's daemon-level Noise host pubkey. The receiver pins
        /// every advertised agent's `host_pubkey` to this value, so
        /// `(agent_id, host_pubkey)` is the cross-host directory key.
        host_pubkey: PubkeyBytes,
        /// Agents hosted by this daemon. Must include `envelope.from.id`
        /// (self-inclusion is the proof that the sender belongs to the
        /// claimed host).
        agents: Vec<AdvertisedAgent>,
    },
}

/// One channel descriptor inside a [`MessageBody::WorkspaceChannelsResponse`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceChannelEntry {
    /// 16-byte channel id (hex-encoded by the storage layer; raw on
    /// the wire).
    pub channel_id: ByteBuf,
    /// Human-readable channel name. Members derive the matching
    /// channel id locally via `secret.channel_id(name)` for private
    /// workspaces.
    pub name: String,
}

/// One member descriptor inside a [`MessageBody::WorkspaceRosterResponse`]. The
/// pubkey is bound to the agent_id by
/// `agent_id == blake3(pubkey)[:26]` so the receiver can verify
/// every entry independently and reject any responder that lies
/// about another member's identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosterMember {
    pub id: AgentId,
    pub pubkey: PubkeyBytes,
}

/// One agent descriptor inside a [`MessageBody::PeerAdvertise`].
/// `id` is bound to `pubkey` by `id == blake3(pubkey)[:26]`; the
/// receiver verifies this binding before upserting. `alias`
/// surfaces the operator-set local alias as a `peer_asserted_alias`
/// hint for the receiver — never overwrites the receiver's own
/// `local_alias` for this agent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdvertisedAgent {
    pub id: AgentId,
    pub pubkey: PubkeyBytes,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<AgentAlias>,
}

impl MessageBody {
    pub fn kind(&self) -> MessageKind {
        match self {
            MessageBody::Direct { .. } => MessageKind::Direct,
            MessageBody::Brief { .. } => MessageKind::Brief,
            MessageBody::ChannelBroadcast { .. } => MessageKind::ChannelBroadcast,
            MessageBody::WorkspaceInvite { .. } => MessageKind::WorkspaceInvite,
            MessageBody::ChannelAdvertise { .. } => MessageKind::ChannelAdvertise,
            MessageBody::Presence { .. } => MessageKind::Presence,
            MessageBody::File { .. } => MessageKind::File,
            MessageBody::PermissionPrompt { .. } => MessageKind::PermissionPrompt,
            MessageBody::PermissionResponse { .. } => MessageKind::PermissionResponse,
            MessageBody::CapabilityGrant { .. } => MessageKind::CapabilityGrant,
            MessageBody::AuditFederate { .. } => MessageKind::AuditFederate,
            MessageBody::WorkspaceRosterRequest { .. } => MessageKind::WorkspaceRosterRequest,
            MessageBody::WorkspaceRosterResponse { .. } => MessageKind::WorkspaceRosterResponse,
            MessageBody::WorkspaceChannelsRequest { .. } => MessageKind::WorkspaceChannelsRequest,
            MessageBody::WorkspaceChannelsResponse { .. } => MessageKind::WorkspaceChannelsResponse,
            MessageBody::PeerAdvertise { .. } => MessageKind::PeerAdvertise,
        }
    }

    /// JSON-friendly summary for the metadata column (`messages.body_json`)
    /// — strips bulky binary fields so the SQL projection stays small
    /// while the canonical CBOR (in `messages.envelope_cbor`) keeps the
    /// full payload. The summary is purely an indexing/inspection aid;
    /// callers needing the original `data` deserialize from CBOR.
    pub fn summary_json(&self) -> serde_json::Value {
        match self {
            MessageBody::File {
                name,
                mime,
                hash,
                data,
            } => serde_json::json!({
                "kind": "file",
                "name": name,
                "mime": mime,
                "size": data.len(),
                "hash": hex::encode(hash.as_ref()),
            }),
            // Other variants have no binary fan-out; serialize as-is.
            other => serde_json::to_value(other).unwrap_or(serde_json::Value::Null),
        }
    }

    /// Natural-language surface for substring matching by routing
    /// rules. `Direct.text`, `File.name`, `Brief.summary`,
    /// `ChannelBroadcast.text`. `None` for kinds whose body is
    /// purely structural (Presence, capability grants, workspace
    /// gossip RPCs, peer advertise) — `RuleCondition::BodyContainsAny`
    /// against those falls through `false` rather than matching by
    /// accident on JSON-serialised structure.
    pub fn searchable_text(&self) -> Option<&str> {
        match self {
            MessageBody::Direct { text } => Some(text.as_str()),
            MessageBody::File { name, .. } => Some(name.as_str()),
            MessageBody::Brief { summary, .. } => Some(summary.as_str()),
            MessageBody::ChannelBroadcast { text, .. } => Some(text.as_str()),
            _ => None,
        }
    }
}

/// Signed envelope — the unit of transmission in Hermod.
///
/// Field order matters: canonical signing serializes these fields in declaration order
/// and excludes `sig`. See `hermod-crypto::canonical` for the signing routine.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Envelope {
    pub v: u16,
    pub id: MessageId,
    pub ts: Timestamp,
    pub from: AgentAddress,
    /// Sender's ed25519 public key. Self-introducing — receivers
    /// verify the binding `agent_id == blake3(from_pubkey)[:26]` and
    /// then verify `sig` against this key, without consulting an
    /// external directory. Auto-populated by `Signer::sign_envelope`
    /// at sign time, identical to how `sig` is populated.
    pub from_pubkey: PubkeyBytes,
    pub to: AgentAddress,
    pub kind: MessageKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread: Option<MessageId>,
    pub priority: MessagePriority,
    pub ttl_secs: u32,
    pub body: MessageBody,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub caps: Vec<CapabilityToken>,
    pub sig: SignatureBytes,
}

impl Envelope {
    /// Construct an unsigned envelope with `from_pubkey` and `sig`
    /// both zero-initialized. `Signer::sign_envelope` overwrites
    /// both at sign time.
    pub fn draft(
        from: AgentAddress,
        to: AgentAddress,
        body: MessageBody,
        priority: MessagePriority,
        ttl_secs: u32,
    ) -> Self {
        let kind = body.kind();
        Self {
            v: PROTOCOL_VERSION,
            id: MessageId::new(),
            ts: Timestamp::now(),
            from,
            from_pubkey: PubkeyBytes::zero(),
            to,
            kind,
            thread: None,
            priority,
            ttl_secs,
            body,
            caps: Vec::new(),
            sig: SignatureBytes::zero(),
        }
    }

    /// Construct an unsigned `File` envelope. Validates the file name
    /// (no path separators, no NUL, no control chars) and the payload
    /// size against [`MAX_FILE_PAYLOAD_BYTES`], computes `hash =
    /// blake3(data)` automatically, and returns the unsigned envelope
    /// ready for `hermod-crypto::sign_envelope`.
    pub fn draft_file(
        from: AgentAddress,
        to: AgentAddress,
        name: String,
        mime: String,
        data: Vec<u8>,
        priority: MessagePriority,
        ttl_secs: u32,
    ) -> Result<Self, HermodError> {
        validate_file_name(&name)?;
        if data.len() > MAX_FILE_PAYLOAD_BYTES {
            return Err(HermodError::InvalidEnvelope(format!(
                "file payload {} bytes exceeds compile-time cap {} bytes",
                data.len(),
                MAX_FILE_PAYLOAD_BYTES
            )));
        }
        let hash = blake3_32(&data);
        let body = MessageBody::File {
            name,
            mime,
            hash: ByteBuf::from(hash.to_vec()),
            data: ByteBuf::from(data),
        };
        Ok(Self::draft(from, to, body, priority, ttl_secs))
    }

    pub fn with_thread(mut self, thread: MessageId) -> Self {
        self.thread = Some(thread);
        self
    }

    pub fn with_capability(mut self, token: CapabilityToken) -> Self {
        self.caps.push(token);
        self
    }

    /// Kind-body mismatch check (invariant).
    pub fn validate_kind_body(&self) -> Result<(), HermodError> {
        if self.body.kind() != self.kind {
            return Err(HermodError::InvalidEnvelope(format!(
                "kind {:?} does not match body variant {:?}",
                self.kind,
                self.body.kind()
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::AgentId;
    use std::str::FromStr;

    fn fake_agent() -> AgentId {
        AgentId::from_str("abcdefghijklmnopqrstuvwxyz").unwrap()
    }

    #[test]
    fn draft_roundtrip_json() {
        let env = Envelope::draft(
            AgentAddress::local(fake_agent()),
            AgentAddress::local(fake_agent()),
            MessageBody::Direct { text: "hi".into() },
            MessagePriority::Normal,
            3600,
        );
        let j = serde_json::to_string(&env).unwrap();
        let back: Envelope = serde_json::from_str(&j).unwrap();
        assert_eq!(env, back);
        assert_eq!(back.kind, MessageKind::Direct);
    }

    #[test]
    fn priority_ord() {
        assert!(MessagePriority::Low < MessagePriority::Normal);
        assert!(MessagePriority::High < MessagePriority::Urgent);
    }

    #[test]
    fn kind_body_mismatch_detected() {
        let mut env = Envelope::draft(
            AgentAddress::local(fake_agent()),
            AgentAddress::local(fake_agent()),
            MessageBody::Direct { text: "hi".into() },
            MessagePriority::Normal,
            60,
        );
        env.kind = MessageKind::Brief;
        assert!(env.validate_kind_body().is_err());
    }
}
