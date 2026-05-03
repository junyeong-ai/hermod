//! Shared request / result types for IPC methods.
//!
//! **Naming invariant**: wire methods are `<namespace>.<verb>`; Rust types
//! use `<Namespace><Verb>{Params,Result}`. Add new namespaces only when an
//! existing one would be a forced fit — the round-trip cost of a stable
//! grammar is small, and adapters (CLI, MCP, audit log) all assume it.

use hermod_core::{
    AgentAddress, AgentAlias, AgentId, CapabilityDirection, CapabilityTag, CapabilityToken,
    Endpoint, McpSessionId, MessageBody, MessageDisposition, MessageId, MessageKind,
    MessagePriority, MessageStatus, NotificationStatus, SessionLabel, Timestamp, TrustLevel,
};
use serde::{Deserialize, Serialize};

// Re-exported so CLI / MCP callers don't need a separate `use hermod_core::…`
// for types that appear in IPC params and results.
pub use hermod_core::WorkspaceVisibility;

/// `serde(skip_serializing_if = "is_false")` helper — drop the field
/// from the wire when its value is the boolean default. Keeps the
/// shape stable for callers that haven't seen the new field yet.
fn is_false(b: &bool) -> bool {
    !*b
}

// ---------- method names ----------

pub mod method {
    // Status / identity — both are namespace.get for symmetry.
    pub const STATUS_GET: &str = "status.get";
    pub const IDENTITY_GET: &str = "identity.get";

    // Messages — `message.send` and `message.ack` are the sender-side
    // and read-receipt surface. The inbox lister lives at `inbox.list`
    // (richer projection: `MessageView` carries `from_alias` /
    // `from_alias_ambiguous` / `from_host_pubkey` plus the recipient's
    // `disposition` so operator CLI and MCP poller share one source).
    pub const MESSAGE_SEND: &str = "message.send";
    pub const MESSAGE_ACK: &str = "message.ack";

    // Inbox — recipient-side delivery surface.
    //   `inbox.list`     — list inbox rows; defaults to all dispositions
    //                      (operator CLI). MCP channel poller passes
    //                      `dispositions: Some(vec![Push])` so silent
    //                      rows never enter AI-agent context.
    //   `inbox.promote`  — flip a silent row to push so the channel
    //                      emitter surfaces it on the next poll.
    pub const INBOX_LIST: &str = "inbox.list";
    pub const INBOX_PROMOTE: &str = "inbox.promote";

    // Notification queue — recipient-side OS-notification dispatch.
    //   `notification.list`     — operator inspection.
    //   `notification.claim`    — MCP NotificationDispatcher's atomic
    //                             pull (mirrors messages outbox).
    //   `notification.complete` — terminal success.
    //   `notification.fail`     — terminal failure with reason.
    //   `notification.dismiss`  — operator-driven dismissal.
    //   `notification.purge`    — janitor / operator-triggered reap of
    //                             terminal rows past retention.
    pub const NOTIFICATION_LIST: &str = "notification.list";
    pub const NOTIFICATION_CLAIM: &str = "notification.claim";
    pub const NOTIFICATION_COMPLETE: &str = "notification.complete";
    pub const NOTIFICATION_FAIL: &str = "notification.fail";
    pub const NOTIFICATION_DISMISS: &str = "notification.dismiss";
    pub const NOTIFICATION_PURGE: &str = "notification.purge";

    // Agents
    pub const AGENT_LIST: &str = "agent.list";
    pub const AGENT_GET: &str = "agent.get";
    pub const AGENT_REGISTER: &str = "agent.register";

    // Peers
    // Local agents — daemon-side mutation of the live registry. The
    // operator runs `hermod local add` etc. while the daemon is
    // running; the registry's bearer index updates in-place and any
    // session pinned to a removed/rotated bearer is force-closed.
    pub const LOCAL_LIST: &str = "local.list";
    pub const LOCAL_ADD: &str = "local.add";
    pub const LOCAL_REMOVE: &str = "local.remove";
    pub const LOCAL_ROTATE: &str = "local.rotate";
    /// Replace the operator-set capability tag set on one local
    /// agent. Discovery metadata only — never trust-bearing.
    pub const LOCAL_TAG_SET: &str = "local.tag_set";
    /// Live MCP sessions for the caller agent — used by the operator
    /// to see which Claude Code windows are currently attached and
    /// under which `session_label`.
    pub const LOCAL_SESSIONS: &str = "local.sessions";

    pub const PEER_ADD: &str = "peer.add";
    pub const PEER_LIST: &str = "peer.list";
    pub const PEER_TRUST: &str = "peer.trust";
    pub const PEER_REMOVE: &str = "peer.remove";
    pub const PEER_REPIN: &str = "peer.repin";
    /// Push a `PeerAdvertise` envelope to one peer (or all known
    /// peers) describing the agents this daemon hosts. Operator-
    /// triggered explicit form; the daemon also auto-advertises on
    /// successful `peer.add`.
    pub const PEER_ADVERTISE: &str = "peer.advertise";

    // Capabilities
    pub const CAPABILITY_ISSUE: &str = "capability.issue";
    pub const CAPABILITY_REVOKE: &str = "capability.revoke";
    pub const CAPABILITY_LIST: &str = "capability.list";
    /// Issue + envelope-deliver to the audience in one step. The
    /// resulting `CapabilityGrant` envelope is auto-imported on the
    /// receiver into the audience-side `capabilities` table so the
    /// operator can immediately attach the token to outbound
    /// envelopes.
    pub const CAPABILITY_DELIVER: &str = "capability.deliver";

    // Brief — operator-authored summary of an agent's recent activity.
    pub const BRIEF_PUBLISH: &str = "brief.publish";
    pub const BRIEF_READ: &str = "brief.read";

    // Presence — operator-set manual hint + derived liveness.
    pub const PRESENCE_SET_MANUAL: &str = "presence.set_manual";
    pub const PRESENCE_CLEAR_MANUAL: &str = "presence.clear_manual";
    pub const PRESENCE_GET: &str = "presence.get";

    // MCP stdio session lifecycle. The MCP server (running inside Claude
    // Code) attaches on initialize, heartbeats periodically, and detaches
    // on stdin EOF. The daemon derives self liveness from these rows.
    pub const MCP_ATTACH: &str = "mcp.attach";
    pub const MCP_DETACH: &str = "mcp.detach";
    pub const MCP_HEARTBEAT: &str = "mcp.heartbeat";
    /// Persist the session's delivery cursors so a Claude Code restart
    /// resumes from the same position rather than re-emitting the
    /// agent's entire backlog. Idempotent partial advance — only
    /// `Some(_)` fields are written.
    pub const MCP_CURSOR_ADVANCE: &str = "mcp.cursor_advance";

    // Workspaces (group container).
    pub const WORKSPACE_CREATE: &str = "workspace.create";
    pub const WORKSPACE_JOIN: &str = "workspace.join";
    pub const WORKSPACE_LIST: &str = "workspace.list";
    pub const WORKSPACE_GET: &str = "workspace.get";
    pub const WORKSPACE_DELETE: &str = "workspace.delete";
    pub const WORKSPACE_MUTE: &str = "workspace.mute";
    pub const WORKSPACE_INVITE: &str = "workspace.invite";
    pub const WORKSPACE_ROSTER: &str = "workspace.roster";
    pub const WORKSPACE_CHANNELS: &str = "workspace.channels";

    // Channels within a workspace.
    pub const CHANNEL_CREATE: &str = "channel.create";
    pub const CHANNEL_LIST: &str = "channel.list";
    pub const CHANNEL_HISTORY: &str = "channel.history";
    pub const CHANNEL_DELETE: &str = "channel.delete";
    pub const CHANNEL_MUTE: &str = "channel.mute";
    pub const CHANNEL_ADVERTISE: &str = "channel.advertise";
    pub const CHANNEL_DISCOVER: &str = "channel.discover";
    pub const CHANNEL_ADOPT: &str = "channel.adopt";

    // Broadcast a message to a channel.
    pub const BROADCAST_SEND: &str = "broadcast.send";

    // Confirmation gate.
    pub const CONFIRMATION_LIST: &str = "confirmation.list";
    pub const CONFIRMATION_ACCEPT: &str = "confirmation.accept";
    pub const CONFIRMATION_REJECT: &str = "confirmation.reject";

    // Audit
    pub const AUDIT_QUERY: &str = "audit.query";
    pub const AUDIT_VERIFY: &str = "audit.verify";
    pub const AUDIT_ARCHIVE_NOW: &str = "audit.archive_now";
    pub const AUDIT_ARCHIVES_LIST: &str = "audit.archives_list";
    pub const AUDIT_VERIFY_ARCHIVE: &str = "audit.verify_archive";

    // Permission relay — Claude Code Channels permission_request bridge.
    // `request` parks an inbound prompt and mints a 5-letter short id;
    // `respond` applies a verdict; `list` enumerates the live set;
    // `list_resolved` is the cursor-based feed the MCP server consumes
    // to learn that a verdict is ready for forwarding.
    pub const PERMISSION_REQUEST: &str = "permission.request";
    pub const PERMISSION_RESPOND: &str = "permission.respond";
    pub const PERMISSION_LIST: &str = "permission.list";
    pub const PERMISSION_LIST_RESOLVED: &str = "permission.list_resolved";
}

// ---------- status.get ----------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StatusGetResult {
    pub version: String,
    pub agent_id: AgentId,
    /// This daemon's own alias as configured at `init`. Singular (vs the
    /// `local_alias` / `peer_asserted_alias` split used elsewhere) because
    /// "self" has only one alias namespace — the operator's choice. The
    /// same value is broadcast to peers in Hello frames as their
    /// `peer_asserted_alias` for us.
    pub alias: Option<AgentAlias>,
    pub pending_messages: i64,
    pub peer_count: i64,
    pub uptime_secs: u64,
    /// Number of MCP stdio sessions currently attached to this daemon.
    /// Operators reading `status` use this to confirm at least one Claude
    /// Code session is live before expecting synchronous DMs to be answered.
    pub attached_sessions: u32,
    /// Schema version recorded in `schema_meta`. `hermod doctor`
    /// surfaces this so an operator notices a binary/database
    /// mismatch immediately.
    pub schema_version: String,
}

// ---------- identity.get ----------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityGetResult {
    /// Caller's own agent_id — derived from the IPC bearer (remote)
    /// or the Unix-socket peer (local). One daemon can host multiple
    /// agents; this field reflects the bearer that authenticated
    /// the call, not a daemon-wide identity.
    pub agent_id: AgentId,
    /// Caller's operator-assigned local alias (singular — self has no
    /// peer-asserted facet).
    pub alias: Option<AgentAlias>,
    /// 8-char prefix of the caller's pubkey fingerprint, for human
    /// confirmation against an out-of-band shared value.
    pub fingerprint: String,
    /// Hex-encoded ed25519 host pubkey (Noise/TLS layer). Multiple
    /// agents share one host; cross-host disambiguation uses this
    /// prefix when local aliases collide.
    pub host_pubkey_hex: String,
}

// ---------- message.send ----------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageSendParams {
    pub to: AgentAddress,
    pub body: MessageBody,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<MessagePriority>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread: Option<MessageId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_secs: Option<u32>,
    /// Capability tokens to attach to the outgoing envelope. Required when the
    /// recipient enforces `policy.require_capability`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caps: Option<Vec<CapabilityToken>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageSendResult {
    pub id: MessageId,
    pub status: MessageStatus,
    /// Whether the recipient currently has at least one attached Claude
    /// Code session. `false` means the message is queued and will be
    /// surfaced on next session attach — the CLI prints a warning so the
    /// operator knows not to expect a synchronous reply.
    pub recipient_live: bool,
}

// ---------- inbox.list ----------

/// Canonical inbox lister. Used by `hermod inbox list` (operator CLI,
/// no `dispositions` filter ⇒ all rows) and the MCP channel poller
/// (passes `dispositions: Some(vec![Push])` so silent rows are kept
/// out of AI-agent context).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct InboxListParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statuses: Option<Vec<MessageStatus>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority_min: Option<MessagePriority>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    /// Cursor for pagination / streaming readers. When set, only messages
    /// with `id > after_id` are returned. ULIDs are monotonic, so this is
    /// equivalent to "delivered after this point" for monotonic-time
    /// readers like the MCP channel emitter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_id: Option<MessageId>,
    /// Restrict to rows whose `disposition` is in this set. `None` ⇒
    /// all dispositions (operator CLI default). The MCP channel
    /// poller passes `Some(vec![Push])` — silent rows must never
    /// reach AI-agent context. Operators promote silent → push via
    /// `inbox.promote`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dispositions: Option<Vec<MessageDisposition>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageView {
    pub id: MessageId,
    pub from: AgentId,
    /// Operator's local nickname for `from` (sacred, routing-resolvable).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_local_alias: Option<AgentAlias>,
    /// What `from` claims their own display name is (advisory).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_peer_alias: Option<AgentAlias>,
    /// Best display name available — local wins, falls back to peer-asserted.
    /// UIs/LLMs that just want "the sender's name" should read this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_alias: Option<AgentAlias>,
    /// `true` iff another agent (different `id`) shares the same
    /// `from_alias`. Receivers MUST surface `from_host_pubkey` (or
    /// the raw `from` id) before acting on the alias to avoid acting
    /// on the wrong identity.
    #[serde(default, skip_serializing_if = "is_false")]
    pub from_alias_ambiguous: bool,
    /// Hex-encoded ed25519 host pubkey of the daemon hosting `from`.
    /// `None` for local-only senders that have never been federated.
    /// UIs render the leading 8 chars when local aliases collide.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_host_pubkey: Option<String>,
    pub to: AgentId,
    pub kind: MessageKind,
    pub priority: MessagePriority,
    pub status: MessageStatus,
    /// Recipient-side delivery disposition assigned by the routing
    /// engine. `Push` ⇒ surfaced on the AI-agent channel; `Silent`
    /// ⇒ inbox-only. Operators see `Silent` rows in `inbox list`
    /// and promote them via `inbox promote <id>`.
    pub disposition: MessageDisposition,
    pub created_at: Timestamp,
    pub body: MessageBody,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread: Option<MessageId>,
    /// Opaque `hermod_storage::BlobStore` location for File-kind
    /// messages whose payload was written to the store on inbound.
    /// Operator surfaces (CLI, MCP) hand this to the BlobStore to
    /// fetch the bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_blob_location: Option<String>,
    /// File payload size in bytes for File-kind messages — surfaced
    /// from the storage `body_json` metadata projection so callers
    /// don't need to fetch the blob just to render a size hint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_size: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InboxListResult {
    pub messages: Vec<MessageView>,
    pub total: i64,
}

// ---------- inbox.promote ----------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InboxPromoteParams {
    pub id: MessageId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InboxPromoteResult {
    /// `true` iff a silent row was flipped to push. `false` for any
    /// no-op (row missing, owned by another agent, already push).
    /// CLI surfaces this as exit code 1 so scripts notice stale ids.
    pub promoted: bool,
}

// ---------- notification.* ----------

/// Wire-side projection of a `notifications` row. Hides storage
/// internals (claim_token, claimed_at) the operator never needs;
/// keeps observable fields the dispatcher and `hermod doctor` use.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NotificationView {
    pub id: String,
    pub recipient_agent_id: AgentId,
    pub message_id: MessageId,
    pub status: NotificationStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sound: Option<String>,
    pub attempts: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dispatched_at: Option<Timestamp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed_reason: Option<String>,
    pub created_at: Timestamp,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NotificationListParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statuses: Option<Vec<NotificationStatus>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NotificationListResult {
    pub notifications: Vec<NotificationView>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NotificationClaimParams {
    /// Worker identifier — the MCP NotificationDispatcher's
    /// per-process UUID. Mirrors the messages outbox claim ownership.
    pub worker_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NotificationClaimResult {
    /// Claimed rows including their `claim_token` (for the subsequent
    /// `complete` / `fail` call) and `message_id` (so the dispatcher
    /// can fetch the body for the platform notifier).
    pub notifications: Vec<NotificationClaimView>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NotificationClaimView {
    pub id: String,
    pub message_id: MessageId,
    pub recipient_agent_id: AgentId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sound: Option<String>,
    /// Echoed by the dispatcher on `complete` / `fail` so the daemon
    /// rejects late completes from a stale worker.
    pub claim_token: String,
    pub created_at: Timestamp,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NotificationCompleteParams {
    pub id: String,
    pub claim_token: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NotificationCompleteResult {
    pub matched: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NotificationFailParams {
    pub id: String,
    pub claim_token: String,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NotificationFailResult {
    pub matched: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NotificationDismissParams {
    pub id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NotificationDismissResult {
    pub matched: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NotificationPurgeParams {
    /// Maximum age in seconds for terminal rows to keep. `None`
    /// uses the operator-configured `[routing.notification]
    /// retention_days`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub older_than_secs: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NotificationPurgeResult {
    pub purged: u64,
}

// ---------- message.ack ----------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageAckParams {
    pub message_ids: Vec<MessageId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageAckResult {
    pub acked: Vec<MessageId>,
}

// ---------- agent.list / get / register ----------

/// `agent.list` returns only agents that are *live right now* — i.e. an agent
/// is included iff a synchronous reply is realistic. There is no "include
/// offline" knob: an offline agent in a list view has no operational value
/// (you can't talk to them), and listing all known identities for forensic
/// purposes is the audit log's job.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AgentListParams {
    /// Match agents whose effective tag set contains *every* tag
    /// listed here (AND). Empty / absent ⇒ no constraint.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags_all: Vec<CapabilityTag>,
    /// Match agents whose effective tag set contains *at least one*
    /// of these tags (OR). Empty / absent ⇒ no constraint. Combined
    /// with `tags_all` via AND: a row must satisfy both filters.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags_any: Vec<CapabilityTag>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentSummary {
    pub id: AgentId,
    /// Operator's local nickname for this agent (set via `peer add --alias`,
    /// `agent register --alias`, or `init --alias`). Sacred — never overwritten
    /// by peer self-claims. Used for `--to @alias` resolution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_alias: Option<AgentAlias>,
    /// What the agent claims their own display name is, as observed in their
    /// most recent signed Hello / Presence frame. Advisory — never used for
    /// routing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_asserted_alias: Option<AgentAlias>,
    /// Best display name available — `local_alias` if set, otherwise
    /// `peer_asserted_alias`. UIs and LLMs that just want "the agent's name"
    /// should read this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_alias: Option<AgentAlias>,
    pub endpoint: Option<Endpoint>,
    pub trust_level: TrustLevel,
    pub last_seen: Option<Timestamp>,
    /// Effective presence — what the operator should treat as the agent's
    /// current status. See `presence.get` for the derivation rules.
    pub status: hermod_core::PresenceStatus,
    pub manual_status: Option<hermod_core::PresenceStatus>,
    /// Effective tag set — local tags (operator-set on hosted
    /// agents) merged with peer-asserted tags (from inbound
    /// `peer.advertise`), local-first and deduplicated. Discovery
    /// metadata only — never trust-bearing.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<CapabilityTag>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentListResult {
    pub agents: Vec<AgentSummary>,
}

/// Single-id lookup. Returns even when the agent is offline — used for audit
/// trail and operator inspection where `agent.list` would have hidden the row.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentGetParams {
    pub agent: String, // AgentId or @alias
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentGetResult {
    pub id: AgentId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_alias: Option<AgentAlias>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_asserted_alias: Option<AgentAlias>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_alias: Option<AgentAlias>,
    pub endpoint: Option<Endpoint>,
    pub trust_level: TrustLevel,
    pub first_seen: Timestamp,
    pub last_seen: Option<Timestamp>,
    pub fingerprint: String,
    pub status: hermod_core::PresenceStatus,
    pub live: bool,
    pub manual_status: Option<hermod_core::PresenceStatus>,
    /// Operator-set local tags (only populated for agents this
    /// daemon hosts — peers have no `local_agents` row).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub local_tags: Vec<CapabilityTag>,
    /// Tags the peer asserted in their most recent `peer.advertise`.
    /// Empty for peers that haven't advertised yet.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peer_asserted_tags: Vec<CapabilityTag>,
    /// `effective_tags(local, peer_asserted)` — local-first, deduped.
    /// Discovery metadata only — never trust-bearing.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub effective_tags: Vec<CapabilityTag>,
}

/// Register an agent identity in the directory. Routing — endpoint
/// or broker — is wired up separately via `peer add`, which has the
/// host pubkey context this directory-only call doesn't.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentRegisterParams {
    pub pubkey_hex: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_alias: Option<AgentAlias>,
    pub trust_level: TrustLevel,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentRegisterResult {
    pub id: AgentId,
}

// ---------- local.* ----------

/// Summary of one locally-hosted agent. Used by `local.list` and
/// returned from `local.add` so the operator immediately sees the
/// freshly-provisioned agent.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalAgentSummary {
    pub agent_id: AgentId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<AgentAlias>,
    /// Path to the bearer file on disk. Operators piping into MCP
    /// `.mcp.json` (`HERMOD_BEARER_FILE`) reference this directly.
    pub bearer_file: String,
    /// Path to the ed25519 secret on disk.
    pub secret_file: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalListResult {
    pub agents: Vec<LocalAgentSummary>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LocalAddParams {
    /// Operator-set label, mirrored to the on-disk `alias` file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<AgentAlias>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalAddResult {
    pub agent: LocalAgentSummary,
    /// Plaintext bearer token for the freshly-provisioned agent.
    /// Returned once at creation; subsequent reads must come from
    /// `bearer_file`. CLI commands surface this so the operator can
    /// pipe it into a remote-IPC client immediately.
    pub bearer_token: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalRemoveParams {
    /// Either `agent_id` or `@<alias>`.
    pub reference: String,
    /// Required confirmation — the agent's keypair is unrecoverable
    /// once archived. Without this, the call is rejected.
    #[serde(default)]
    pub force: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalRemoveResult {
    pub agent_id: AgentId,
    /// Filesystem path to the archived directory.
    pub archive_path: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalRotateParams {
    pub reference: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalRotateResult {
    pub agent_id: AgentId,
    /// New plaintext bearer. Surfaced once at rotation time;
    /// subsequent reads must come from `bearer_file`.
    pub bearer_token: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalTagSetParams {
    /// Local agent to retag — `agent_id` or `@<alias>`.
    pub reference: String,
    /// Replacement tag set (NOT additive). Each entry is parsed
    /// through `CapabilityTag::parse`; daemon validates the
    /// cardinality (≤16) before persisting.
    pub tags: Vec<CapabilityTag>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalTagSetResult {
    pub agent_id: AgentId,
    /// What's now stored — echo so the caller can verify the
    /// validator's dedup / parse pass against what they sent.
    pub tags: Vec<CapabilityTag>,
}

// ---------- peer.* ----------

/// Reachability hint: a peer is either dialed directly or reached
/// through a broker that's already in the directory. Mutually
/// exclusive at the schema level (`agents.host_id` XOR
/// `agents.via_agent`); the wire enum mirrors that XOR so the
/// operator can't accidentally ask for both, AND host_pubkey_hex
/// rides inside `Direct` only — brokered peers don't need their
/// own host pubkey at add time (the broker dials, not us).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PeerReach {
    /// Direct dial: `endpoint` is the peer daemon's WSS+Noise URL,
    /// `host_pubkey_hex` is pinned for the Noise XX handshake.
    Direct {
        endpoint: Endpoint,
        host_pubkey_hex: String,
    },
    /// Brokered: envelopes go through `via` (an existing directory
    /// entry — agent_id or `@<local_alias>`). The broker's own
    /// endpoint is the dial target; `to.id` is preserved so the
    /// broker's `BrokerMode::RelayOnly` fall-through forwards.
    Via { via: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerAddParams {
    pub reach: PeerReach,
    /// The peer agent we want to address by name. Envelopes sent
    /// `--to <local_alias>` resolve to this agent_id; sig verification
    /// uses this pubkey.
    pub agent_pubkey_hex: String,
    /// Operator's local nickname for the agent. Stored as `local_alias`.
    /// Validated by `AgentAlias`'s `try_from` impl at deserialize time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_alias: Option<AgentAlias>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerAddResult {
    pub id: AgentId,
    pub fingerprint: String,
    pub trust_level: TrustLevel,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerSummary {
    pub id: AgentId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_alias: Option<AgentAlias>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_asserted_alias: Option<AgentAlias>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_alias: Option<AgentAlias>,
    /// Direct dial endpoint (joined from the peer's host record).
    /// `None` for brokered peers — their dial target is the broker,
    /// not their own host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<Endpoint>,
    pub trust_level: TrustLevel,
    pub fingerprint: String,
    pub reputation: i64,
    /// Cached effective presence for this peer (from the most recent
    /// inbound `MessageBody::Presence` envelope they fanned out).
    pub status: hermod_core::PresenceStatus,
    /// Cached liveness — `true` while the peer claimed an attached MCP
    /// session in their last broadcast and the cached value is still
    /// fresh. Falls to `false` once the freshness window elapses, even
    /// without an explicit "I went offline" envelope.
    pub live: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerListResult {
    pub peers: Vec<PeerSummary>,
}

/// Push a `PeerAdvertise` envelope to one peer (or all known peers).
/// Reply lets the operator confirm the fan-out reach + see any
/// per-peer enqueue errors.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PeerAdvertiseParams {
    /// Target peer reference — agent_id (26-char base32) or
    /// `@<local_alias>`. `None` advertises to every peer with a
    /// non-empty `endpoint` in the directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
}

/// Per-target outcome of an advertise fan-out. One entry per
/// resolved peer agent_id; ordering matches dispatch order. Mirrors
/// [`MessageSendResult`]'s honesty contract — `status` reflects the
/// actual wire delivery, not the queue ack.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerAdvertiseOutcome {
    /// Peer agent the advertise envelope was addressed to.
    pub target: AgentId,
    /// Wire delivery status. `Delivered` means the recipient daemon
    /// ack'd the envelope; `Failed` means dispatch erred (peer down,
    /// TLS mismatch, rate limit). `Pending` is treated as `Failed`
    /// here — for `peer advertise` the operator wants to know when
    /// the wire didn't see an ack right now.
    pub status: MessageStatus,
    /// Failure reason, present iff `status == Failed`. Operator-
    /// readable; scripts key off `status`, not the prose.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerAdvertiseResult {
    /// Per-target outcomes. Empty when the directory had no federated
    /// peers to advertise to (no-op success).
    pub outcomes: Vec<PeerAdvertiseOutcome>,
    /// Number of locally-hosted agents listed in the envelope body.
    /// Independent of `outcomes.len()` — body content is the same
    /// regardless of how many peers it fans out to.
    pub agents: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerTrustParams {
    pub peer: String,
    pub level: TrustLevel,
}

/// Drop a peer's federation endpoint and TLS pin. The agent row stays so
/// the audit chain references resolve, but the peer is no longer dialled
/// and re-discovery has to TOFU again.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerRemoveParams {
    pub peer: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerRemoveResult {
    pub removed: bool,
}

/// Replace a peer's TLS fingerprint pin. Required when a Verified peer
/// rotates their cert — the operator confirms the new fingerprint OOB,
/// then submits it here. Refused for non-Verified trust levels (TOFU
/// re-pin happens automatically on next contact).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerRepinParams {
    pub peer: String,
    /// Lowercase hex-encoded SHA-256 of the peer's new TLS cert,
    /// `aa:bb:…:ff` form (matching `hermod_crypto::tls::sha256_fingerprint`).
    pub fingerprint: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerRepinResult {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous: Option<String>,
    pub new: String,
}

// ---------- capability.* ----------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CapabilityIssueParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<AgentId>,
    pub scope: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_in_secs: Option<u64>,
}

/// Issue + envelope-deliver to the audience in one step. The result
/// is the same `CapabilityIssueResult` plus the message id of the
/// envelope sent to the audience.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CapabilityDeliverParams {
    pub audience: AgentAddress,
    pub scope: String,
    /// Optional resource target (e.g. a tool name pattern for
    /// `permission:respond`). `None` = scope applies to any target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_target: Option<String>,
    /// Expiry, seconds from now. `None` = non-expiring.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp_secs: Option<i64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CapabilityDeliverResult {
    /// jti of the newly minted capability.
    pub jti: String,
    /// Envelope id of the `CapabilityGrant` sent to the audience.
    pub envelope_id: MessageId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CapabilityIssueResult {
    pub token: CapabilityToken,
    pub id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CapabilityRevokeParams {
    pub token_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CapabilityRevokeResult {
    pub revoked: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CapabilityListParams {
    /// Include rows whose `revoked_at` is set.
    #[serde(default)]
    pub include_revoked: bool,
    /// Include rows whose `expires_at` is in the past.
    #[serde(default)]
    pub include_expired: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_id: Option<String>,
    /// Which side of the capability table to query — `Issued` (tokens
    /// this daemon minted, default) or `Received` (tokens granted to
    /// us by another agent). Two perspectives, same query shape; the
    /// caller picks which is meaningful for the moment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direction: Option<CapabilityDirection>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CapabilityView {
    pub id: String,
    /// Issuer agent_id — meaningful on Received-direction queries
    /// (which agent granted this to us) and redundant on Issued
    /// (always self_id). Always populated so a single view shape
    /// works for both directions.
    pub issuer: AgentId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<AgentId>,
    pub scope: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<Timestamp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<Timestamp>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CapabilityListResult {
    pub capabilities: Vec<CapabilityView>,
    /// Echo of the direction the server actually queried — lets the
    /// CLI render an unambiguous header even when the operator omits
    /// the flag and inherits the default.
    pub direction: CapabilityDirection,
}

// ---------- brief ----------

/// Publish a self-authored summary of *this* agent's recent activity. The
/// content is whatever the operator (or the agent's own instruction set)
/// chooses to disclose — there is no model in this path.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BriefPublishParams {
    pub summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,
    /// TTL in seconds; defaults to 1 hour. After expiry, `brief.read` returns
    /// `None` rather than the stale text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_secs: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BriefPublishResult {
    pub published_at: Timestamp,
    pub expires_at: Option<Timestamp>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BriefReadParams {
    /// Whose brief to read: `<agent_id>` or `@alias`.
    pub agent: String,
    /// Optional topic filter — match the publisher's `topic` exactly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BriefView {
    pub agent: AgentId,
    pub summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,
    pub published_at: Timestamp,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<Timestamp>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BriefReadResult {
    pub brief: Option<BriefView>,
}

// ---------- presence ----------

/// Set the operator-supplied manual hint. Pass `ttl_secs = None` for a
/// permanent override (until next call); `Some(n)` makes the hint decay to
/// "no manual override" after `n` seconds — useful for short statuses
/// like "in a meeting".
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PresenceSetManualParams {
    pub status: hermod_core::PresenceStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_secs: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PresenceSetManualResult {
    pub set_at: Timestamp,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<Timestamp>,
}

/// Drop the operator's manual hint and return to fully derived presence
/// (online iff a Claude Code session is attached). Idempotent.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PresenceClearManualParams {}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PresenceClearManualResult {
    pub cleared_at: Timestamp,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PresenceGetParams {
    pub agent: String,
}

/// What `presence.get` returns. `status` is the *effective* presence after
/// combining the manual hint with current liveness; `live` and
/// `manual_status` are exposed alongside so callers can render either facet
/// independently.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PresenceView {
    pub agent: AgentId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_local_alias: Option<AgentAlias>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_peer_alias: Option<AgentAlias>,
    /// Best display name available for `agent` — local wins.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_alias: Option<AgentAlias>,
    pub status: hermod_core::PresenceStatus,
    pub live: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manual_status: Option<hermod_core::PresenceStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manual_status_set_at: Option<Timestamp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manual_status_expires_at: Option<Timestamp>,
    /// Last time we observed liveness for this agent — heartbeat for self,
    /// inbound Presence envelope for peers. None when nothing has been
    /// observed yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen_at: Option<Timestamp>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PresenceGetResult {
    pub presence: Option<PresenceView>,
}

// ---------- mcp.attach + mcp.heartbeat + mcp.cursor_advance + mcp.detach ----------

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct McpAttachParams {
    /// `clientInfo.name` from the MCP `initialize` request, e.g. `"Claude Code"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_version: Option<String>,
    /// Operator-supplied stable nickname (`HERMOD_SESSION_LABEL`).
    /// When set, the daemon resumes prior cursors keyed by
    /// `(caller_agent, session_label)` — a Claude Code restart with
    /// the same label picks up where the previous attach left off.
    /// `None` ⇒ ephemeral session, no cursor resumption.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_label: Option<SessionLabel>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct McpAttachResult {
    pub session_id: McpSessionId,
    /// Operator-supplied label, echoed for client display. `None`
    /// when the attach was unlabelled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_label: Option<SessionLabel>,
    /// `true` iff a stale labelled row was found and its cursors
    /// were carried into this attach. `false` for fresh attaches
    /// (no label or label not previously seen).
    pub resumed: bool,
    /// Cadence the daemon expects heartbeats at. The MCP server schedules
    /// its heartbeat task using this so the two ends agree without a config.
    pub heartbeat_interval_secs: u32,
    /// Resumed delivery cursors. Clients seed their pollers from
    /// these — only messages / confirmations / verdicts past these
    /// positions are emitted to the host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_message_id: Option<MessageId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_confirmation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_resolved_seq: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct McpDetachParams {
    pub session_id: McpSessionId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct McpDetachResult {
    pub session_id: McpSessionId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct McpHeartbeatParams {
    pub session_id: McpSessionId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct McpHeartbeatResult {
    /// Server-side ack timestamp. Useful for the client to detect clock skew.
    pub ack_at: Timestamp,
    /// `false` iff the server has no record of this session — the client
    /// should re-attach (typically the daemon was restarted under us).
    pub recognised: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct McpCursorAdvanceParams {
    pub session_id: McpSessionId,
    /// Inbox cursor — last `MessageId` the MCP client successfully
    /// emitted to Claude Code on the channel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_message_id: Option<MessageId>,
    /// Held-confirmation cursor. Stored as opaque string (matches
    /// `PendingConfirmationView.id` shape).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_confirmation_id: Option<String>,
    /// Permission verdict cursor (monotonic seq from `permission.list_resolved`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_resolved_seq: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct McpCursorAdvanceResult {
    /// `false` iff the session_id is unknown — caller should re-attach
    /// before retrying.
    pub recognised: bool,
}

// ---------- local.sessions ----------

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LocalSessionsParams {}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalSessionsResult {
    pub sessions: Vec<McpSessionSummary>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct McpSessionSummary {
    pub session_id: McpSessionId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_label: Option<SessionLabel>,
    pub attached_at: Timestamp,
    pub last_heartbeat_at: Timestamp,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_message_id: Option<MessageId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_confirmation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_resolved_seq: Option<u64>,
}

// ---------- audit ----------

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AuditQueryParams {
    /// Filter by actor — agent_id or @alias.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    /// Filter by action name (e.g. `brief.publish`, `message.delivered`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    /// Only return entries newer than `now - since_secs`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since_secs: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEntryView {
    pub id: i64,
    pub created_at: Timestamp,
    pub actor: AgentId,
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditQueryResult {
    pub entries: Vec<AuditEntryView>,
}

// ---------- workspace ----------

/// Create a new workspace owned by this agent. For `private` the daemon
/// generates a 32-byte secret and returns it hex-encoded — the operator must
/// share it out-of-band with anyone who should join.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkspaceCreateParams {
    pub name: String,
    pub visibility: WorkspaceVisibility,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkspaceCreateResult {
    pub id: String, // 16-byte WorkspaceId, hex
    pub visibility: WorkspaceVisibility,
    /// Present iff visibility == Private.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_hex: Option<String>,
}

/// Join an existing private workspace via shared secret. Public workspaces
/// don't need joining — knowing `(creator_pubkey, name)` is enough.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkspaceJoinParams {
    pub name: String,
    pub secret_hex: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkspaceJoinResult {
    pub id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkspaceView {
    pub id: String,
    pub name: String,
    pub visibility: WorkspaceVisibility,
    pub created_locally: bool,
    pub muted: bool,
    pub joined_at: Timestamp,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_active: Option<Timestamp>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkspaceListResult {
    pub workspaces: Vec<WorkspaceView>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkspaceGetParams {
    pub workspace_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkspaceGetResult {
    pub workspace: Option<WorkspaceView>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkspaceDeleteParams {
    pub workspace_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkspaceDeleteResult {
    pub id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkspaceMuteParams {
    pub workspace_id: String,
    pub muted: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkspaceMuteResult {
    pub id: String,
    pub muted: bool,
}

/// Invite a target agent to join a private workspace by sending them a
/// WorkspaceInvite envelope carrying the secret. The invite lands at the
/// target through the confirmation gate (Sensitivity::Sensitive).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkspaceInviteParams {
    pub workspace_id: String,
    /// `<agent_id>` or `@alias`.
    pub target: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkspaceInviteResult {
    pub id: MessageId,
}

/// Query the workspace roster (gossip-union of every known member's
/// view). Daemon fans out to known members in parallel and unions the
/// returned member sets within a short timeout.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkspaceRosterParams {
    /// Hex-encoded 16-byte workspace id.
    pub workspace_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkspaceRosterResult {
    /// Sorted union of every known + responding member.
    pub members: Vec<hermod_core::AgentId>,
}

/// Query the workspace channel listing (gossip-union of joined +
/// discovered + remote-reported channels).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkspaceChannelsParams {
    pub workspace_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkspaceChannelsResult {
    pub channels: Vec<WorkspaceChannelView>,
}

/// One channel descriptor. `channel_id` is hex-encoded 16-byte id;
/// `name` is the human-readable name.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkspaceChannelView {
    pub channel_id: String,
    pub name: String,
}

// ---------- channel ----------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChannelCreateParams {
    pub workspace_id: String,
    pub name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChannelCreateResult {
    pub id: String, // 16-byte ChannelId, hex
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChannelListParams {
    pub workspace_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChannelView {
    pub id: String,
    pub workspace_id: String,
    pub name: String,
    pub muted: bool,
    pub joined_at: Timestamp,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_active: Option<Timestamp>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChannelDeleteParams {
    pub channel_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChannelDeleteResult {
    pub id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChannelMuteParams {
    pub channel_id: String,
    pub muted: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChannelMuteResult {
    pub id: String,
    pub muted: bool,
}

/// Push a ChannelAdvertise to every known workspace member so they can
/// learn about the channel without us pinging each peer manually.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChannelAdvertiseParams {
    pub channel_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChannelAdvertiseResult {
    pub id: String,
    /// How many workspace members the advertise was fanned out to.
    pub fanout: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChannelDiscoverParams {
    pub workspace_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiscoveredChannelView {
    pub workspace_id: String,
    pub channel_id: String,
    pub channel_name: String,
    pub advertised_by: AgentId,
    pub discovered_at: Timestamp,
    pub last_seen: Timestamp,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChannelDiscoverResult {
    pub channels: Vec<DiscoveredChannelView>,
}

/// Adopt a channel that another workspace member previously advertised.
/// The daemon looks up `discovered_channels` by id, re-derives the channel
/// crypto material from the local workspace secret + channel name, and
/// upserts the channel locally. Idempotent — re-adopting a channel is a
/// no-op.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChannelAdoptParams {
    pub channel_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChannelAdoptResult {
    pub id: String,
    pub workspace_id: String,
    pub name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChannelListResult {
    pub channels: Vec<ChannelView>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChannelHistoryParams {
    pub channel_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChannelMessageView {
    pub id: MessageId,
    pub channel_id: String,
    pub from: AgentId,
    pub text: String,
    pub received_at: Timestamp,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChannelHistoryResult {
    pub messages: Vec<ChannelMessageView>,
}

// ---------- broadcast ----------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BroadcastSendParams {
    pub channel_id: String,
    pub text: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BroadcastSendResult {
    pub id: MessageId,
    /// Number of remote members the broadcast was fanned out to.
    pub fanout: u32,
}

// ---------- confirmation gate ----------

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ConfirmationListParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    /// Cursor; only confirmations with `id > after_id` are returned. ULIDs
    /// are monotonic so this captures "held since this point".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingConfirmationView {
    pub id: String,
    pub requested_at: Timestamp,
    /// Sender of the held envelope. Mirrors `MessageView.from`.
    pub from: AgentId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_local_alias: Option<AgentAlias>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_peer_alias: Option<AgentAlias>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_alias: Option<AgentAlias>,
    /// Mirrors [`MessageView::from_alias_ambiguous`].
    #[serde(default, skip_serializing_if = "is_false")]
    pub from_alias_ambiguous: bool,
    /// Hex-encoded ed25519 host pubkey of the daemon hosting `from`.
    /// Mirrors [`MessageView::from_host_pubkey`] — surfaced for
    /// cross-host disambiguation when local aliases collide.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_host_pubkey: Option<String>,
    /// What the operator would authorise by accepting (e.g.
    /// `"message.deliver"`, `"workspace.invite"`). Mirrors the
    /// `HeldIntent` enum's `as_str()`. Distinct from
    /// `audit_log.action` (which records *events*, not intents).
    pub intent: String,
    pub sensitivity: String,
    pub trust_level: TrustLevel,
    pub summary: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfirmationListResult {
    pub confirmations: Vec<PendingConfirmationView>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfirmationAcceptParams {
    pub confirmation_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfirmationAcceptResult {
    pub id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfirmationRejectParams {
    pub confirmation_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfirmationRejectResult {
    pub id: String,
}

// ---------- audit.verify ----------

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum AuditVerifyResult {
    Ok { rows: u64 },
    BrokenLink { row_id: i64 },
    HashMismatch { row_id: i64 },
    BadSignature { row_id: i64 },
}

// ---------- audit archival ----------

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AuditArchiveNowParams {
    /// Archive every fully-elapsed UTC day older than this many
    /// seconds. `None` defaults to `policy.audit_retention_secs`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub older_than_secs: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditArchiveNowResult {
    pub archives_created: u32,
    pub rows_archived: u64,
    pub archives: Vec<AuditArchiveSummaryView>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditArchiveSummaryView {
    pub epoch_start: Timestamp,
    pub epoch_end: Timestamp,
    pub blob_location: String,
    pub row_count: u64,
    pub file_size: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AuditArchivesListParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditArchivesListResult {
    pub archives: Vec<AuditArchiveIndexView>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditArchiveIndexView {
    pub epoch_start: Timestamp,
    pub epoch_end: Timestamp,
    pub row_count: u64,
    pub file_size: u64,
    pub blob_location: String,
    pub archived_at: Timestamp,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditVerifyArchiveParams {
    /// `epoch_start` of the archive to verify (matches the index PK).
    pub epoch_start: Timestamp,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum AuditVerifyArchiveResult {
    Ok { rows: u64 },
    IndexMissing,
    BlobMissing { blob_location: String },
    ParseError,
    SigInvalid,
    ManifestMismatch,
    BrokenLink { row_id: i64 },
    HashMismatch { row_id: i64 },
}

// ---------- permission relay ----------

/// Verdict for a permission-relay request. Mirrors the `behavior` field of
/// the Claude Code `notifications/claude/channel/permission` notification
/// so the wire format round-trips cleanly.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, strum::EnumIter)]
#[serde(rename_all = "snake_case")]
pub enum PermissionBehavior {
    Allow,
    Deny,
}

impl PermissionBehavior {
    pub fn as_str(&self) -> &'static str {
        match self {
            PermissionBehavior::Allow => "allow",
            PermissionBehavior::Deny => "deny",
        }
    }

    /// Canonical audit-action string. Single source of truth — used by
    /// `services::permission` and pinned by the docs_coverage snapshot
    /// test so a new variant breaks the build until both sites and
    /// `docs/audit_actions.md` catch up.
    pub fn audit_action(&self) -> &'static str {
        match self {
            PermissionBehavior::Allow => "permission.allow",
            PermissionBehavior::Deny => "permission.deny",
        }
    }
}

/// Open a permission-relay request. The MCP server calls this when Claude
/// Code emits `notifications/claude/channel/permission_request`; the daemon
/// mints a 5-letter short id (`hermod_crypto::short_id`) and parks the
/// request in memory until a verdict arrives or the TTL elapses.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PermissionRequestParams {
    /// Tool the host wants to invoke (e.g. `"Bash"`, `"Write"`).
    pub tool_name: String,
    /// Human-readable summary of what this specific call does, mirrored
    /// verbatim from the inbound `description` field.
    pub description: String,
    /// Tool arguments as a JSON string, truncated to ~200 chars by the
    /// caller per the Channels reference.
    pub input_preview: String,
    /// MCP session that originated this prompt. The daemon stores
    /// it on the open request so `permission.list` /
    /// `permission.list_resolved` filtered by `session_id` only
    /// see verdicts originating from the same Claude Code window.
    /// `None` for non-MCP callers (e.g. operator-driven flows that
    /// open a prompt without a session — none today, future-proofing).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<McpSessionId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PermissionRequestResult {
    /// The 5-letter id (alphabet `[a-km-z]`) the operator types back. Echoed
    /// in the eventual `permission.respond` call so the daemon can match the
    /// verdict against an open request.
    pub request_id: String,
    /// Wall-clock instant after which the request will be auto-dropped.
    /// The MCP server can surface this to the operator so a stale prompt
    /// is visibly expired.
    pub expires_at: Timestamp,
}

/// Submit a verdict for a previously-issued permission request. Idempotent
/// per `request_id`: a second call with the same id is a no-op (`matched =
/// false`), matching the Channels reference semantic that whichever side
/// answers first wins.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PermissionRespondParams {
    pub request_id: String,
    pub behavior: PermissionBehavior,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PermissionRespondResult {
    /// `true` iff this verdict was applied to a live request. `false` means
    /// the id was unknown, already-resolved, or expired — the caller should
    /// treat it as a no-op and not retry.
    pub matched: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PermissionListParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    /// Filter to prompts originated from this MCP session. `None`
    /// surfaces every open prompt for the caller agent (operator
    /// CLI use case). `Some(id)` is the Claude Code path —
    /// sibling windows of the same agent only ever observe their
    /// own prompts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<McpSessionId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PermissionRequestView {
    pub request_id: String,
    pub tool_name: String,
    pub description: String,
    pub input_preview: String,
    pub requested_at: Timestamp,
    pub expires_at: Timestamp,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PermissionListResult {
    pub requests: Vec<PermissionRequestView>,
}

/// Cursor-based feed of resolved permission requests. The MCP server polls
/// this to learn that a verdict is ready and emit the corresponding
/// `notifications/claude/channel/permission` frame back to Claude Code.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PermissionListResolvedParams {
    /// Only return entries with `seq > after_seq`. The MCP server advances
    /// this monotonically across batches; on restart the cursor resets to
    /// zero (the in-memory ring buffer in the daemon is naturally
    /// fresh-only, so re-emission of long-stale verdicts is impossible).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    /// Filter to verdicts whose originating prompt was owned by
    /// this MCP session. Critical for multi-instance isolation:
    /// without this filter, sibling Claude Code windows of the same
    /// agent would observe each other's tool-call verdicts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<McpSessionId>,
}

/// Outcome of a resolved permission request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, strum::EnumIter)]
#[serde(rename_all = "snake_case")]
pub enum PermissionOutcome {
    Allow,
    Deny,
    /// TTL elapsed before any verdict arrived. The MCP server should NOT
    /// emit a verdict frame for this case — Claude Code's local terminal
    /// dialog stays open and the host's own timeout takes over.
    Expired,
}

impl PermissionOutcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            PermissionOutcome::Allow => "allow",
            PermissionOutcome::Deny => "deny",
            PermissionOutcome::Expired => "expired",
        }
    }

    /// Canonical audit-action string for the resolved-event family.
    /// Mirrors [`PermissionBehavior::audit_action`] so a sweep over
    /// either enum produces the same set of audit actions.
    pub fn audit_action(&self) -> &'static str {
        match self {
            PermissionOutcome::Allow => "permission.allow",
            PermissionOutcome::Deny => "permission.deny",
            PermissionOutcome::Expired => "permission.expired",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PermissionResolvedView {
    /// Strict-monotonic, daemon-wide. Cursor advances by max(seq).
    pub seq: u64,
    pub request_id: String,
    pub outcome: PermissionOutcome,
    pub resolved_at: Timestamp,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PermissionListResolvedResult {
    pub resolved: Vec<PermissionResolvedView>,
    /// The next `seq` value the daemon will allocate. Always strictly
    /// greater than every `seq` currently in the resolved ring (or `1`
    /// if the ring has never held an entry). Cursor consumers (the MCP
    /// verdict-emitter) compare this against their own `after_seq` to
    /// detect daemon restarts: when `daemon_next_seq <= after_seq` the
    /// daemon's monotonic counter has gone backwards (almost always
    /// because the in-memory ring was wiped on process restart) and the
    /// consumer must reset its cursor to `None` or `0` to avoid
    /// permanently silently dropping verdicts.
    pub daemon_next_seq: u64,
}
