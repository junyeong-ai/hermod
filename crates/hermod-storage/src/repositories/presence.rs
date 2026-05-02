//! Presence + MCP session contracts.
//!
//! Two collaborating repositories:
//!
//! * [`AgentPresenceRepository`] holds the operator's manual hint
//!   (`busy`, `idle`, etc.) for *this* agent and a cache of each peer's
//!   last-advertised liveness.
//!
//! * [`McpSessionRepository`] tracks live MCP stdio sessions attached to
//!   this daemon. The janitor prunes rows older than [`SESSION_TTL_SECS`].
//!
//! The wire-level `presence.get` reply combines both into an *effective*
//! status using [`effective_status`].

use async_trait::async_trait;
use hermod_core::{AgentId, McpSessionId, MessageId, PresenceStatus, SessionLabel, Timestamp};

use crate::error::Result;

/// Default heartbeat cadence. The MCP stdio client sends one heartbeat per
/// interval; the daemon treats a session as stale after [`SESSION_TTL_SECS`].
pub const HEARTBEAT_INTERVAL_SECS: u64 = 30;

/// How long a session can go without a heartbeat before considered dead.
/// Three heartbeat intervals so a single dropped beat isn't fatal.
pub const SESSION_TTL_SECS: u64 = 90;

/// Default freshness window for a peer's advertised liveness.
pub const PEER_LIVE_TTL_SECS: u64 = 3600;

#[derive(Debug, Clone, PartialEq)]
pub struct AgentPresenceRecord {
    pub agent_id: AgentId,
    pub manual_status: Option<PresenceStatus>,
    pub manual_status_set_at: Option<Timestamp>,
    pub manual_status_expires_at: Option<Timestamp>,
    pub peer_live: Option<bool>,
    pub peer_live_updated_at: Option<Timestamp>,
    pub peer_live_expires_at: Option<Timestamp>,
}

impl AgentPresenceRecord {
    /// The publisher-set hint, if it's still active at `now`.
    pub fn active_manual_status(&self, now: Timestamp) -> Option<PresenceStatus> {
        let status = self.manual_status?;
        match self.manual_status_expires_at {
            Some(exp) if exp.unix_ms() <= now.unix_ms() => None,
            _ => Some(status),
        }
    }

    /// The most recent peer-advertised liveness, if still fresh at `now`.
    pub fn active_peer_live(&self, now: Timestamp) -> Option<bool> {
        let live = self.peer_live?;
        match self.peer_live_expires_at {
            Some(exp) if exp.unix_ms() <= now.unix_ms() => None,
            _ => Some(live),
        }
    }
}

/// Pieces from a peer's Presence envelope that the receiver caches verbatim.
#[derive(Debug, Clone, Copy)]
pub struct ObservedPresence {
    pub manual_status: Option<PresenceStatus>,
    pub live: bool,
    pub observed_at: Timestamp,
    pub expires_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq)]
pub struct McpSession {
    pub session_id: McpSessionId,
    /// Locally-hosted agent the bearer authenticated as on
    /// `mcp.attach`. Liveness for that agent is "any active session
    /// row with this `agent_id`".
    pub agent_id: AgentId,
    /// Operator-supplied stable nickname (`HERMOD_SESSION_LABEL`).
    /// `None` for legacy/unlabelled attaches; `Some(label)` allows
    /// resumption of cursors across MCP process restart.
    pub session_label: Option<SessionLabel>,
    pub attached_at: Timestamp,
    pub last_heartbeat_at: Timestamp,
    pub client_name: Option<String>,
    pub client_version: Option<String>,
    /// Delivery cursors. Server-side persisted via `cursor_advance`
    /// after the MCP client writes a batch to stdout — restart
    /// resumes from these positions, not zero.
    pub last_message_id: Option<MessageId>,
    pub last_confirmation_id: Option<String>,
    pub last_resolved_seq: Option<u64>,
}

/// What the caller hands to [`McpSessionRepository::attach`]. Repos
/// own the resume / conflict logic; the service layer just supplies
/// the freshly-minted handle and the operator-provided label.
#[derive(Debug, Clone)]
pub struct AttachParams {
    pub session_id: McpSessionId,
    pub agent_id: AgentId,
    pub session_label: Option<SessionLabel>,
    pub attached_at: Timestamp,
    pub client_name: Option<String>,
    pub client_version: Option<String>,
    /// Heartbeat-staleness cutoff used to classify the prior label
    /// holder (live ⇒ reject, stale ⇒ resume). The service passes
    /// `SESSION_TTL_SECS * 1_000`.
    pub ttl_ms: i64,
}

/// Outcome of [`McpSessionRepository::attach`]. The success branch
/// carries the row as it now stands in the DB (cursors carried over
/// if a stale labelled row was found); the conflict branch carries
/// the live holder's identity so the service can return a clear
/// error to the caller.
#[derive(Debug, Clone)]
pub enum AttachOutcome {
    /// Fresh insert. `resumed` is true iff a stale labelled row
    /// existed and its cursors were carried into the new row;
    /// `was_live` reports whether *any* session for the host was
    /// live before this attach (drives the offline→online presence
    /// broadcast).
    Inserted {
        session: McpSession,
        was_live: bool,
        resumed: bool,
    },
    /// Label is currently held by a live session. The caller
    /// surfaces this as `ServiceError::Conflict`; the operator
    /// either picks a different label or waits for the prior
    /// session's heartbeat TTL to elapse.
    LabelInUse {
        live_session_id: McpSessionId,
        last_heartbeat_at: Timestamp,
    },
}

/// Server-side cursor write. All four fields optional — callers pass
/// only what advanced. Idempotent: the same value twice is a no-op.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CursorAdvance {
    pub last_message_id: Option<MessageId>,
    pub last_confirmation_id: Option<String>,
    pub last_resolved_seq: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DetachOutcome {
    pub was_live: bool,
    pub is_live: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PruneOutcome {
    pub pruned: u64,
    pub was_live: bool,
    pub is_live: bool,
}

#[async_trait]
pub trait AgentPresenceRepository: Send + Sync + std::fmt::Debug {
    async fn set_manual(
        &self,
        agent: &AgentId,
        status: PresenceStatus,
        set_at: Timestamp,
        expires_at: Option<Timestamp>,
    ) -> Result<()>;

    /// Cache a peer's advertised liveness + manual hint.
    async fn observe_peer(&self, peer: &AgentId, observed: ObservedPresence) -> Result<()>;

    async fn clear_manual(&self, agent: &AgentId) -> Result<()>;

    async fn get(&self, agent: &AgentId) -> Result<Option<AgentPresenceRecord>>;
}

#[async_trait]
pub trait McpSessionRepository: Send + Sync + std::fmt::Debug {
    /// Attach a session, atomically resolving label collisions:
    /// stale labelled rows are evicted and their cursors carried;
    /// live labelled rows are reported as [`AttachOutcome::LabelInUse`].
    async fn attach(&self, params: AttachParams) -> Result<AttachOutcome>;

    /// Bump `last_heartbeat_at` to `now`. Returns `false` if the session
    /// row is gone (already detached or pruned).
    async fn heartbeat(&self, session_id: &McpSessionId, now: Timestamp) -> Result<bool>;

    /// Persist delivery cursors. Each `Some(_)` is written; `None`
    /// fields are left untouched. Returns `false` if the session row
    /// is gone (caller should re-attach before retrying).
    async fn cursor_advance(
        &self,
        session_id: &McpSessionId,
        advance: &CursorAdvance,
    ) -> Result<bool>;

    /// Detach a session and report the resulting liveness, atomically.
    async fn detach_atomic(
        &self,
        session_id: &McpSessionId,
        now: Timestamp,
        ttl_ms: i64,
    ) -> Result<DetachOutcome>;

    async fn count_live(&self, now: Timestamp, ttl_ms: i64) -> Result<u64>;

    /// Live-session count for one specific locally-hosted agent.
    /// Used by `PresenceService::view_for` to decide whether *that
    /// agent* (not the host as a whole) is online — distinct
    /// addressable identities mean distinct liveness.
    async fn count_live_for(&self, agent_id: &AgentId, now: Timestamp, ttl_ms: i64) -> Result<u64>;

    /// Live MCP sessions for one locally-hosted agent. Used by
    /// `local.sessions` IPC so the operator can see which Claude
    /// Code windows are currently attached as `agent_id`.
    /// Sorted by `attached_at` ascending (oldest first).
    async fn list_for_agent(
        &self,
        agent_id: &AgentId,
        now: Timestamp,
        ttl_ms: i64,
    ) -> Result<Vec<McpSession>>;

    /// Look up one session by its handle. `None` if pruned or detached.
    async fn get(&self, session_id: &McpSessionId) -> Result<Option<McpSession>>;

    /// Prune stale rows and report the liveness transition.
    async fn prune_with_transition(&self, now: Timestamp, ttl_ms: i64) -> Result<PruneOutcome>;
}

/// Combine the cached/manual record with current self-liveness into the
/// effective presence status.
///
/// Precedence:
///   1. Active manual hint (operator/agent override).
///   2. Liveness — `online` if live, `offline` otherwise.
pub fn effective_status(
    rec: Option<&AgentPresenceRecord>,
    live: bool,
    now: Timestamp,
) -> PresenceStatus {
    if let Some(s) = rec.and_then(|r| r.active_manual_status(now)) {
        return s;
    }
    if live {
        PresenceStatus::Online
    } else {
        PresenceStatus::Offline
    }
}
