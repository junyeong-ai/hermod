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
use hermod_core::{AgentId, PresenceStatus, Timestamp};

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
    pub session_id: String,
    pub attached_at: Timestamp,
    pub last_heartbeat_at: Timestamp,
    pub client_name: Option<String>,
    pub client_version: Option<String>,
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
    /// Attach a session and report whether self was already live before the
    /// insert, in a single transaction.
    async fn attach_atomic(&self, session: &McpSession, ttl_ms: i64) -> Result<bool>;

    /// Bump `last_heartbeat_at` to `now`. Returns `false` if the session
    /// row is gone (already detached or pruned).
    async fn heartbeat(&self, session_id: &str, now: Timestamp) -> Result<bool>;

    /// Detach a session and report the resulting liveness, atomically.
    async fn detach_atomic(
        &self,
        session_id: &str,
        now: Timestamp,
        ttl_ms: i64,
    ) -> Result<DetachOutcome>;

    async fn count_live(&self, now: Timestamp, ttl_ms: i64) -> Result<u64>;

    /// Prune stale rows and report the liveness transition.
    async fn prune_with_transition(
        &self,
        now: Timestamp,
        ttl_ms: i64,
    ) -> Result<PruneOutcome>;
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
