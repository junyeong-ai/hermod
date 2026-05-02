//! Sub-relation for agents this daemon hosts.
//!
//! `agents` (the directory) carries every agent we know about — peers
//! and ours alike. `local_agents` is the strict subset we *host*: we
//! hold their private keypair (on disk under
//! `$HERMOD_HOME/agents/<id>/`), and we issue per-agent bearer tokens
//! that authenticate IPC connections as that agent.
//!
//! The split keeps the public-facing directory and the privileged
//! local material on separate access paths — every non-host code site
//! reads from `AgentRepository`; only the very few flows that need
//! the host material (boot identity load, IPC auth, `hermod local
//! rotate`) touch `LocalAgentRepository`.

use async_trait::async_trait;
use hermod_core::{AgentId, CapabilityTagSet, Timestamp};

use crate::error::Result;

/// One row of the local-agent registry.
///
/// `bearer_hash` is the blake3 of the raw token. The raw token lives
/// in the filesystem at `$HERMOD_HOME/agents/<agent_id>/bearer_token`
/// (mode 0600); only its hash is in the DB. This keeps the DB
/// snapshot useless to an attacker without filesystem access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalAgentRecord {
    pub agent_id: AgentId,
    pub bearer_hash: [u8; 32],
    /// Operator-set context — typically the project root path. Surfaced
    /// in the MCP server's `instructions` so Claude Code can announce
    /// which project this agent represents.
    pub workspace_root: Option<String>,
    pub created_at: Timestamp,
    /// Operator-set capability tags. Discovery metadata only —
    /// propagated to peers via `peer.advertise`; never trust-bearing.
    /// Empty for agents the operator hasn't tagged yet.
    pub tags: CapabilityTagSet,
}

/// Outcome of `LocalAgentRepository::insert` — distinguishes the two
/// success paths an operator cares about. Replaces a generic
/// `Result<()>` so a stale alias collision surfaces as a typed signal
/// the CLI can render without parsing error text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalAgentInsertOutcome {
    Created,
    /// An agent with this `agent_id` is already hosted. The caller
    /// should not silently overwrite; `hermod local rotate` is the
    /// supported path for credential refresh.
    AlreadyHosted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalAgentRemoveOutcome {
    Removed,
    NotFound,
}

#[async_trait]
pub trait LocalAgentRepository: Send + Sync + std::fmt::Debug {
    /// Register a new local agent. Idempotent on (agent_id) — repeated
    /// inserts of the same id return [`LocalAgentInsertOutcome::AlreadyHosted`]
    /// without overwriting the bearer hash. Use [`Self::rotate_bearer`]
    /// to refresh credentials.
    async fn insert(&self, record: &LocalAgentRecord) -> Result<LocalAgentInsertOutcome>;

    async fn list(&self) -> Result<Vec<LocalAgentRecord>>;

    async fn lookup_by_id(&self, id: &AgentId) -> Result<Option<LocalAgentRecord>>;

    /// Bearer-hash → agent_id mapping. The IPC handshake's hot path —
    /// must be O(log n) (indexed in the schema).
    async fn lookup_by_bearer_hash(&self, hash: &[u8; 32]) -> Result<Option<AgentId>>;

    /// Replace the bearer hash for an existing agent. Used by
    /// `hermod local rotate <alias>` and by any future "force-rotate
    /// every bearer" flow. The caller is responsible for invalidating
    /// any in-flight IPC session held under the previous bearer
    /// (see `LocalAgentRegistry::rotate_bearer` in the daemon).
    async fn rotate_bearer(&self, id: &AgentId, new_hash: [u8; 32]) -> Result<bool>;

    /// Replace the operator-set tag set for one local agent. Used
    /// by `hermod local tag set <agent> <tags…>`. Returns `true` if
    /// the row exists and was updated, `false` if no such agent.
    /// Caller has already validated through `CapabilityTagSet::from_validated`.
    async fn set_tags(&self, id: &AgentId, tags: &CapabilityTagSet) -> Result<bool>;

    /// Remove the local-agent row. The matching `agents` row is *not*
    /// touched here — operator policy decides whether to also forget
    /// the directory entry. (`hermod local rm` cascades both.)
    async fn remove(&self, id: &AgentId) -> Result<LocalAgentRemoveOutcome>;
}
