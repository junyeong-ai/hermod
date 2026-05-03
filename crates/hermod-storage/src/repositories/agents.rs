//! Agent directory contract.

use async_trait::async_trait;
use hermod_core::{AgentAlias, AgentId, CapabilityTagSet, PubkeyBytes, Timestamp, TrustLevel};

use crate::error::Result;

/// One row of the agent directory.
///
/// Identity / display split (best practice — Signal / GitHub / PGP):
///   * **Identity**: `id` (ed25519 pubkey hash) is the canonical
///     identifier. Routing, crypto, audit, every foreign key references
///     `id`. Immutable.
///   * **Operator's local label**: `local_alias` is what *this* daemon's
///     operator chose to call this peer. Sacred — peer self-claims never
///     overwrite it. UNIQUE within the daemon. Used for `--to @alias`
///     resolution.
///   * **Peer's self-asserted label**: `peer_asserted_alias` is what the
///     peer claims their own display name is, as observed in their
///     latest signed Hello / Presence frame. Advisory — never used for
///     routing, never UNIQUE-constrained.
///
/// **Routing**: an agent is reachable via either its host (`host_id`
/// FK → `hosts.endpoint`) or a broker (`via_agent` FK → another
/// agent that relays on its behalf). Mutually exclusive at the
/// schema level. A directory-only entry (both `None`) is known but
/// not yet routable; subsequent `peer.advertise` / `peer add` fills
/// in the routing target.
#[derive(Debug, Clone)]
pub struct AgentRecord {
    pub id: AgentId,
    /// Agent's own ed25519 public key — verifies envelope signatures.
    pub pubkey: PubkeyBytes,
    /// FK → `hosts.id`. The daemon this agent runs on; the host
    /// record carries the federation endpoint + TLS pin used to
    /// dial. `None` for entries observed before the host was
    /// learned (e.g. a brokered peer registered before the broker
    /// brought the underlying host record online).
    pub host_id: Option<AgentId>,
    /// Indirect routing target. NULL ⇒ dial `host_id`'s endpoint
    /// directly. `Some(broker)` ⇒ envelopes addressed to this agent
    /// are dispatched to the broker's host with `to.id` preserved;
    /// the broker's `BrokerMode::RelayOnly` fall-through relays the
    /// second hop. Mutually exclusive with `host_id` at the schema
    /// level.
    pub via_agent: Option<AgentId>,
    pub local_alias: Option<AgentAlias>,
    pub peer_asserted_alias: Option<AgentAlias>,
    pub trust_level: TrustLevel,
    /// Operator-managed feedback signal.
    pub reputation: i64,
    pub first_seen: Timestamp,
    pub last_seen: Option<Timestamp>,
    /// Capability tags the *peer* claimed about themselves in
    /// their most recent `PeerAdvertise`. Discovery-only metadata,
    /// **never trust-bearing** (see
    /// `hermod_core::capability_tag` module docs +
    /// `scripts/check_trust_boundaries.sh`). Empty for peers that
    /// have never advertised.
    ///
    /// Persistence semantics:
    ///   * `upsert_observed` (peer-driven) — latest-wins. The set
    ///     in this `AgentRecord` is written verbatim, including
    ///     the empty set when a peer drops every label.
    ///   * `upsert` (operator-driven) — peer-asserted is owned by
    ///     the peer; the conflict path leaves the existing column
    ///     untouched.
    pub peer_asserted_tags: CapabilityTagSet,
}

impl AgentRecord {
    /// Operator's label wins; peer self-claim is the fallback.
    pub fn effective_alias(&self) -> Option<&AgentAlias> {
        self.local_alias
            .as_ref()
            .or(self.peer_asserted_alias.as_ref())
    }
}

/// Outcome of an inbound (peer-driven) upsert. The receiver-side `local_alias`
/// is sacred — if a peer's claim collides with an existing local label,
/// only the peer-asserted slot updates, and the collision is reported so
/// callers can audit it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AliasOutcome {
    Accepted,
    LocalDropped {
        proposed: AgentAlias,
        conflicting_id: AgentId,
    },
}

#[async_trait]
pub trait AgentRepository: Send + Sync + std::fmt::Debug {
    /// Operator-driven upsert (e.g. `init`, `peer add`, `agent register`).
    async fn upsert(&self, record: &AgentRecord) -> Result<()>;

    /// Inbound upsert that respects receiver sovereignty. Atomic: in one
    /// transaction, looks up whether the proposed `local_alias` (if any) is
    /// already attached to a *different* agent_id. If so, drops just that
    /// field and reports `AliasOutcome::LocalDropped`.
    async fn upsert_observed(&self, record: &AgentRecord) -> Result<AliasOutcome>;

    async fn get(&self, id: &AgentId) -> Result<Option<AgentRecord>>;

    /// Resolve `--to @alias`. **`local_alias` only** — peer self-claims are
    /// never routable.
    async fn get_by_local_alias(&self, alias: &AgentAlias) -> Result<Option<AgentRecord>>;

    async fn list(&self) -> Result<Vec<AgentRecord>>;

    /// Remote agents reachable via the federation pool — carry a
    /// `host_id` (direct) or `via_agent` (brokered), and are NOT
    /// hosted by this daemon (excluded via the `local_agents`
    /// sub-relation). Used by every operator-facing peer
    /// enumeration: `peer list`, `peer advertise` fan-out, status
    /// peer count. The local-agent exclusion keeps us from
    /// fan-out-looping a daemon's own advertise back to itself.
    async fn list_federated(&self) -> Result<Vec<AgentRecord>>;

    /// Count agents whose effective alias (local override winning,
    /// peer-asserted as fallback) equals `alias`, *excluding* the
    /// `exclude` row itself. Used by sender projections to surface
    /// the `from_alias_ambiguous` flag — receivers see "this name
    /// isn't unique on your roster" without the daemon needing to
    /// compute the full collision set.
    async fn count_with_effective_alias(
        &self,
        alias: &AgentAlias,
        exclude: &AgentId,
    ) -> Result<u64>;

    async fn set_trust(&self, id: &AgentId, trust: TrustLevel) -> Result<()>;
    async fn touch(&self, id: &AgentId, at: Timestamp) -> Result<()>;

    /// Pin direct routing: this agent is dialled through `host_id`'s
    /// federation endpoint. Atomic with `via_agent` clear, so the
    /// `host_id XOR via_agent` CHECK invariant is satisfied without
    /// a multi-statement window. Operator-driven (`peer add
    /// --endpoint`); never invoked from the inbound path.
    async fn set_routing_direct(&self, id: &AgentId, host_id: &AgentId) -> Result<()>;

    /// Pin brokered routing: this agent is dialled through
    /// `via_agent`'s host endpoint with `to.id` preserved on the
    /// envelope. Atomic with `host_id` clear. Operator-driven
    /// (`peer add --via`).
    async fn set_routing_brokered(&self, id: &AgentId, via_agent: &AgentId) -> Result<()>;

    /// Drop both routing pointers without deleting the agent row.
    /// Used by `peer.remove`'s service path after the host's endpoint
    /// has been forgotten — the agent row stays in the directory for
    /// audit / capability lineage but becomes "directory-only / not
    /// yet routable".
    async fn clear_routing(&self, id: &AgentId) -> Result<()>;
}
