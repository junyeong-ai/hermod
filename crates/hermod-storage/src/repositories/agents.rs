//! Agent directory contract.

use async_trait::async_trait;
use hermod_core::{
    AgentAlias, AgentId, CapabilityTagSet, Endpoint, PubkeyBytes, Timestamp, TrustLevel,
};

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
#[derive(Debug, Clone)]
pub struct AgentRecord {
    pub id: AgentId,
    /// Agent's own ed25519 public key — verifies envelope signatures.
    pub pubkey: PubkeyBytes,
    /// Host's ed25519 public key — the static key the *daemon* hosting
    /// this agent presents during the federation Noise XX handshake.
    /// Multiple agents on the same host share one `host_pubkey`.
    /// `None` for legacy entries observed before the host key was
    /// learned. For our own hosted agents (rows joined to `local_agents`),
    /// equals this daemon's host pubkey.
    pub host_pubkey: Option<PubkeyBytes>,
    /// Network endpoint of the host (`wss://host:port`). Host-level,
    /// not agent-level — multiple agents at one endpoint.
    pub endpoint: Option<Endpoint>,
    /// Indirect routing target. NULL ⇒ dial `endpoint` directly.
    /// `Some(broker)` ⇒ envelopes addressed to this agent are
    /// dispatched to the broker's endpoint with `to.id` preserved;
    /// the broker's `BrokerMode::RelayOnly` fall-through relays the
    /// second hop. Mutually exclusive with `endpoint` at the schema
    /// level — operators choose direct OR brokered, never both.
    pub via_agent: Option<AgentId>,
    pub local_alias: Option<AgentAlias>,
    pub peer_asserted_alias: Option<AgentAlias>,
    pub trust_level: TrustLevel,
    /// SHA-256 of the *host*'s TLS cert DER, captured on first
    /// successful TLS handshake. Pinned per-host (multiple agents on
    /// the same host share one cert). Lowercase, colon-separated.
    pub tls_fingerprint: Option<String>,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForgetOutcome {
    pub existed: bool,
    pub prior_endpoint: Option<Endpoint>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepinOutcome {
    Replaced {
        previous: Option<String>,
        endpoint: Option<Endpoint>,
    },
    TrustMismatch {
        actual: TrustLevel,
    },
    NotFound,
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

    /// Peers with a federation endpoint registered.
    async fn list_federated(&self) -> Result<Vec<AgentRecord>>;

    /// Replace `peer_asserted_tags` for one row. Used by the
    /// inbound `peer.advertise` acceptor on every advertise — the
    /// sender's most-recent claim is authoritative for the
    /// peer-side facet, just like `peer_asserted_alias`. Tags are
    /// validated through `CapabilityTagSet::parse_lossy` upstream;
    /// this method just persists the result.
    async fn set_peer_asserted_tags(&self, id: &AgentId, tags: &CapabilityTagSet) -> Result<()>;

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

    /// Atomic TOFU primitive for a peer's federation TLS cert. Pins
    /// `tls_fingerprint` if currently `NULL`. Returns `Ok(true)` if pinned or
    /// already matched, `Ok(false)` if a different fingerprint is stored.
    async fn pin_or_match_tls_fingerprint(&self, id: &AgentId, observed: &str) -> Result<bool>;

    /// Replace the stored TLS fingerprint, requiring the row's current
    /// trust level to match `require`. Used by `peer.repin`.
    async fn replace_tls_fingerprint(
        &self,
        id: &AgentId,
        new: &str,
        require: TrustLevel,
    ) -> Result<RepinOutcome>;

    /// Drop a peer's federation endpoint and TLS pin without deleting the
    /// agent row. Read-then-clear is atomic so the caller can use
    /// `prior_endpoint` to evict the matching pool entry without a TOCTOU
    /// window.
    async fn forget_peer(&self, id: &AgentId) -> Result<ForgetOutcome>;
}
