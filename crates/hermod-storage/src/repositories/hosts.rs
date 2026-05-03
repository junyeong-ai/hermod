//! Federation host directory.
//!
//! A host is a *daemon* — the entity authenticated by the federation
//! Noise XX handshake. The host is never an envelope recipient (that
//! role belongs to the agents it carries); keeping hosts in their own
//! table means peer enumeration, fan-out, and the dial pool never
//! need to filter "is this row a host or an agent?" out of one
//! conflated directory.
//!
//! Identity model: `id = base32(blake3(pubkey))[:26]`, same derivation
//! as `AgentId`. The table-level `pubkey` UNIQUE keeps the (id,
//! pubkey) pair self-certifying.

use async_trait::async_trait;
use hermod_core::{AgentAlias, AgentId, Endpoint, PubkeyBytes, Timestamp};

use crate::error::Result;

/// One row of the host directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostRecord {
    /// `agent_id_from_pubkey(pubkey)` — same shape as `AgentId` so a
    /// single newtype carries either kind of identity through the
    /// codebase.
    pub id: AgentId,
    pub pubkey: PubkeyBytes,
    /// Federation dial target (`wss://host:port`). NULL when the host
    /// has only ever been observed via inbound TOFU and the operator
    /// hasn't run `peer add --endpoint <wss://>` yet.
    pub endpoint: Option<Endpoint>,
    /// SHA-256 of the host's TLS leaf cert DER, captured on first
    /// successful TLS handshake. Pinned per-host (every agent on
    /// this host shares this cert).
    pub tls_fingerprint: Option<String>,
    /// Host-level peer-claimed display name. Distinct from
    /// `AgentRecord::peer_asserted_alias` (the agent persona's
    /// self-claim).
    pub peer_asserted_alias: Option<AgentAlias>,
    pub first_seen: Timestamp,
    pub last_seen: Option<Timestamp>,
}

/// Outcome of `replace_tls_fingerprint`. The previous fingerprint and
/// endpoint are returned so the caller can evict the matching pool
/// entry without a TOCTOU window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepinOutcome {
    Replaced {
        previous: Option<String>,
        endpoint: Option<Endpoint>,
    },
    NotFound,
}

/// Outcome of `forget`. `prior_endpoint` lets the caller evict the
/// matching pool entry without a TOCTOU window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForgetOutcome {
    pub existed: bool,
    pub prior_endpoint: Option<Endpoint>,
}

#[async_trait]
pub trait HostRepository: Send + Sync + std::fmt::Debug {
    /// Idempotent upsert. Identity-shaped fields (`pubkey`, `id`) are
    /// always written; `endpoint`, `tls_fingerprint`,
    /// `peer_asserted_alias` follow COALESCE semantics so re-observing
    /// a host with partial information never clears a known value.
    /// `last_seen` always advances.
    async fn upsert(&self, record: &HostRecord) -> Result<()>;

    async fn get(&self, id: &AgentId) -> Result<Option<HostRecord>>;

    async fn get_by_pubkey(&self, pubkey: &PubkeyBytes) -> Result<Option<HostRecord>>;

    async fn list(&self) -> Result<Vec<HostRecord>>;

    /// Atomic TOFU primitive for a host's federation TLS cert. Pins
    /// `tls_fingerprint` if currently `NULL`. Returns `Ok(true)` if
    /// pinned or already matched, `Ok(false)` if a different
    /// fingerprint is stored (caller decides: alert and refuse,
    /// or operator-driven repin).
    async fn pin_or_match_tls_fingerprint(&self, id: &AgentId, observed: &str) -> Result<bool>;

    /// Replace the stored TLS fingerprint unconditionally. The
    /// operator-driven `peer.repin` path uses this after confirming
    /// the new cert out of band; returns the previous fingerprint
    /// + endpoint so the caller can evict the matching pool entry
    /// in the same step. `peer.repin`'s trust-level gate runs in
    /// the daemon (against the agent row) before this call.
    async fn replace_tls_fingerprint(&self, id: &AgentId, new: &str) -> Result<RepinOutcome>;

    /// Drop a host's federation endpoint and TLS pin without deleting
    /// the row. Atomic read-then-clear so the caller can evict the
    /// matching pool entry without a TOCTOU window.
    async fn forget(&self, id: &AgentId) -> Result<ForgetOutcome>;

    async fn touch(&self, id: &AgentId, at: Timestamp) -> Result<()>;
}
