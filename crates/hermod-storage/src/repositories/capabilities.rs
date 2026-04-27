//! Capability token storage contract.

use async_trait::async_trait;
use hermod_core::{AgentId, CapabilityDirection, Timestamp};

use crate::error::Result;

#[derive(Debug, Clone, Default)]
pub struct CapabilityFilter {
    pub include_revoked: bool,
    pub include_expired: bool,
    pub limit: Option<u32>,
    pub after_id: Option<String>,
    /// Restrict listing to issued vs received rows. `None` (default)
    /// returns issued only — the legacy "what did I grant?" view —
    /// to keep `capability list` callers without explicit direction
    /// from accidentally seeing received-side rows.
    pub direction: Option<CapabilityDirection>,
}

#[derive(Debug, Clone)]
pub struct CapabilityRecord {
    pub id: String,
    pub issuer: AgentId,
    pub audience: Option<AgentId>,
    pub scope: String,
    pub target: Option<String>,
    pub expires_at: Option<Timestamp>,
    pub revoked_at: Option<Timestamp>,
    pub raw_token: Vec<u8>,
}

#[async_trait]
pub trait CapabilityRepository: Send + Sync + std::fmt::Debug {
    /// Issuer-side upsert (this daemon minted the cap).
    async fn upsert(&self, cap: &CapabilityRecord) -> Result<()>;

    /// Audience-side upsert (cap delivered to us by another agent).
    async fn upsert_received(&self, cap: &CapabilityRecord) -> Result<()>;

    async fn revoke(&self, id: &str, at: Timestamp) -> Result<bool>;
    async fn is_revoked(&self, id: &str) -> Result<bool>;

    /// Drop expired capability rows.
    async fn prune_terminal(&self, now_ms: i64) -> Result<u64>;

    /// Distinct audience agent_ids holding an active issued capability for
    /// `scope` from `issuer`. Used by federated-relay fan-out.
    async fn active_audiences_for_scope(
        &self,
        issuer: &AgentId,
        scope: &str,
        now_ms: i64,
    ) -> Result<Vec<AgentId>>;

    /// Find a received capability authorising `audience` to invoke `scope`
    /// against `issuer`. Returns the most recently issued matching row.
    async fn find_active_received(
        &self,
        issuer: &AgentId,
        scope: &str,
        now_ms: i64,
    ) -> Result<Option<CapabilityRecord>>;

    /// List capabilities for the operator's agent. The pivot column is
    /// chosen by the backend based on `filter.direction`: `issuer = self_id`
    /// for Issued, `audience = self_id` for Received.
    async fn list(
        &self,
        self_id: &AgentId,
        now_ms: i64,
        filter: &CapabilityFilter,
    ) -> Result<Vec<CapabilityRecord>>;
}
