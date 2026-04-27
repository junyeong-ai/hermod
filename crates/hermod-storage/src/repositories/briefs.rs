//! Per-agent self-published "what I'm doing" summary contract.

use async_trait::async_trait;
use hermod_core::{AgentId, Timestamp};

use crate::error::Result;

#[derive(Debug, Clone, PartialEq)]
pub struct BriefRecord {
    pub agent_id: AgentId,
    /// `None` is the default (untagged) brief; each named topic gets its
    /// own slot per agent. The `(agent_id, topic)` pair is unique.
    pub topic: Option<String>,
    pub summary: String,
    pub published_at: Timestamp,
    pub expires_at: Option<Timestamp>,
}

#[async_trait]
pub trait BriefRepository: Send + Sync + std::fmt::Debug {
    /// Drop briefs whose `expires_at` is older than `now_ms`. Returns rows swept.
    async fn prune_expired(&self, now_ms: i64) -> Result<u64>;

    async fn upsert(&self, record: &BriefRecord) -> Result<()>;

    /// Most recent unexpired brief for `agent`, optionally filtered by topic.
    async fn latest(
        &self,
        agent: &AgentId,
        topic: Option<&str>,
        now_ms: i64,
    ) -> Result<Option<BriefRecord>>;
}
