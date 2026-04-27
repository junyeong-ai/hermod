//! Workspace + channel + member contracts.

use async_trait::async_trait;
use hermod_core::{AgentId, Timestamp, WorkspaceVisibility};
use hermod_crypto::{ChannelId, ChannelMacKey, WorkspaceId, WorkspaceSecret};

use crate::error::Result;

#[derive(Debug, Clone)]
pub struct WorkspaceRecord {
    pub id: WorkspaceId,
    pub name: String,
    pub visibility: WorkspaceVisibility,
    /// Present iff `visibility == Private`.
    pub secret: Option<WorkspaceSecret>,
    /// True iff this daemon called `workspace.create` on this row.
    pub created_locally: bool,
    pub muted: bool,
    pub joined_at: Timestamp,
    pub last_active: Option<Timestamp>,
}

#[derive(Debug, Clone)]
pub struct ChannelRecord {
    pub id: ChannelId,
    pub workspace_id: WorkspaceId,
    pub name: String,
    /// Present iff the parent workspace is private.
    pub mac_key: Option<ChannelMacKey>,
    pub muted: bool,
    pub joined_at: Timestamp,
    pub last_active: Option<Timestamp>,
}

#[derive(Debug, Clone)]
pub struct ChannelMessage {
    pub id: hermod_core::MessageId,
    pub channel_id: ChannelId,
    pub from_agent: AgentId,
    pub body_text: String,
    pub received_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DiscoveredChannel {
    pub workspace_id: WorkspaceId,
    pub channel_id: ChannelId,
    pub channel_name: String,
    pub advertised_by: AgentId,
    pub discovered_at: Timestamp,
    pub last_seen: Timestamp,
}

#[async_trait]
pub trait WorkspaceRepository: Send + Sync + std::fmt::Debug {
    async fn upsert(&self, w: &WorkspaceRecord) -> Result<()>;
    async fn get(&self, id: &WorkspaceId) -> Result<Option<WorkspaceRecord>>;
    async fn list(&self) -> Result<Vec<WorkspaceRecord>>;
    /// Cascades to channels, channel_messages, workspace_members.
    async fn delete(&self, id: &WorkspaceId) -> Result<bool>;
    async fn set_muted(&self, id: &WorkspaceId, muted: bool) -> Result<bool>;
}

#[async_trait]
pub trait ChannelRepository: Send + Sync + std::fmt::Debug {
    async fn upsert(&self, c: &ChannelRecord) -> Result<()>;
    async fn get(&self, id: &ChannelId) -> Result<Option<ChannelRecord>>;
    async fn list_in(&self, workspace: &WorkspaceId) -> Result<Vec<ChannelRecord>>;
    /// Cascades to channel_messages.
    async fn delete(&self, id: &ChannelId) -> Result<bool>;
    async fn set_muted(&self, id: &ChannelId, muted: bool) -> Result<bool>;
    async fn record_message(&self, m: &ChannelMessage) -> Result<()>;
    async fn history(&self, channel: &ChannelId, limit: u32) -> Result<Vec<ChannelMessage>>;
}

#[async_trait]
pub trait DiscoveredChannelRepository: Send + Sync + std::fmt::Debug {
    /// Upsert by (workspace_id, channel_id) — re-advertise refreshes
    /// `last_seen` and the advertiser.
    async fn observe(
        &self,
        workspace_id: &WorkspaceId,
        channel_id: &ChannelId,
        channel_name: &str,
        advertised_by: &AgentId,
        now: Timestamp,
    ) -> Result<()>;

    async fn list_in(&self, workspace_id: &WorkspaceId) -> Result<Vec<DiscoveredChannel>>;
    async fn get(&self, channel_id: &ChannelId) -> Result<Option<DiscoveredChannel>>;
    async fn prune_older_than(&self, cutoff_ms: i64) -> Result<u64>;
}

#[async_trait]
pub trait WorkspaceMemberRepository: Send + Sync + std::fmt::Debug {
    async fn touch(
        &self,
        workspace: &WorkspaceId,
        agent: &AgentId,
        now: Timestamp,
    ) -> Result<()>;

    async fn list(&self, workspace: &WorkspaceId) -> Result<Vec<AgentId>>;

    /// Distinct agents across every workspace I'm a member of, excluding
    /// `exclude` (typically self). Used for brief / presence fanout.
    async fn list_distinct_excluding(&self, exclude: &AgentId) -> Result<Vec<AgentId>>;
}
