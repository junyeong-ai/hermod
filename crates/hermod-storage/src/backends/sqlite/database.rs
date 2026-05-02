//! `Database` implementation backed by SQLite.

use async_trait::async_trait;
use hermod_crypto::Signer;
use sqlx::SqlitePool;
use std::path::Path;
use std::sync::Arc;

use crate::blobs::BlobStore;
use crate::database::{Database, MetricsSnapshot};
use crate::error::Result;
use crate::repositories::{
    agents::AgentRepository,
    audit::AuditRepository,
    briefs::BriefRepository,
    capabilities::CapabilityRepository,
    confirmations::ConfirmationRepository,
    local_agents::LocalAgentRepository,
    messages::MessageRepository,
    notifications::NotificationRepository,
    presence::{AgentPresenceRepository, McpSessionRepository},
    rate_limit::RateLimitRepository,
    workspaces::{
        ChannelRepository, DiscoveredChannelRepository, WorkspaceMemberRepository,
        WorkspaceRepository,
    },
};

use super::agents::SqliteAgentRepository;
use super::audit::SqliteAuditRepository;
use super::briefs::SqliteBriefRepository;
use super::capabilities::SqliteCapabilityRepository;
use super::confirmations::SqliteConfirmationRepository;
use super::local_agents::SqliteLocalAgentRepository;
use super::messages::SqliteMessageRepository;
use super::notifications::SqliteNotificationRepository;
use super::pool::{open_pool, run_migrations};
use super::presence::{SqliteAgentPresenceRepository, SqliteMcpSessionRepository};
use super::rate_limit::SqliteRateLimitRepository;
use super::workspaces::{
    SqliteChannelRepository, SqliteDiscoveredChannelRepository, SqliteWorkspaceMemberRepository,
    SqliteWorkspaceRepository,
};

#[derive(Clone)]
pub struct SqliteDatabase {
    pool: SqlitePool,
    blobs: Arc<dyn BlobStore>,
    agents: SqliteAgentRepository,
    audit: SqliteAuditRepository,
    briefs: SqliteBriefRepository,
    capabilities: SqliteCapabilityRepository,
    channels: SqliteChannelRepository,
    confirmations: SqliteConfirmationRepository,
    discovered_channels: SqliteDiscoveredChannelRepository,
    local_agents: SqliteLocalAgentRepository,
    mcp_sessions: SqliteMcpSessionRepository,
    messages: SqliteMessageRepository,
    notifications: SqliteNotificationRepository,
    presences: SqliteAgentPresenceRepository,
    rate_limits: SqliteRateLimitRepository,
    workspaces: SqliteWorkspaceRepository,
    workspace_members: SqliteWorkspaceMemberRepository,
}

impl std::fmt::Debug for SqliteDatabase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqliteDatabase")
            .field("pool", &self.pool)
            .field("blobs", &self.blobs)
            .finish_non_exhaustive()
    }
}

impl SqliteDatabase {
    pub async fn connect(
        path: &Path,
        signer: Arc<dyn Signer>,
        blobs: Arc<dyn BlobStore>,
    ) -> Result<Self> {
        let pool = open_pool(path).await?;
        run_migrations(&pool).await?;
        Ok(Self {
            pool: pool.clone(),
            blobs,
            agents: SqliteAgentRepository::new(pool.clone()),
            audit: SqliteAuditRepository::new(pool.clone(), signer),
            briefs: SqliteBriefRepository::new(pool.clone()),
            capabilities: SqliteCapabilityRepository::new(pool.clone()),
            channels: SqliteChannelRepository::new(pool.clone()),
            confirmations: SqliteConfirmationRepository::new(pool.clone()),
            discovered_channels: SqliteDiscoveredChannelRepository::new(pool.clone()),
            local_agents: SqliteLocalAgentRepository::new(pool.clone()),
            mcp_sessions: SqliteMcpSessionRepository::new(pool.clone()),
            messages: SqliteMessageRepository::new(pool.clone()),
            notifications: SqliteNotificationRepository::new(pool.clone()),
            presences: SqliteAgentPresenceRepository::new(pool.clone()),
            rate_limits: SqliteRateLimitRepository::new(pool.clone()),
            workspaces: SqliteWorkspaceRepository::new(pool.clone()),
            workspace_members: SqliteWorkspaceMemberRepository::new(pool.clone()),
        })
    }

    /// Backend pool — exposed for tests that exercise the SQLite layer
    /// directly (e.g. tampering with `audit_log` to verify the chain
    /// detection). Production code stays on the `Database` trait.
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }
}

#[async_trait]
impl Database for SqliteDatabase {
    fn backend(&self) -> crate::DatabaseBackend {
        crate::DatabaseBackend::Sqlite
    }

    fn agents(&self) -> &dyn AgentRepository {
        &self.agents
    }
    fn audit(&self) -> &dyn AuditRepository {
        &self.audit
    }
    fn blobs(&self) -> Arc<dyn BlobStore> {
        self.blobs.clone()
    }
    fn briefs(&self) -> &dyn BriefRepository {
        &self.briefs
    }
    fn capabilities(&self) -> &dyn CapabilityRepository {
        &self.capabilities
    }
    fn channels(&self) -> &dyn ChannelRepository {
        &self.channels
    }
    fn confirmations(&self) -> &dyn ConfirmationRepository {
        &self.confirmations
    }
    fn discovered_channels(&self) -> &dyn DiscoveredChannelRepository {
        &self.discovered_channels
    }
    fn local_agents(&self) -> &dyn LocalAgentRepository {
        &self.local_agents
    }
    fn mcp_sessions(&self) -> &dyn McpSessionRepository {
        &self.mcp_sessions
    }
    fn messages(&self) -> &dyn MessageRepository {
        &self.messages
    }
    fn notifications(&self) -> &dyn NotificationRepository {
        &self.notifications
    }
    fn presences(&self) -> &dyn AgentPresenceRepository {
        &self.presences
    }
    fn rate_limits(&self) -> &dyn RateLimitRepository {
        &self.rate_limits
    }
    fn workspaces(&self) -> &dyn WorkspaceRepository {
        &self.workspaces
    }
    fn workspace_members(&self) -> &dyn WorkspaceMemberRepository {
        &self.workspace_members
    }

    async fn ping(&self) -> Result<()> {
        sqlx::query_scalar::<_, i64>("SELECT 1")
            .fetch_one(&self.pool)
            .await?;
        Ok(())
    }

    async fn schema_version(&self) -> Result<String> {
        let row =
            sqlx::query_scalar::<_, String>("SELECT value FROM schema_meta WHERE key = 'version'")
                .fetch_one(&self.pool)
                .await?;
        Ok(row)
    }

    async fn shutdown(&self) {
        self.pool.close().await;
    }

    async fn metrics_snapshot(&self, now_ms: i64) -> Result<MetricsSnapshot> {
        let messages_pending: i64 =
            sqlx::query_scalar(r#"SELECT COUNT(*) FROM messages WHERE status = 'pending'"#)
                .fetch_one(&self.pool)
                .await?;
        let messages_failed: i64 =
            sqlx::query_scalar(r#"SELECT COUNT(*) FROM messages WHERE status = 'failed'"#)
                .fetch_one(&self.pool)
                .await?;
        let peers_total: i64 = sqlx::query_scalar(
            r#"SELECT COUNT(*) FROM agents
               WHERE endpoint IS NOT NULL AND endpoint NOT LIKE 'unix://%'"#,
        )
        .fetch_one(&self.pool)
        .await?;
        let workspaces_total: i64 = sqlx::query_scalar(r#"SELECT COUNT(*) FROM workspaces"#)
            .fetch_one(&self.pool)
            .await?;
        let channels_total: i64 = sqlx::query_scalar(r#"SELECT COUNT(*) FROM channels"#)
            .fetch_one(&self.pool)
            .await?;
        let confirmations_pending: i64 = sqlx::query_scalar(
            r#"SELECT COUNT(*) FROM pending_confirmations WHERE status = 'pending'"#,
        )
        .fetch_one(&self.pool)
        .await?;
        let audit_rows_total: i64 = sqlx::query_scalar(r#"SELECT COUNT(*) FROM audit_log"#)
            .fetch_one(&self.pool)
            .await?;
        let discovered_channels_total: i64 =
            sqlx::query_scalar(r#"SELECT COUNT(*) FROM discovered_channels"#)
                .fetch_one(&self.pool)
                .await?;
        let rate_buckets_total: i64 = sqlx::query_scalar(r#"SELECT COUNT(*) FROM rate_buckets"#)
            .fetch_one(&self.pool)
            .await?;
        let capabilities_active: i64 = sqlx::query_scalar(
            r#"SELECT COUNT(*) FROM capabilities
               WHERE revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)"#,
        )
        .bind(now_ms)
        .fetch_one(&self.pool)
        .await?;
        Ok(MetricsSnapshot {
            messages_pending,
            messages_failed,
            peers_total,
            workspaces_total,
            channels_total,
            confirmations_pending,
            audit_rows_total,
            discovered_channels_total,
            rate_buckets_total,
            capabilities_active,
        })
    }
}
