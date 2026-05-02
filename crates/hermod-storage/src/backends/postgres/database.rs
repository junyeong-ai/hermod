//! `Database` implementation backed by PostgreSQL.
//!
//! Functional twin of `backends::sqlite::SqliteDatabase`. Identical
//! trait surface; the only callsite that names this type is
//! `crate::connect()`'s `postgres://` arm.

use async_trait::async_trait;
use hermod_crypto::Signer;
use sqlx::PgPool;
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

use super::agents::PostgresAgentRepository;
use super::audit::PostgresAuditRepository;
use super::briefs::PostgresBriefRepository;
use super::capabilities::PostgresCapabilityRepository;
use super::confirmations::PostgresConfirmationRepository;
use super::local_agents::PostgresLocalAgentRepository;
use super::messages::PostgresMessageRepository;
use super::notifications::PostgresNotificationRepository;
use super::pool::{open_pool, run_migrations};
use super::presence::{PostgresAgentPresenceRepository, PostgresMcpSessionRepository};
use super::rate_limit::PostgresRateLimitRepository;
use super::workspaces::{
    PostgresChannelRepository, PostgresDiscoveredChannelRepository,
    PostgresWorkspaceMemberRepository, PostgresWorkspaceRepository,
};

#[derive(Clone)]
pub struct PostgresDatabase {
    pool: PgPool,
    blobs: Arc<dyn BlobStore>,
    agents: PostgresAgentRepository,
    audit: PostgresAuditRepository,
    briefs: PostgresBriefRepository,
    capabilities: PostgresCapabilityRepository,
    channels: PostgresChannelRepository,
    confirmations: PostgresConfirmationRepository,
    discovered_channels: PostgresDiscoveredChannelRepository,
    local_agents: PostgresLocalAgentRepository,
    mcp_sessions: PostgresMcpSessionRepository,
    messages: PostgresMessageRepository,
    notifications: PostgresNotificationRepository,
    presences: PostgresAgentPresenceRepository,
    rate_limits: PostgresRateLimitRepository,
    workspaces: PostgresWorkspaceRepository,
    workspace_members: PostgresWorkspaceMemberRepository,
}

impl std::fmt::Debug for PostgresDatabase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PostgresDatabase")
            .field("pool", &self.pool)
            .field("blobs", &self.blobs)
            .finish_non_exhaustive()
    }
}

impl PostgresDatabase {
    pub async fn connect(
        url: &str,
        signer: Arc<dyn Signer>,
        blobs: Arc<dyn BlobStore>,
    ) -> Result<Self> {
        let pool = open_pool(url).await?;
        run_migrations(&pool).await?;
        Ok(Self {
            pool: pool.clone(),
            blobs,
            agents: PostgresAgentRepository::new(pool.clone()),
            audit: PostgresAuditRepository::new(pool.clone(), signer),
            briefs: PostgresBriefRepository::new(pool.clone()),
            capabilities: PostgresCapabilityRepository::new(pool.clone()),
            channels: PostgresChannelRepository::new(pool.clone()),
            confirmations: PostgresConfirmationRepository::new(pool.clone()),
            discovered_channels: PostgresDiscoveredChannelRepository::new(pool.clone()),
            local_agents: PostgresLocalAgentRepository::new(pool.clone()),
            mcp_sessions: PostgresMcpSessionRepository::new(pool.clone()),
            messages: PostgresMessageRepository::new(pool.clone()),
            notifications: PostgresNotificationRepository::new(pool.clone()),
            presences: PostgresAgentPresenceRepository::new(pool.clone()),
            rate_limits: PostgresRateLimitRepository::new(pool.clone()),
            workspaces: PostgresWorkspaceRepository::new(pool.clone()),
            workspace_members: PostgresWorkspaceMemberRepository::new(pool.clone()),
        })
    }

    /// Backend pool — exposed for tests that exercise the Postgres
    /// layer directly. Production code stays on the `Database` trait.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

#[async_trait]
impl Database for PostgresDatabase {
    fn backend(&self) -> crate::DatabaseBackend {
        crate::DatabaseBackend::Postgres
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
    fn local_agents(&self) -> &dyn LocalAgentRepository {
        &self.local_agents
    }
    fn discovered_channels(&self) -> &dyn DiscoveredChannelRepository {
        &self.discovered_channels
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
        // `1` is INT4 in Postgres; cast to BIGINT so the row decoder
        // matches the SQLite backend's `SELECT 1` shape.
        sqlx::query_scalar::<_, i64>("SELECT 1::bigint")
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
               WHERE revoked_at IS NULL AND (expires_at IS NULL OR expires_at > $1)"#,
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
