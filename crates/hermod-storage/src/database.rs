//! Backend-agnostic database trait.
//!
//! The daemon depends on this trait only — concrete backends
//! (`backends::sqlite::SqliteDatabase`, future `backends::postgres::PostgresDatabase`)
//! are constructed at startup and passed as `Arc<dyn Database>`.
//!
//! Each repository accessor returns `&dyn <Repo>` so callers can hold the
//! reference for the duration of one operation without cloning. The
//! lifetime is tied to `&self` so the trait remains object-safe.

use std::sync::Arc;

use crate::blobs::BlobStore;
use crate::error::Result;
use crate::repositories::{
    agents::AgentRepository,
    audit::AuditRepository,
    briefs::BriefRepository,
    capabilities::CapabilityRepository,
    confirmations::ConfirmationRepository,
    hosts::HostRepository,
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

/// Identifies which concrete relational backend is in use. Returned
/// by [`crate::classify_database_dsn`] for callers that need to
/// branch on the backend before opening it (e.g. `home_layout`
/// deciding whether SQLite WAL/SHM files belong in the boot
/// enforcement spec).
///
/// Variants are unconditional — classification is a static fact
/// about the DSN, independent of which backend was compiled in. The
/// `postgres` cargo feature only affects whether [`crate::open_database`]
/// can construct a Postgres backend; classification answers without it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatabaseBackend {
    Sqlite,
    Postgres,
}

/// Snapshot of every count the `/metrics` endpoint surfaces. Returned in
/// one round-trip to keep the scrape cheap; backends that can compute
/// these in a single query batch should do so.
#[derive(Debug, Clone, Default)]
pub struct MetricsSnapshot {
    pub messages_pending: i64,
    pub messages_failed: i64,
    pub peers_total: i64,
    pub workspaces_total: i64,
    pub channels_total: i64,
    pub confirmations_pending: i64,
    pub audit_rows_total: i64,
    pub discovered_channels_total: i64,
    pub rate_buckets_total: i64,
    pub capabilities_active: i64,
}

/// The single contract the daemon depends on for persistence. Each
/// accessor returns the trait object for one repository; backend-specific
/// implementations are entirely opaque from this layer.
#[async_trait::async_trait]
pub trait Database: Send + Sync + std::fmt::Debug + 'static {
    /// Identify which concrete backend this instance is. Mirrors
    /// [`crate::BlobStore::backend`] for the blob layer; together
    /// the two methods give callers a uniform "what is this?" answer
    /// without downcasting.
    fn backend(&self) -> DatabaseBackend;

    fn agents(&self) -> &dyn AgentRepository;
    fn audit(&self) -> &dyn AuditRepository;
    fn blobs(&self) -> Arc<dyn BlobStore>;
    fn briefs(&self) -> &dyn BriefRepository;
    fn capabilities(&self) -> &dyn CapabilityRepository;
    fn channels(&self) -> &dyn ChannelRepository;
    fn confirmations(&self) -> &dyn ConfirmationRepository;
    fn discovered_channels(&self) -> &dyn DiscoveredChannelRepository;
    fn hosts(&self) -> &dyn HostRepository;
    fn local_agents(&self) -> &dyn LocalAgentRepository;
    fn mcp_sessions(&self) -> &dyn McpSessionRepository;
    fn messages(&self) -> &dyn MessageRepository;
    fn notifications(&self) -> &dyn NotificationRepository;
    fn presences(&self) -> &dyn AgentPresenceRepository;
    fn rate_limits(&self) -> &dyn RateLimitRepository;
    fn workspaces(&self) -> &dyn WorkspaceRepository;
    fn workspace_members(&self) -> &dyn WorkspaceMemberRepository;

    /// Backend connectivity check — returns `Ok(())` if a trivial query
    /// succeeds. Used by `/readyz` without coupling the daemon to any
    /// specific SQL.
    async fn ping(&self) -> Result<()>;

    /// Schema version recorded in the `schema_meta` table. Used by
    /// `hermod doctor` to detect a binary/database mismatch before
    /// touching any other surface — the daemon refuses to operate
    /// against a schema it doesn't recognise.
    async fn schema_version(&self) -> Result<String>;

    /// Counts for the `/metrics` endpoint. A single backend call returns
    /// every gauge so the scrape doesn't fan out to N repository methods.
    async fn metrics_snapshot(&self, now_ms: i64) -> Result<MetricsSnapshot>;

    /// Graceful shutdown — drains in-flight queries and closes connection
    /// resources. Idempotent. Implementations that have nothing to drain
    /// may return immediately. Distinct from `Drop` which only releases
    /// memory; some backends (SQLite WAL) want an explicit close to flush.
    async fn shutdown(&self);
}
