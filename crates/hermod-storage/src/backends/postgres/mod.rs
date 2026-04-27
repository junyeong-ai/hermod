//! PostgreSQL backend.
//!
//! A `Database` implementation backed by PostgreSQL via sqlx. Suitable
//! for HA / multi-region deployments where SQLite's single-writer
//! model would be a bottleneck.
//!
//! Build behind the `postgres` cargo feature on this crate
//! (`cargo build --features hermod-storage/postgres`); operators
//! select the backend at runtime via `[storage] url = "postgres://…"`.
//!
//! Status: **complete** — every repository in the `Database` trait is
//! implemented. `connect()` dispatches `postgres://` URLs to
//! [`PostgresDatabase::connect`] and returns the daemon's standard
//! `Arc<dyn Database>` trait object. The implementation has dialect
//! parity with `backends::sqlite`:
//!
//!   * `?` → `$N` placeholders, with sequential numbering on every
//!     dynamic SQL builder.
//!   * `INSERT OR IGNORE` → `INSERT … ON CONFLICT DO NOTHING`
//!     (with `RETURNING id` where the SQLite version relied on
//!     `last_insert_rowid()` or `rows_affected`).
//!   * `BEGIN IMMEDIATE` (single writer-lock serialization) →
//!     `pg_advisory_xact_lock(hashtext($key)::bigint)` for keyed
//!     pessimistic locks (rate_limit, confirmations.enqueue) or a
//!     constant key (`hashtext('audit_log')`) for global chain
//!     serialization (audit.append).
//!   * Outbox claim → `FOR UPDATE SKIP LOCKED` on the inner SELECT
//!     so concurrent workers see disjoint candidate sets.
//!   * `last_insert_rowid()` → `RETURNING id` on `INSERT`.
//!
//! Hash-chain canonicalisation is bit-for-bit identical between the
//! two backends (see `audit::compute_row_hash` in each), so an
//! audit-archive blob exported from one backend verifies under the
//! other — useful for migrations and disaster recovery.

pub mod agents;
pub mod audit;
pub mod briefs;
pub mod capabilities;
pub mod confirmations;
pub mod database;
pub mod messages;
pub mod pool;
pub mod presence;
pub mod rate_limit;
pub mod workspaces;

pub use agents::PostgresAgentRepository;
pub use audit::PostgresAuditRepository;
pub use briefs::PostgresBriefRepository;
pub use capabilities::PostgresCapabilityRepository;
pub use confirmations::PostgresConfirmationRepository;
pub use database::PostgresDatabase;
pub use messages::PostgresMessageRepository;
pub use pool::{open_pool, run_migrations};
pub use presence::{PostgresAgentPresenceRepository, PostgresMcpSessionRepository};
pub use rate_limit::PostgresRateLimitRepository;
pub use workspaces::{
    PostgresChannelRepository, PostgresDiscoveredChannelRepository,
    PostgresWorkspaceMemberRepository, PostgresWorkspaceRepository,
};
