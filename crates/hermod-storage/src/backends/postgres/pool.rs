//! PostgreSQL pool setup + migration runner.
//!
//! Mirrors `backends::sqlite::pool` so callers see a uniform shape.
//! Migrations live under `migrations-postgres/` (separate from the
//! SQLite `migrations/` dir) because dialect differences make a
//! single shared SQL file impossible — see
//! `migrations-postgres/20260425000001_initial.sql` for the table-by-
//! table mapping.

use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use std::time::Duration;

use crate::error::Result;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations-postgres");

/// Open a Postgres connection pool. `url` must be a full
/// `postgres://user:pass@host:port/db` DSN; the higher-level
/// [`crate::connect`] dispatcher feeds us already-validated URLs.
pub async fn open_pool(url: &str) -> Result<PgPool> {
    let pool = PgPoolOptions::new()
        // Roughly mirrors the SQLite pool sizing. Postgres can sustain
        // far more connections than this; bumping it is an operator
        // tuning exercise based on workload concurrency.
        .max_connections(16)
        .acquire_timeout(Duration::from_secs(10))
        .connect(url)
        .await?;
    Ok(pool)
}

pub async fn run_migrations(pool: &PgPool) -> Result<()> {
    MIGRATOR.run(pool).await?;
    Ok(())
}
