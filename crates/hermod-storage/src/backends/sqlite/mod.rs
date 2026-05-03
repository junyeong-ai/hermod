//! SQLite backend.
//!
//! A `Database` implementation backed by a SQLite WAL file. Suitable
//! for single-host deployments. For HA / multi-region deployments
//! operators select the `postgres://` backend at startup via
//! `[storage] dsn`; both implement the same `Database` trait surface.

mod agents;
mod audit;
mod briefs;
mod capabilities;
mod confirmations;
mod database;
mod hosts;
mod local_agents;
mod messages;
mod notifications;
mod pool;
mod presence;
mod rate_limit;
mod workspaces;

pub use database::SqliteDatabase;
