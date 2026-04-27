//! Backend implementations of the storage traits.
//!
//! Each backend lives in its own module and implements `crate::Database`
//! plus the per-repository traits in `crate::repositories::*`. The
//! daemon picks one at startup and consumes it as `Arc<dyn Database>`.
//! The `postgres` backend is gated behind the crate-level `postgres`
//! cargo feature so a build that doesn't need it doesn't pay for the
//! Postgres driver chain.

pub mod sqlite;

#[cfg(feature = "postgres")]
pub mod postgres;
