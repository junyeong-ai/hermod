//! Trait contracts for every persistent collection.
//!
//! The daemon depends on these traits only — concrete backends
//! (`backends::sqlite`, future `backends::postgres`) implement them and
//! are constructed at startup via `Arc<dyn Database>`.

pub mod agents;
pub mod audit;
pub mod briefs;
pub mod capabilities;
pub mod confirmations;
pub mod messages;
pub mod presence;
pub mod rate_limit;
pub mod workspaces;
