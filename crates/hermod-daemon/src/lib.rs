//! Library face of the Hermod daemon. Re-exports configuration, identity, and path
//! helpers for use by the CLI (`hermod`) which shares the same filesystem conventions.

pub mod config;
mod fs_atomic;
pub mod home_layout;
pub mod host_identity;
pub mod local_agent;
pub mod paths;
