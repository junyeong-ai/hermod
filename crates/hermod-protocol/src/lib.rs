//! Hermod protocol layer.
//!
//! - `ipc` — JSON-RPC 2.0 over length-delimited framing, used between the
//!   daemon (`hermodd`) and clients (CLI, MCP server).
//! - `envelope` — signing / verification helpers and protocol-version checks
//!   for received envelopes.
//! - `handshake` / `wire` — Noise XX handshake and federation wire framing
//!   for inter-daemon WSS connections.

pub mod envelope;
pub mod handshake;
pub mod ipc;
pub mod wire;

pub use hermod_core::PROTOCOL_VERSION;
