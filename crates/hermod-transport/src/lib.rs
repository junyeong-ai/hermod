//! Transports for Hermod.
//!
//! - Unix-socket IPC (CLI ↔ daemon).
//! - WebSocket+TLS (WSS) for federation between daemons.

pub mod error;
pub mod tls;
pub mod unix;
pub mod ws;

pub use error::TransportError;
pub use tls::install_default_crypto_provider;
pub use unix::{UnixIpcListener, UnixIpcStream};
pub use ws::{InnerStream, WsListener, WsStream, connect, connect_tls};
