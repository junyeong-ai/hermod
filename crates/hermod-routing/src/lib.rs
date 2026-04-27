//! Routing, access control, rate limiting, and the inbound confirmation gate
//! for Hermod. Owns no I/O beyond storage; the network layers (federation
//! server, peer pool) live above this crate and feed verified state in.

pub mod access;
pub mod confirmation;
pub mod error;
pub(crate) mod peer;
pub mod pool;
pub mod rate_limit;
pub mod remote;
pub mod router;
pub mod transport;
pub mod wss_noise;

pub use access::{AccessController, AccessVerdict, AccessPolicy, scope};
pub use confirmation::{Sensitivity, Verdict, classify, decide, summarize};
pub use error::{Result, RoutingError};
pub use pool::{PeerPool, spawn_sweeper};
pub use rate_limit::RateLimiter;
pub use remote::{InboundDelivery, RemoteDeliverer};
pub use router::{RouteDecision, Router};
pub use transport::{
    PeerIdentity, PeerTransportError, Transport, TransportConnection, TransportListener,
};
pub use wss_noise::WssNoiseTransport;
