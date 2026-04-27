//! Remote delivery wrapper.
//!
//! Thin facade over [`PeerPool`]. Pool eviction on error is the pool's
//! responsibility; this layer just keys delivery on `(envelope, endpoint)`.

use hermod_core::{Endpoint, Envelope};
use hermod_storage::Database;
use std::sync::Arc;

use crate::error::Result;
use crate::pool::PeerPool;
use crate::transport::Transport;

/// Decision returned to the caller after attempting one delivery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveryOutcome {
    Delivered,
    Rejected,
    Deferred,
}

/// Inbound delivery as parsed off a peer connection.
#[derive(Debug)]
pub struct InboundDelivery {
    pub envelope: Envelope,
}

#[derive(Clone)]
pub struct RemoteDeliverer {
    pool: Arc<PeerPool>,
}

impl std::fmt::Debug for RemoteDeliverer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteDeliverer")
            .field("pool", &*self.pool)
            .finish()
    }
}

impl RemoteDeliverer {
    pub fn new(transport: Arc<dyn Transport>, db: Arc<dyn Database>) -> Self {
        Self {
            pool: Arc::new(PeerPool::new(transport, db)),
        }
    }

    /// Returns the underlying pool for sweeper / shutdown wiring.
    pub fn pool(&self) -> Arc<PeerPool> {
        self.pool.clone()
    }

    /// Originator-side delivery — emits a frame with `hops = 0`.
    pub async fn deliver(
        &self,
        envelope: &Envelope,
        endpoint: &Endpoint,
    ) -> Result<DeliveryOutcome> {
        self.pool.deliver(envelope, endpoint, 0).await
    }

    /// Broker-side delivery — caller passes the post-increment hop
    /// count. Errors out before dialling if the count would exceed
    /// [`hermod_protocol::wire::MAX_RELAY_HOPS`]; the caller (broker
    /// service) treats that as a loop-detection signal rather than a
    /// transport failure.
    pub async fn forward(
        &self,
        envelope: &Envelope,
        endpoint: &Endpoint,
        outbound_hops: u8,
    ) -> Result<DeliveryOutcome> {
        if outbound_hops > hermod_protocol::wire::MAX_RELAY_HOPS {
            return Err(crate::error::RoutingError::Federation(format!(
                "relay hops {outbound_hops} exceeds MAX_RELAY_HOPS={}",
                hermod_protocol::wire::MAX_RELAY_HOPS
            )));
        }
        self.pool.deliver(envelope, endpoint, outbound_hops).await
    }
}
