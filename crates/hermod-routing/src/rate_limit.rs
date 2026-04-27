use hermod_core::{AgentId, Timestamp};
use hermod_storage::Database;
use std::sync::Arc;

use crate::error::{Result, RoutingError};

/// Token-bucket rate limiter, persisted via `RateLimitRepository`.
///
/// Buckets are keyed by `<from>|<to>`. Capacity equals `refill_per_min` (i.e.
/// burst = full minute of allowance). Setting `refill_per_min = 0` short-
/// circuits `consume_one` to a no-op without ever touching storage.
#[derive(Clone)]
pub struct RateLimiter {
    db: Arc<dyn Database>,
    capacity: u32,
    refill_per_min: u32,
}

impl std::fmt::Debug for RateLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RateLimiter")
            .field("capacity", &self.capacity)
            .field("refill_per_min", &self.refill_per_min)
            .finish_non_exhaustive()
    }
}

impl RateLimiter {
    pub fn new(db: Arc<dyn Database>, refill_per_min: u32) -> Self {
        Self {
            db,
            capacity: refill_per_min,
            refill_per_min,
        }
    }

    pub async fn consume_one(&self, from: &AgentId, to: &AgentId) -> Result<()> {
        if self.refill_per_min == 0 {
            return Ok(());
        }
        let key = format!("{}|{}", from, to);
        let allowed = self
            .db
            .rate_limits()
            .try_consume_one(&key, self.capacity, self.refill_per_min, Timestamp::now())
            .await?;
        if allowed {
            Ok(())
        } else {
            Err(RoutingError::RateLimited)
        }
    }
}
