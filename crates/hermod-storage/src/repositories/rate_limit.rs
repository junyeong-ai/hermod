//! Token-bucket rate-limit contract.

use async_trait::async_trait;
use hermod_core::Timestamp;

use crate::error::Result;

#[async_trait]
pub trait RateLimitRepository: Send + Sync + std::fmt::Debug {
    /// Atomic per-row token consumption. Refills based on
    /// `(now - updated_at)`, caps at `capacity`, decrements one token,
    /// persists. Returns `Ok(true)` if a token was consumed,
    /// `Ok(false)` if the bucket was empty.
    async fn try_consume_one(
        &self,
        pair_key: &str,
        capacity: u32,
        refill_per_min: u32,
        now: Timestamp,
    ) -> Result<bool>;

    /// Drop buckets idle past `cutoff_ms` AND full to `capacity` (so
    /// dropping is equivalent to recreating on next traffic).
    /// Partially-drained buckets are preserved.
    async fn prune_idle(&self, cutoff_ms: i64, capacity: u32) -> Result<u64>;
}
