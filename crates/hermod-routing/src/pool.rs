//! Connection pool for outbound peer connections.
//!
//! Each peer (keyed by their post-handshake `agent_id`) gets at most one live
//! connection. Concurrent deliveries to the same peer serialize through the
//! per-peer mutex; deliveries to different peers proceed in parallel. A
//! background sweeper closes idle entries after `idle_ttl`.
//!
//! Backend-agnostic: holds `Arc<dyn Transport>` and never touches the
//! underlying WSS+Noise / gRPC / QUIC machinery directly. The only
//! routing-layer policy applied here is TLS fingerprint TOFU pinning,
//! and that's gated on `identity.tls_fingerprint.is_some()` so backends
//! without TLS skip it cleanly.

use hermod_core::{Endpoint, Envelope, MessageId};
use hermod_protocol::wire::{AckStatus, Ping, Pong, WireFrame};
use hermod_storage::Database;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex as AsyncMutex, RwLock};
use tracing::{debug, warn};

use crate::error::{Result, RoutingError};
use crate::remote::DeliveryOutcome;
use crate::transport::{Transport, TransportConnection};

#[derive(Clone, Debug)]
pub(crate) struct PoolConfig {
    /// Idle period after which a connection is closed by the sweeper.
    pub idle_ttl: Duration,
    /// Sweep interval. The sweeper also drives the heartbeat probe.
    pub sweep_interval: Duration,
    /// Per-call ack timeout.
    pub ack_timeout: Duration,
    /// Bound on the full handshake when dialling a peer. Without this
    /// an unresponsive remote could pin a sender task during the
    /// connect / handshake phase indefinitely.
    pub dial_timeout: Duration,
    /// Send a Ping if the slot has been idle for at least this long. The
    /// probe runs from the sweeper, so the effective minimum cadence is
    /// `max(sweep_interval, heartbeat_idle_threshold)`.
    pub heartbeat_idle_threshold: Duration,
    /// Drop the slot if no Pong matching the Ping arrives within this
    /// window. Tuned conservatively against typical congestion plus
    /// transport jitter; aggressive operators can tighten it.
    pub heartbeat_timeout: Duration,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            idle_ttl: Duration::from_secs(120),
            sweep_interval: Duration::from_secs(30),
            ack_timeout: Duration::from_secs(10),
            dial_timeout: Duration::from_secs(15),
            heartbeat_idle_threshold: Duration::from_secs(30),
            heartbeat_timeout: Duration::from_secs(10),
        }
    }
}

struct Slot {
    conn: Box<dyn TransportConnection>,
    last_used: Instant,
}

/// One entry per peer endpoint key. The outer `Arc<RwLock<…>>` wraps the
/// directory itself; per-entry `Arc<AsyncMutex<Option<Slot>>>` lets a
/// single waiter dial / hand back the connection without serialising
/// every peer behind a global lock. `Option` because a slot can be
/// reserved (taken out by the active sender) before the connection
/// returns; `None` means "owned, in flight".
type SlotMap = HashMap<String, Arc<AsyncMutex<Option<Slot>>>>;

#[derive(Clone)]
pub struct PeerPool {
    transport: Arc<dyn Transport>,
    config: PoolConfig,
    slots: Arc<RwLock<SlotMap>>,
    db: Arc<dyn Database>,
    /// Strict-monotonic source for Ping nonces. A connection-scoped
    /// counter would let the recipient correlate against an incorrect
    /// (older) ping; a pool-scoped counter is unambiguous and the
    /// uniqueness window dwarfs any plausible round-trip.
    next_nonce: Arc<AtomicU64>,
}

impl std::fmt::Debug for PeerPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerPool")
            .field("idle_ttl_ms", &self.config.idle_ttl.as_millis())
            .field("transport", &self.transport.name())
            .finish_non_exhaustive()
    }
}

impl PeerPool {
    pub fn new(transport: Arc<dyn Transport>, db: Arc<dyn Database>) -> Self {
        Self::with_config(transport, db, PoolConfig::default())
    }

    pub(crate) fn with_config(
        transport: Arc<dyn Transport>,
        db: Arc<dyn Database>,
        config: PoolConfig,
    ) -> Self {
        Self {
            transport,
            config,
            slots: Arc::new(RwLock::new(HashMap::new())),
            db,
            next_nonce: Arc::new(AtomicU64::new(1)),
        }
    }

    /// Send an envelope to `endpoint`, reusing an existing connection if one is live.
    /// Keys the pool entry by `endpoint.to_string()` so callers don't need to know
    /// the post-handshake agent_id ahead of time. `hops` is the number of relays
    /// the envelope has already crossed — originators pass 0; brokers pass the
    /// outbound count after their own increment.
    pub async fn deliver(
        &self,
        envelope: &Envelope,
        endpoint: &Endpoint,
        hops: u8,
    ) -> Result<DeliveryOutcome> {
        let key = endpoint.to_string();
        let entry = self.slot_for(&key).await;
        let mut guard = entry.lock().await;

        // Establish on first use.
        if guard.is_none() {
            let conn = self.dial(endpoint).await?;
            *guard = Some(Slot {
                conn,
                last_used: Instant::now(),
            });
        }

        let outcome = {
            let slot = guard.as_mut().expect("just initialised");
            send_with_ack(slot.conn.as_mut(), envelope, hops, self.config.ack_timeout).await
        };

        match outcome {
            Ok(o) => {
                if let Some(slot) = guard.as_mut() {
                    slot.last_used = Instant::now();
                }
                Ok(o)
            }
            Err(e) => {
                debug!(error = %e, "evicting connection after error");
                if let Some(slot) = guard.take() {
                    slot.conn.close().await;
                }
                drop(guard);
                self.evict(&key).await;
                Err(e)
            }
        }
    }

    async fn slot_for(&self, key: &str) -> Arc<AsyncMutex<Option<Slot>>> {
        {
            let r = self.slots.read().await;
            if let Some(s) = r.get(key) {
                return s.clone();
            }
        }
        let mut w = self.slots.write().await;
        w.entry(key.to_string())
            .or_insert_with(|| Arc::new(AsyncMutex::new(None)))
            .clone()
    }

    async fn evict(&self, key: &str) {
        let mut w = self.slots.write().await;
        w.remove(key);
    }

    /// Drop any pooled connection to `endpoint`. Used by operator-driven
    /// state changes (`peer.remove`, `peer.repin`) so a stale-context
    /// connection doesn't keep functioning past the policy change.
    pub async fn evict_endpoint(&self, endpoint: &Endpoint) {
        self.evict(&endpoint.to_string()).await;
    }

    async fn dial(&self, endpoint: &Endpoint) -> Result<Box<dyn TransportConnection>> {
        tokio::time::timeout(self.config.dial_timeout, self.dial_inner(endpoint))
            .await
            .map_err(|_| {
                RoutingError::Federation(format!(
                    "dial to {endpoint} timed out after {:?}",
                    self.config.dial_timeout
                ))
            })?
    }

    async fn dial_inner(&self, endpoint: &Endpoint) -> Result<Box<dyn TransportConnection>> {
        let conn = self
            .transport
            .dial(endpoint)
            .await
            .map_err(|e| RoutingError::Federation(e.to_string()))?;
        let identity = conn.identity().clone();
        debug!(
            backend = self.transport.name(),
            remote = %identity.agent_id,
            "pool: dialed new peer"
        );

        // TLS fingerprint TOFU. Skipped when the backend has no TLS
        // (`identity.tls_fingerprint = None` — e.g. a future raw-TCP
        // in-cluster transport) or when the peer is not yet in the
        // agents table (first-contact ingestion happens elsewhere).
        // When both are present, the stored fingerprint must match
        // what the transport observed, or we tear down the connection.
        if let Some(fp) = identity.tls_fingerprint {
            let peer_id = identity.agent_id.clone();
            match self
                .db
                .agents()
                .pin_or_match_tls_fingerprint(&peer_id, &fp)
                .await
            {
                Ok(true) => {
                    debug!(peer = %peer_id, fingerprint = %fp, "tls fingerprint pinned/match");
                }
                Ok(false) => {
                    warn!(
                        peer = %peer_id,
                        observed = %fp,
                        "tls fingerprint mismatch — refusing connection"
                    );
                    conn.close().await;
                    return Err(RoutingError::TlsFingerprintMismatch {
                        peer: peer_id.to_string(),
                        observed: fp,
                    });
                }
                Err(e) => {
                    // Fail-closed: a transient DB error must not silently
                    // promote an unverified peer. The outbox will retry
                    // through the normal backoff schedule.
                    let id_str = peer_id.to_string();
                    warn!(
                        peer = %id_str,
                        error = %e,
                        "tls fingerprint TOFU lookup failed — refusing connection"
                    );
                    conn.close().await;
                    return Err(RoutingError::TofuLookupFailed {
                        peer: id_str,
                        detail: e.to_string(),
                    });
                }
            }
        }
        Ok(conn)
    }

    /// Periodic maintenance pass:
    ///   * **Idle eviction.** A slot untouched for > `idle_ttl` is closed.
    ///   * **Half-open detection.** A slot untouched for >
    ///     `heartbeat_idle_threshold` (but ≤ `idle_ttl`) is probed with a
    ///     Ping; no Pong within `heartbeat_timeout` evicts it.
    ///
    /// Returns the number of slots removed for any reason. Sender tasks
    /// can race the sweeper for the same slot; the per-slot async mutex
    /// serialises that — a probe and a delivery never run together, and
    /// a delivery in flight (slot momentarily `None`) is its own
    /// liveness check, so the probe is skipped that round.
    pub async fn sweep(&self) -> usize {
        let now = Instant::now();
        let ttl = self.config.idle_ttl;
        let probe_threshold = self.config.heartbeat_idle_threshold;
        let probe_timeout = self.config.heartbeat_timeout;

        let candidates: Vec<(String, Arc<AsyncMutex<Option<Slot>>>)> = {
            let r = self.slots.read().await;
            r.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
        };

        let mut count = 0;
        for (key, slot_lock) in candidates {
            let mut g = slot_lock.lock().await;
            let action = match &*g {
                None => SweepAction::Evict, // owned-in-flight/orphan: drop key.
                Some(s) => {
                    let idle = now.duration_since(s.last_used);
                    if idle > ttl {
                        SweepAction::Evict
                    } else if idle > probe_threshold {
                        SweepAction::Probe
                    } else {
                        SweepAction::Skip
                    }
                }
            };
            match action {
                SweepAction::Skip => {}
                SweepAction::Probe => {
                    let slot = g.as_mut().expect("Probe path requires Some(slot)");
                    let nonce = self.next_nonce.fetch_add(1, Ordering::Relaxed);
                    match probe_one(slot.conn.as_mut(), nonce, probe_timeout).await {
                        Ok(()) => slot.last_used = Instant::now(),
                        Err(e) => {
                            warn!(peer_key = %key, error = %e, "heartbeat probe failed; evicting");
                            if let Some(s) = g.take() {
                                s.conn.close().await;
                            }
                            drop(g);
                            self.evict(&key).await;
                            count += 1;
                        }
                    }
                }
                SweepAction::Evict => {
                    if let Some(s) = g.take() {
                        s.conn.close().await;
                    }
                    drop(g);
                    self.evict(&key).await;
                    count += 1;
                }
            }
        }
        count
    }

    /// Close every entry, draining the pool.
    pub async fn close_all(&self) {
        let entries: Vec<(String, Arc<AsyncMutex<Option<Slot>>>)> = {
            let r = self.slots.read().await;
            r.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
        };
        for (_, slot_lock) in &entries {
            let mut g = slot_lock.lock().await;
            if let Some(s) = g.take() {
                s.conn.close().await;
            }
        }
        self.slots.write().await.clear();
    }
}

#[derive(Clone, Copy, Debug)]
enum SweepAction {
    /// Slot is fresh enough — no action.
    Skip,
    /// Slot has been idle past the heartbeat threshold; send a probe.
    Probe,
    /// Slot is past `idle_ttl` (or empty); close + remove.
    Evict,
}

/// Send a Ping with `nonce` and wait `timeout` for a matching Pong.
/// Intermediate frames (Pong with a stale nonce, peer's own Ping that we
/// auto-pong, lingering DeliveryAck) are consumed transparently.
async fn probe_one(
    conn: &mut dyn TransportConnection,
    nonce: u64,
    timeout: Duration,
) -> Result<()> {
    conn.send_frame(&WireFrame::Ping(Ping { nonce }))
        .await
        .map_err(|e| RoutingError::Federation(e.to_string()))?;
    tokio::time::timeout(timeout, await_pong(conn, nonce))
        .await
        .map_err(|_| RoutingError::DeadLink)?
}

async fn await_pong(conn: &mut dyn TransportConnection, expect: u64) -> Result<()> {
    loop {
        let frame = conn
            .recv_frame()
            .await
            .map_err(|e| RoutingError::Federation(e.to_string()))?
            .ok_or_else(|| RoutingError::Federation("peer closed before pong".into()))?;
        match frame {
            WireFrame::Pong(p) if p.nonce == expect => return Ok(()),
            WireFrame::Pong(_) => continue, // stale pong — keep waiting
            WireFrame::Ping(p) => {
                // Reflexive pong so the peer's correlator clears.
                conn.send_frame(&WireFrame::Pong(Pong { nonce: p.nonce }))
                    .await
                    .map_err(|e| RoutingError::Federation(e.to_string()))?;
            }
            WireFrame::DeliveryAck(_) => continue, // unrelated; drop
            WireFrame::Close(c) => {
                return Err(RoutingError::Federation(format!(
                    "peer closed during probe: {} {}",
                    c.code, c.reason
                )));
            }
            other => {
                return Err(RoutingError::Federation(format!(
                    "unexpected frame waiting for pong: {other:?}"
                )));
            }
        }
    }
}

async fn send_with_ack(
    conn: &mut dyn TransportConnection,
    envelope: &Envelope,
    hops: u8,
    ack_timeout: Duration,
) -> Result<DeliveryOutcome> {
    let id = envelope.id;
    conn.send_frame(&WireFrame::Envelope(hermod_protocol::wire::EnvelopeFrame {
        hops,
        envelope: Box::new(envelope.clone()),
    }))
    .await
    .map_err(|e| RoutingError::Federation(e.to_string()))?;
    let frame = tokio::time::timeout(ack_timeout, next_ack(conn, id))
        .await
        .map_err(|_| RoutingError::AckTimeout)??;
    match frame {
        AckResult::Delivered => Ok(DeliveryOutcome::Delivered),
        AckResult::Deferred => Ok(DeliveryOutcome::Deferred),
        AckResult::Rejected(reason) => Err(RoutingError::Rejected(reason)),
    }
}

enum AckResult {
    Delivered,
    Deferred,
    Rejected(String),
}

async fn next_ack(conn: &mut dyn TransportConnection, expect: MessageId) -> Result<AckResult> {
    loop {
        let frame = conn
            .recv_frame()
            .await
            .map_err(|e| RoutingError::Federation(e.to_string()))?
            .ok_or_else(|| RoutingError::Federation("peer closed before ack".into()))?;
        match frame {
            WireFrame::DeliveryAck(a) if a.message_id == expect => {
                return Ok(match a.status {
                    AckStatus::Delivered => AckResult::Delivered,
                    AckStatus::Deferred => AckResult::Deferred,
                    AckStatus::Rejected => {
                        AckResult::Rejected(a.reason.unwrap_or_else(|| "unspecified".into()))
                    }
                });
            }
            WireFrame::DeliveryAck(_) => {
                // Stale ack from a previous in-flight; ignore.
                continue;
            }
            // Sent in response to our own Ping; consume and continue
            // waiting for the actual ack we're blocking on.
            WireFrame::Pong(_) => continue,
            // Inbound probe from the peer mid-delivery — pong back so the
            // peer's correlator matches and the link stays alive. We bail
            // on send error: a write failure here means the connection is
            // already gone, and surfacing it here is cleaner than letting
            // the next ack-wait time out.
            WireFrame::Ping(p) => {
                conn.send_frame(&WireFrame::Pong(hermod_protocol::wire::Pong {
                    nonce: p.nonce,
                }))
                .await
                .map_err(|e| RoutingError::Federation(e.to_string()))?;
                continue;
            }
            WireFrame::Close(c) => {
                return Err(RoutingError::Federation(format!(
                    "peer close: {} {}",
                    c.code, c.reason
                )));
            }
            other => {
                return Err(RoutingError::Federation(format!(
                    "unexpected frame waiting for ack: {other:?}"
                )));
            }
        }
    }
}

/// Spawn a panic-supervised sweeper. The sweeper itself runs in a child
/// task; a tiny supervisor watches its JoinHandle and respawns the
/// child on panic. Without supervision a panic would leave idle slots
/// accumulating forever — the symptom is "memory crawls up and probes
/// stop firing" with no obvious failure on the metrics dashboard.
///
/// Panic budget: at most [`MAX_SWEEPER_RESTARTS`] restarts per
/// [`RESTART_WINDOW`]. Past that, the supervisor stops respawning and
/// logs at `error!` — recurrent panics indicate a real bug, and a
/// crash-loop would just fill the log.
pub fn spawn_sweeper(pool: PeerPool, shutdown: tokio::sync::oneshot::Receiver<()>) {
    /// Maximum panic count within `RESTART_WINDOW` before the supervisor
    /// gives up and the daemon admin must take over.
    const MAX_SWEEPER_RESTARTS: u32 = 5;
    /// Sliding window over which the panic count is measured.
    const RESTART_WINDOW: Duration = Duration::from_secs(300);
    /// Cooldown between an observed panic and the respawn attempt — avoids
    /// burning CPU on a tight panic loop while the operator notices.
    const RESTART_BACKOFF: Duration = Duration::from_millis(500);

    tokio::spawn(async move {
        let mut shutdown = shutdown;
        let mut restarts: std::collections::VecDeque<Instant> =
            std::collections::VecDeque::with_capacity(MAX_SWEEPER_RESTARTS as usize + 1);

        loop {
            let pool_for_child = pool.clone();
            let (child_shutdown_tx, child_shutdown_rx) = tokio::sync::oneshot::channel::<()>();
            let mut handle = tokio::spawn(sweeper_loop(pool_for_child, child_shutdown_rx));

            tokio::select! {
                _ = &mut shutdown => {
                    let _ = child_shutdown_tx.send(());
                    let _ = (&mut handle).await;
                    return;
                }
                join = &mut handle => {
                    match join {
                        Ok(()) => {
                            warn!("pool sweeper exited cleanly without shutdown signal; not restarting");
                            return;
                        }
                        Err(e) if e.is_panic() => {
                            let now = Instant::now();
                            restarts.push_back(now);
                            while restarts
                                .front()
                                .is_some_and(|t| now.duration_since(*t) > RESTART_WINDOW)
                            {
                                restarts.pop_front();
                            }
                            if restarts.len() > MAX_SWEEPER_RESTARTS as usize {
                                tracing::error!(
                                    restarts = restarts.len(),
                                    "pool sweeper has panicked {MAX_SWEEPER_RESTARTS} times in {RESTART_WINDOW:?}; giving up"
                                );
                                return;
                            }
                            tracing::error!(
                                error = ?e,
                                restart_attempt = restarts.len(),
                                "pool sweeper panicked; restarting after backoff"
                            );
                            tokio::time::sleep(RESTART_BACKOFF).await;
                            continue;
                        }
                        Err(_) => {
                            return;
                        }
                    }
                }
            }
        }
    });
}

async fn sweeper_loop(pool: PeerPool, mut shutdown: tokio::sync::oneshot::Receiver<()>) {
    let mut ticker = tokio::time::interval(pool.config.sweep_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    ticker.tick().await; // skip the immediate first tick
    loop {
        tokio::select! {
            _ = &mut shutdown => return,
            _ = ticker.tick() => {
                let n = pool.sweep().await;
                if n > 0 {
                    debug!(evicted = n, "pool sweep");
                }
            }
        }
    }
}
