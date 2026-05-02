//! Periodic state cleanup.
//!
//! Runs every `sweep_interval` and prunes:
//!   * expired briefs (briefs.expires_at <= now)
//!   * stale pending confirmations (status='pending' AND requested_at < now − R)
//!   * stale discovered channels (last_seen < now − R)
//!
//! The audit log is **not** swept. Truncating signed rows would invalidate the
//! hash chain at a non-deterministic point and turn `audit verify` into a
//! flaky check; retention there is an operator concern handled out-of-band
//! (snapshot, archive, then rotate the DB).

use hermod_core::Timestamp;
use hermod_storage::{AuditSink, Database, SESSION_TTL_SECS};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::oneshot;
use tracing::{debug, info, warn};

use crate::local_agent::LocalAgentRegistry;
use crate::services::presence::PresenceService;

#[derive(Clone, Debug)]
pub struct JanitorConfig {
    pub sweep_interval: Duration,
    /// Pending confirmations older than this are marked `expired`. None
    /// disables the sweep entirely.
    pub confirmation_retention: Option<Duration>,
    /// Discovered channels last_seen older than this are dropped. None
    /// disables.
    pub discovery_retention: Option<Duration>,
    /// MCP sessions whose `last_heartbeat_at` is older than this are
    /// considered dead and removed. Decays self-liveness to offline if the
    /// last attached session disappears without a clean detach.
    pub session_ttl: Duration,
    /// `read` / `failed` messages older than this are deleted to bound
    /// the messages table growth. None keeps them forever (operator-managed).
    pub message_terminal_retention: Option<Duration>,
    /// Idle, full rate-limit buckets older than this are dropped to bound
    /// `rate_buckets` growth — one row per (sender, recipient) pair would
    /// otherwise accumulate forever. None keeps them all.
    pub rate_bucket_idle_retention: Option<Duration>,
    /// Capacity used when deciding whether a rate bucket is "full" for
    /// pruning. Mirrors `PolicyConfig::rate_limit_per_sender`.
    pub rate_bucket_capacity: u32,
    /// Live `audit_log` rows older than this are sealed into
    /// gzip-JSONL day-buckets in the `BlobStore` and deleted from the
    /// table. None disables (operator-managed via
    /// `hermod audit archive`).
    pub audit_retention: Option<Duration>,
}

impl Default for JanitorConfig {
    fn default() -> Self {
        Self {
            sweep_interval: Duration::from_secs(5 * 60),
            confirmation_retention: Some(Duration::from_secs(7 * 24 * 3600)),
            discovery_retention: Some(Duration::from_secs(24 * 3600)),
            session_ttl: Duration::from_secs(SESSION_TTL_SECS),
            // 30 days — read history stays for "what did we discuss last
            // month?", but doesn't accumulate to gigabytes over years.
            message_terminal_retention: Some(Duration::from_secs(30 * 24 * 3600)),
            rate_bucket_idle_retention: Some(Duration::from_secs(24 * 3600)),
            rate_bucket_capacity: 60,
            audit_retention: Some(Duration::from_secs(30 * 24 * 3600)),
        }
    }
}

#[derive(Clone)]
pub struct JanitorWorker {
    db: Arc<dyn Database>,
    audit_sink: Arc<dyn AuditSink>,
    config: JanitorConfig,
    /// Audit fallback actor for janitor-emitted rows (e.g.
    /// `audit.archive`). The janitor acts on behalf of *this*
    /// daemon, so attributing the row to the host id is the honest
    /// answer when no IPC caller is in scope.
    host_actor: hermod_core::AgentId,
    /// When set, a transition from ≥1 live session to 0 live sessions
    /// triggers a federation broadcast so peers stop showing us as live
    /// before their own cache TTL ages out — once per locally-hosted
    /// agent (the schema treats sessions as host-wide, so every hosted
    /// agent flips offline together).
    presence: Option<PresenceService>,
    /// Locally-hosted agents the janitor broadcasts a presence flip
    /// for when the last MCP session decays. Set alongside
    /// `presence` via [`Self::with_presence`].
    local_agents: Option<LocalAgentRegistry>,
}

impl std::fmt::Debug for JanitorWorker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JanitorWorker")
            .field("sweep_interval_s", &self.config.sweep_interval.as_secs())
            .finish_non_exhaustive()
    }
}

impl JanitorWorker {
    pub fn new(
        db: Arc<dyn Database>,
        audit_sink: Arc<dyn AuditSink>,
        host_actor: hermod_core::AgentId,
        config: JanitorConfig,
    ) -> Self {
        Self {
            db,
            audit_sink,
            config,
            host_actor,
            presence: None,
            local_agents: None,
        }
    }

    /// Wire the PresenceService and the local-agent registry so a
    /// session-decay transition fires a federation broadcast for every
    /// locally-hosted agent. Without this, the daemon still prunes stale
    /// session rows but peers learn about it only when their own cached
    /// TTL expires.
    pub fn with_presence(
        mut self,
        presence: PresenceService,
        local_agents: LocalAgentRegistry,
    ) -> Self {
        self.presence = Some(presence);
        self.local_agents = Some(local_agents);
        self
    }

    pub async fn run(self, mut shutdown: oneshot::Receiver<()>) {
        let mut ticker = tokio::time::interval(self.config.sweep_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        info!(?self, "janitor started");
        loop {
            tokio::select! {
                _ = &mut shutdown => {
                    info!("janitor shutting down");
                    break;
                }
                _ = ticker.tick() => {
                    if let Err(e) = self.sweep_once().await {
                        warn!(error = %e, "janitor sweep failed");
                    }
                }
            }
        }
    }

    pub async fn sweep_once(&self) -> anyhow::Result<JanitorReport> {
        let now = Timestamp::now();
        let now_ms = now.unix_ms();

        let briefs_pruned = self.db.briefs().prune_expired(now_ms).await?;
        // Honour envelope TTL across all message statuses — if the sender
        // capped lifetime at N seconds, drop rows past that mark. Each
        // prune call returns the BlobStore locations the deleted rows
        // referenced; we sweep those alongside so binary content
        // doesn't outlive its metadata.
        let expired_outcome = self.db.messages().prune_expired(now_ms).await?;
        let terminal_outcome = match self.config.message_terminal_retention {
            Some(retention) => {
                let cutoff = now_ms.saturating_sub(retention.as_millis() as i64);
                self.db.messages().prune_terminal_older_than(cutoff).await?
            }
            None => hermod_storage::MessagePruneOutcome::default(),
        };
        let messages_expired = expired_outcome.rows;
        let messages_terminal = terminal_outcome.rows;
        let blobs = self.db.blobs();
        for loc in expired_outcome
            .blob_locations
            .iter()
            .chain(terminal_outcome.blob_locations.iter())
        {
            if let Err(e) = blobs.delete(loc).await {
                warn!(location = %loc, error = %e, "blob delete failed during prune");
            }
        }
        let capabilities_pruned = self.db.capabilities().prune_terminal(now_ms).await?;

        let confirmations_expired = match self.config.confirmation_retention {
            Some(retention) => {
                let cutoff = now_ms.saturating_sub(retention.as_millis() as i64);
                self.db
                    .confirmations()
                    .expire_pending_older_than(cutoff)
                    .await?
            }
            None => 0,
        };

        let discovered_pruned = match self.config.discovery_retention {
            Some(retention) => {
                let cutoff = now_ms.saturating_sub(retention.as_millis() as i64);
                self.db
                    .discovered_channels()
                    .prune_older_than(cutoff)
                    .await?
            }
            None => 0,
        };

        let rate_buckets_pruned = match self.config.rate_bucket_idle_retention {
            Some(retention) => {
                let cutoff = now_ms.saturating_sub(retention.as_millis() as i64);
                self.db
                    .rate_limits()
                    .prune_idle(cutoff, self.config.rate_bucket_capacity)
                    .await?
            }
            None => 0,
        };

        // MCP sessions: prune stale heartbeats. The atomic call returns the
        // before/after liveness so we can broadcast Presence(offline)
        // exactly when the prune flipped us from live to dark — no race
        // with a fresh attach happening mid-sweep.
        let ttl_ms = self.config.session_ttl.as_millis() as i64;
        let outcome = self
            .db
            .mcp_sessions()
            .prune_with_transition(now, ttl_ms)
            .await?;
        if outcome.was_live
            && !outcome.is_live
            && let (Some(presence), Some(registry)) = (&self.presence, &self.local_agents)
        {
            for agent in registry.list() {
                if let Err(e) = presence.broadcast_for(&agent.agent_id).await {
                    warn!(
                        agent = %agent.agent_id,
                        error = %e,
                        "broadcast offline after janitor prune",
                    );
                }
            }
        }

        // Audit archival: when retention is configured, walk every
        // fully-elapsed UTC day older than the cutoff and seal it
        // into a gzip-JSONL bucket in the BlobStore. Idempotent —
        // running on the same day twice finds nothing eligible the
        // second time. A failure on one day doesn't block the rest of
        // the sweep; the next tick retries.
        let mut audit_archives_created: u64 = 0;
        if let Some(retention) = self.config.audit_retention {
            let cutoff_secs = retention.as_secs();
            match crate::services::AuditService::new(self.db.clone(), cutoff_secs)
                .archive_now(hermod_protocol::ipc::methods::AuditArchiveNowParams {
                    older_than_secs: Some(cutoff_secs),
                })
                .await
            {
                Ok(res) => {
                    audit_archives_created = res.archives_created as u64;
                    if audit_archives_created > 0 {
                        debug!(
                            archives = audit_archives_created,
                            rows = res.rows_archived,
                            "janitor sealed audit archives"
                        );
                        crate::services::audit_or_warn(
                            &*self.audit_sink,
                            hermod_storage::AuditEntry {
                                id: None,
                                ts: hermod_core::Timestamp::now(),
                                actor: self.host_actor.clone(),
                                action: "audit.archived".into(),
                                target: None,
                                details: Some(serde_json::json!({
                                    "outcome": "success",
                                    "archives": audit_archives_created,
                                    "rows": res.rows_archived,
                                })),
                                client_ip: None,
                                federation: hermod_storage::AuditFederationPolicy::Default,
                            },
                        )
                        .await;
                    }
                }
                Err(e) => {
                    warn!(error = %e, "janitor audit archival failed");
                    crate::services::audit_or_warn(
                        &*self.audit_sink,
                        hermod_storage::AuditEntry {
                            id: None,
                            ts: hermod_core::Timestamp::now(),
                            actor: self.host_actor.clone(),
                            action: "audit.archived".into(),
                            target: None,
                            details: Some(serde_json::json!({
                                "outcome": "failure",
                                "reason": e.to_string(),
                            })),
                            client_ip: None,
                            federation: hermod_storage::AuditFederationPolicy::Default,
                        },
                    )
                    .await;
                }
            }
        }

        let report = JanitorReport {
            briefs_pruned,
            confirmations_expired,
            discovered_pruned,
            sessions_pruned: outcome.pruned,
            messages_expired,
            messages_terminal,
            capabilities_pruned,
            rate_buckets_pruned,
            audit_archives_created,
        };

        if report.touched_anything() {
            debug!(?report, "janitor swept");
        }
        Ok(report)
    }
}

#[derive(Clone, Debug, Default)]
pub struct JanitorReport {
    pub briefs_pruned: u64,
    pub confirmations_expired: u64,
    pub discovered_pruned: u64,
    pub sessions_pruned: u64,
    pub messages_expired: u64,
    pub messages_terminal: u64,
    pub capabilities_pruned: u64,
    pub rate_buckets_pruned: u64,
    pub audit_archives_created: u64,
}

impl JanitorReport {
    pub fn touched_anything(&self) -> bool {
        self.briefs_pruned
            + self.confirmations_expired
            + self.discovered_pruned
            + self.sessions_pruned
            + self.messages_expired
            + self.messages_terminal
            + self.capabilities_pruned
            + self.rate_buckets_pruned
            + self.audit_archives_created
            > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hermod_core::{AgentId, PubkeyBytes, TrustLevel};
    use hermod_storage::{AgentRecord, BriefRecord};

    async fn fresh_db() -> Arc<dyn Database> {
        let mut p = std::env::temp_dir();
        p.push(format!("hermod-janitor-{}.sqlite", ulid::Ulid::new()));
        let dsn = format!("sqlite://{}", p.display());
        hermod_storage::open_database(
            &dsn,
            std::sync::Arc::new(hermod_crypto::LocalKeySigner::new(std::sync::Arc::new(
                hermod_crypto::Keypair::generate(),
            ))) as std::sync::Arc<dyn hermod_crypto::Signer>,
            std::sync::Arc::new(hermod_storage::MemoryBlobStore::new()),
        )
        .await
        .unwrap()
    }

    fn fake_agent(b: u8) -> AgentId {
        hermod_crypto::agent_id_from_pubkey(&PubkeyBytes([b; 32]))
    }

    async fn ensure_agent(db: &Arc<dyn Database>, id: &AgentId) {
        let now = Timestamp::now();
        db.agents()
            .upsert(&AgentRecord {
                id: id.clone(),
                pubkey: PubkeyBytes([1u8; 32]),
                host_pubkey: None,
                endpoint: None,
                via_agent: None,
                local_alias: None,
                peer_asserted_alias: None,
                trust_level: TrustLevel::Local,
                tls_fingerprint: None,
                reputation: 0,
                first_seen: now,
                last_seen: Some(now),
                peer_asserted_tags: hermod_core::CapabilityTagSet::empty(),
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn sweep_prunes_expired_brief_and_expires_old_confirmation() {
        let db = fresh_db().await;
        let agent = fake_agent(1);
        ensure_agent(&db, &agent).await;

        // Brief that expired 1s ago.
        let now = Timestamp::now();
        let past = Timestamp::from_unix_ms(now.unix_ms() - 1_000).unwrap();
        db.briefs()
            .upsert(&BriefRecord {
                agent_id: agent.clone(),
                topic: None,
                summary: "stale".into(),
                published_at: past,
                expires_at: Some(past),
            })
            .await
            .unwrap();

        // A pending confirmation captured fresh; we sweep with a 0-second
        // retention to force expiry (the time math is the same one the
        // daemon uses with config-driven retention).
        let env_id = hermod_core::MessageId::new();
        let id = db
            .confirmations()
            .enqueue(hermod_storage::HoldRequest {
                envelope_id: &env_id,
                actor: &agent,
                recipient: &agent,
                intent: hermod_storage::HoldedIntent::DirectMessage,
                sensitivity: "review",
                trust_level: TrustLevel::Tofu,
                summary: "stale held",
                envelope_cbor: b"\x00\x01",
            })
            .await
            .unwrap()
            .expect("first enqueue inserts");

        let audit_sink: Arc<dyn AuditSink> =
            Arc::new(hermod_storage::StorageAuditSink::new(db.clone()));
        let janitor = JanitorWorker::new(
            db.clone(),
            audit_sink,
            agent.clone(),
            JanitorConfig {
                sweep_interval: Duration::from_secs(60),
                confirmation_retention: Some(Duration::ZERO),
                discovery_retention: Some(Duration::ZERO),
                session_ttl: Duration::from_secs(SESSION_TTL_SECS),
                message_terminal_retention: Some(Duration::ZERO),
                rate_bucket_idle_retention: Some(Duration::ZERO),
                rate_bucket_capacity: 60,
                audit_retention: None,
            },
        );
        let report = janitor.sweep_once().await.unwrap();
        assert_eq!(report.briefs_pruned, 1);
        assert_eq!(report.confirmations_expired, 1);

        // Brief gone, confirmation marked expired (still present, not deleted).
        let brief = db
            .briefs()
            .latest(&agent, None, Timestamp::now().unix_ms())
            .await
            .unwrap();
        assert!(brief.is_none());
        let conf = db.confirmations().get(&id).await.unwrap().unwrap();
        assert_eq!(conf.status, hermod_storage::ConfirmationStatus::Expired);

        // Idempotency: a second sweep finds nothing to do.
        let report2 = janitor.sweep_once().await.unwrap();
        assert!(!report2.touched_anything());
    }
}
