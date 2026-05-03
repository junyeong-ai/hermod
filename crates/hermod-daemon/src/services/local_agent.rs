//! Live registry mutation: `local.add` / `local.remove` /
//! `local.rotate` / `local.list`. Operator-driven IPC paths that
//! provision, archive, or rotate a hosted agent **without restarting
//! the daemon**.
//!
//! Each mutation:
//!   1. Writes the on-disk authoritative state (keypair, bearer
//!      file, alias file) atomically.
//!   2. Updates the `local_agents` + `agents` DB rows in lockstep.
//!   3. Updates the in-memory `LocalAgentRegistry` (which
//!      simultaneously refreshes the bearer-hash index used by the
//!      remote-IPC handshake).
//!   4. On `remove` / `rotate`, force-closes any active IPC session
//!      pinned to the agent's previous bearer (per-session
//!      `oneshot::Sender<()>` registered at handshake time).
//!
//! The disk → DB → registry order matters: a crash mid-mutation
//! leaves disk authoritative and the next daemon boot reconciles via
//! `merge_with_db`. DB-first or registry-first ordering would let a
//! reboot diverge from disk silently.

use hermod_core::{AgentAlias, AgentId, Timestamp, TrustLevel};
use hermod_protocol::ipc::methods::{
    LocalAddParams, LocalAddResult, LocalAgentSummary, LocalListResult, LocalRemoveParams,
    LocalRemoveResult, LocalRotateParams, LocalRotateResult, LocalTagSetParams, LocalTagSetResult,
};
use hermod_storage::{AgentRecord, AuditEntry, AuditSink, Database, LocalAgentRecord};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use crate::local_agent::{
    self as la, LocalAgentRegistry, archive_agent, bearer_token_path, create_additional,
    rotate_bearer_on_disk, secret_path,
};
use crate::services::{ServiceError, audit_or_warn};

/// Static announce parameters threaded into [`LocalAgentService`] so
/// `local.add` can publish a freshly-provisioned agent's mDNS beacon
/// immediately. `None` when `[federation] discover_mdns` is off (the
/// daemon doesn't have an active discoverer).
#[derive(Clone, Debug)]
pub struct LocalDiscoverHook {
    pub discoverer: Arc<dyn hermod_discovery::Discoverer>,
    /// `<host_id_prefix>.local.` — same hostname the boot-time
    /// announce loop used.
    pub hostname: String,
    pub listen_port: u16,
    pub validity_secs: u32,
}

#[derive(Debug, Clone)]
pub struct LocalAgentService {
    db: Arc<dyn Database>,
    audit_sink: Arc<dyn AuditSink>,
    /// Audit-fallback actor for emissions on this path. The
    /// `audit_or_warn` overlay still replaces it with the IPC
    /// caller's agent_id when one is in scope.
    host_actor: AgentId,
    /// Daemon's host pubkey — fed into freshly-inserted `agents`
    /// rows so federation peers know which host owns the new agent.
    host_pubkey: hermod_core::PubkeyBytes,
    registry: LocalAgentRegistry,
    home: PathBuf,
    /// `Some` when mDNS auto-discovery is enabled. The service
    /// announces a fresh beacon on `local.add` and unannounces on
    /// `local.remove` so the LAN view stays consistent without a
    /// daemon restart.
    discover: Option<LocalDiscoverHook>,
}

impl LocalAgentService {
    pub fn new(
        db: Arc<dyn Database>,
        audit_sink: Arc<dyn AuditSink>,
        host_actor: AgentId,
        host_pubkey: hermod_core::PubkeyBytes,
        registry: LocalAgentRegistry,
        home: PathBuf,
    ) -> Self {
        Self {
            db,
            audit_sink,
            host_actor,
            host_pubkey,
            registry,
            home,
            discover: None,
        }
    }

    /// Wire the mDNS hook so live `local.add` / `local.remove`
    /// publish + unannounce beacons. Called by `server.rs` after the
    /// discoverer is constructed; called only when
    /// `[federation] discover_mdns = true`.
    pub fn with_discover_hook(mut self, hook: LocalDiscoverHook) -> Self {
        self.discover = Some(hook);
        self
    }

    pub async fn list(&self) -> Result<LocalListResult, ServiceError> {
        let agents = self
            .registry
            .list()
            .into_iter()
            .map(|a| summary_for(&self.home, &a))
            .collect();
        Ok(LocalListResult { agents })
    }

    pub async fn add(&self, params: LocalAddParams) -> Result<LocalAddResult, ServiceError> {
        let alias = params.alias.clone();
        // 1. Disk: write keypair + bearer + alias atomically.
        let agent = create_additional(&self.home, alias.clone())
            .map_err(|e| ServiceError::InvalidParam(format!("create on disk: {e}")))?;

        // 2. DB: insert agents directory row first (the local_agents
        //    FK references it), then the local_agents row.
        let bearer_hash = agent.bearer_hash();
        let now = Timestamp::now();
        let host_id = hermod_crypto::agent_id_from_pubkey(&self.host_pubkey);
        let agent_record = AgentRecord {
            id: agent.agent_id.clone(),
            pubkey: agent.keypair.to_pubkey_bytes(),
            host_id: None,
            via_agent: None,
            local_alias: alias.clone(),
            peer_asserted_alias: None,
            trust_level: TrustLevel::Local,
            reputation: 0,
            first_seen: now,
            last_seen: Some(now),
            // local agents have no peer-asserted facet (we host
            // them) — the operator-set tags live on the
            // `local_agents.tags` column instead.
            peer_asserted_tags: hermod_core::CapabilityTagSet::empty(),
        };
        self.db
            .agents()
            .upsert(&agent_record)
            .await
            .map_err(ServiceError::Storage)?;
        self.db
            .agents()
            .set_routing_direct(&agent.agent_id, &host_id)
            .await
            .map_err(ServiceError::Storage)?;
        let db_record = LocalAgentRecord {
            agent_id: agent.agent_id.clone(),
            bearer_hash,
            workspace_root: None,
            created_at: now,
            tags: hermod_core::CapabilityTagSet::empty(),
        };
        self.db
            .local_agents()
            .insert(&db_record)
            .await
            .map_err(ServiceError::Storage)?;

        // 3. Registry: insert in memory.
        let bearer_token_str = agent.bearer_token.expose_secret().to_string();
        self.registry
            .insert(agent.clone())
            .map_err(|e| ServiceError::InvalidParam(format!("registry insert: {e}")))?;

        // 4. mDNS announce, when enabled. Best-effort — a failure
        //    here doesn't undo the disk + DB + registry insert; the
        //    operator can republish via the next daemon boot.
        if let Some(hook) = &self.discover {
            let alias_str = agent.local_alias.as_ref().map(|a| a.as_str().to_string());
            let signer: Arc<dyn hermod_crypto::Signer> =
                Arc::new(hermod_crypto::LocalKeySigner::new(agent.keypair.clone()));
            let params = hermod_discovery::AnnounceParams {
                hostname: &hook.hostname,
                port: hook.listen_port,
                signer,
                validity_secs: hook.validity_secs,
                alias: alias_str.as_deref(),
            };
            if let Err(e) = hook.discoverer.announce(params).await {
                tracing::warn!(
                    agent = %agent.agent_id,
                    error = %e,
                    "mdns announce failed for new local agent",
                );
            }
        }

        audit_or_warn(
            &*self.audit_sink,
            AuditEntry {
                id: None,
                ts: now,
                actor: self.host_actor.clone(),
                action: "local.add".into(),
                target: Some(agent.agent_id.to_string()),
                details: Some(serde_json::json!({
                    "alias": alias.as_ref().map(|a| a.as_str()),
                })),
                client_ip: None,
                federation: hermod_storage::AuditFederationPolicy::Default,
            },
        )
        .await;

        Ok(LocalAddResult {
            agent: summary_for(&self.home, &agent),
            bearer_token: bearer_token_str,
        })
    }

    pub async fn remove(
        &self,
        params: LocalRemoveParams,
    ) -> Result<LocalRemoveResult, ServiceError> {
        if !params.force {
            return Err(ServiceError::InvalidParam(
                "local.remove requires force=true — the agent's keypair is unrecoverable once archived".into(),
            ));
        }
        let agent = self.resolve(&params.reference).await?;

        // 1. Force-close active sessions + drop from registry. We do
        //    this BEFORE the disk archive so any in-flight RPC running
        //    under this agent's bearer terminates immediately rather
        //    than continuing against a half-deleted state.
        let removed = self.registry.remove(&agent.agent_id);
        if !removed {
            return Err(ServiceError::NotFound);
        }

        // 2. Disk: archive the agent dir.
        let archive = archive_agent(&self.home, &agent.agent_id)
            .map_err(|e| ServiceError::InvalidParam(format!("archive: {e}")))?;

        // 3. DB: delete local_agents row. The `agents` directory row
        //    stays so downstream audit references resolve; the row's
        //    cascade-delete fires only when the operator explicitly
        //    runs `peer remove` on it (the agent is no longer hosted
        //    here, but its identity is still real).
        self.db
            .local_agents()
            .remove(&agent.agent_id)
            .await
            .map_err(ServiceError::Storage)?;

        // 4. mDNS unannounce. Best-effort — peers fall off via the
        //    beacon validity TTL anyway, but explicit unannounce
        //    drops them immediately.
        if let Some(hook) = &self.discover
            && let Err(e) = hook.discoverer.unannounce(agent.agent_id.as_str()).await
        {
            tracing::warn!(
                agent = %agent.agent_id,
                error = %e,
                "mdns unannounce failed for removed local agent",
            );
        }

        audit_or_warn(
            &*self.audit_sink,
            AuditEntry {
                id: None,
                ts: Timestamp::now(),
                actor: self.host_actor.clone(),
                action: "local.remove".into(),
                target: Some(agent.agent_id.to_string()),
                details: Some(serde_json::json!({
                    "archive": archive.display().to_string(),
                })),
                client_ip: None,
                federation: hermod_storage::AuditFederationPolicy::Default,
            },
        )
        .await;

        Ok(LocalRemoveResult {
            agent_id: agent.agent_id,
            archive_path: archive.display().to_string(),
        })
    }

    pub async fn rotate(
        &self,
        params: LocalRotateParams,
    ) -> Result<LocalRotateResult, ServiceError> {
        let agent = self.resolve(&params.reference).await?;
        // 1. Disk first — keypair + bearer file are the canonical
        //    source. A rotate that succeeds on disk but fails to
        //    update DB / registry is recovered via `merge_with_db` on
        //    next daemon boot.
        let new_secret = rotate_bearer_on_disk(&self.home, &agent.agent_id)
            .map_err(|e| ServiceError::InvalidParam(format!("disk rotate: {e}")))?;
        let new_str = new_secret.expose_secret().to_string();
        let new_hash = la::bearer_hash(&new_secret);

        // 2. DB.
        let updated = self
            .db
            .local_agents()
            .rotate_bearer(&agent.agent_id, new_hash)
            .await
            .map_err(ServiceError::Storage)?;
        if !updated {
            return Err(ServiceError::NotFound);
        }

        // 3. Registry — replaces the bearer index entry + force-
        //    closes any active session still using the previous
        //    bearer.
        let swapped = self.registry.replace_bearer(&agent.agent_id, new_secret);
        if !swapped {
            return Err(ServiceError::NotFound);
        }

        audit_or_warn(
            &*self.audit_sink,
            AuditEntry {
                id: None,
                ts: Timestamp::now(),
                actor: self.host_actor.clone(),
                action: "local.rotate".into(),
                target: Some(agent.agent_id.to_string()),
                details: None,
                client_ip: None,
                federation: hermod_storage::AuditFederationPolicy::Default,
            },
        )
        .await;

        Ok(LocalRotateResult {
            agent_id: agent.agent_id,
            bearer_token: new_str,
        })
    }

    /// Resolve a `local.*` reference: either a bare `agent_id`
    /// (26-char base32) or `@<alias>`.
    async fn resolve(
        &self,
        reference: &str,
    ) -> Result<crate::local_agent::LocalAgent, ServiceError> {
        if let Some(alias_raw) = reference.strip_prefix('@') {
            let alias = AgentAlias::from_str(alias_raw)
                .map_err(|e| ServiceError::InvalidParam(format!("invalid alias: {e}")))?;
            return self
                .registry
                .list()
                .into_iter()
                .find(|a| a.local_alias.as_ref() == Some(&alias))
                .ok_or(ServiceError::NotFound);
        }
        let id = AgentId::from_str(reference)
            .map_err(|e| ServiceError::InvalidParam(format!("invalid agent id: {e}")))?;
        self.registry.lookup(&id).ok_or(ServiceError::NotFound)
    }

    /// Replace the operator-set tag set on one local agent.
    /// Validates cardinality + dedup through `from_validated`.
    /// Audits `local.tag_set` so an operator review trail captures
    /// the change.
    pub async fn tag_set(
        &self,
        params: LocalTagSetParams,
    ) -> Result<LocalTagSetResult, ServiceError> {
        let agent = self.resolve(&params.reference).await?;
        let tag_set = hermod_core::CapabilityTagSet::from_validated(params.tags)
            .map_err(|e| ServiceError::InvalidParam(format!("tags: {e}")))?;
        let updated = self
            .db
            .local_agents()
            .set_tags(&agent.agent_id, &tag_set)
            .await
            .map_err(ServiceError::Storage)?;
        if !updated {
            return Err(ServiceError::NotFound);
        }
        audit_or_warn(
            &*self.audit_sink,
            AuditEntry {
                id: None,
                ts: Timestamp::now(),
                actor: self.host_actor.clone(),
                action: "local.tag_set".into(),
                target: Some(agent.agent_id.to_string()),
                details: Some(serde_json::json!({
                    "tags": tag_set
                        .iter()
                        .map(|t| t.as_str().to_string())
                        .collect::<Vec<_>>(),
                })),
                client_ip: None,
                federation: hermod_storage::AuditFederationPolicy::Default,
            },
        )
        .await;
        Ok(LocalTagSetResult {
            agent_id: agent.agent_id,
            tags: tag_set.iter().cloned().collect(),
        })
    }
}

fn summary_for(
    home: &std::path::Path,
    agent: &crate::local_agent::LocalAgent,
) -> LocalAgentSummary {
    LocalAgentSummary {
        agent_id: agent.agent_id.clone(),
        alias: agent.local_alias.clone(),
        pubkey_hex: hex::encode(agent.keypair.to_pubkey_bytes().as_slice()),
        bearer_file: bearer_token_path(home, &agent.agent_id)
            .display()
            .to_string(),
        secret_file: secret_path(home, &agent.agent_id).display().to_string(),
    }
}
