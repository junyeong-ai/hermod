use hermod_core::{AgentId, Timestamp};
use hermod_crypto::PublicKey;
use hermod_protocol::ipc::methods::{IdentityGetResult, StatusGetResult};
use hermod_storage::{Database, SESSION_TTL_SECS};
use std::sync::Arc;
use std::time::Instant;

use crate::audit_context::current_caller_agent;
use crate::local_agent::LocalAgentRegistry;
use crate::services::ServiceError;

#[derive(Debug, Clone)]
pub struct StatusService {
    db: Arc<dyn Database>,
    started_at: Instant,
    registry: LocalAgentRegistry,
    host_pubkey_hex: String,
}

impl StatusService {
    pub fn new(
        db: Arc<dyn Database>,
        registry: LocalAgentRegistry,
        host_pubkey: &PublicKey,
        started_at: Instant,
    ) -> Self {
        Self {
            db,
            started_at,
            registry,
            host_pubkey_hex: hex::encode(host_pubkey.to_bytes().0),
        }
    }

    fn caller(&self) -> Result<AgentId, ServiceError> {
        current_caller_agent().ok_or_else(|| {
            ServiceError::InvalidParam(
                "status/identity require an IPC caller scope (no caller_agent in context)".into(),
            )
        })
    }

    pub async fn status(&self) -> Result<StatusGetResult, ServiceError> {
        let caller = self.caller()?;
        let agent = self
            .registry
            .lookup(&caller)
            .ok_or(ServiceError::NotFound)?;
        let pending = self.db.messages().count_pending_to(&caller).await?;
        let peers = self.db.agents().list_federated().await?.len() as i64;
        let attached_sessions = self
            .db
            .mcp_sessions()
            .count_live(Timestamp::now(), (SESSION_TTL_SECS * 1_000) as i64)
            .await? as u32;
        let schema_version = self.db.schema_version().await?;
        Ok(StatusGetResult {
            version: env!("CARGO_PKG_VERSION").to_string(),
            agent_id: caller,
            alias: agent.local_alias.clone(),
            pending_messages: pending,
            peer_count: peers,
            uptime_secs: self.started_at.elapsed().as_secs(),
            attached_sessions,
            schema_version,
        })
    }

    pub async fn identity(&self) -> Result<IdentityGetResult, ServiceError> {
        let caller = self.caller()?;
        let agent = self
            .registry
            .lookup(&caller)
            .ok_or(ServiceError::NotFound)?;
        let fingerprint = agent.keypair.fingerprint().to_human_prefix(8);
        Ok(IdentityGetResult {
            agent_id: caller,
            alias: agent.local_alias.clone(),
            fingerprint,
            host_pubkey_hex: self.host_pubkey_hex.clone(),
        })
    }
}
