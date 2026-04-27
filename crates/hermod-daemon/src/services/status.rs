use std::sync::Arc;
use hermod_core::Timestamp;
use hermod_crypto::Keypair;
use hermod_protocol::ipc::methods::{IdentityGetResult, StatusGetResult};
use hermod_storage::{Database, SESSION_TTL_SECS};
use std::time::Instant;

use crate::services::ServiceError;

#[derive(Debug, Clone)]
pub struct StatusService {
    db: Arc<dyn Database>,
    started_at: Instant,
    keypair: KeyRef,
}

#[derive(Debug, Clone)]
pub struct KeyRef {
    pub agent_id: hermod_core::AgentId,
    pub alias: Option<hermod_core::AgentAlias>,
    pub fingerprint: String,
}

impl KeyRef {
    pub fn from_keypair(kp: &Keypair, alias: Option<hermod_core::AgentAlias>) -> Self {
        Self {
            agent_id: kp.agent_id(),
            alias,
            fingerprint: kp.fingerprint().to_human_prefix(8),
        }
    }
}

impl StatusService {
    pub fn new(db: Arc<dyn Database>, keypair: KeyRef, started_at: Instant) -> Self {
        Self {
            db,
            started_at,
            keypair,
        }
    }

    pub async fn status(&self) -> Result<StatusGetResult, ServiceError> {
        let pending = self
            .db
            .messages()
            .count_pending_to(&self.keypair.agent_id)
            .await?;
        let peers = self.db.agents().list_federated().await?.len() as i64;
        let attached_sessions = self
            .db
            .mcp_sessions()
            .count_live(Timestamp::now(), (SESSION_TTL_SECS * 1_000) as i64)
            .await? as u32;
        let schema_version = self.db.schema_version().await?;
        Ok(StatusGetResult {
            version: env!("CARGO_PKG_VERSION").to_string(),
            agent_id: self.keypair.agent_id.clone(),
            alias: self.keypair.alias.clone(),
            pending_messages: pending,
            peer_count: peers,
            uptime_secs: self.started_at.elapsed().as_secs(),
            attached_sessions,
            schema_version,
        })
    }

    pub async fn identity(&self) -> Result<IdentityGetResult, ServiceError> {
        Ok(IdentityGetResult {
            agent_id: self.keypair.agent_id.clone(),
            alias: self.keypair.alias.clone(),
            fingerprint: self.keypair.fingerprint.clone(),
        })
    }
}
