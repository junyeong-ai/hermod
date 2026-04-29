use hermod_core::{AgentAlias, AgentId, MessageBody, MessagePriority, Timestamp};
use hermod_protocol::ipc::methods::{
    BriefPublishParams, BriefPublishResult, BriefReadParams, BriefReadResult, BriefView,
};
use hermod_storage::{AuditEntry, AuditSink, BriefRecord, Database};
use std::str::FromStr;
use std::sync::Arc;

use crate::services::{ServiceError, audit_or_warn, fanout, message::MessageService};

const DEFAULT_BRIEF_TTL_SECS: u32 = 3600;
/// 30 days. A brief older than that is operator hygiene to refresh; the
/// upper bound also keeps us safely inside `Timestamp::from_unix_ms`.
const MAX_BRIEF_TTL_SECS: u32 = 30 * 24 * 3600;
const MAX_SUMMARY_BYTES: usize = 4096;
const MAX_TOPIC_BYTES: usize = 64;

#[derive(Debug, Clone)]
pub struct BriefService {
    db: Arc<dyn Database>,
    audit_sink: Arc<dyn AuditSink>,
    self_id: AgentId,
    messages: MessageService,
}

impl BriefService {
    pub fn new(
        db: Arc<dyn Database>,
        audit_sink: Arc<dyn AuditSink>,
        self_id: AgentId,
        messages: MessageService,
    ) -> Self {
        Self {
            db,
            audit_sink,
            self_id,
            messages,
        }
    }

    pub async fn publish(
        &self,
        params: BriefPublishParams,
    ) -> Result<BriefPublishResult, ServiceError> {
        if params.summary.is_empty() {
            return Err(ServiceError::InvalidParam("summary is empty".into()));
        }
        if params.summary.len() > MAX_SUMMARY_BYTES {
            return Err(ServiceError::InvalidParam(format!(
                "summary exceeds {MAX_SUMMARY_BYTES} bytes"
            )));
        }
        if let Some(t) = &params.topic
            && t.len() > MAX_TOPIC_BYTES
        {
            return Err(ServiceError::InvalidParam(format!(
                "topic exceeds {MAX_TOPIC_BYTES} bytes"
            )));
        }
        let now = Timestamp::now();
        let ttl = params.ttl_secs.unwrap_or(DEFAULT_BRIEF_TTL_SECS);
        if ttl > MAX_BRIEF_TTL_SECS {
            return Err(ServiceError::InvalidParam(format!(
                "ttl_secs > {MAX_BRIEF_TTL_SECS} (30 days)"
            )));
        }
        let expires_at = if ttl == 0 {
            None
        } else {
            Some(
                Timestamp::from_unix_ms(now.unix_ms() + (ttl as i64) * 1_000)
                    .expect("bounded ttl never overflows Timestamp"),
            )
        };

        self.db
            .briefs()
            .upsert(&BriefRecord {
                agent_id: self.self_id.clone(),
                topic: params.topic.clone(),
                summary: params.summary.clone(),
                published_at: now,
                expires_at,
            })
            .await?;

        // Fan out to workspace collaborators so cross-daemon `brief read`
        // returns the same content. Local-only deployments have no members
        // and fanout=0 — that's the silent-success path.
        let body = MessageBody::Brief {
            summary: params.summary.clone(),
            topic: params.topic.clone(),
        };
        let outcome = fanout::fanout_to_workspace_members(
            &*self.db,
            &self.messages,
            &self.self_id,
            body,
            MessagePriority::Low,
            ttl,
        )
        .await?;

        audit_or_warn(
            &*self.audit_sink,
            AuditEntry {
                id: None,
                ts: now,
                actor: self.self_id.clone(),
                action: "brief.publish".into(),
                target: None,
                details: Some(serde_json::json!({
                    "topic": params.topic,
                    "len": params.summary.len(),
                    "ttl_secs": ttl,
                    "fanout": outcome.delivered,
                    "skipped": outcome.skipped,
                    "truncated_at": outcome.truncated_at,
                })),
                client_ip: None,
                federation: hermod_storage::AuditFederationPolicy::Default,
            },
        )
        .await;

        Ok(BriefPublishResult {
            published_at: now,
            expires_at,
        })
    }

    pub async fn read(&self, params: BriefReadParams) -> Result<BriefReadResult, ServiceError> {
        let agent_id = self.resolve_agent(&params.agent).await?;
        let now = Timestamp::now();
        let rec = self
            .db
            .briefs()
            .latest(&agent_id, params.topic.as_deref(), now.unix_ms())
            .await?;
        Ok(BriefReadResult {
            brief: rec.map(|r| BriefView {
                agent: r.agent_id,
                summary: r.summary,
                topic: r.topic,
                published_at: r.published_at,
                expires_at: r.expires_at,
            }),
        })
    }

    async fn resolve_agent(&self, reference: &str) -> Result<AgentId, ServiceError> {
        if let Some(alias_raw) = reference.strip_prefix('@') {
            let alias = AgentAlias::from_str(alias_raw)
                .map_err(|e| ServiceError::InvalidParam(format!("invalid alias: {e}")))?;
            let rec = self
                .db
                .agents()
                .get_by_local_alias(&alias)
                .await?
                .ok_or(ServiceError::NotFound)?;
            Ok(rec.id)
        } else {
            AgentId::from_str(reference)
                .map_err(|e| ServiceError::InvalidParam(format!("invalid agent id: {e}")))
        }
    }
}
