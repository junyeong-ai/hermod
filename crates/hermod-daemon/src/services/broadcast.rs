use futures::stream::{self, StreamExt};
use hermod_core::{AgentAddress, AgentId, MessageBody, MessageId, MessagePriority, Timestamp};
use hermod_crypto::ChannelId;
use hermod_protocol::ipc::methods::{BroadcastSendParams, BroadcastSendResult, MessageSendParams};
use hermod_storage::{AuditEntry, AuditSink, ChannelMessage, Database};
use serde_bytes::ByteBuf;
use std::sync::Arc;
use tracing::warn;

use crate::services::{
    ServiceError, audit_or_warn, fanout::FANOUT_CONCURRENCY, message::MessageService,
};

const MAX_BROADCAST_BYTES: usize = 4096;

/// Hard ceiling on a single broadcast fan-out. Mirrors
/// `fanout::MAX_FANOUT_PER_CALL` (256) — channels and workspace-wide
/// briefs share the same operational scale assumption: workspaces
/// beyond a few hundred members should split.
const MAX_BROADCAST_FANOUT: usize = 256;

#[derive(Debug, Clone)]
pub struct BroadcastService {
    db: Arc<dyn Database>,
    audit_sink: Arc<dyn AuditSink>,
    self_id: AgentId,
    messages: MessageService,
}

impl BroadcastService {
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

    pub async fn send(
        &self,
        params: BroadcastSendParams,
    ) -> Result<BroadcastSendResult, ServiceError> {
        if params.text.is_empty() {
            return Err(ServiceError::InvalidParam("text is empty".into()));
        }
        if params.text.len() > MAX_BROADCAST_BYTES {
            return Err(ServiceError::InvalidParam(format!(
                "text exceeds {MAX_BROADCAST_BYTES} bytes"
            )));
        }
        let channel_id = ChannelId::from_hex(&params.channel_id)
            .map_err(|e| ServiceError::InvalidParam(format!("channel id: {e}")))?;
        let channel = self
            .db
            .channels()
            .get(&channel_id)
            .await?
            .ok_or(ServiceError::NotFound)?;
        if channel.muted {
            return Err(ServiceError::InvalidParam(
                "channel is muted; unmute it first to broadcast".into(),
            ));
        }
        let workspace = self
            .db
            .workspaces()
            .get(&channel.workspace_id)
            .await?
            .ok_or(ServiceError::NotFound)?;
        if workspace.muted {
            return Err(ServiceError::InvalidParam(
                "workspace is muted; unmute it first to broadcast".into(),
            ));
        }

        // Compute the per-broadcast MAC under the channel's MAC key (if private).
        let hmac = channel
            .mac_key
            .as_ref()
            .map(|key| ByteBuf::from(key.mac(params.text.as_bytes()).to_vec()));

        let body = MessageBody::ChannelBroadcast {
            workspace_id: ByteBuf::from(channel.workspace_id.0.to_vec()),
            channel_id: ByteBuf::from(channel_id.0.to_vec()),
            text: params.text.clone(),
            hmac,
        };

        // Local copy: the author sees their own broadcast in history. The
        // envelope id is generated below per-fanout, so we synthesise a
        // dedicated id for the local copy.
        let local_id = MessageId::new();
        let now = Timestamp::now();
        self.db
            .channels()
            .record_message(&ChannelMessage {
                id: local_id,
                channel_id,
                from_agent: self.self_id.clone(),
                body_text: params.text.clone(),
                received_at: now,
            })
            .await?;

        // Fan out to every known remote member, in parallel up to
        // `FANOUT_CONCURRENCY` in flight. Sequential delivery would
        // multiply transport latency by the workspace size — the
        // bounded-parallelism stream keeps a 100-member channel
        // broadcast within sub-second latency. Members beyond
        // `MAX_BROADCAST_FANOUT` are dropped (warn) so a misconfigured
        // mega-workspace can't pin the daemon for minutes per send.
        let mut members = self
            .db
            .workspace_members()
            .list(&channel.workspace_id)
            .await?;
        let total = members.len();
        if total > MAX_BROADCAST_FANOUT {
            warn!(
                total,
                cap = MAX_BROADCAST_FANOUT,
                channel = %channel_id.to_hex(),
                "broadcast truncated: member count exceeds per-call cap"
            );
            members.truncate(MAX_BROADCAST_FANOUT);
        }

        let self_id = self.self_id.clone();
        let outcomes: Vec<bool> = stream::iter(
            members
                .into_iter()
                .filter(move |m| m.as_str() != self_id.as_str()),
        )
        .map(|member| {
            let body = body.clone();
            let messages = self.messages.clone();
            let db = self.db.clone();
            async move { dispatch_one(&*db, &messages, member, body).await }
        })
        .buffer_unordered(FANOUT_CONCURRENCY)
        .collect()
        .await;
        let fanout: u32 = outcomes.into_iter().filter(|ok| *ok).count() as u32;

        audit_or_warn(
            &*self.audit_sink,
            AuditEntry {
                id: None,
                ts: now,
                actor: self.self_id.clone(),
                action: "broadcast.send".into(),
                target: Some(channel_id.to_hex()),
                details: Some(serde_json::json!({
                    "workspace_id": channel.workspace_id.to_hex(),
                    "len": params.text.len(),
                    "fanout": fanout,
                })),
                federation: hermod_storage::AuditFederationPolicy::Default,
            },
        )
        .await;

        Ok(BroadcastSendResult {
            id: local_id,
            fanout,
        })
    }
}

/// Resolve `member`'s endpoint and dispatch one envelope. Returns
/// `true` on successful enqueue, `false` on any skip / error. Run
/// concurrently up to `FANOUT_CONCURRENCY` per broadcast.
async fn dispatch_one(
    db: &dyn Database,
    messages: &MessageService,
    member: AgentId,
    body: MessageBody,
) -> bool {
    let recipient = match db.agents().get(&member).await {
        Ok(Some(rec)) => match rec.endpoint {
            Some(ep) if !ep.is_local() => AgentAddress::with_endpoint(rec.id, ep),
            _ => AgentAddress::local(rec.id),
        },
        Ok(None) => {
            warn!(member = %member, "skipping fanout: agent not in directory");
            return false;
        }
        Err(e) => {
            warn!(member = %member, error = %e, "skipping fanout: directory lookup failed");
            return false;
        }
    };
    match messages
        .send(MessageSendParams {
            to: recipient,
            body,
            priority: Some(MessagePriority::Normal),
            thread: None,
            ttl_secs: Some(3600),
            caps: None,
        })
        .await
    {
        Ok(_) => true,
        Err(e) => {
            warn!(member = %member, error = %e, "fanout send failed");
            false
        }
    }
}
