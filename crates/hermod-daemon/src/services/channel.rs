use std::sync::Arc;
use hermod_core::WorkspaceVisibility;
use hermod_core::{AgentAddress, AgentId, Endpoint, MessageBody, MessagePriority, Timestamp};
use hermod_crypto::{ChannelId, WorkspaceId, public_channel_id};
use hermod_protocol::ipc::methods::{
    ChannelAdoptParams, ChannelAdoptResult, ChannelAdvertiseParams, ChannelAdvertiseResult,
    ChannelCreateParams, ChannelCreateResult, ChannelDeleteParams, ChannelDeleteResult,
    ChannelDiscoverParams, ChannelDiscoverResult, ChannelHistoryParams, ChannelHistoryResult,
    ChannelListParams, ChannelListResult, ChannelMessageView, ChannelMuteParams, ChannelMuteResult,
    ChannelView, DiscoveredChannelView, MessageSendParams,
};
use hermod_storage::{AuditEntry, ChannelRecord, Database, WorkspaceRecord, AuditSink};
use serde_bytes::ByteBuf;
use tracing::warn;

use crate::services::{ServiceError, audit_or_warn, message::MessageService};

const MAX_CHANNEL_NAME: usize = 64;
const DEFAULT_HISTORY_LIMIT: u32 = 50;
const MAX_HISTORY_LIMIT: u32 = 500;

#[derive(Debug, Clone)]
pub struct ChannelService {
    db: Arc<dyn Database>,
    audit_sink: Arc<dyn AuditSink>,
    self_id: AgentId,
    messages: MessageService,
}

impl ChannelService {
    pub fn new(db: Arc<dyn Database>, audit_sink: Arc<dyn AuditSink>,
        self_id: AgentId, messages: MessageService) -> Self {
        Self {
            db,
            audit_sink,
            self_id,
            messages,
        }
    }

    pub async fn create(
        &self,
        params: ChannelCreateParams,
    ) -> Result<ChannelCreateResult, ServiceError> {
        validate_name(&params.name)?;
        let workspace_id = parse_workspace_id(&params.workspace_id)?;
        let workspace = self
            .db
            .workspaces()
            .get(&workspace_id)
            .await?
            .ok_or(ServiceError::NotFound)?;

        let (channel_id, mac_key) = derive_channel(&workspace, &params.name)?;

        let now = Timestamp::now();
        self.db
            .channels()
            .upsert(&ChannelRecord {
                id: channel_id,
                workspace_id,
                name: params.name.clone(),
                mac_key,
                muted: false,
                joined_at: now,
                last_active: Some(now),
            })
            .await?;

        audit_or_warn(&*self.audit_sink,
            AuditEntry {
                id: None,
                ts: now,
                actor: self.self_id.clone(),
                action: "channel.create".into(),
                target: Some(channel_id.to_hex()),
                details: Some(serde_json::json!({
                    "workspace_id": params.workspace_id,
                    "name": params.name,
                })),
                federation: hermod_storage::AuditFederationPolicy::Default,
            },
        )
        .await;

        Ok(ChannelCreateResult {
            id: channel_id.to_hex(),
        })
    }

    pub async fn list(&self, params: ChannelListParams) -> Result<ChannelListResult, ServiceError> {
        let workspace_id = parse_workspace_id(&params.workspace_id)?;
        let rows = self.db.channels().list_in(&workspace_id).await?;
        Ok(ChannelListResult {
            channels: rows.into_iter().map(record_to_view).collect(),
        })
    }

    pub async fn history(
        &self,
        params: ChannelHistoryParams,
    ) -> Result<ChannelHistoryResult, ServiceError> {
        let channel_id = parse_channel_id(&params.channel_id)?;
        let limit = params
            .limit
            .unwrap_or(DEFAULT_HISTORY_LIMIT)
            .min(MAX_HISTORY_LIMIT);
        let rows = self.db.channels().history(&channel_id, limit).await?;
        Ok(ChannelHistoryResult {
            messages: rows
                .into_iter()
                .map(|m| ChannelMessageView {
                    id: m.id,
                    channel_id: m.channel_id.to_hex(),
                    from: m.from_agent,
                    text: m.body_text,
                    received_at: m.received_at,
                })
                .collect(),
        })
    }

    pub async fn delete(
        &self,
        params: ChannelDeleteParams,
    ) -> Result<ChannelDeleteResult, ServiceError> {
        let id = parse_channel_id(&params.channel_id)?;
        let removed = self.db.channels().delete(&id).await?;
        if !removed {
            return Err(ServiceError::NotFound);
        }
        audit_or_warn(&*self.audit_sink,
            AuditEntry {
                id: None,
                ts: Timestamp::now(),
                actor: self.self_id.clone(),
                action: "channel.delete".into(),
                target: Some(id.to_hex()),
                details: None,
                federation: hermod_storage::AuditFederationPolicy::Default,
            },
        )
        .await;
        Ok(ChannelDeleteResult { id: id.to_hex() })
    }

    pub async fn advertise(
        &self,
        params: ChannelAdvertiseParams,
    ) -> Result<ChannelAdvertiseResult, ServiceError> {
        let channel_id = parse_channel_id(&params.channel_id)?;
        let channel = self
            .db
            .channels()
            .get(&channel_id)
            .await?
            .ok_or(ServiceError::NotFound)?;

        let body = MessageBody::ChannelAdvertise {
            workspace_id: ByteBuf::from(channel.workspace_id.0.to_vec()),
            channel_id: ByteBuf::from(channel.id.0.to_vec()),
            channel_name: channel.name.clone(),
        };

        let members = self
            .db
            .workspace_members()
            .list(&channel.workspace_id)
            .await?;
        let mut fanout = 0u32;
        for member in members {
            if member.as_str() == self.self_id.as_str() {
                continue;
            }
            let recipient = match self.db.agents().get(&member).await? {
                Some(rec) => match rec.endpoint {
                    Some(Endpoint::Wss(w)) => AgentAddress::with_endpoint(rec.id, Endpoint::Wss(w)),
                    _ => AgentAddress::local(rec.id),
                },
                None => continue,
            };
            match self
                .messages
                .send(MessageSendParams {
                    to: recipient,
                    body: body.clone(),
                    priority: Some(MessagePriority::Low),
                    thread: None,
                    ttl_secs: Some(3600),
                    caps: None,
                })
                .await
            {
                Ok(_) => fanout = fanout.saturating_add(1),
                Err(e) => warn!(member = %member, error = %e, "advertise send failed"),
            }
        }

        audit_or_warn(&*self.audit_sink,
            AuditEntry {
                id: None,
                ts: Timestamp::now(),
                actor: self.self_id.clone(),
                action: "channel.advertise".into(),
                target: Some(channel.id.to_hex()),
                details: Some(serde_json::json!({
                    "workspace_id": channel.workspace_id.to_hex(),
                    "fanout": fanout,
                })),
                federation: hermod_storage::AuditFederationPolicy::Default,
            },
        )
        .await;

        Ok(ChannelAdvertiseResult {
            id: channel.id.to_hex(),
            fanout,
        })
    }

    pub async fn discover(
        &self,
        params: ChannelDiscoverParams,
    ) -> Result<ChannelDiscoverResult, ServiceError> {
        let workspace_id = parse_workspace_id(&params.workspace_id)?;
        let rows = self.db.discovered_channels().list_in(&workspace_id).await?;
        Ok(ChannelDiscoverResult {
            channels: rows
                .into_iter()
                .map(|d| DiscoveredChannelView {
                    workspace_id: d.workspace_id.to_hex(),
                    channel_id: d.channel_id.to_hex(),
                    channel_name: d.channel_name,
                    advertised_by: d.advertised_by,
                    discovered_at: d.discovered_at,
                    last_seen: d.last_seen,
                })
                .collect(),
        })
    }

    pub async fn adopt(
        &self,
        params: ChannelAdoptParams,
    ) -> Result<ChannelAdoptResult, ServiceError> {
        let channel_id = parse_channel_id(&params.channel_id)?;
        let discovered = self
            .db
            .discovered_channels()
            .get(&channel_id)
            .await?
            .ok_or(ServiceError::NotFound)?;
        let workspace = self
            .db
            .workspaces()
            .get(&discovered.workspace_id)
            .await?
            .ok_or_else(|| {
                ServiceError::InvalidParam(
                    "discovered channel references a workspace this daemon hasn't joined yet"
                        .into(),
                )
            })?;

        let (derived_id, mac_key) = derive_channel(&workspace, &discovered.channel_name)?;
        if derived_id != channel_id {
            return Err(ServiceError::InvalidParam(
                "discovered channel id does not match (workspace_secret, name) derivation".into(),
            ));
        }

        let now = Timestamp::now();
        self.db
            .channels()
            .upsert(&ChannelRecord {
                id: channel_id,
                workspace_id: workspace.id,
                name: discovered.channel_name.clone(),
                mac_key,
                muted: false,
                joined_at: now,
                last_active: Some(now),
            })
            .await?;

        audit_or_warn(&*self.audit_sink,
            AuditEntry {
                id: None,
                ts: now,
                actor: self.self_id.clone(),
                action: "channel.adopt".into(),
                target: Some(channel_id.to_hex()),
                details: Some(serde_json::json!({
                    "workspace_id": workspace.id.to_hex(),
                    "name": discovered.channel_name,
                })),
                federation: hermod_storage::AuditFederationPolicy::Default,
            },
        )
        .await;

        Ok(ChannelAdoptResult {
            id: channel_id.to_hex(),
            workspace_id: workspace.id.to_hex(),
            name: discovered.channel_name,
        })
    }

    pub async fn mute(&self, params: ChannelMuteParams) -> Result<ChannelMuteResult, ServiceError> {
        let id = parse_channel_id(&params.channel_id)?;
        let updated = self.db.channels().set_muted(&id, params.muted).await?;
        if !updated {
            return Err(ServiceError::NotFound);
        }
        audit_or_warn(&*self.audit_sink,
            AuditEntry {
                id: None,
                ts: Timestamp::now(),
                actor: self.self_id.clone(),
                action: "channel.mute".into(),
                target: Some(id.to_hex()),
                details: Some(serde_json::json!({ "muted": params.muted })),
                federation: hermod_storage::AuditFederationPolicy::Default,
            },
        )
        .await;
        Ok(ChannelMuteResult {
            id: id.to_hex(),
            muted: params.muted,
        })
    }
}

fn validate_name(s: &str) -> Result<(), ServiceError> {
    if s.is_empty() || s.len() > MAX_CHANNEL_NAME {
        return Err(ServiceError::InvalidParam(format!(
            "channel name must be 1..={MAX_CHANNEL_NAME} bytes"
        )));
    }
    Ok(())
}

fn parse_workspace_id(s: &str) -> Result<WorkspaceId, ServiceError> {
    WorkspaceId::from_hex(s).map_err(|e| ServiceError::InvalidParam(format!("workspace id: {e}")))
}

fn parse_channel_id(s: &str) -> Result<ChannelId, ServiceError> {
    ChannelId::from_hex(s).map_err(|e| ServiceError::InvalidParam(format!("channel id: {e}")))
}

fn record_to_view(c: ChannelRecord) -> ChannelView {
    ChannelView {
        id: c.id.to_hex(),
        workspace_id: c.workspace_id.to_hex(),
        name: c.name,
        muted: c.muted,
        joined_at: c.joined_at,
        last_active: c.last_active,
    }
}

/// Derive the channel id and (for private workspaces) MAC key for `name`.
///
/// Returns InvalidParam when the storage invariant "private workspaces carry a
/// secret" is violated — silently degrading to public-mode would generate
/// broadcasts that fail HMAC at every healthy receiver and look mysteriously
/// dropped. Surface the corruption so the operator can re-create the workspace.
fn derive_channel(
    workspace: &WorkspaceRecord,
    name: &str,
) -> Result<(ChannelId, Option<hermod_crypto::ChannelMacKey>), ServiceError> {
    match (&workspace.visibility, &workspace.secret) {
        (WorkspaceVisibility::Private, Some(secret)) => {
            Ok((secret.channel_id(name), Some(secret.channel_mac_key(name))))
        }
        (WorkspaceVisibility::Public, _) => Ok((public_channel_id(&workspace.id, name), None)),
        (WorkspaceVisibility::Private, None) => Err(ServiceError::InvalidParam(format!(
            "workspace {} marked private but has no secret stored — \
             storage corruption; re-create the workspace",
            workspace.id
        ))),
    }
}
