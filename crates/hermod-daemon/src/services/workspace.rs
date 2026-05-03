use hermod_core::{
    AgentAddress, AgentAlias, AgentId, MessageBody, MessagePriority, Timestamp, WorkspaceVisibility,
};
use hermod_crypto::{WorkspaceId, WorkspaceSecret, public_workspace_id};
use hermod_protocol::ipc::methods::{
    MessageSendParams, WorkspaceCreateParams, WorkspaceCreateResult, WorkspaceDeleteParams,
    WorkspaceDeleteResult, WorkspaceGetParams, WorkspaceGetResult, WorkspaceInviteParams,
    WorkspaceInviteResult, WorkspaceJoinParams, WorkspaceJoinResult, WorkspaceListResult,
    WorkspaceMuteParams, WorkspaceMuteResult, WorkspaceView,
};
use hermod_storage::{AuditEntry, AuditSink, Database, WorkspaceRecord};
use serde_bytes::ByteBuf;
use std::str::FromStr;
use std::sync::Arc;

use crate::audit_context::current_caller_agent;
use crate::local_agent::LocalAgentRegistry;
use crate::services::{ServiceError, audit_or_warn, message::MessageService};

const MAX_NAME_LEN: usize = 64;

#[derive(Debug, Clone)]
pub struct WorkspaceService {
    db: Arc<dyn Database>,
    audit_sink: Arc<dyn AuditSink>,
    /// Audit fallback actor for emissions outside an IPC scope.
    /// `audit_or_warn` overlays the IPC caller's agent_id when one
    /// is in scope; this value is what lands when no caller is
    /// present (background paths).
    host_actor: AgentId,
    registry: LocalAgentRegistry,
    messages: MessageService,
}

impl WorkspaceService {
    pub fn new(
        db: Arc<dyn Database>,
        audit_sink: Arc<dyn AuditSink>,
        host_actor: AgentId,
        registry: LocalAgentRegistry,
        messages: MessageService,
    ) -> Self {
        Self {
            db,
            audit_sink,
            host_actor,
            registry,
            messages,
        }
    }

    fn caller(&self) -> Result<AgentId, ServiceError> {
        current_caller_agent().ok_or_else(|| {
            ServiceError::InvalidParam(
                "workspace.* requires an IPC caller scope (no caller_agent in context)".into(),
            )
        })
    }

    pub async fn create(
        &self,
        params: WorkspaceCreateParams,
    ) -> Result<WorkspaceCreateResult, ServiceError> {
        validate_name(&params.name)?;
        let caller = self.caller()?;
        let agent = self
            .registry
            .lookup(&caller)
            .ok_or(ServiceError::NotFound)?;
        let now = Timestamp::now();

        let (id, secret, visibility) = match params.visibility {
            WorkspaceVisibility::Private => {
                let secret = WorkspaceSecret::generate();
                let id = secret.workspace_id();
                (id, Some(secret), WorkspaceVisibility::Private)
            }
            WorkspaceVisibility::Public => {
                let id = public_workspace_id(&agent.keypair.to_pubkey_bytes(), &params.name);
                (id, None, WorkspaceVisibility::Public)
            }
        };

        let secret_hex = secret.as_ref().map(|s| s.to_hex());

        self.db
            .workspaces()
            .upsert(&WorkspaceRecord {
                id,
                name: params.name.clone(),
                visibility,
                secret,
                created_locally: true,
                muted: false,
                joined_at: now,
                last_active: Some(now),
            })
            .await?;

        self.db.workspace_members().touch(&id, &caller, now).await?;

        audit_or_warn(
            &*self.audit_sink,
            AuditEntry {
                id: None,
                ts: now,
                actor: self.host_actor.clone(),
                action: "workspace.create".into(),
                target: Some(id.to_hex()),
                details: Some(serde_json::json!({
                    "name": params.name,
                    "visibility": visibility.as_str(),
                })),
                client_ip: None,
                federation: hermod_storage::AuditFederationPolicy::Default,
            },
        )
        .await;

        Ok(WorkspaceCreateResult {
            id: id.to_hex(),
            visibility: params.visibility,
            secret_hex,
        })
    }

    pub async fn join(
        &self,
        params: WorkspaceJoinParams,
    ) -> Result<WorkspaceJoinResult, ServiceError> {
        validate_name(&params.name)?;
        let caller = self.caller()?;
        let secret = WorkspaceSecret::from_hex(&params.secret_hex)
            .map_err(|e| ServiceError::InvalidParam(format!("secret_hex: {e}")))?;
        let id = secret.workspace_id();
        let now = Timestamp::now();

        self.db
            .workspaces()
            .upsert(&WorkspaceRecord {
                id,
                name: params.name.clone(),
                visibility: WorkspaceVisibility::Private,
                secret: Some(secret),
                created_locally: false,
                muted: false,
                joined_at: now,
                last_active: Some(now),
            })
            .await?;

        self.db.workspace_members().touch(&id, &caller, now).await?;

        audit_or_warn(
            &*self.audit_sink,
            AuditEntry {
                id: None,
                ts: now,
                actor: self.host_actor.clone(),
                action: "workspace.join".into(),
                target: Some(id.to_hex()),
                details: Some(serde_json::json!({ "name": params.name })),
                client_ip: None,
                federation: hermod_storage::AuditFederationPolicy::Default,
            },
        )
        .await;

        Ok(WorkspaceJoinResult { id: id.to_hex() })
    }

    pub async fn list(&self) -> Result<WorkspaceListResult, ServiceError> {
        let rows = self.db.workspaces().list().await?;
        Ok(WorkspaceListResult {
            workspaces: rows.into_iter().map(record_to_view).collect(),
        })
    }

    pub async fn get(
        &self,
        params: WorkspaceGetParams,
    ) -> Result<WorkspaceGetResult, ServiceError> {
        let id = parse_workspace_id(&params.workspace_id)?;
        let rec = self.db.workspaces().get(&id).await?;
        Ok(WorkspaceGetResult {
            workspace: rec.map(record_to_view),
        })
    }

    pub async fn delete(
        &self,
        params: WorkspaceDeleteParams,
    ) -> Result<WorkspaceDeleteResult, ServiceError> {
        let id = parse_workspace_id(&params.workspace_id)?;
        let removed = self.db.workspaces().delete(&id).await?;
        if !removed {
            return Err(ServiceError::NotFound);
        }
        audit_or_warn(
            &*self.audit_sink,
            AuditEntry {
                id: None,
                ts: Timestamp::now(),
                actor: self.host_actor.clone(),
                action: "workspace.delete".into(),
                target: Some(id.to_hex()),
                details: None,
                client_ip: None,
                federation: hermod_storage::AuditFederationPolicy::Default,
            },
        )
        .await;
        Ok(WorkspaceDeleteResult { id: id.to_hex() })
    }

    pub async fn invite(
        &self,
        params: WorkspaceInviteParams,
    ) -> Result<WorkspaceInviteResult, ServiceError> {
        let id = parse_workspace_id(&params.workspace_id)?;
        let workspace = self
            .db
            .workspaces()
            .get(&id)
            .await?
            .ok_or(ServiceError::NotFound)?;

        // Public workspaces don't carry a secret to share — invitations are
        // a private-workspace primitive. Joining a public workspace is
        // simply re-deriving the id from (creator_pubkey, name).
        let secret = match (&workspace.visibility, &workspace.secret) {
            (WorkspaceVisibility::Private, Some(s)) => s.clone(),
            (WorkspaceVisibility::Private, None) => {
                return Err(ServiceError::InvalidParam(
                    "private workspace has no stored secret".into(),
                ));
            }
            (WorkspaceVisibility::Public, _) => {
                return Err(ServiceError::InvalidParam(
                    "public workspaces don't need invites".into(),
                ));
            }
        };

        let recipient = self.resolve_recipient(&params.target).await?;
        let recipient_id = recipient.id.clone();

        let body = MessageBody::WorkspaceInvite {
            workspace_id: ByteBuf::from(workspace.id.0.to_vec()),
            name: workspace.name.clone(),
            secret: ByteBuf::from(secret.as_bytes().to_vec()),
        };
        let send = self
            .messages
            .send(MessageSendParams {
                to: recipient,
                body,
                priority: Some(MessagePriority::High),
                thread: None,
                ttl_secs: Some(86_400),
                caps: None,
            })
            .await?;

        // Optimistically record the recipient as a workspace member so that
        // subsequent channel.advertise / broadcast.send can fan out to them.
        // If the invite is later declined, the operator can prune via
        // workspace.delete or by re-issuing the invite.
        self.db
            .workspace_members()
            .touch(&workspace.id, &recipient_id, Timestamp::now())
            .await?;

        audit_or_warn(
            &*self.audit_sink,
            AuditEntry {
                id: None,
                ts: Timestamp::now(),
                actor: self.host_actor.clone(),
                action: "workspace.invite".into(),
                target: Some(workspace.id.to_hex()),
                details: Some(serde_json::json!({
                    "envelope_id": send.id.to_string(),
                    "recipient": params.target,
                })),
                client_ip: None,
                federation: hermod_storage::AuditFederationPolicy::Default,
            },
        )
        .await;

        Ok(WorkspaceInviteResult { id: send.id })
    }

    async fn resolve_recipient(&self, reference: &str) -> Result<AgentAddress, ServiceError> {
        // Resolution returns just the recipient's `AgentId` plus an
        // optional endpoint hint when the directory has one. The
        // router is the single arbiter of how to deliver — direct
        // for known endpoints, brokered for endpointless recipients
        // when an upstream broker is configured. We never reject up
        // front for a missing endpoint; that mishandles broker
        // mode.
        let rec = if let Some(alias_raw) = reference.strip_prefix('@') {
            let alias = AgentAlias::from_str(alias_raw)
                .map_err(|e| ServiceError::InvalidParam(format!("invalid alias: {e}")))?;
            self.db
                .agents()
                .get_by_local_alias(&alias)
                .await?
                .ok_or(ServiceError::NotFound)?
        } else {
            let id = AgentId::from_str(reference)
                .map_err(|e| ServiceError::InvalidParam(format!("invalid agent id: {e}")))?;
            self.db
                .agents()
                .get(&id)
                .await?
                .ok_or(ServiceError::NotFound)?
        };
        Ok(
            match crate::services::resolve_host_endpoint(&*self.db, &rec).await {
                Some(ep) if !ep.is_local() => AgentAddress::with_endpoint(rec.id, ep),
                _ => AgentAddress::local(rec.id),
            },
        )
    }

    pub async fn mute(
        &self,
        params: WorkspaceMuteParams,
    ) -> Result<WorkspaceMuteResult, ServiceError> {
        let id = parse_workspace_id(&params.workspace_id)?;
        let updated = self.db.workspaces().set_muted(&id, params.muted).await?;
        if !updated {
            return Err(ServiceError::NotFound);
        }
        audit_or_warn(
            &*self.audit_sink,
            AuditEntry {
                id: None,
                ts: Timestamp::now(),
                actor: self.host_actor.clone(),
                action: "workspace.mute".into(),
                target: Some(id.to_hex()),
                details: Some(serde_json::json!({ "muted": params.muted })),
                client_ip: None,
                federation: hermod_storage::AuditFederationPolicy::Default,
            },
        )
        .await;
        Ok(WorkspaceMuteResult {
            id: id.to_hex(),
            muted: params.muted,
        })
    }
}

fn validate_name(s: &str) -> Result<(), ServiceError> {
    if s.is_empty() {
        return Err(ServiceError::InvalidParam("name is empty".into()));
    }
    if s.len() > MAX_NAME_LEN {
        return Err(ServiceError::InvalidParam(format!(
            "name exceeds {MAX_NAME_LEN} bytes"
        )));
    }
    Ok(())
}

fn parse_workspace_id(s: &str) -> Result<WorkspaceId, ServiceError> {
    WorkspaceId::from_hex(s).map_err(|e| ServiceError::InvalidParam(format!("workspace id: {e}")))
}

fn record_to_view(r: WorkspaceRecord) -> WorkspaceView {
    WorkspaceView {
        id: r.id.to_hex(),
        name: r.name,
        visibility: r.visibility,
        created_locally: r.created_locally,
        muted: r.muted,
        joined_at: r.joined_at,
        last_active: r.last_active,
    }
}
