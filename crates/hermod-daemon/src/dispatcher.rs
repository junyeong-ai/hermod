//! RPC dispatcher — maps JSON-RPC method names to service calls.

use hermod_protocol::ipc::error::{RpcError, code};
use hermod_protocol::ipc::{Request, Response, methods::method};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use tracing::{debug, warn};

use crate::services::{
    AgentService, AuditService, BriefService, BroadcastService, CapabilityService, ChannelService,
    ConfirmationService, InboxService, LocalAgentService, McpService, MessageService,
    NotificationService, PeerService, PermissionService, PresenceService, ServiceError,
    StatusService, WorkspaceObservabilityService, WorkspaceService,
};

#[derive(Clone)]
pub struct Dispatcher {
    pub status: StatusService,
    pub messages: MessageService,
    pub inbox: InboxService,
    pub notifications: NotificationService,
    pub agents: AgentService,
    pub briefs: BriefService,
    pub presence: PresenceService,
    pub mcp: McpService,
    pub workspaces: WorkspaceService,
    pub workspace_observability: WorkspaceObservabilityService,
    pub channels: ChannelService,
    pub broadcasts: BroadcastService,
    pub confirmations: ConfirmationService,
    pub peers: PeerService,
    pub permissions: PermissionService,
    pub audit: AuditService,
    pub capabilities: CapabilityService,
    pub local_agents: LocalAgentService,
}

impl Dispatcher {
    pub async fn handle(&self, req: Request) -> Response {
        let id = req.id.clone();
        debug!(method = %req.method, "rpc");
        match self.dispatch(&req.method, req.params).await {
            Ok(v) => Response::ok(id, v),
            Err(e) => {
                warn!(method = %req.method, error = %e, "rpc error");
                Response::err(id, e)
            }
        }
    }

    async fn dispatch(&self, method: &str, params: Option<Value>) -> Result<Value, RpcError> {
        match method {
            method::STATUS_GET => to_value(self.status.status().await),
            method::IDENTITY_GET => to_value(self.status.identity().await),

            method::MESSAGE_SEND => {
                let p = parse_params(params)?;
                to_value(self.messages.send(p).await)
            }
            method::MESSAGE_ACK => {
                let p = parse_params(params)?;
                to_value(self.messages.ack(p).await)
            }

            method::INBOX_LIST => {
                let p = parse_params_or_default(params)?;
                to_value(self.inbox.list(p).await)
            }
            method::INBOX_PROMOTE => {
                let p = parse_params(params)?;
                to_value(self.inbox.promote(p).await)
            }

            method::NOTIFICATION_LIST => {
                let p = parse_params_or_default(params)?;
                to_value(self.notifications.list(p).await)
            }
            method::NOTIFICATION_CLAIM => {
                let p = parse_params(params)?;
                to_value(self.notifications.claim(p).await)
            }
            method::NOTIFICATION_COMPLETE => {
                let p = parse_params(params)?;
                to_value(self.notifications.complete(p).await)
            }
            method::NOTIFICATION_FAIL => {
                let p = parse_params(params)?;
                to_value(self.notifications.fail(p).await)
            }
            method::NOTIFICATION_DISMISS => {
                let p = parse_params(params)?;
                to_value(self.notifications.dismiss(p).await)
            }
            method::NOTIFICATION_PURGE => {
                let p = parse_params_or_default(params)?;
                to_value(self.notifications.purge(p).await)
            }

            method::AGENT_LIST => {
                let p = parse_params_or_default(params)?;
                to_value(self.agents.list(p).await)
            }
            method::AGENT_GET => {
                let p = parse_params(params)?;
                to_value(self.agents.get(p).await)
            }
            method::AGENT_REGISTER => {
                let p = parse_params(params)?;
                to_value(self.agents.register(p).await)
            }

            method::BRIEF_PUBLISH => {
                let p = parse_params(params)?;
                to_value(self.briefs.publish(p).await)
            }
            method::BRIEF_READ => {
                let p = parse_params(params)?;
                to_value(self.briefs.read(p).await)
            }

            method::PRESENCE_SET_MANUAL => {
                let p = parse_params(params)?;
                to_value(self.presence.set_manual(p).await)
            }
            method::PRESENCE_CLEAR_MANUAL => {
                let p = parse_params_or_default(params)?;
                to_value(self.presence.clear_manual(p).await)
            }
            method::PRESENCE_GET => {
                let p = parse_params(params)?;
                to_value(self.presence.get(p).await)
            }

            method::MCP_ATTACH => {
                let p = parse_params_or_default(params)?;
                to_value(self.mcp.attach(p).await)
            }
            method::MCP_DETACH => {
                let p = parse_params(params)?;
                to_value(self.mcp.detach(p).await)
            }
            method::MCP_HEARTBEAT => {
                let p = parse_params(params)?;
                to_value(self.mcp.heartbeat(p).await)
            }
            method::MCP_CURSOR_ADVANCE => {
                let p = parse_params(params)?;
                to_value(self.mcp.cursor_advance(p).await)
            }

            method::WORKSPACE_CREATE => {
                let p = parse_params(params)?;
                to_value(self.workspaces.create(p).await)
            }
            method::WORKSPACE_JOIN => {
                let p = parse_params(params)?;
                to_value(self.workspaces.join(p).await)
            }
            method::WORKSPACE_LIST => to_value(self.workspaces.list().await),
            method::WORKSPACE_GET => {
                let p = parse_params(params)?;
                to_value(self.workspaces.get(p).await)
            }
            method::WORKSPACE_DELETE => {
                let p = parse_params(params)?;
                to_value(self.workspaces.delete(p).await)
            }
            method::WORKSPACE_MUTE => {
                let p = parse_params(params)?;
                to_value(self.workspaces.mute(p).await)
            }
            method::WORKSPACE_INVITE => {
                let p = parse_params(params)?;
                to_value(self.workspaces.invite(p).await)
            }
            method::WORKSPACE_ROSTER => {
                let p = parse_params(params)?;
                to_value(self.workspace_observability.ipc_roster(p).await)
            }
            method::WORKSPACE_CHANNELS => {
                let p = parse_params(params)?;
                to_value(self.workspace_observability.ipc_channels(p).await)
            }

            method::CHANNEL_CREATE => {
                let p = parse_params(params)?;
                to_value(self.channels.create(p).await)
            }
            method::CHANNEL_LIST => {
                let p = parse_params(params)?;
                to_value(self.channels.list(p).await)
            }
            method::CHANNEL_HISTORY => {
                let p = parse_params(params)?;
                to_value(self.channels.history(p).await)
            }
            method::CHANNEL_DELETE => {
                let p = parse_params(params)?;
                to_value(self.channels.delete(p).await)
            }
            method::CHANNEL_MUTE => {
                let p = parse_params(params)?;
                to_value(self.channels.mute(p).await)
            }
            method::CHANNEL_ADVERTISE => {
                let p = parse_params(params)?;
                to_value(self.channels.advertise(p).await)
            }
            method::CHANNEL_DISCOVER => {
                let p = parse_params(params)?;
                to_value(self.channels.discover(p).await)
            }
            method::CHANNEL_ADOPT => {
                let p = parse_params(params)?;
                to_value(self.channels.adopt(p).await)
            }

            method::BROADCAST_SEND => {
                let p = parse_params(params)?;
                to_value(self.broadcasts.send(p).await)
            }

            method::CONFIRMATION_LIST => {
                let p = parse_params_or_default(params)?;
                to_value(self.confirmations.list(p).await)
            }
            method::CONFIRMATION_ACCEPT => {
                let p = parse_params(params)?;
                to_value(self.confirmations.accept(p).await)
            }
            method::CONFIRMATION_REJECT => {
                let p = parse_params(params)?;
                to_value(self.confirmations.reject(p).await)
            }

            method::PEER_ADD => {
                let p = parse_params(params)?;
                to_value(self.peers.add(p).await)
            }
            method::PEER_LIST => to_value(self.peers.list().await),
            method::PEER_TRUST => {
                let p = parse_params(params)?;
                to_value(self.peers.trust(p).await)
            }
            method::PEER_REMOVE => {
                let p = parse_params(params)?;
                to_value(self.peers.remove(p).await)
            }
            method::PEER_REPIN => {
                let p = parse_params(params)?;
                to_value(self.peers.repin(p).await)
            }
            method::PEER_ADVERTISE => {
                let p = parse_params_or_default(params)?;
                to_value(self.peers.advertise(p).await)
            }

            method::LOCAL_LIST => to_value(self.local_agents.list().await),
            method::LOCAL_ADD => {
                let p = parse_params_or_default(params)?;
                to_value(self.local_agents.add(p).await)
            }
            method::LOCAL_REMOVE => {
                let p = parse_params(params)?;
                to_value(self.local_agents.remove(p).await)
            }
            method::LOCAL_ROTATE => {
                let p = parse_params(params)?;
                to_value(self.local_agents.rotate(p).await)
            }
            method::LOCAL_TAG_SET => {
                let p = parse_params(params)?;
                to_value(self.local_agents.tag_set(p).await)
            }
            method::LOCAL_SESSIONS => {
                let p = parse_params_or_default(params)?;
                to_value(self.mcp.list_sessions(p).await)
            }

            method::AUDIT_QUERY => {
                let p = parse_params_or_default(params)?;
                to_value(self.audit.query(p).await)
            }
            method::AUDIT_VERIFY => to_value(self.audit.verify().await),
            method::AUDIT_ARCHIVE_NOW => {
                let p = parse_params_or_default(params)?;
                to_value(self.audit.archive_now(p).await)
            }
            method::AUDIT_ARCHIVES_LIST => {
                let p = parse_params_or_default(params)?;
                to_value(self.audit.archives_list(p).await)
            }
            method::AUDIT_VERIFY_ARCHIVE => {
                let p = parse_params(params)?;
                to_value(self.audit.verify_archive(p).await)
            }

            method::CAPABILITY_ISSUE => {
                let p = parse_params(params)?;
                to_value(self.capabilities.issue(p).await)
            }
            method::CAPABILITY_REVOKE => {
                let p = parse_params(params)?;
                to_value(self.capabilities.revoke(p).await)
            }
            method::CAPABILITY_LIST => {
                let p = parse_params_or_default(params)?;
                to_value(self.capabilities.list(p).await)
            }
            method::CAPABILITY_DELIVER => {
                let p = parse_params(params)?;
                to_value(self.capabilities.deliver(p).await)
            }

            method::PERMISSION_REQUEST => {
                let p = parse_params(params)?;
                to_value(self.permissions.request(p).await)
            }
            method::PERMISSION_RESPOND => {
                let p = parse_params(params)?;
                to_value(self.permissions.respond(p).await)
            }
            method::PERMISSION_LIST => {
                let p = parse_params_or_default(params)?;
                to_value(self.permissions.list(p).await)
            }
            method::PERMISSION_LIST_RESOLVED => {
                let p = parse_params_or_default(params)?;
                to_value(self.permissions.list_resolved(p).await)
            }

            other => Err(RpcError::new(
                code::METHOD_NOT_FOUND,
                format!("method not found: {other}"),
            )),
        }
    }
}

fn parse_params<P: DeserializeOwned>(params: Option<Value>) -> Result<P, RpcError> {
    let v = params.ok_or_else(|| RpcError::new(code::INVALID_PARAMS, "missing `params`"))?;
    serde_json::from_value(v)
        .map_err(|e| RpcError::new(code::INVALID_PARAMS, format!("invalid params: {e}")))
}

fn parse_params_or_default<P: DeserializeOwned + Default>(
    params: Option<Value>,
) -> Result<P, RpcError> {
    match params {
        None | Some(Value::Null) => Ok(P::default()),
        Some(v) => serde_json::from_value(v)
            .map_err(|e| RpcError::new(code::INVALID_PARAMS, format!("invalid params: {e}"))),
    }
}

fn to_value<T: Serialize>(res: Result<T, ServiceError>) -> Result<Value, RpcError> {
    match res {
        Ok(v) => serde_json::to_value(v)
            .map_err(|e| RpcError::new(code::INTERNAL_ERROR, format!("serialize result: {e}"))),
        Err(e) => Err(service_to_rpc_err(e)),
    }
}

fn service_to_rpc_err(e: ServiceError) -> RpcError {
    use hermod_routing::RoutingError;
    use hermod_storage::StorageError;
    let (c, msg) = match &e {
        ServiceError::Storage(StorageError::QuotaExceeded(_)) => {
            (code::RATE_LIMITED, format!("{e}"))
        }
        ServiceError::Storage(StorageError::NotFound) => (code::NOT_FOUND, format!("{e}")),
        ServiceError::Storage(_) => (code::STORAGE, format!("{e}")),
        ServiceError::Blob(_) => (code::STORAGE, format!("{e}")),
        ServiceError::Crypto(_) => (code::CRYPTO, format!("{e}")),
        ServiceError::InvalidParam(_) => (code::INVALID_PARAMS, format!("{e}")),
        ServiceError::NotFound => (code::NOT_FOUND, "not found".to_string()),
        ServiceError::Conflict(_) => (code::CONFLICT, format!("{e}")),
        ServiceError::Routing(re) => match re {
            RoutingError::RecipientNotFound(_) => (code::NOT_FOUND, format!("{e}")),
            RoutingError::Blocked | RoutingError::Unauthorized(_) => {
                (code::UNAUTHORIZED, format!("{e}"))
            }
            RoutingError::RateLimited => (code::RATE_LIMITED, format!("{e}")),
            RoutingError::Storage(_) => (code::STORAGE, format!("{e}")),
            RoutingError::Crypto(_) => (code::CRYPTO, format!("{e}")),
            // Network-layer / handshake / wire errors all collapse to
            // INTERNAL_ERROR — these aren't actionable for the caller
            // beyond "something went wrong on the way out".
            _ => (code::INTERNAL_ERROR, format!("{e}")),
        },
    };
    RpcError::new(c, msg)
}
