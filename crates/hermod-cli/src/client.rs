//! Daemon RPC client. Two transports share one type-safe surface:
//!   * `connect` opens a Unix-socket IPC session (default).
//!   * `connect_remote` opens a WSS+Bearer session to a remote daemon.
//!
//! Every typed helper (`message_send`, `workspace_invite`, …) routes through
//! `call` / `call_noparams`, which dispatch on the underlying transport.
//!
//! Command modules don't pick a transport themselves — they take a
//! [`ClientTarget`] and call `target.connect()`. Top-level argument parsing
//! decides Local vs Remote once.

use anyhow::{Context, Result, anyhow};
use hermod_protocol::ipc::{IpcClient, methods};
use serde::{Serialize, de::DeserializeOwned};
use std::path::{Path, PathBuf};

use crate::pins::PinPolicy;
use crate::remote::RemoteIpcClient;

/// Where a CLI / MCP invocation should send its RPCs.
#[derive(Clone, Debug)]
pub enum ClientTarget {
    Local(PathBuf),
    Remote {
        url: String,
        token: String,
        pin: PinPolicy,
    },
}

impl ClientTarget {
    pub async fn connect(&self) -> Result<DaemonClient> {
        match self {
            ClientTarget::Local(p) => DaemonClient::connect(p).await,
            ClientTarget::Remote { url, token, pin } => {
                DaemonClient::connect_remote(url, token, pin.clone()).await
            }
        }
    }
}

pub struct DaemonClient {
    inner: Inner,
}

/// Boxed `Remote` so the variant size doesn't blow up `DaemonClient` —
/// `RemoteIpcClient` carries TLS state (~1.4 KB) that would otherwise inflate
/// every `Local` value too. The indirection costs one heap allocation per
/// remote-mode connect, which happens at most once per CLI invocation.
enum Inner {
    Local(IpcClient),
    Remote(Box<RemoteIpcClient>),
}

impl DaemonClient {
    /// Open a local Unix-socket IPC session.
    pub async fn connect(socket: &Path) -> Result<Self> {
        let ipc = IpcClient::connect_unix(socket)
            .await
            .with_context(|| format!("connect daemon at {}", socket.display()))?;
        Ok(Self {
            inner: Inner::Local(ipc),
        })
    }

    /// Open a remote IPC session — `wss://host:port/` with Bearer auth.
    pub async fn connect_remote(url: &str, token: &str, pin: PinPolicy) -> Result<Self> {
        let remote = RemoteIpcClient::connect(url, token, pin)
            .await
            .with_context(|| format!("connect remote daemon at {url}"))?;
        Ok(Self {
            inner: Inner::Remote(Box::new(remote)),
        })
    }

    async fn call<P: Serialize, R: DeserializeOwned>(
        &mut self,
        method: &str,
        params: P,
    ) -> Result<R> {
        match &mut self.inner {
            Inner::Local(c) => c.call(method, params).await.map_err(Into::into),
            Inner::Remote(r) => r
                .call_typed(method, Some(serde_json::to_value(params)?))
                .await
                .and_then(|v| serde_json::from_value(v).map_err(|e| anyhow!("decode: {e}"))),
        }
    }

    async fn call_noparams<R: DeserializeOwned>(&mut self, method: &str) -> Result<R> {
        match &mut self.inner {
            Inner::Local(c) => c.call_noparams(method).await.map_err(Into::into),
            Inner::Remote(r) => r
                .call_typed(method, None)
                .await
                .and_then(|v| serde_json::from_value(v).map_err(|e| anyhow!("decode: {e}"))),
        }
    }

    pub async fn status(&mut self) -> Result<methods::StatusGetResult> {
        self.call_noparams(methods::method::STATUS_GET).await
    }

    pub async fn message_send(
        &mut self,
        params: methods::MessageSendParams,
    ) -> Result<methods::MessageSendResult> {
        self.call(methods::method::MESSAGE_SEND, params).await
    }

    pub async fn message_list(
        &mut self,
        params: methods::MessageListParams,
    ) -> Result<methods::MessageListResult> {
        self.call(methods::method::MESSAGE_LIST, params).await
    }

    pub async fn message_ack(
        &mut self,
        params: methods::MessageAckParams,
    ) -> Result<methods::MessageAckResult> {
        self.call(methods::method::MESSAGE_ACK, params).await
    }

    pub async fn agent_list(
        &mut self,
        params: methods::AgentListParams,
    ) -> Result<methods::AgentListResult> {
        self.call(methods::method::AGENT_LIST, params).await
    }

    pub async fn agent_get(
        &mut self,
        params: methods::AgentGetParams,
    ) -> Result<methods::AgentGetResult> {
        self.call(methods::method::AGENT_GET, params).await
    }

    pub async fn agent_register(
        &mut self,
        params: methods::AgentRegisterParams,
    ) -> Result<methods::AgentRegisterResult> {
        self.call(methods::method::AGENT_REGISTER, params).await
    }

    pub async fn brief_publish(
        &mut self,
        params: methods::BriefPublishParams,
    ) -> Result<methods::BriefPublishResult> {
        self.call(methods::method::BRIEF_PUBLISH, params).await
    }

    pub async fn brief_read(
        &mut self,
        params: methods::BriefReadParams,
    ) -> Result<methods::BriefReadResult> {
        self.call(methods::method::BRIEF_READ, params).await
    }

    pub async fn presence_set_manual(
        &mut self,
        params: methods::PresenceSetManualParams,
    ) -> Result<methods::PresenceSetManualResult> {
        self.call(methods::method::PRESENCE_SET_MANUAL, params)
            .await
    }

    pub async fn presence_clear_manual(
        &mut self,
        params: methods::PresenceClearManualParams,
    ) -> Result<methods::PresenceClearManualResult> {
        self.call(methods::method::PRESENCE_CLEAR_MANUAL, params)
            .await
    }

    pub async fn presence_get(
        &mut self,
        params: methods::PresenceGetParams,
    ) -> Result<methods::PresenceGetResult> {
        self.call(methods::method::PRESENCE_GET, params).await
    }

    pub async fn mcp_attach(
        &mut self,
        params: methods::McpAttachParams,
    ) -> Result<methods::McpAttachResult> {
        self.call(methods::method::MCP_ATTACH, params).await
    }

    pub async fn mcp_detach(
        &mut self,
        params: methods::McpDetachParams,
    ) -> Result<methods::McpDetachResult> {
        self.call(methods::method::MCP_DETACH, params).await
    }

    pub async fn mcp_heartbeat(
        &mut self,
        params: methods::McpHeartbeatParams,
    ) -> Result<methods::McpHeartbeatResult> {
        self.call(methods::method::MCP_HEARTBEAT, params).await
    }

    pub async fn workspace_create(
        &mut self,
        params: methods::WorkspaceCreateParams,
    ) -> Result<methods::WorkspaceCreateResult> {
        self.call(methods::method::WORKSPACE_CREATE, params).await
    }

    pub async fn workspace_join(
        &mut self,
        params: methods::WorkspaceJoinParams,
    ) -> Result<methods::WorkspaceJoinResult> {
        self.call(methods::method::WORKSPACE_JOIN, params).await
    }

    pub async fn workspace_list(&mut self) -> Result<methods::WorkspaceListResult> {
        self.call_noparams(methods::method::WORKSPACE_LIST).await
    }

    pub async fn workspace_get(
        &mut self,
        params: methods::WorkspaceGetParams,
    ) -> Result<methods::WorkspaceGetResult> {
        self.call(methods::method::WORKSPACE_GET, params).await
    }

    pub async fn workspace_delete(
        &mut self,
        params: methods::WorkspaceDeleteParams,
    ) -> Result<methods::WorkspaceDeleteResult> {
        self.call(methods::method::WORKSPACE_DELETE, params).await
    }

    pub async fn workspace_mute(
        &mut self,
        params: methods::WorkspaceMuteParams,
    ) -> Result<methods::WorkspaceMuteResult> {
        self.call(methods::method::WORKSPACE_MUTE, params).await
    }

    pub async fn workspace_invite(
        &mut self,
        params: methods::WorkspaceInviteParams,
    ) -> Result<methods::WorkspaceInviteResult> {
        self.call(methods::method::WORKSPACE_INVITE, params).await
    }

    pub async fn workspace_roster(
        &mut self,
        params: methods::WorkspaceRosterParams,
    ) -> Result<methods::WorkspaceRosterResult> {
        self.call(methods::method::WORKSPACE_ROSTER, params).await
    }

    pub async fn workspace_channels(
        &mut self,
        params: methods::WorkspaceChannelsParams,
    ) -> Result<methods::WorkspaceChannelsResult> {
        self.call(methods::method::WORKSPACE_CHANNELS, params).await
    }

    pub async fn channel_create(
        &mut self,
        params: methods::ChannelCreateParams,
    ) -> Result<methods::ChannelCreateResult> {
        self.call(methods::method::CHANNEL_CREATE, params).await
    }

    pub async fn channel_list(
        &mut self,
        params: methods::ChannelListParams,
    ) -> Result<methods::ChannelListResult> {
        self.call(methods::method::CHANNEL_LIST, params).await
    }

    pub async fn channel_history(
        &mut self,
        params: methods::ChannelHistoryParams,
    ) -> Result<methods::ChannelHistoryResult> {
        self.call(methods::method::CHANNEL_HISTORY, params).await
    }

    pub async fn channel_delete(
        &mut self,
        params: methods::ChannelDeleteParams,
    ) -> Result<methods::ChannelDeleteResult> {
        self.call(methods::method::CHANNEL_DELETE, params).await
    }

    pub async fn channel_mute(
        &mut self,
        params: methods::ChannelMuteParams,
    ) -> Result<methods::ChannelMuteResult> {
        self.call(methods::method::CHANNEL_MUTE, params).await
    }

    pub async fn channel_advertise(
        &mut self,
        params: methods::ChannelAdvertiseParams,
    ) -> Result<methods::ChannelAdvertiseResult> {
        self.call(methods::method::CHANNEL_ADVERTISE, params).await
    }

    pub async fn channel_discover(
        &mut self,
        params: methods::ChannelDiscoverParams,
    ) -> Result<methods::ChannelDiscoverResult> {
        self.call(methods::method::CHANNEL_DISCOVER, params).await
    }

    pub async fn channel_adopt(
        &mut self,
        params: methods::ChannelAdoptParams,
    ) -> Result<methods::ChannelAdoptResult> {
        self.call(methods::method::CHANNEL_ADOPT, params).await
    }

    pub async fn broadcast_send(
        &mut self,
        params: methods::BroadcastSendParams,
    ) -> Result<methods::BroadcastSendResult> {
        self.call(methods::method::BROADCAST_SEND, params).await
    }

    pub async fn confirmation_list(
        &mut self,
        params: methods::ConfirmationListParams,
    ) -> Result<methods::ConfirmationListResult> {
        self.call(methods::method::CONFIRMATION_LIST, params).await
    }

    pub async fn confirmation_accept(
        &mut self,
        params: methods::ConfirmationAcceptParams,
    ) -> Result<methods::ConfirmationAcceptResult> {
        self.call(methods::method::CONFIRMATION_ACCEPT, params)
            .await
    }

    pub async fn confirmation_reject(
        &mut self,
        params: methods::ConfirmationRejectParams,
    ) -> Result<methods::ConfirmationRejectResult> {
        self.call(methods::method::CONFIRMATION_REJECT, params)
            .await
    }

    pub async fn peer_add(
        &mut self,
        params: methods::PeerAddParams,
    ) -> Result<methods::PeerAddResult> {
        self.call(methods::method::PEER_ADD, params).await
    }

    pub async fn peer_list(&mut self) -> Result<methods::PeerListResult> {
        self.call_noparams(methods::method::PEER_LIST).await
    }

    pub async fn peer_trust(
        &mut self,
        params: methods::PeerTrustParams,
    ) -> Result<methods::PeerSummary> {
        self.call(methods::method::PEER_TRUST, params).await
    }

    pub async fn peer_remove(
        &mut self,
        params: methods::PeerRemoveParams,
    ) -> Result<methods::PeerRemoveResult> {
        self.call(methods::method::PEER_REMOVE, params).await
    }

    pub async fn peer_repin(
        &mut self,
        params: methods::PeerRepinParams,
    ) -> Result<methods::PeerRepinResult> {
        self.call(methods::method::PEER_REPIN, params).await
    }

    pub async fn audit_query(
        &mut self,
        params: methods::AuditQueryParams,
    ) -> Result<methods::AuditQueryResult> {
        self.call(methods::method::AUDIT_QUERY, params).await
    }

    pub async fn audit_verify(&mut self) -> Result<methods::AuditVerifyResult> {
        self.call_noparams(methods::method::AUDIT_VERIFY).await
    }

    pub async fn audit_archive_now(
        &mut self,
        params: methods::AuditArchiveNowParams,
    ) -> Result<methods::AuditArchiveNowResult> {
        self.call(methods::method::AUDIT_ARCHIVE_NOW, params).await
    }

    pub async fn audit_archives_list(
        &mut self,
        params: methods::AuditArchivesListParams,
    ) -> Result<methods::AuditArchivesListResult> {
        self.call(methods::method::AUDIT_ARCHIVES_LIST, params).await
    }

    pub async fn audit_verify_archive(
        &mut self,
        params: methods::AuditVerifyArchiveParams,
    ) -> Result<methods::AuditVerifyArchiveResult> {
        self.call(methods::method::AUDIT_VERIFY_ARCHIVE, params).await
    }

    pub async fn capability_issue(
        &mut self,
        params: methods::CapabilityIssueParams,
    ) -> Result<methods::CapabilityIssueResult> {
        self.call(methods::method::CAPABILITY_ISSUE, params).await
    }

    pub async fn capability_revoke(
        &mut self,
        params: methods::CapabilityRevokeParams,
    ) -> Result<methods::CapabilityRevokeResult> {
        self.call(methods::method::CAPABILITY_REVOKE, params).await
    }

    pub async fn capability_list(
        &mut self,
        params: methods::CapabilityListParams,
    ) -> Result<methods::CapabilityListResult> {
        self.call(methods::method::CAPABILITY_LIST, params).await
    }

    pub async fn capability_deliver(
        &mut self,
        params: methods::CapabilityDeliverParams,
    ) -> Result<methods::CapabilityDeliverResult> {
        self.call(methods::method::CAPABILITY_DELIVER, params).await
    }

    pub async fn permission_request(
        &mut self,
        params: methods::PermissionRequestParams,
    ) -> Result<methods::PermissionRequestResult> {
        self.call(methods::method::PERMISSION_REQUEST, params).await
    }

    pub async fn permission_respond(
        &mut self,
        params: methods::PermissionRespondParams,
    ) -> Result<methods::PermissionRespondResult> {
        self.call(methods::method::PERMISSION_RESPOND, params).await
    }

    pub async fn permission_list(
        &mut self,
        params: methods::PermissionListParams,
    ) -> Result<methods::PermissionListResult> {
        self.call(methods::method::PERMISSION_LIST, params).await
    }

    pub async fn permission_list_resolved(
        &mut self,
        params: methods::PermissionListResolvedParams,
    ) -> Result<methods::PermissionListResolvedResult> {
        self.call(methods::method::PERMISSION_LIST_RESOLVED, params)
            .await
    }
}
