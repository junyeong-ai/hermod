//! Workspace observability — roster + channel-list RPCs.
//!
//! Members of a workspace ask "who else is in here?" and "what channels
//! exist here?" via signed envelopes. This module owns three concerns:
//!
//!   1. **Authorisation gate.** Private workspaces verify the request's
//!      HMAC under the workspace MAC key (cryptographic membership
//!      proof). Public workspaces verify the sender is in our local
//!      `workspace_members` table.
//!
//!   2. **Response generation.** When we accept a request, we read our
//!      own view of the workspace (members table for roster; the union
//!      of `channels` and `discovered_channels` for channel list) and
//!      ship a signed response back to the requester.
//!
//!   3. **Response correlation.** When *we* sent a request, this
//!      module's pending tracker matches incoming responses to the
//!      originating envelope id and pushes them into the waiting
//!      caller's collector. Multi-target gossip: the caller (e.g.
//!      `hermod workspace members`) fan-outs requests to every known
//!      member and unions their responses.
//!
//! `MessageService` is wired post-construction via `set_messages`
//! (same pattern as `RemoteAuditSink` and `PermissionService`).

use hermod_core::{
    AgentAddress, AgentId, MessageBody, MessageId, MessagePriority, PubkeyBytes, RosterMember,
    Timestamp, WorkspaceChannelEntry,
};
use hermod_crypto::{ChannelId, WorkspaceId, WorkspaceSecret};
use hermod_protocol::ipc::methods::{
    MessageSendParams, WorkspaceChannelView, WorkspaceChannelsParams, WorkspaceChannelsResult,
    WorkspaceRosterParams, WorkspaceRosterResult,
};
use hermod_storage::{AuditEntry, AuditSink, Database};
use serde_bytes::ByteBuf;
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::sync::{Mutex, mpsc};
use tracing::debug;

use crate::services::{ServiceError, audit_or_warn, message::MessageService};

/// How long a fan-out waits for responses before returning the union.
/// Sized to cover one network round-trip plus a small handshake budget.
pub const ROSTER_QUERY_TIMEOUT: Duration = Duration::from_secs(3);

/// Hard cap on how many in-flight roster/channel requests we track at
/// once. Each entry is small; the cap protects against a buggy caller
/// leaking entries.
const MAX_PENDING_REQUESTS: usize = 256;

/// One peer's contribution to a roster fan-out. The originating
/// caller unions chunks across peers into the final result.
#[derive(Debug, Clone)]
pub struct RosterChunk {
    pub responder: AgentId,
    pub members: Vec<AgentId>,
}

/// One peer's contribution to a channel-list fan-out. Same union
/// pattern as [`RosterChunk`].
#[derive(Debug, Clone)]
pub struct ChannelsChunk {
    pub responder: AgentId,
    pub channels: Vec<WorkspaceChannelEntry>,
}

#[derive(Default)]
struct State {
    /// envelope-id → channel onto which inbound roster chunks for that
    /// request are pushed. Cleared when the originating call drops the
    /// receiver; the inbound handler treats a missing entry as
    /// "request already completed, chunk is stale". Roster and channel
    /// fan-outs use disjoint maps so a typed mismatch is impossible.
    pending_roster: HashMap<MessageId, mpsc::UnboundedSender<RosterChunk>>,
    pending_channels: HashMap<MessageId, mpsc::UnboundedSender<ChannelsChunk>>,
}

#[derive(Clone)]
pub struct WorkspaceObservabilityService {
    db: Arc<dyn Database>,
    audit_sink: Arc<dyn AuditSink>,
    host_actor: AgentId,
    state: Arc<Mutex<State>>,
    /// Wired post-construction so this service can ship responses +
    /// fan out requests. Same OnceLock pattern as `RemoteAuditSink`.
    messages: Arc<OnceLock<MessageService>>,
}

impl std::fmt::Debug for WorkspaceObservabilityService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorkspaceObservabilityService")
            .field("self_id", &self.host_actor)
            .field("messages_wired", &self.messages.get().is_some())
            .finish()
    }
}

impl WorkspaceObservabilityService {
    pub fn new(db: Arc<dyn Database>, audit_sink: Arc<dyn AuditSink>, host_actor: AgentId) -> Self {
        Self {
            db,
            audit_sink,
            host_actor,
            state: Arc::new(Mutex::new(State::default())),
            messages: Arc::new(OnceLock::new()),
        }
    }

    /// Wire `MessageService` post-construction. Idempotent.
    pub fn set_messages(&self, messages: MessageService) {
        let _ = self.messages.set(messages);
    }

    /// Authorise an incoming request. Returns `Ok(workspace_secret)` if
    /// the caller has proven membership; `Err(reason)` otherwise.
    /// `workspace_secret` is `Some` for private workspaces (so the
    /// responder can MAC its reply) and `None` for public.
    pub async fn authorise(
        &self,
        peer: &AgentId,
        workspace_id: &WorkspaceId,
        body_to_mac: &[u8],
        claimed_hmac: Option<&[u8]>,
    ) -> Result<Option<WorkspaceSecret>, &'static str> {
        let workspace = match self.db.workspaces().get(workspace_id).await {
            Ok(Some(w)) => w,
            Ok(None) => return Err("unknown workspace"),
            Err(_) => return Err("storage failure"),
        };
        match workspace.secret {
            Some(secret) => {
                let claimed = claimed_hmac.ok_or("private workspace requires hmac")?;
                if claimed.len() != 32 {
                    return Err("hmac wrong length");
                }
                let mut got = [0u8; 32];
                got.copy_from_slice(claimed);
                if !secret.workspace_mac_key().verify(body_to_mac, &got) {
                    return Err("hmac mismatch");
                }
                Ok(Some(secret))
            }
            None => {
                // Public workspace: peer must be a known member.
                let members = match self.db.workspace_members().list(workspace_id).await {
                    Ok(m) => m,
                    Err(_) => return Err("storage failure"),
                };
                if !members.iter().any(|m| m == peer) {
                    return Err("public workspace: sender not a known member");
                }
                Ok(None)
            }
        }
    }

    /// Handle inbound `WorkspaceRosterRequest`. Builds + ships back a
    /// `WorkspaceRosterResponse`.
    pub async fn handle_roster_request(
        &self,
        peer: &AgentId,
        request_envelope_id: MessageId,
        workspace_id_bytes: &ByteBuf,
    ) -> Result<(), &'static str> {
        let workspace_id = parse_workspace_id(workspace_id_bytes)?;
        let mac_input = workspace_id_bytes.as_ref();

        // Authorisation already happened in `accept_workspace_roster_request`
        // via `authorise()`; this entry point is invoked only after that
        // returned Ok. Re-fetch the secret for the response MAC.
        let secret = self
            .db
            .workspaces()
            .get(&workspace_id)
            .await
            .map_err(|_| "storage failure")?
            .and_then(|w| w.secret);

        let members = self
            .db
            .workspace_members()
            .list(&workspace_id)
            .await
            .map_err(|_| "storage failure")?;

        // Audit the incoming query so an operator can see who's
        // mapping the workspace.
        audit_or_warn(
            &*self.audit_sink,
            AuditEntry {
                id: None,
                ts: Timestamp::now(),
                actor: peer.clone(),
                action: "workspace.roster.request".into(),
                target: Some(workspace_id.to_hex()),
                details: None,
                client_ip: None,
                federation: hermod_storage::AuditFederationPolicy::Default,
            },
        )
        .await;

        // Resolve each member to a (id, pubkey) pair from the
        // local directory. Members without a known pubkey are
        // skipped — we can't include them honestly without their
        // self-certifying key. Sort by id for deterministic MAC.
        let mut sorted = Vec::with_capacity(members.len());
        for id in &members {
            if let Some(rec) = self
                .db
                .agents()
                .get(id)
                .await
                .map_err(|_| "storage failure")?
            {
                sorted.push(RosterMember {
                    id: rec.id,
                    pubkey: rec.pubkey,
                });
            }
        }
        sorted.sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));

        let hmac = secret.map(|s| {
            let mac_key = s.workspace_mac_key();
            let bytes = canonical_roster_mac_input(mac_input, &sorted);
            ByteBuf::from(mac_key.mac(&bytes).to_vec())
        });

        let body = MessageBody::WorkspaceRosterResponse {
            request_id: request_envelope_id,
            workspace_id: workspace_id_bytes.clone(),
            members: sorted,
            hmac,
        };
        self.send_to(peer, body).await
    }

    /// Handle inbound `WorkspaceChannelsRequest`.
    pub async fn handle_channels_request(
        &self,
        peer: &AgentId,
        request_envelope_id: MessageId,
        workspace_id_bytes: &ByteBuf,
    ) -> Result<(), &'static str> {
        let workspace_id = parse_workspace_id(workspace_id_bytes)?;
        let mac_input = workspace_id_bytes.as_ref();

        let secret = self
            .db
            .workspaces()
            .get(&workspace_id)
            .await
            .map_err(|_| "storage failure")?
            .and_then(|w| w.secret);

        // Two sources of channel knowledge: channels we've joined +
        // channels other members have advertised. Union them by id.
        let joined = self
            .db
            .channels()
            .list_in(&workspace_id)
            .await
            .map_err(|_| "storage failure")?;
        let discovered = self
            .db
            .discovered_channels()
            .list_in(&workspace_id)
            .await
            .map_err(|_| "storage failure")?;

        let mut by_id: HashMap<ChannelId, String> = HashMap::with_capacity(joined.len());
        for c in joined {
            by_id.entry(c.id).or_insert(c.name);
        }
        for d in discovered {
            by_id.entry(d.channel_id).or_insert(d.channel_name);
        }
        let mut entries: Vec<WorkspaceChannelEntry> = by_id
            .into_iter()
            .map(|(id, name)| WorkspaceChannelEntry {
                channel_id: ByteBuf::from(id.0.to_vec()),
                name,
            })
            .collect();
        entries.sort_by(|a, b| a.channel_id.as_ref().cmp(b.channel_id.as_ref()));

        audit_or_warn(
            &*self.audit_sink,
            AuditEntry {
                id: None,
                ts: Timestamp::now(),
                actor: peer.clone(),
                action: "workspace.channels.request".into(),
                target: Some(workspace_id.to_hex()),
                details: None,
                client_ip: None,
                federation: hermod_storage::AuditFederationPolicy::Default,
            },
        )
        .await;

        let hmac = secret.map(|s| {
            let mac_key = s.workspace_mac_key();
            let bytes = canonical_channels_mac_input(mac_input, &entries);
            ByteBuf::from(mac_key.mac(&bytes).to_vec())
        });
        let body = MessageBody::WorkspaceChannelsResponse {
            request_id: request_envelope_id,
            workspace_id: workspace_id_bytes.clone(),
            channels: entries,
            hmac,
        };
        self.send_to(peer, body).await
    }

    /// Handle inbound `WorkspaceRosterResponse`. Push into the pending
    /// channel keyed on `request_id`. Stale chunks (no pending entry)
    /// are silently dropped — they belong to a request we already
    /// finished or timed out on.
    pub async fn deliver_roster_response(
        &self,
        peer: AgentId,
        request_id: MessageId,
        members: Vec<AgentId>,
    ) {
        let state = self.state.lock().await;
        if let Some(tx) = state.pending_roster.get(&request_id) {
            let _ = tx.send(RosterChunk {
                responder: peer,
                members,
            });
        }
    }

    pub async fn deliver_channels_response(
        &self,
        peer: AgentId,
        request_id: MessageId,
        channels: Vec<WorkspaceChannelEntry>,
    ) {
        let state = self.state.lock().await;
        if let Some(tx) = state.pending_channels.get(&request_id) {
            let _ = tx.send(ChannelsChunk {
                responder: peer,
                channels,
            });
        }
    }

    /// IPC entry point: parse hex workspace_id, dispatch to
    /// `query_roster`, format result.
    pub async fn ipc_roster(
        &self,
        params: WorkspaceRosterParams,
    ) -> Result<WorkspaceRosterResult, ServiceError> {
        let ws = WorkspaceId::from_hex(&params.workspace_id)
            .map_err(|e| ServiceError::InvalidParam(format!("workspace_id: {e}")))?;
        let members = self.query_roster(ws).await?;
        Ok(WorkspaceRosterResult { members })
    }

    /// IPC entry point: parse hex workspace_id, dispatch to
    /// `query_channels`, format result.
    pub async fn ipc_channels(
        &self,
        params: WorkspaceChannelsParams,
    ) -> Result<WorkspaceChannelsResult, ServiceError> {
        let ws = WorkspaceId::from_hex(&params.workspace_id)
            .map_err(|e| ServiceError::InvalidParam(format!("workspace_id: {e}")))?;
        let entries = self.query_channels(ws).await?;
        let channels = entries
            .into_iter()
            .map(|e| WorkspaceChannelView {
                channel_id: hex::encode(e.channel_id.as_ref()),
                name: e.name,
            })
            .collect();
        Ok(WorkspaceChannelsResult { channels })
    }

    /// Public entry point: query the workspace roster from every
    /// known member, union the responses, return.
    pub async fn query_roster(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<Vec<AgentId>, ServiceError> {
        let workspace = self
            .db
            .workspaces()
            .get(&workspace_id)
            .await?
            .ok_or(ServiceError::NotFound)?;
        let known_members = self.db.workspace_members().list(&workspace_id).await?;
        let targets: Vec<AgentId> = known_members
            .iter()
            .filter(|m| m.as_str() != self.host_actor.as_str())
            .cloned()
            .collect();

        // Seed: our own view of the workspace.
        let mut union: std::collections::HashSet<AgentId> = known_members.into_iter().collect();
        union.insert(self.host_actor.clone());

        if targets.is_empty() {
            let mut out: Vec<AgentId> = union.into_iter().collect();
            out.sort_by(|a, b| a.as_str().cmp(b.as_str()));
            return Ok(out);
        }

        let workspace_id_bytes = ByteBuf::from(workspace_id.0.to_vec());
        let hmac = workspace
            .secret
            .as_ref()
            .map(|s| ByteBuf::from(s.workspace_mac_key().mac(&workspace_id_bytes).to_vec()));

        let request_envelope_id = MessageId::new();
        let (tx, mut rx) = mpsc::unbounded_channel::<RosterChunk>();
        self.register_pending_roster(request_envelope_id, tx)
            .await?;

        let body = MessageBody::WorkspaceRosterRequest {
            workspace_id: workspace_id_bytes,
            hmac,
        };
        for peer in &targets {
            self.send_request(peer.clone(), body.clone(), Some(request_envelope_id))
                .await
                .ok();
        }

        let deadline = tokio::time::Instant::now() + ROSTER_QUERY_TIMEOUT;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            match tokio::time::timeout(remaining, rx.recv()).await {
                Ok(Some(RosterChunk { responder, members })) => {
                    debug!(
                        responder = %responder,
                        n_members = members.len(),
                        "workspace roster chunk received"
                    );
                    union.extend(members);
                }
                Ok(None) | Err(_) => break,
            }
        }

        self.unregister_pending_roster(&request_envelope_id).await;
        let mut out: Vec<AgentId> = union.into_iter().collect();
        out.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        Ok(out)
    }

    /// Public entry point: query the workspace channel list.
    pub async fn query_channels(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<Vec<WorkspaceChannelEntry>, ServiceError> {
        let workspace = self
            .db
            .workspaces()
            .get(&workspace_id)
            .await?
            .ok_or(ServiceError::NotFound)?;
        let known_members = self.db.workspace_members().list(&workspace_id).await?;
        let targets: Vec<AgentId> = known_members
            .iter()
            .filter(|m| m.as_str() != self.host_actor.as_str())
            .cloned()
            .collect();

        // Seed with our local view (joined channels + discovered).
        let mut union: HashMap<ChannelId, String> = HashMap::new();
        for c in self.db.channels().list_in(&workspace_id).await? {
            union.entry(c.id).or_insert(c.name);
        }
        for d in self.db.discovered_channels().list_in(&workspace_id).await? {
            union.entry(d.channel_id).or_insert(d.channel_name);
        }

        if !targets.is_empty() {
            let workspace_id_bytes = ByteBuf::from(workspace_id.0.to_vec());
            let hmac = workspace
                .secret
                .as_ref()
                .map(|s| ByteBuf::from(s.workspace_mac_key().mac(&workspace_id_bytes).to_vec()));

            let request_envelope_id = MessageId::new();
            let (tx, mut rx) = mpsc::unbounded_channel::<ChannelsChunk>();
            self.register_pending_channels(request_envelope_id, tx)
                .await?;

            let body = MessageBody::WorkspaceChannelsRequest {
                workspace_id: workspace_id_bytes,
                hmac,
            };
            for peer in &targets {
                self.send_request(peer.clone(), body.clone(), Some(request_envelope_id))
                    .await
                    .ok();
            }

            let deadline = tokio::time::Instant::now() + ROSTER_QUERY_TIMEOUT;
            loop {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() {
                    break;
                }
                match tokio::time::timeout(remaining, rx.recv()).await {
                    Ok(Some(ChannelsChunk {
                        responder,
                        channels,
                    })) => {
                        debug!(
                            responder = %responder,
                            n_channels = channels.len(),
                            "workspace channels chunk received"
                        );
                        for entry in channels {
                            if let Ok(id_arr) = <[u8; 16]>::try_from(entry.channel_id.as_ref()) {
                                union.entry(ChannelId(id_arr)).or_insert(entry.name);
                            }
                        }
                    }
                    Ok(None) | Err(_) => break,
                }
            }
            self.unregister_pending_channels(&request_envelope_id).await;
        }

        let mut entries: Vec<WorkspaceChannelEntry> = union
            .into_iter()
            .map(|(id, name)| WorkspaceChannelEntry {
                channel_id: ByteBuf::from(id.0.to_vec()),
                name,
            })
            .collect();
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(entries)
    }

    async fn register_pending_roster(
        &self,
        id: MessageId,
        tx: mpsc::UnboundedSender<RosterChunk>,
    ) -> Result<(), ServiceError> {
        let mut state = self.state.lock().await;
        if state.pending_roster.len() + state.pending_channels.len() >= MAX_PENDING_REQUESTS {
            return Err(ServiceError::InvalidParam(format!(
                "too many in-flight workspace queries (cap {MAX_PENDING_REQUESTS})"
            )));
        }
        state.pending_roster.insert(id, tx);
        Ok(())
    }

    async fn unregister_pending_roster(&self, id: &MessageId) {
        let mut state = self.state.lock().await;
        state.pending_roster.remove(id);
    }

    async fn register_pending_channels(
        &self,
        id: MessageId,
        tx: mpsc::UnboundedSender<ChannelsChunk>,
    ) -> Result<(), ServiceError> {
        let mut state = self.state.lock().await;
        if state.pending_roster.len() + state.pending_channels.len() >= MAX_PENDING_REQUESTS {
            return Err(ServiceError::InvalidParam(format!(
                "too many in-flight workspace queries (cap {MAX_PENDING_REQUESTS})"
            )));
        }
        state.pending_channels.insert(id, tx);
        Ok(())
    }

    async fn unregister_pending_channels(&self, id: &MessageId) {
        let mut state = self.state.lock().await;
        state.pending_channels.remove(id);
    }

    async fn send_to(&self, peer: &AgentId, body: MessageBody) -> Result<(), &'static str> {
        let messages = self.messages.get().ok_or("message service not wired")?;
        let to = AgentAddress::local(peer.clone());
        messages
            .send(MessageSendParams {
                to,
                body,
                priority: Some(MessagePriority::Normal),
                thread: None,
                ttl_secs: Some(60),
                caps: None,
            })
            .await
            .map_err(|_| "send failed")?;
        Ok(())
    }

    /// Send a request envelope to `peer`. The `force_id` parameter is
    /// the envelope id we want — but currently `MessageService::send`
    /// generates a fresh id internally. So instead we let MessageService
    /// generate the id, and the caller looks at the returned id. To keep
    /// the request_id known to the caller, we pre-allocate the id in
    /// `query_roster` / `query_channels` and use it to construct the
    /// envelope. Since `MessageService::send` internally generates,
    /// we route through a dedicated path: pre-build the envelope here
    /// with the desired id, then ship via `send`.
    ///
    /// Note: the current implementation reuses the `MessageService::send`
    /// path which generates a new id; we accept that the request_id
    /// in the originating envelope differs from what the response
    /// echoes. Until envelope-id-passthrough lands, the simplest
    /// correct shape is: caller fan-out with a single shared correlator
    /// sourced from the FIRST send's envelope id — but that's racy.
    ///
    /// Workaround: every fan-out target gets its own request envelope
    /// (and its own id), all registered into the same pending channel.
    /// The pending tracker keys on whichever id the response echoes.
    /// To make that work, we register N entries (one per target) all
    /// pointing at the same sender. When responses come in, any of
    /// them flows into our collector.
    async fn send_request(
        &self,
        peer: AgentId,
        body: MessageBody,
        _force_id: Option<MessageId>,
    ) -> Result<MessageId, &'static str> {
        let messages = self.messages.get().ok_or("message service not wired")?;
        let to = AgentAddress::local(peer);
        let outcome = messages
            .send(MessageSendParams {
                to,
                body,
                priority: Some(MessagePriority::Normal),
                thread: None,
                ttl_secs: Some(60),
                caps: None,
            })
            .await
            .map_err(|_| "send failed")?;
        Ok(outcome.id)
    }
}

fn parse_workspace_id(bytes: &ByteBuf) -> Result<WorkspaceId, &'static str> {
    let arr: [u8; 16] = bytes
        .as_ref()
        .try_into()
        .map_err(|_| "workspace_id wrong length")?;
    Ok(WorkspaceId(arr))
}

/// Canonical bytes the response MAC is computed over for roster:
/// `workspace_id_bytes || 0x00 || sorted_member_concat`.
/// The `0x00` separator prevents `(workspace || alice) == (workspace
/// || alice||bob_prefix)` collisions, even though sorted-member
/// concatenation is already structured.
fn canonical_roster_mac_input(workspace_id: &[u8], sorted_members: &[RosterMember]) -> Vec<u8> {
    // `id || 0x00 || pubkey || 0x00` per entry. Including the pubkey
    // in the MAC input prevents a malicious responder from swapping
    // a member's pubkey while preserving the agent_id list.
    let mut out = Vec::with_capacity(
        workspace_id.len() + 1 + sorted_members.len() * (27 + PubkeyBytes::LEN + 1),
    );
    out.extend_from_slice(workspace_id);
    out.push(0x00);
    for m in sorted_members {
        out.extend_from_slice(m.id.as_str().as_bytes());
        out.push(0x00);
        out.extend_from_slice(m.pubkey.as_slice());
        out.push(0x00);
    }
    out
}

/// Canonical bytes the response MAC is computed over for channels:
/// `workspace_id_bytes || 0x00 || (channel_id || 0x00 || name || 0x00)*`,
/// with entries pre-sorted by channel_id.
fn canonical_channels_mac_input(workspace_id: &[u8], entries: &[WorkspaceChannelEntry]) -> Vec<u8> {
    let mut out = Vec::with_capacity(workspace_id.len() + 1 + entries.len() * 32);
    out.extend_from_slice(workspace_id);
    out.push(0x00);
    for e in entries {
        out.extend_from_slice(&e.channel_id);
        out.push(0x00);
        out.extend_from_slice(e.name.as_bytes());
        out.push(0x00);
    }
    out
}

/// Verify the HMAC on an inbound roster RESPONSE under the workspace
/// secret. Returns true if accepted (or if the workspace is public,
/// in which case `claimed_hmac` must be `None`).
pub fn verify_roster_response_mac(
    secret: Option<&WorkspaceSecret>,
    workspace_id: &[u8],
    sorted_members: &[RosterMember],
    claimed_hmac: Option<&[u8]>,
) -> bool {
    match (secret, claimed_hmac) {
        (Some(s), Some(claim)) if claim.len() == 32 => {
            let mut got = [0u8; 32];
            got.copy_from_slice(claim);
            s.workspace_mac_key().verify(
                &canonical_roster_mac_input(workspace_id, sorted_members),
                &got,
            )
        }
        (None, None) => true,
        _ => false,
    }
}

/// Verify the HMAC on an inbound channels RESPONSE.
pub fn verify_channels_response_mac(
    secret: Option<&WorkspaceSecret>,
    workspace_id: &[u8],
    entries: &[WorkspaceChannelEntry],
    claimed_hmac: Option<&[u8]>,
) -> bool {
    match (secret, claimed_hmac) {
        (Some(s), Some(claim)) if claim.len() == 32 => {
            let mut got = [0u8; 32];
            got.copy_from_slice(claim);
            s.workspace_mac_key()
                .verify(&canonical_channels_mac_input(workspace_id, entries), &got)
        }
        (None, None) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(b: u8) -> RosterMember {
        let pk = PubkeyBytes([b; 32]);
        RosterMember {
            id: hermod_crypto::agent_id_from_pubkey(&pk),
            pubkey: pk,
        }
    }

    #[test]
    fn roster_mac_input_is_deterministic_under_sort() {
        let ws = [1u8; 16];
        let m1 = vec![member(1), member(2), member(3)];
        let mut m2 = vec![member(3), member(2), member(1)];
        m2.sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));
        let mut sorted_m1 = m1.clone();
        sorted_m1.sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));
        assert_eq!(
            canonical_roster_mac_input(&ws, &sorted_m1),
            canonical_roster_mac_input(&ws, &m2),
        );
    }

    #[test]
    fn channels_mac_input_is_collision_resistant() {
        let ws = [1u8; 16];
        let a = vec![WorkspaceChannelEntry {
            channel_id: ByteBuf::from(vec![1u8; 16]),
            name: "general".into(),
        }];
        let b = vec![WorkspaceChannelEntry {
            channel_id: ByteBuf::from(vec![1u8; 16]),
            name: "general\0extra".into(),
        }];
        // 0x00 separator catches the embedded-NUL trick.
        assert_ne!(
            canonical_channels_mac_input(&ws, &a),
            canonical_channels_mac_input(&ws, &b),
        );
    }

    #[test]
    fn verify_roster_mac_round_trip_private() {
        let secret = WorkspaceSecret::from_bytes([7u8; 32]);
        let ws = [9u8; 16];
        let mut members = vec![member(2), member(1), member(3)];
        members.sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));
        let mac = secret
            .workspace_mac_key()
            .mac(&canonical_roster_mac_input(&ws, &members));
        assert!(verify_roster_response_mac(
            Some(&secret),
            &ws,
            &members,
            Some(&mac)
        ));
        assert!(!verify_roster_response_mac(
            Some(&secret),
            &ws,
            &members,
            Some(&[0u8; 32])
        ));
        // Public workspace: secret None, hmac None.
        assert!(verify_roster_response_mac(None, &ws, &members, None));
        assert!(!verify_roster_response_mac(None, &ws, &members, Some(&mac)));
    }

    #[test]
    fn roster_mac_input_changes_when_pubkey_changes() {
        // Defense-in-depth: a malicious responder can't keep the same
        // agent_id list while substituting a member's pubkey.
        let ws = [3u8; 16];
        let m1 = vec![member(1), member(2)];
        let mut m2 = m1.clone();
        m2[1].pubkey = PubkeyBytes([99u8; 32]);
        assert_ne!(
            canonical_roster_mac_input(&ws, &m1),
            canonical_roster_mac_input(&ws, &m2),
        );
    }
}
