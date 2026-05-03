//! Workspace-scoped fanout helper.
//!
//! Brief and Presence are "self-status" updates the operator publishes locally;
//! collaborators see them by virtue of sharing a workspace. This module turns a
//! local publish into one envelope per distinct workspace member, routed
//! through `MessageService::send` (which handles signing, outbox, retry).
//!
//! "Send to workspace members" — not "send to every Verified peer" — because:
//!   * brief/presence are collaboration signals, not broadcasts;
//!   * unrelated Verified peers shouldn't see what I'm working on;
//!   * the workspace_members table is already the canonical "who I collaborate with" set.
//!
//! ## Parallelism
//!
//! Members are dispatched concurrently up to [`FANOUT_CONCURRENCY`] in
//! flight. Sequential delivery would multiply transport latency by the
//! workspace size (1 second per member × 100 members = wedged for two
//! minutes); the bounded-parallelism `buffer_unordered` keeps each
//! publish predictable while still pipelining the network round-trips.
//! The bound also caps inbound DB pressure on the storage backend
//! (every send is one transaction).

use futures::stream::{self, StreamExt};
use hermod_core::{AgentAddress, AgentId, Endpoint, MessageBody, MessagePriority};
use hermod_protocol::ipc::methods::MessageSendParams;
use hermod_storage::Database;
use tracing::{debug, warn};

use crate::services::{ServiceError, message::MessageService};

/// Hard ceiling on a single fanout. Brief / Presence land in every workspace
/// member's inbox, so a workspace with N members generates N envelopes
/// (signing + DB write + outbox enqueue). Beyond this we truncate and
/// report it back to the caller — operators with larger groups should
/// restructure into multiple workspaces.
pub const MAX_FANOUT_PER_CALL: usize = 256;

/// Concurrency cap for in-flight per-member dispatches. Tuned for typical
/// LAN/WAN federation: 16 parallel envelope sends saturate a 1Gbps link
/// at ~1KB envelopes without overrunning the storage backend's writer
/// lock. Operators with very high-fan-out workspaces who see contention
/// can lower it; operators with thin daemons running on high-RTT links
/// can raise it.
pub const FANOUT_CONCURRENCY: usize = 16;

#[derive(Debug, Clone, Default)]
pub struct FanoutOutcome {
    pub delivered: u32,
    pub skipped: u32,
    pub truncated_at: Option<usize>,
}

/// Per-member dispatch outcome. Collected by the parallel stream, then
/// folded into [`FanoutOutcome`] once every in-flight task completes.
enum MemberOutcome {
    Delivered,
    Skipped,
}

/// Send `body` to every distinct workspace member except `self`. Returns
/// counts plus a truncation marker — members beyond [`MAX_FANOUT_PER_CALL`]
/// are skipped and the caller is told how big the original member set was.
/// Members without a registered remote endpoint are skipped (they're either
/// local-only or not reachable yet). Up to [`FANOUT_CONCURRENCY`] members
/// are dispatched in parallel.
pub async fn fanout_to_workspace_members(
    db: &dyn Database,
    messages: &MessageService,
    from_agent: &AgentId,
    body: MessageBody,
    priority: MessagePriority,
    ttl_secs: u32,
) -> Result<FanoutOutcome, ServiceError> {
    let members = db
        .workspace_members()
        .list_distinct_excluding(from_agent)
        .await?;

    let total = members.len();
    let truncated_at = (total > MAX_FANOUT_PER_CALL).then_some(total);
    if let Some(n) = truncated_at {
        warn!(
            total = n,
            cap = MAX_FANOUT_PER_CALL,
            "fanout truncated: workspace member count exceeds per-call cap"
        );
    }

    let outcomes: Vec<MemberOutcome> = stream::iter(members.into_iter().take(MAX_FANOUT_PER_CALL))
        .map(|member| {
            let body = body.clone();
            async move { dispatch_one(db, messages, member, body, priority, ttl_secs).await }
        })
        .buffer_unordered(FANOUT_CONCURRENCY)
        .collect()
        .await;

    let mut outcome = FanoutOutcome {
        truncated_at,
        ..FanoutOutcome::default()
    };
    for o in outcomes {
        match o {
            MemberOutcome::Delivered => outcome.delivered = outcome.delivered.saturating_add(1),
            MemberOutcome::Skipped => outcome.skipped = outcome.skipped.saturating_add(1),
        }
    }
    Ok(outcome)
}

/// Resolve `member`'s endpoint and dispatch one envelope. Lookup +
/// send happen inside this function so each member's work is one
/// future on the parallel stream.
async fn dispatch_one(
    db: &dyn Database,
    messages: &MessageService,
    member: AgentId,
    body: MessageBody,
    priority: MessagePriority,
    ttl_secs: u32,
) -> MemberOutcome {
    let recipient = match db.agents().get(&member).await {
        Ok(Some(rec)) => match crate::services::resolve_host_endpoint(db, &rec).await {
            Some(Endpoint::Wss(w)) => AgentAddress::with_endpoint(rec.id, Endpoint::Wss(w)),
            _ => AgentAddress::local(rec.id),
        },
        Ok(None) => {
            debug!(member = %member, "fanout skipped: agent not in directory");
            return MemberOutcome::Skipped;
        }
        Err(e) => {
            warn!(member = %member, error = %e, "fanout skipped: directory lookup failed");
            return MemberOutcome::Skipped;
        }
    };
    match messages
        .send(MessageSendParams {
            to: recipient,
            body,
            priority: Some(priority),
            thread: None,
            ttl_secs: Some(ttl_secs),
            caps: None,
        })
        .await
    {
        Ok(_) => MemberOutcome::Delivered,
        Err(e) => {
            warn!(member = %member, error = %e, "fanout send failed");
            MemberOutcome::Skipped
        }
    }
}
