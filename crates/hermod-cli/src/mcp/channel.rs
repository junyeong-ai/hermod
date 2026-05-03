//! Claude Code "channel" emitter — bridges Hermod's inbox into the running
//! MCP session as `notifications/claude/channel` server-push notifications.
//!
//! ## Design
//!
//! The MCP server reads inbox + held-confirmation state from the daemon and
//! emits one notification per *new* item. New-ness is determined by ULID
//! cursor — `InboxListParams.after_id` and `ConfirmationListParams.after_id`
//! filter to "id > last seen", and the cursor advances after each batch.
//! `inbox.list` is filtered to `dispositions: [Push]` so silent rows
//! (held by the routing engine) never enter AI-agent context.
//! The cursor is also persisted to the daemon via `mcp.cursor_advance` so a
//! Claude Code restart with the same `HERMOD_SESSION_LABEL` resumes mid-stream.
//!
//! Why polling, not streaming: durable messaging systems converge on
//! cursor-based pull (Kafka, SQS, GCP Pub/Sub) because correctness still
//! demands a cursor for reconnect/restart. Streaming would be a performance
//! optimization on top of the same cursor — and Hermod's actual workload
//! (chat-rate, < 1 msg/sec) makes the latency win imperceptible.
//!
//! The [`ChannelSource`] trait is the seam: a future streaming source can
//! drop in without touching emit/serialization code.
//!
//! ## AI-agent context discipline
//!
//! [`ChannelEvent`] carries the slim view: `from_alias` (effective) plus
//! `from_alias_ambiguous` plus `from_host_pubkey` (used only when
//! ambiguous). Operator-debugging fields (`from_local_alias`,
//! `from_peer_alias`) live on the IPC `MessageView` for human surfaces
//! and never enter the channel-frame meta.

use anyhow::Result;
use hermod_core::{
    AgentAlias, AgentId, McpSessionId, MessageBody, MessageDisposition, MessageId, MessagePriority,
    MessageStatus,
};
use hermod_protocol::ipc::methods::{ConfirmationListParams, InboxListParams, PresenceGetParams};
use std::collections::HashMap;
use std::time::Duration;
use tracing::warn;

use crate::client::{ClientTarget, DaemonClient};

/// How often the MCP server polls the daemon for new inbox events.
///
/// 500 ms keeps push latency below human "real-time" perception (~100 ms +
/// network) while imposing negligible CPU on a localhost Unix socket. The
/// SQLite query is indexed and finishes sub-millisecond.
pub const POLL_INTERVAL: Duration = Duration::from_millis(500);

/// Single batch limit per poll. Far above expected steady-state arrival rate;
/// caps catch-up burst on first connect or after long downtime.
const BATCH_LIMIT: u32 = 100;

/// One Hermod inbox/control event that warrants a Claude Code channel
/// notification. Variants stay small and exhaustive — adding a new event
/// kind requires updating every match in this module (compiler-enforced).
///
/// Every variant carries:
///   * `from`: canonical agent_id (hash) — for crypto, dedup, audit.
///   * `from_alias`: effective display — local wins, falls back to peer.
///   * `from_alias_ambiguous`: set when another agent shares this alias;
///     the receiver MUST surface `from_host_pubkey` (or the raw `from`)
///     before acting on the alias.
///   * `from_host_pubkey`: hex ed25519 host pubkey of the daemon
///     hosting `from`. UIs surface the leading 8 chars when the alias
///     is ambiguous.
///   * `from_live`: whether a synchronous reply is realistic right now.
#[derive(Debug, Clone)]
pub enum ChannelEvent {
    /// A direct message has been delivered to my inbox.
    DirectMessage {
        id: MessageId,
        from: AgentId,
        from_alias: Option<AgentAlias>,
        from_alias_ambiguous: bool,
        from_host_pubkey: Option<String>,
        from_live: bool,
        priority: MessagePriority,
        body: String,
    },
    /// A `MessageBody::File` payload landed in my inbox. The bytes
    /// themselves live in the BlobStore at `location`; the operator's
    /// host fetches them via `Read` (LocalFs backend resolves to a
    /// real path) or — once cloud backends ship — `hermod blob fetch`.
    FileMessage {
        id: MessageId,
        from: AgentId,
        from_alias: Option<AgentAlias>,
        from_alias_ambiguous: bool,
        from_host_pubkey: Option<String>,
        from_live: bool,
        priority: MessagePriority,
        name: String,
        mime: String,
        size: u64,
        hash_hex: String,
        location: String,
    },
    /// An inbound action was held by the trust gate; surfaces to the operator
    /// who must accept or reject via `hermod confirm` CLI. Agents only
    /// observe — they cannot decide, by design.
    HeldConfirmation {
        id: String,
        from: AgentId,
        from_alias: Option<AgentAlias>,
        from_alias_ambiguous: bool,
        from_host_pubkey: Option<String>,
        from_live: bool,
        /// Operator-facing intent label (e.g. `"message.deliver"`,
        /// `"workspace.invite"`). Mirrors `HeldIntent::as_str()`.
        intent: String,
        /// Wire-format sensitivity (`"routine" | "review" | "sensitive"`).
        /// String here keeps the MCP layer free of routing-internal types.
        sensitivity: String,
        summary: String,
    },
}

/// Source of [`ChannelEvent`]s. Implementations drive the emitter loop.
#[async_trait::async_trait]
pub trait ChannelSource: Send {
    /// Block until the next batch of events is available (or the source
    /// errors). An empty `Vec` is allowed — the emitter will sleep and retry.
    async fn next_batch(&mut self) -> Result<Vec<ChannelEvent>>;
}

/// Cursor-based pulling source. Polls the daemon's `inbox.list` and
/// `confirmation.list` at [`POLL_INTERVAL`], advancing per-stream cursors
/// so every event is emitted exactly once across the MCP subprocess
/// lifetime, and persisting the advanced cursor to the daemon after each
/// batch so a process restart with the same `session_label` picks up
/// from the same position rather than re-emitting the entire backlog.
///
/// A single [`DaemonClient`] is held open across polls so Remote IPC
/// transports don't pay TLS handshake + bearer auth on every cycle. The
/// connection is dropped + reopened on the first error, then any
/// subsequent error backs off through `next_batch`.
///
/// Cadence is anchored to a [`tokio::time::Interval`] (Skip on missed ticks)
/// rather than `sleep(POLL_INTERVAL)` after each poll. Under sustained
/// daemon slowness, `sleep`-after-poll lets the loop drift fast (every poll
/// takes >interval, so sleep-then-poll-then-sleep advances faster than
/// real-time). `Interval::tick().await` only fires at fixed wall-clock
/// boundaries; missed ticks are *skipped*, never queued.
pub struct PollingChannelSource {
    target: ClientTarget,
    client: Option<DaemonClient>,
    ticker: tokio::time::Interval,
    /// MCP session this poller belongs to — drives `mcp.cursor_advance`
    /// at the end of each batch so the cursor survives MCP restart.
    session_id: McpSessionId,
    last_message_id: Option<MessageId>,
    last_confirmation_id: Option<String>,
    /// Tracks whether `last_message_id` / `last_confirmation_id` have
    /// advanced since the last `cursor_advance` call so we only emit
    /// the IPC when there's something to persist.
    dirty_message: bool,
    dirty_confirmation: bool,
}

impl PollingChannelSource {
    /// Construct a source seeded with the cursors returned by
    /// `mcp.attach`. Pass `None` for a fresh stream.
    pub fn new_with_seed(
        target: ClientTarget,
        session_id: McpSessionId,
        last_message_id: Option<MessageId>,
        last_confirmation_id: Option<String>,
    ) -> Self {
        let mut ticker = tokio::time::interval(POLL_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        Self {
            target,
            client: None,
            ticker,
            session_id,
            last_message_id,
            last_confirmation_id,
            dirty_message: false,
            dirty_confirmation: false,
        }
    }

    /// Take the cached connection (or open a new one). The caller owns it
    /// for the duration of `poll_once` and reinstates it on success; on
    /// failure the connection is dropped and a fresh one is opened next
    /// poll cycle.
    async fn take_client(&mut self) -> Result<DaemonClient> {
        match self.client.take() {
            Some(c) => Ok(c),
            None => Ok(self.target.connect().await?),
        }
    }

    async fn poll_once(&mut self) -> Result<Vec<ChannelEvent>> {
        let after_msg = self.last_message_id;
        let after_conf = self.last_confirmation_id.clone();
        let mut client = self.take_client().await?;

        let inbox = match client
            .inbox_list(InboxListParams {
                statuses: Some(vec![MessageStatus::Delivered]),
                priority_min: None,
                limit: Some(BATCH_LIMIT),
                after_id: after_msg,
                // Push only — silent rows must never reach AI-agent
                // context. Operators see them via `hermod inbox list`
                // (default `--disposition all`) and can promote with
                // `hermod inbox promote <id>`.
                dispositions: Some(vec![MessageDisposition::Push]),
            })
            .await
        {
            Ok(r) => r,
            Err(e) => return Err(e),
        };
        let confirmations = match client
            .confirmation_list(ConfirmationListParams {
                limit: Some(BATCH_LIMIT),
                after_id: after_conf,
            })
            .await
        {
            Ok(r) => r,
            Err(e) => return Err(e),
        };

        let mut out = Vec::with_capacity(inbox.messages.len() + confirmations.confirmations.len());
        // Per-batch cache: many DMs from the same sender in one cycle resolve
        // to a single `presence.get` round-trip.
        let mut live_cache: HashMap<AgentId, bool> = HashMap::new();

        for m in inbox.messages {
            self.last_message_id = Some(m.id);
            self.dirty_message = true;
            let from_live = resolve_live(&mut client, &m.from, &mut live_cache).await;
            // The inbox now holds `Direct` and `File` bodies. Other
            // kinds (Brief / Presence / channel-broadcast / etc.) have
            // their own tables and never reach `messages.list`.
            match &m.body {
                MessageBody::Direct { text } => {
                    out.push(ChannelEvent::DirectMessage {
                        id: m.id,
                        from: m.from,
                        from_alias: m.from_alias,
                        from_alias_ambiguous: m.from_alias_ambiguous,
                        from_host_pubkey: m.from_host_pubkey,
                        from_live,
                        priority: m.priority,
                        body: text.clone(),
                    });
                }
                MessageBody::File {
                    name, mime, hash, ..
                } => {
                    out.push(ChannelEvent::FileMessage {
                        id: m.id,
                        from: m.from,
                        from_alias: m.from_alias,
                        from_alias_ambiguous: m.from_alias_ambiguous,
                        from_host_pubkey: m.from_host_pubkey,
                        from_live,
                        priority: m.priority,
                        name: name.clone(),
                        mime: if mime.is_empty() {
                            "application/octet-stream".into()
                        } else {
                            mime.clone()
                        },
                        // `body.data` is empty in the storage
                        // projection (the bytes live in the BlobStore);
                        // pull the authoritative size from the
                        // dedicated `file_size` projection field.
                        size: m.file_size.unwrap_or(0),
                        hash_hex: hex::encode(hash.as_ref()),
                        location: m.file_blob_location.unwrap_or_default(),
                    });
                }
                other => {
                    tracing::warn!(
                        kind = ?other,
                        "messages.list returned a body kind that should live elsewhere; dropping"
                    );
                }
            }
        }

        for c in confirmations.confirmations {
            self.last_confirmation_id = Some(c.id.clone());
            self.dirty_confirmation = true;
            let from_live = resolve_live(&mut client, &c.from, &mut live_cache).await;
            out.push(ChannelEvent::HeldConfirmation {
                id: c.id,
                from: c.from,
                from_alias: c.from_alias,
                from_alias_ambiguous: c.from_alias_ambiguous,
                from_host_pubkey: c.from_host_pubkey,
                from_live,
                intent: c.intent,
                sensitivity: c.sensitivity,
                summary: c.summary,
            });
        }

        // Persist advanced cursors so a process restart resumes
        // mid-stream. Best-effort — failure leaves dirty flags set
        // and the next batch retries the persist.
        if self.dirty_message || self.dirty_confirmation {
            super::session::persist_cursor(
                &self.target,
                &self.session_id,
                if self.dirty_message {
                    self.last_message_id
                } else {
                    None
                },
                if self.dirty_confirmation {
                    self.last_confirmation_id.clone()
                } else {
                    None
                },
                None,
            )
            .await;
            self.dirty_message = false;
            self.dirty_confirmation = false;
        }

        // Reinstate the connection so the next poll skips the connect().
        self.client = Some(client);
        Ok(out)
    }
}

/// Look up `from`'s liveness via the daemon, caching by id within a batch.
/// On any error we degrade to `false` (offline) — the LLM treats unknown
/// liveness as "do not assume sync reply is possible", which is the safe
/// default.
async fn resolve_live(
    client: &mut DaemonClient,
    from: &AgentId,
    cache: &mut HashMap<AgentId, bool>,
) -> bool {
    if let Some(v) = cache.get(from) {
        return *v;
    }
    let live = match client
        .presence_get(PresenceGetParams {
            agent: from.to_string(),
        })
        .await
    {
        Ok(r) => r.presence.map(|p| p.live).unwrap_or(false),
        Err(_) => false,
    };
    cache.insert(from.clone(), live);
    live
}

#[async_trait::async_trait]
impl ChannelSource for PollingChannelSource {
    async fn next_batch(&mut self) -> Result<Vec<ChannelEvent>> {
        loop {
            // Anchor to wall-clock-fixed ticks. The first tick fires
            // immediately on a fresh interval, so the very first call returns
            // any backlog without delay; subsequent calls wait for the next
            // boundary regardless of how long `poll_once` took.
            self.ticker.tick().await;
            match self.poll_once().await {
                Ok(batch) if !batch.is_empty() => return Ok(batch),
                Ok(_) => continue,
                Err(e) => {
                    // Daemon unreachable / transient — log and let the next
                    // tick retry. Cursor state is preserved so we resume
                    // cleanly.
                    warn!(error = %e, "channel poll failed");
                }
            }
        }
    }
}
