//! MCP session lifecycle: attach → heartbeat → cursor_advance → detach,
//! plus the two background emitters (channel events and permission
//! verdicts).
//!
//! Self-healing: if the daemon flushes our session row (e.g. a restart
//! happened), the supervisor re-attaches automatically and the emitters
//! are restarted with the freshly-resumed cursors. Operators don't need
//! to bounce the MCP server when the daemon goes down.
//!
//! ## Per-instance boundary
//!
//! The MCP process passes `HERMOD_SESSION_LABEL` on attach. When set,
//! the daemon resumes the same session row (including delivery
//! cursors) on reconnect — a Claude Code restart with the same label
//! picks up the inbox / verdict stream where it left off rather than
//! re-emitting the entire backlog. Two live attaches with the same
//! label are rejected by the daemon (`Conflict`), so two windows
//! can't silently share a single cursor stream.

use anyhow::Result;
use hermod_core::{McpSessionId, SessionLabel};
use hermod_protocol::ipc::methods::{
    McpAttachParams, McpAttachResult, McpCursorAdvanceParams, McpDetachParams, McpHeartbeatParams,
    PermissionBehavior, PermissionOutcome,
};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::Stdout;
use tokio::sync::{Mutex, oneshot, watch};
use tokio::task::JoinHandle;

use super::channel::{ChannelEvent, ChannelSource, POLL_INTERVAL, PollingChannelSource};
use super::notification::{channel as channel_notification, permission_verdict};
use super::permission::ResolvedCursor;
use super::{ClientInfo, DETACH_TIMEOUT, write_json};
use crate::client::{ClientTarget, DaemonClient};

/// Snapshot of the daemon's response to a successful `mcp.attach`.
/// Cloned freely between supervisor and emitters; on re-attach a
/// fresh value lands and emitters re-seed their cursors.
#[derive(Debug, Clone)]
pub(crate) struct SessionAttach {
    pub session_id: McpSessionId,
    pub last_message_id: Option<hermod_core::MessageId>,
    pub last_confirmation_id: Option<String>,
    pub last_resolved_seq: Option<u64>,
}

/// Bundle of session state set up after the MCP `initialize` handshake.
pub(crate) struct Session {
    shutdown_tx: oneshot::Sender<()>,
    /// Latest successful attach published by the supervisor. The
    /// `route_notification` path reads this to stamp inbound
    /// `permission_request` notifications with the originating
    /// session — `None` until the very first attach lands.
    state_rx: watch::Receiver<Option<SessionAttach>>,
    supervisor: JoinHandle<()>,
}

impl Session {
    pub(crate) async fn start(
        target: Arc<ClientTarget>,
        stdout: Arc<Mutex<Stdout>>,
        client_info: Option<ClientInfo>,
        session_label: Option<SessionLabel>,
    ) -> Self {
        let info = client_info.unwrap_or_default();
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let (state_tx, state_rx) = watch::channel::<Option<SessionAttach>>(None);
        let supervisor = tokio::spawn(supervisor_loop(
            target,
            stdout,
            info,
            session_label,
            state_tx,
            shutdown_rx,
        ));
        Session {
            shutdown_tx,
            state_rx,
            supervisor,
        }
    }

    /// Latest `session_id` published by the supervisor — `None` until
    /// the first attach completes. Read by the run-loop's
    /// `permission_request` path so prompts ship with their
    /// originating-session binding.
    pub(crate) fn current_session_id(&self) -> Option<McpSessionId> {
        self.state_rx
            .borrow()
            .as_ref()
            .map(|s| s.session_id.clone())
    }

    pub(crate) async fn shutdown(self) {
        // Signal the supervisor to detach + exit. If it doesn't return
        // within DETACH_TIMEOUT, we abort and leave cleanup to the
        // daemon's session TTL.
        let _ = self.shutdown_tx.send(());
        let _ = tokio::time::timeout(DETACH_TIMEOUT, self.supervisor).await;
    }
}

async fn supervisor_loop(
    target: Arc<ClientTarget>,
    stdout: Arc<Mutex<Stdout>>,
    info: ClientInfo,
    session_label: Option<SessionLabel>,
    state_tx: watch::Sender<Option<SessionAttach>>,
    mut shutdown_rx: oneshot::Receiver<()>,
) {
    /// Backoff between failed (re-)attach attempts. Short enough that a
    /// daemon restart is recovered well within the SESSION_TTL window;
    /// long enough not to thrash a permanently-down daemon.
    const ATTACH_RETRY: Duration = Duration::from_secs(5);

    // Notification dispatcher is process-scoped — its worker_id
    // identifies *this MCP process*, not any specific attach. It
    // survives re-attach cleanly (claim_token semantics; no
    // dependency on session_id). Spawned once; aborted on shutdown.
    let worker_id = format!("mcp-{}", hermod_core::MessageId::new());
    let (notifier_shutdown, notifier_handle) = super::notifier::spawn(target.clone(), worker_id);

    loop {
        let attach = tokio::select! {
            biased;
            _ = &mut shutdown_rx => return,
            res = attach_once(&target, &info, &session_label) => res,
        };
        let (session, interval) = match attach {
            Ok(r) => {
                let interval = Duration::from_secs(r.heartbeat_interval_secs.max(1) as u64);
                let session = SessionAttach {
                    session_id: r.session_id,
                    last_message_id: r.last_message_id,
                    last_confirmation_id: r.last_confirmation_id,
                    last_resolved_seq: r.last_resolved_seq,
                };
                if r.resumed {
                    tracing::info!(
                        session_id = %session.session_id,
                        "resumed session — cursors carried from prior attach"
                    );
                }
                let _ = state_tx.send(Some(session.clone()));
                (session, interval)
            }
            Err(e) => {
                tracing::debug!(error = %e, "session attach failed; retrying");
                tokio::select! {
                    biased;
                    _ = &mut shutdown_rx => return,
                    _ = tokio::time::sleep(ATTACH_RETRY) => continue,
                }
            }
        };

        // Spawn fresh emitters bound to this attach's session_id +
        // cursors. They run until the supervisor aborts them on
        // re-attach or shutdown.
        let channel_handle = spawn_channel_emitter(target.clone(), stdout.clone(), session.clone());
        let verdict_handle = spawn_verdict_emitter(target.clone(), stdout.clone(), session.clone());

        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // The attach call itself just bumped last_heartbeat_at; skip the
        // immediate-fire tick so the first real heartbeat is spaced out.
        ticker.tick().await;
        let needs_reattach = loop {
            tokio::select! {
                biased;
                _ = &mut shutdown_rx => {
                    detach_best_effort(&target, &session.session_id).await;
                    let _ = state_tx.send(None);
                    channel_handle.abort();
                    verdict_handle.abort();
                    let _ = notifier_shutdown.send(());
                    let _ = tokio::time::timeout(DETACH_TIMEOUT, notifier_handle).await;
                    return;
                    // ↑ shutdown ⇒ exit the function entirely. No
                    // outer-loop iteration after this.
                    #[allow(unreachable_code)]
                    {}
                }
                _ = ticker.tick() => {
                    match heartbeat_once(&target, &session.session_id).await {
                        HeartbeatOutcome::Ok => continue,
                        HeartbeatOutcome::Unknown => break true,
                        HeartbeatOutcome::Transient => continue,
                    }
                }
            }
        };
        // Tear down the emitters before re-attaching — fresh attach
        // means fresh cursors, and the new emitters spawn at the top
        // of the outer loop.
        channel_handle.abort();
        verdict_handle.abort();
        if needs_reattach {
            tracing::info!(
                session_id = %session.session_id,
                "daemon flushed our session row; re-attaching"
            );
        }
    }
}

enum HeartbeatOutcome {
    Ok,
    Unknown,
    Transient,
}

async fn attach_once(
    target: &Arc<ClientTarget>,
    info: &ClientInfo,
    session_label: &Option<SessionLabel>,
) -> Result<McpAttachResult> {
    let mut client: DaemonClient = target.connect().await?;
    let res = client
        .mcp_attach(McpAttachParams {
            client_name: info.name.clone(),
            client_version: info.version.clone(),
            session_label: session_label.clone(),
        })
        .await?;
    Ok(res)
}

async fn heartbeat_once(target: &Arc<ClientTarget>, session_id: &McpSessionId) -> HeartbeatOutcome {
    let mut client = match target.connect().await {
        Ok(c) => c,
        Err(e) => {
            tracing::debug!(error = %e, "heartbeat: connect failed");
            return HeartbeatOutcome::Transient;
        }
    };
    match client
        .mcp_heartbeat(McpHeartbeatParams {
            session_id: session_id.clone(),
        })
        .await
    {
        Ok(res) if res.recognised => HeartbeatOutcome::Ok,
        Ok(_) => HeartbeatOutcome::Unknown,
        Err(e) => {
            tracing::debug!(error = %e, "heartbeat call failed");
            HeartbeatOutcome::Transient
        }
    }
}

async fn detach_best_effort(target: &Arc<ClientTarget>, session_id: &McpSessionId) {
    if let Ok(mut c) = target.connect().await {
        let _ = c
            .mcp_detach(McpDetachParams {
                session_id: session_id.clone(),
            })
            .await;
    }
}

/// Spawn the channel emitter bound to one specific attach. The
/// emitter reads from the daemon's inbox + held-confirmation streams,
/// emits one notification per new item, and persists its cursor via
/// `mcp.cursor_advance` after each batch so the next attach (process
/// restart) resumes mid-stream.
fn spawn_channel_emitter(
    target: Arc<ClientTarget>,
    stdout: Arc<Mutex<Stdout>>,
    session: SessionAttach,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let source = PollingChannelSource::new_with_seed(
            ClientTarget::clone(&target),
            session.session_id.clone(),
            session.last_message_id,
            session.last_confirmation_id.clone(),
        );
        run_channel_emitter(stdout, source).await;
    })
}

/// Spawn the permission-verdict emitter bound to one specific attach.
fn spawn_verdict_emitter(
    target: Arc<ClientTarget>,
    stdout: Arc<Mutex<Stdout>>,
    session: SessionAttach,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        run_verdict_emitter(stdout, ClientTarget::clone(&target), session).await;
    })
}

/// Drive a [`ChannelSource`] until the emitter is aborted, mapping
/// each event to a `notifications/claude/channel` JSON-RPC
/// notification on stdout.
async fn run_channel_emitter<S: ChannelSource>(stdout: Arc<Mutex<Stdout>>, mut source: S) {
    loop {
        let batch = match source.next_batch().await {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(error = %e, "channel emitter stopping");
                return;
            }
        };
        for event in batch {
            let notif = event_to_channel_notification(&event);
            if let Err(e) = write_json(&stdout, notif).await {
                tracing::warn!(error = %e, "failed to write channel notification");
                return;
            }
        }
    }
}

/// Drive the permission-verdict cursor poller. For each `(allow|deny)`
/// resolution observed since the last poll, emit a
/// `notifications/claude/channel/permission` frame back to Claude Code,
/// then persist the advanced cursor via `mcp.cursor_advance`.
async fn run_verdict_emitter(
    stdout: Arc<Mutex<Stdout>>,
    target: ClientTarget,
    session: SessionAttach,
) {
    let mut ticker = tokio::time::interval(POLL_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut cursor = ResolvedCursor::new(session.session_id.clone(), session.last_resolved_seq);

    loop {
        ticker.tick().await;
        let batch = match cursor.poll(&target, 64).await {
            Ok(b) => b,
            Err(e) => {
                tracing::debug!(error = %e, "permission verdict poll failed; backing off");
                continue;
            }
        };
        for entry in batch {
            let behavior = match entry.outcome {
                PermissionOutcome::Allow => PermissionBehavior::Allow,
                PermissionOutcome::Deny => PermissionBehavior::Deny,
                // `Expired` is observable but never sent to Claude Code —
                // the host's local terminal dialog has its own timeout.
                PermissionOutcome::Expired => continue,
            };
            let notif = permission_verdict(&entry.request_id, behavior);
            if let Err(e) = write_json(&stdout, notif).await {
                tracing::warn!(error = %e, "failed to write permission verdict");
                return;
            }
        }
        // Persist the cursor so a restart with the same label
        // resumes here rather than at the start of the ring.
        if let Some(seq) = cursor.after_seq() {
            persist_cursor(&target, &session.session_id, None, None, Some(seq)).await;
        }
    }
}

/// Best-effort `mcp.cursor_advance`. Failures are logged but never
/// kill the emitter — at worst the next batch re-emits a few events
/// after restart, which is far better than dying.
pub(crate) async fn persist_cursor(
    target: &ClientTarget,
    session_id: &McpSessionId,
    last_message_id: Option<hermod_core::MessageId>,
    last_confirmation_id: Option<String>,
    last_resolved_seq: Option<u64>,
) {
    if last_message_id.is_none() && last_confirmation_id.is_none() && last_resolved_seq.is_none() {
        return;
    }
    let mut client = match target.connect().await {
        Ok(c) => c,
        Err(e) => {
            tracing::debug!(error = %e, "cursor_advance: connect failed");
            return;
        }
    };
    if let Err(e) = client
        .mcp_cursor_advance(McpCursorAdvanceParams {
            session_id: session_id.clone(),
            last_message_id,
            last_confirmation_id,
            last_resolved_seq,
        })
        .await
    {
        tracing::debug!(error = %e, "cursor_advance call failed");
    }
}

/// Map a [`ChannelEvent`] to the `notifications/claude/channel` frame
/// Claude Code expects. Match is exhaustive — adding a new variant in
/// `channel.rs` is a compile error here, not a silent drop.
///
/// ## AI-agent context discipline
///
/// The frame meta is intentionally slim. Operator-debugging fields
/// (`from_local_alias`, `from_peer_alias`) live in the IPC
/// `MessageView` for human surfaces; the channel-frame meta carries
/// only what the host model needs to act on the message:
///
///   * `kind`, `id`, `from`, `priority` — addressing
///   * `from_alias` — display name (effective)
///   * `from_alias_ambiguous` — set only when `true`; signals the
///     model that another agent shares the alias and the raw `from`
///     id (or `from_host`) must be used to disambiguate
///   * `from_host` — 8-char prefix, set only when `from_alias_ambiguous`
///   * `from_live` — whether a synchronous reply is realistic now
fn event_to_channel_notification(event: &ChannelEvent) -> Value {
    let (content, meta) = match event {
        ChannelEvent::DirectMessage {
            id,
            from,
            from_alias,
            from_alias_ambiguous,
            from_host_pubkey,
            from_live,
            priority,
            body,
        } => (
            body.clone(),
            base_meta(
                "direct",
                id.to_string(),
                from,
                from_alias.as_ref().map(|a| a.as_str()),
                *from_alias_ambiguous,
                from_host_pubkey.as_deref(),
                *from_live,
            )
            .merge_with(json!({
                "priority": priority.as_str(),
            })),
        ),
        ChannelEvent::HeldConfirmation {
            id,
            from,
            from_alias,
            from_alias_ambiguous,
            from_host_pubkey,
            from_live,
            intent,
            sensitivity,
            summary,
        } => (
            summary.clone(),
            base_meta(
                "confirmation",
                id.clone(),
                from,
                from_alias.as_ref().map(|a| a.as_str()),
                *from_alias_ambiguous,
                from_host_pubkey.as_deref(),
                *from_live,
            )
            .merge_with(json!({
                "intent": intent,
                "sensitivity": sensitivity,
            })),
        ),
        ChannelEvent::FileMessage {
            id,
            from,
            from_alias,
            from_alias_ambiguous,
            from_host_pubkey,
            from_live,
            priority,
            name,
            mime,
            size,
            hash_hex,
            location,
        } => {
            let body = format!("File: {name} ({} bytes, {mime})", size);
            // Best-effort path projection so Claude can `Read` the
            // payload directly when the daemon's BlobStore is the
            // local-fs backend. Cloud backends will leave this empty
            // and require a future `hermod blob fetch` flow.
            let path = location
                .strip_prefix("local-fs://")
                .map(|suffix| suffix.to_string())
                .unwrap_or_default();
            (
                body,
                base_meta(
                    "file",
                    id.to_string(),
                    from,
                    from_alias.as_ref().map(|a| a.as_str()),
                    *from_alias_ambiguous,
                    from_host_pubkey.as_deref(),
                    *from_live,
                )
                .merge_with(json!({
                    "priority": priority.as_str(),
                    "name": name,
                    "mime": mime,
                    "size": size.to_string(),
                    "hash": hash_hex,
                    "location": location,
                    "path_hint": path,
                })),
            )
        }
    };
    channel_notification(content, meta.0)
}

/// Lightweight wrapper around `serde_json::Value` for ergonomic
/// merge with extra kind-specific fields.
struct ChannelMeta(Value);

impl ChannelMeta {
    fn merge_with(mut self, extra: Value) -> Self {
        if let (Some(target), Some(source)) = (self.0.as_object_mut(), extra.as_object()) {
            for (k, v) in source {
                target.insert(k.clone(), v.clone());
            }
        }
        self
    }
}

/// Build the slim base meta common to every kind. Only includes
/// `from_alias_ambiguous` / `from_host` when they carry a real
/// signal — keeping the AI agent context unburdened with
/// always-`false` flags or always-`null` host strings.
fn base_meta(
    kind: &'static str,
    id: String,
    from: &hermod_core::AgentId,
    from_alias: Option<&str>,
    from_alias_ambiguous: bool,
    from_host_pubkey: Option<&str>,
    from_live: bool,
) -> ChannelMeta {
    let mut m = serde_json::Map::new();
    m.insert("kind".into(), Value::String(kind.into()));
    m.insert("id".into(), Value::String(id));
    m.insert("from".into(), Value::String(from.to_string()));
    if let Some(alias) = from_alias {
        m.insert("from_alias".into(), Value::String(alias.into()));
    }
    if from_alias_ambiguous {
        m.insert("from_alias_ambiguous".into(), Value::Bool(true));
        // Force-include `from_host` exactly when the alias is
        // ambiguous — that's when the model needs the
        // disambiguator.
        if let Some(hex) = from_host_pubkey {
            m.insert("from_host".into(), Value::String(host_short(hex)));
        }
    }
    m.insert("from_live".into(), Value::Bool(from_live));
    ChannelMeta(Value::Object(m))
}

/// 8-char prefix of a hex host pubkey — enough to disambiguate cross-host
/// alias collisions while keeping the channel-frame meta compact. Mirrors
/// the `to_human_prefix(8)` shape used elsewhere for fingerprints.
fn host_short(hex: &str) -> String {
    hex.chars().take(8).collect()
}
