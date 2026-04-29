//! MCP session lifecycle: attach → heartbeat → detach, plus the two
//! background emitters (channel events and permission verdicts).
//!
//! Self-healing: if the daemon flushes our session row (e.g. a restart
//! happened), the supervisor re-attaches automatically and the emitters
//! keep running. Operators don't need to bounce the MCP server when the
//! daemon goes down — just restart the daemon and the bridge resumes.

use anyhow::Result;
use hermod_protocol::ipc::methods::{
    McpAttachParams, McpAttachResult, McpDetachParams, McpHeartbeatParams, PermissionBehavior,
    PermissionOutcome,
};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::Stdout;
use tokio::sync::{Mutex, oneshot};
use tokio::task::JoinHandle;

use super::channel::{ChannelEvent, ChannelSource, POLL_INTERVAL, PollingChannelSource};
use super::notification::{channel as channel_notification, permission_verdict};
use super::permission::ResolvedCursor;
use super::{ClientInfo, DETACH_TIMEOUT, write_json};
use crate::client::{ClientTarget, DaemonClient};

/// Bundle of session state set up after the MCP `initialize` handshake.
pub(crate) struct Session {
    shutdown_tx: oneshot::Sender<()>,
    supervisor: JoinHandle<()>,
    emitter: JoinHandle<()>,
    verdict_emitter: JoinHandle<()>,
}

impl Session {
    pub(crate) async fn start(
        target: Arc<ClientTarget>,
        stdout: Arc<Mutex<Stdout>>,
        client_info: Option<ClientInfo>,
    ) -> Self {
        let info = client_info.unwrap_or_default();
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let supervisor = tokio::spawn(supervisor_loop(target.clone(), info, shutdown_rx));

        let emitter = {
            let target_for_emitter = ClientTarget::clone(&target);
            let stdout_for_emitter = stdout.clone();
            tokio::spawn(async move {
                let source = PollingChannelSource::new(target_for_emitter);
                run_channel_emitter(stdout_for_emitter, source).await;
            })
        };

        let verdict_emitter = {
            let target_for_verdicts = ClientTarget::clone(&target);
            tokio::spawn(async move {
                run_verdict_emitter(stdout, target_for_verdicts).await;
            })
        };

        Session {
            shutdown_tx,
            supervisor,
            emitter,
            verdict_emitter,
        }
    }

    pub(crate) async fn shutdown(self) {
        // Signal the supervisor to detach + exit. If it doesn't return
        // within DETACH_TIMEOUT, we abort and leave cleanup to the
        // daemon's session TTL.
        let _ = self.shutdown_tx.send(());
        let _ = tokio::time::timeout(DETACH_TIMEOUT, self.supervisor).await;
        self.emitter.abort();
        self.verdict_emitter.abort();
    }
}

async fn supervisor_loop(
    target: Arc<ClientTarget>,
    info: ClientInfo,
    mut shutdown_rx: oneshot::Receiver<()>,
) {
    /// Backoff between failed (re-)attach attempts. Short enough that a
    /// daemon restart is recovered well within the SESSION_TTL window;
    /// long enough not to thrash a permanently-down daemon.
    const ATTACH_RETRY: Duration = Duration::from_secs(5);

    loop {
        let attach = tokio::select! {
            biased;
            _ = &mut shutdown_rx => return,
            res = attach_once(&target, &info) => res,
        };
        let (session_id, interval) = match attach {
            Ok(r) => (
                r.session_id,
                Duration::from_secs(r.heartbeat_interval_secs.max(1) as u64),
            ),
            Err(e) => {
                tracing::debug!(error = %e, "session attach failed; retrying");
                tokio::select! {
                    biased;
                    _ = &mut shutdown_rx => return,
                    _ = tokio::time::sleep(ATTACH_RETRY) => continue,
                }
            }
        };

        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // The attach call itself just bumped last_heartbeat_at; skip the
        // immediate-fire tick so the first real heartbeat is spaced out.
        ticker.tick().await;
        let needs_reattach = loop {
            tokio::select! {
                biased;
                _ = &mut shutdown_rx => {
                    detach_best_effort(&target, &session_id).await;
                    return;
                }
                _ = ticker.tick() => {
                    match heartbeat_once(&target, &session_id).await {
                        HeartbeatOutcome::Ok => continue,
                        HeartbeatOutcome::Unknown => break true,
                        HeartbeatOutcome::Transient => continue,
                    }
                }
            }
        };
        if needs_reattach {
            tracing::info!(
                session_id = %session_id,
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

async fn attach_once(target: &Arc<ClientTarget>, info: &ClientInfo) -> Result<McpAttachResult> {
    let mut client: DaemonClient = target.connect().await?;
    let res = client
        .mcp_attach(McpAttachParams {
            client_name: info.name.clone(),
            client_version: info.version.clone(),
        })
        .await?;
    Ok(res)
}

async fn heartbeat_once(target: &Arc<ClientTarget>, session_id: &str) -> HeartbeatOutcome {
    let mut client = match target.connect().await {
        Ok(c) => c,
        Err(e) => {
            tracing::debug!(error = %e, "heartbeat: connect failed");
            return HeartbeatOutcome::Transient;
        }
    };
    match client
        .mcp_heartbeat(McpHeartbeatParams {
            session_id: session_id.to_string(),
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

async fn detach_best_effort(target: &Arc<ClientTarget>, session_id: &str) {
    if let Ok(mut c) = target.connect().await {
        let _ = c
            .mcp_detach(McpDetachParams {
                session_id: session_id.to_string(),
            })
            .await;
    }
}

/// Drive a [`ChannelSource`] until shutdown, mapping each event to a
/// `notifications/claude/channel` JSON-RPC notification on stdout.
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
/// `notifications/claude/channel/permission` frame back to Claude Code.
async fn run_verdict_emitter(stdout: Arc<Mutex<Stdout>>, target: ClientTarget) {
    let mut ticker = tokio::time::interval(POLL_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut cursor = ResolvedCursor::new();

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
    }
}

/// Map a [`ChannelEvent`] to the `notifications/claude/channel` frame
/// Claude Code expects. Match is exhaustive — adding a new variant in
/// `channel.rs` is a compile error here, not a silent drop.
fn event_to_channel_notification(event: &ChannelEvent) -> Value {
    let (content, meta) = match event {
        ChannelEvent::DirectMessage {
            id,
            from,
            from_local_alias,
            from_peer_alias,
            from_alias,
            from_host_pubkey,
            from_live,
            priority,
            body,
        } => (
            body.clone(),
            json!({
                "kind": "direct",
                "id": id.to_string(),
                "from": from.to_string(),
                "from_local_alias": from_local_alias.as_ref().map(|a| a.as_str()),
                "from_peer_alias": from_peer_alias.as_ref().map(|a| a.as_str()),
                "from_alias": from_alias.as_ref().map(|a| a.as_str()),
                "from_host": from_host_pubkey.as_deref().map(host_short),
                "from_live": from_live,
                "priority": priority.as_str(),
            }),
        ),
        ChannelEvent::HeldConfirmation {
            id,
            from,
            from_local_alias,
            from_peer_alias,
            from_alias,
            from_host_pubkey,
            from_live,
            intent,
            sensitivity,
            summary,
        } => (
            summary.clone(),
            json!({
                "kind": "confirmation",
                "id": id,
                "from": from.to_string(),
                "from_local_alias": from_local_alias.as_ref().map(|a| a.as_str()),
                "from_peer_alias": from_peer_alias.as_ref().map(|a| a.as_str()),
                "from_alias": from_alias.as_ref().map(|a| a.as_str()),
                "from_host": from_host_pubkey.as_deref().map(host_short),
                "from_live": from_live,
                "intent": intent,
                "sensitivity": sensitivity,
            }),
        ),
        ChannelEvent::FileMessage {
            id,
            from,
            from_local_alias,
            from_peer_alias,
            from_alias,
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
                .map(|suffix| {
                    // The default LocalFs root is `$HERMOD_HOME/blob-store`;
                    // operators can override via `[blob] dsn`. We surface
                    // the location string verbatim and let Claude resolve
                    // via the operator's filesystem.
                    suffix.to_string()
                })
                .unwrap_or_default();
            (
                body,
                json!({
                    "kind": "file",
                    "id": id.to_string(),
                    "from": from.to_string(),
                    "from_local_alias": from_local_alias.as_ref().map(|a| a.as_str()),
                    "from_peer_alias": from_peer_alias.as_ref().map(|a| a.as_str()),
                    "from_alias": from_alias.as_ref().map(|a| a.as_str()),
                    "from_host": from_host_pubkey.as_deref().map(host_short),
                    "from_live": from_live,
                    "priority": priority.as_str(),
                    "name": name,
                    "mime": mime,
                    "size": size.to_string(),
                    "hash": hash_hex,
                    "location": location,
                    "path_hint": path,
                }),
            )
        }
    };
    channel_notification(content, meta)
}

/// 8-char prefix of a hex host pubkey — enough to disambiguate cross-host
/// alias collisions while keeping the channel-frame meta compact. Mirrors
/// the `to_human_prefix(8)` shape used elsewhere for fingerprints.
fn host_short(hex: &str) -> String {
    hex.chars().take(8).collect()
}
