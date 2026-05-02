//! Cross-platform OS-notification dispatcher.
//!
//! Runs alongside the MCP channel + verdict emitters. Each tick:
//!
//!   1. `notification.claim` pulls a batch of pending rows for the
//!      caller agent.
//!   2. For each row, the platform notifier shells out to the
//!      operator's desktop-notification surface (osascript on macOS,
//!      notify-send on XDG Linux, PowerShell on Windows). Failures
//!      are logged but never bubble — a failed dispatcher must not
//!      stall the entire MCP server.
//!   3. Successful dispatch ⇒ `notification.complete`. Terminal
//!      failure ⇒ `notification.fail` with the platform error.
//!
//! The notifier is kept narrowly platform-aware: each backend lives
//! behind a `cfg(target_os)` so the binary on Linux can't accidentally
//! shell out to `osascript`. The `null` backend is always available
//! (used by tests; surfaces only `tracing::info`).

use anyhow::{Context, Result};
use hermod_core::MessageId;
use hermod_protocol::ipc::methods::{
    InboxListParams, NotificationClaimParams, NotificationCompleteParams, NotificationFailParams,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::client::ClientTarget;

/// Poll cadence — short enough to keep notification latency near
/// human-perceptible, long enough to not hammer the daemon at idle.
const POLL_INTERVAL: Duration = Duration::from_millis(750);

/// Rows per claim. Higher absorbs bursts; lower smooths latency on
/// a slow notifier.
const CLAIM_LIMIT: u32 = 16;

/// Spawn the notification dispatcher as a tokio task. Returns the
/// shutdown sender + the handle so the MCP server can abort it on
/// stdin EOF.
pub(crate) fn spawn(
    target: Arc<ClientTarget>,
    worker_id: String,
) -> (oneshot::Sender<()>, JoinHandle<()>) {
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
    let handle = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(POLL_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                _ = &mut shutdown_rx => return,
                _ = ticker.tick() => {
                    if let Err(e) = drain_once(&target, &worker_id).await {
                        tracing::debug!(error = %e, "notification dispatcher: drain failed");
                    }
                }
            }
        }
    });
    (shutdown_tx, handle)
}

async fn drain_once(target: &ClientTarget, worker_id: &str) -> Result<()> {
    let mut client = target.connect().await?;
    let claim = client
        .notification_claim(NotificationClaimParams {
            worker_id: worker_id.to_string(),
            limit: Some(CLAIM_LIMIT),
        })
        .await
        .context("notification.claim")?;
    if claim.notifications.is_empty() {
        return Ok(());
    }
    for row in claim.notifications {
        // Resolve the source message body so the notifier can render
        // a meaningful title/body. Best-effort — a missing or
        // already-acked row falls back to a generic "new message".
        let title = "Hermod".to_string();
        let body = fetch_message_text(&mut client, &row.message_id)
            .await
            .unwrap_or_else(|| "new message".to_string());
        match notify(&title, &body, row.sound.as_deref()).await {
            Ok(()) => {
                let _ = client
                    .notification_complete(NotificationCompleteParams {
                        id: row.id.clone(),
                        claim_token: row.claim_token.clone(),
                    })
                    .await;
            }
            Err(e) => {
                let _ = client
                    .notification_fail(NotificationFailParams {
                        id: row.id.clone(),
                        claim_token: row.claim_token.clone(),
                        reason: e.to_string(),
                    })
                    .await;
            }
        }
    }
    Ok(())
}

async fn fetch_message_text(
    client: &mut crate::client::DaemonClient,
    id: &MessageId,
) -> Option<String> {
    let r = client
        .inbox_list(InboxListParams {
            limit: Some(50),
            ..Default::default()
        })
        .await
        .ok()?;
    let msg = r.messages.into_iter().find(|m| m.id == *id)?;
    match msg.body {
        hermod_core::MessageBody::Direct { text } => Some(text),
        hermod_core::MessageBody::File { name, .. } => Some(format!("File: {name}")),
        hermod_core::MessageBody::Brief { summary, .. } => Some(summary),
        _ => None,
    }
}

#[cfg(target_os = "macos")]
async fn notify(title: &str, body: &str, sound: Option<&str>) -> Result<()> {
    let mut script = format!(
        "display notification \"{}\" with title \"{}\"",
        escape(body),
        escape(title)
    );
    if let Some(s) = sound {
        script.push_str(&format!(" sound name \"{}\"", escape(s)));
    }
    let status = tokio::process::Command::new("osascript")
        .arg("-e")
        .arg(&script)
        .kill_on_drop(true)
        .status()
        .await
        .context("osascript")?;
    if !status.success() {
        anyhow::bail!("osascript exited with {status}");
    }
    Ok(())
}

#[cfg(all(unix, not(target_os = "macos")))]
async fn notify(title: &str, body: &str, _sound: Option<&str>) -> Result<()> {
    let status = tokio::process::Command::new("notify-send")
        .arg(title)
        .arg(body)
        .kill_on_drop(true)
        .status()
        .await
        .context("notify-send")?;
    if !status.success() {
        anyhow::bail!("notify-send exited with {status}");
    }
    Ok(())
}

#[cfg(target_os = "windows")]
async fn notify(title: &str, body: &str, _sound: Option<&str>) -> Result<()> {
    let script = format!(
        r#"[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType=WindowsRuntime] | Out-Null; \
           $template = [Windows.UI.Notifications.ToastTemplateType]::ToastText02; \
           $xml = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent($template); \
           $xml.GetElementsByTagName("text").Item(0).AppendChild($xml.CreateTextNode("{title}")) | Out-Null; \
           $xml.GetElementsByTagName("text").Item(1).AppendChild($xml.CreateTextNode("{body}")) | Out-Null; \
           $toast = New-Object Windows.UI.Notifications.ToastNotification($xml); \
           [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("Hermod").Show($toast)"#,
        title = title.replace('"', "'"),
        body = body.replace('"', "'"),
    );
    let status = tokio::process::Command::new("powershell")
        .arg("-NoProfile")
        .arg("-Command")
        .arg(&script)
        .kill_on_drop(true)
        .status()
        .await
        .context("powershell toast")?;
    if !status.success() {
        anyhow::bail!("powershell exited with {status}");
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(not(any(target_os = "macos", target_os = "windows", unix)))]
async fn notify(title: &str, body: &str, _sound: Option<&str>) -> Result<()> {
    tracing::info!(title = %title, body = %body, "notification (no platform notifier)");
    Ok(())
}
