//! `hermod notification …` — operator surface over the OS-notification queue.
//!
//! Three commands:
//!
//!   * `notification list [--status …]` — inspect what the
//!     dispatcher has done / is doing / failed on. Newest first.
//!   * `notification dismiss <id>` — operator-driven dismissal.
//!     Exit non-zero on no-op so scripts notice stale ids.
//!   * `notification purge [--older-than-secs N]` — reap terminal
//!     rows older than N seconds (default = the daemon's
//!     `[routing.notification] retention_days`).

use anyhow::{Result, bail};
use clap::Args;
use hermod_core::NotificationStatus;
use hermod_protocol::ipc::methods::{
    NotificationDismissParams, NotificationListParams, NotificationPurgeParams,
};

use crate::client::ClientTarget;

#[derive(Args, Debug)]
pub struct ListArgs {
    /// Filter by status (repeatable). Omit to see all.
    #[arg(long, value_enum)]
    pub status: Vec<NotificationStatusArg>,
    #[arg(long)]
    pub limit: Option<u32>,
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum NotificationStatusArg {
    Pending,
    Dispatched,
    Failed,
    Dismissed,
}

impl From<NotificationStatusArg> for NotificationStatus {
    fn from(s: NotificationStatusArg) -> Self {
        match s {
            NotificationStatusArg::Pending => NotificationStatus::Pending,
            NotificationStatusArg::Dispatched => NotificationStatus::Dispatched,
            NotificationStatusArg::Failed => NotificationStatus::Failed,
            NotificationStatusArg::Dismissed => NotificationStatus::Dismissed,
        }
    }
}

#[derive(Args, Debug)]
pub struct DismissArgs {
    /// Notification id (ULID minted by the daemon at enqueue).
    pub id: String,
}

#[derive(Args, Debug)]
pub struct PurgeArgs {
    /// Override the daemon's retention window. Omit for the default.
    #[arg(long)]
    pub older_than_secs: Option<u32>,
}

pub async fn list(args: ListArgs, target: &ClientTarget) -> Result<()> {
    let mut c = target.connect().await?;
    let statuses = if args.status.is_empty() {
        None
    } else {
        Some(args.status.iter().copied().map(Into::into).collect())
    };
    let r = c
        .notification_list(NotificationListParams {
            statuses,
            limit: args.limit,
        })
        .await?;
    println!("{}", serde_json::to_string_pretty(&r)?);
    Ok(())
}

pub async fn dismiss(args: DismissArgs, target: &ClientTarget) -> Result<()> {
    let mut c = target.connect().await?;
    let r = c
        .notification_dismiss(NotificationDismissParams {
            id: args.id.clone(),
        })
        .await?;
    println!("{}", serde_json::to_string_pretty(&r)?);
    if !r.matched {
        bail!(
            "no live notification matching id `{}` (already terminal, missing, or owned by another agent)",
            args.id
        );
    }
    Ok(())
}

pub async fn purge(args: PurgeArgs, target: &ClientTarget) -> Result<()> {
    let mut c = target.connect().await?;
    let r = c
        .notification_purge(NotificationPurgeParams {
            older_than_secs: args.older_than_secs,
        })
        .await?;
    println!("{}", serde_json::to_string_pretty(&r)?);
    Ok(())
}
