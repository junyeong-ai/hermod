//! `hermod inbox …` — recipient-side inbox surface.
//!
//! Two operator paths:
//!
//!   * `inbox list [--disposition push|silent|all] [--limit N] [--priority-min …]`
//!     — show the operator's inbox. `--disposition` defaults to
//!     `all` so a fresh terminal sees both push and silent rows in
//!     one human listing. The MCP channel poller passes `push` so
//!     silent rows never reach AI-agent context.
//!   * `inbox promote <id>` — flip a silent row to push so the
//!     channel emitter surfaces it on the next poll. Exit non-zero
//!     when the id is unknown / already pushed / owned by another
//!     agent — scripts notice stale ids without parsing JSON.

use anyhow::{Result, bail};
use clap::Args;
use hermod_core::{MessageDisposition, MessageId, MessagePriority};
use hermod_protocol::ipc::methods::{InboxListParams, InboxPromoteParams};
use std::str::FromStr;

use crate::client::ClientTarget;
use crate::error::from_underlying;

#[derive(Args, Debug)]
pub struct ListArgs {
    #[arg(long)]
    pub limit: Option<u32>,
    /// Minimum priority (low|normal|high|urgent).
    #[arg(long)]
    pub priority_min: Option<String>,
    /// Disposition filter: `push`, `silent`, or `all` (default).
    /// `all` surfaces both classes — the operator triages silent
    /// rows that the routing engine held back from AI-agent context.
    #[arg(long, default_value = "all")]
    pub disposition: DispositionFilter,
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum DispositionFilter {
    All,
    Push,
    Silent,
}

#[derive(Args, Debug)]
pub struct PromoteArgs {
    /// Message id (ULID).
    pub id: String,
}

pub async fn list(args: ListArgs, target: &ClientTarget) -> Result<()> {
    let mut c = target.connect().await?;
    let priority_min = args
        .priority_min
        .as_deref()
        .map(MessagePriority::from_str)
        .transpose()
        .map_err(|e| from_underlying("priority_min", e))?;
    let dispositions = match args.disposition {
        DispositionFilter::All => None,
        DispositionFilter::Push => Some(vec![MessageDisposition::Push]),
        DispositionFilter::Silent => Some(vec![MessageDisposition::Silent]),
    };
    let r = c
        .inbox_list(InboxListParams {
            limit: args.limit,
            priority_min,
            statuses: None,
            after_id: None,
            dispositions,
        })
        .await?;
    println!("{}", serde_json::to_string_pretty(&r)?);
    Ok(())
}

pub async fn promote(args: PromoteArgs, target: &ClientTarget) -> Result<()> {
    let id = MessageId::from_str(&args.id).map_err(|e| from_underlying("id", e))?;
    let mut c = target.connect().await?;
    let r = c.inbox_promote(InboxPromoteParams { id }).await?;
    println!("{}", serde_json::to_string_pretty(&r)?);
    if !r.promoted {
        bail!(
            "no silent inbox row matching id `{}` (already pushed, missing, or owned by another agent)",
            args.id
        );
    }
    Ok(())
}
