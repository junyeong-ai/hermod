use anyhow::Result;
use clap::Args;
use hermod_core::Timestamp;
use hermod_protocol::ipc::methods::{
    AuditArchiveNowParams, AuditArchivesListParams, AuditQueryParams, AuditVerifyArchiveParams,
};

use crate::client::ClientTarget;

#[derive(Args, Debug)]
pub struct ArchiveNowArgs {
    /// Override `policy.audit_retention_secs`. Forms: `30d`, `2h`, etc.
    #[arg(long = "older-than")]
    pub older_than: Option<String>,
}

#[derive(Args, Debug)]
pub struct ArchivesListArgs {
    #[arg(long)]
    pub limit: Option<u32>,
}

#[derive(Args, Debug)]
pub struct VerifyArchiveArgs {
    /// `epoch_start` of the archive (RFC3339, matches `archives_list`).
    pub epoch_start: String,
}

#[derive(Args, Debug)]
pub struct QueryArgs {
    /// Time window. Forms: 1h, 30m, 2d. Default: 24h.
    #[arg(long)]
    pub since: Option<String>,
    /// Filter by actor (agent_id or @alias).
    #[arg(long)]
    pub actor: Option<String>,
    /// Filter by action name (e.g. `brief.publish`).
    #[arg(long)]
    pub action: Option<String>,
    /// Maximum entries.
    #[arg(long)]
    pub limit: Option<u32>,
}

pub async fn verify(target: &ClientTarget) -> Result<()> {
    let mut c = target.connect().await?;
    let r = c.audit_verify().await?;
    println!("{}", serde_json::to_string_pretty(&r)?);
    Ok(())
}

pub async fn archive_now(args: ArchiveNowArgs, target: &ClientTarget) -> Result<()> {
    let older_than_secs = match args.older_than.as_deref() {
        Some(s) => Some(parse_duration(s)? as u64),
        None => None,
    };
    let mut c = target.connect().await?;
    let r = c
        .audit_archive_now(AuditArchiveNowParams { older_than_secs })
        .await?;
    println!("{}", serde_json::to_string_pretty(&r)?);
    Ok(())
}

pub async fn archives_list(args: ArchivesListArgs, target: &ClientTarget) -> Result<()> {
    let mut c = target.connect().await?;
    let r = c
        .audit_archives_list(AuditArchivesListParams { limit: args.limit })
        .await?;
    println!("{}", serde_json::to_string_pretty(&r)?);
    Ok(())
}

pub async fn verify_archive(args: VerifyArchiveArgs, target: &ClientTarget) -> Result<()> {
    let epoch_start: Timestamp = serde_json::from_str(&format!("\"{}\"", args.epoch_start))
        .map_err(|e| crate::error::invalid("epoch_start", &args.epoch_start, e))?;
    let mut c = target.connect().await?;
    let r = c
        .audit_verify_archive(AuditVerifyArchiveParams { epoch_start })
        .await?;
    println!("{}", serde_json::to_string_pretty(&r)?);
    Ok(())
}

pub async fn query(args: QueryArgs, target: &ClientTarget) -> Result<()> {
    let since_secs = match args.since.as_deref() {
        Some(s) => Some(parse_duration(s)?),
        None => Some(24 * 3600),
    };
    let mut c = target.connect().await?;
    let r = c
        .audit_query(AuditQueryParams {
            actor: args.actor,
            action: args.action,
            since_secs,
            limit: args.limit,
        })
        .await?;
    println!("{}", serde_json::to_string_pretty(&r)?);
    Ok(())
}

fn parse_duration(s: &str) -> Result<i64> {
    if let Ok(n) = s.parse::<i64>() {
        return Ok(n);
    }
    let bytes = s.as_bytes();
    let (num_part, suffix) = bytes.split_at(bytes.len().saturating_sub(1));
    let n: i64 = std::str::from_utf8(num_part)?
        .parse()
        .map_err(|e| crate::error::invalid("duration", s, e))?;
    let mult: i64 = match std::str::from_utf8(suffix)? {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        other => {
            return Err(crate::error::invalid(
                "duration suffix",
                other,
                "expected s|m|h|d",
            ));
        }
    };
    Ok(n.saturating_mul(mult))
}
