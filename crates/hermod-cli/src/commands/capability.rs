use anyhow::Result;
use clap::Args;
use hermod_core::AgentId;
use hermod_protocol::ipc::methods::{
    CapabilityIssueParams, CapabilityListParams, CapabilityRevokeParams,
};

use std::str::FromStr;

use crate::client::ClientTarget;
use crate::error::invalid;

#[derive(Args, Debug)]
pub struct IssueArgs {
    /// Audience: agent_id of the bearer (use `none` for public bearer).
    #[arg(long)]
    pub audience: Option<String>,
    /// Scope (e.g. message:send, brief:read, presence:read).
    #[arg(long)]
    pub scope: String,
    /// Target resource (typically the issuer's own agent_id when restricting access to ourselves).
    #[arg(long)]
    pub target: Option<String>,
    /// Expiry duration: e.g. 30m, 24h, 7d. Default: 24h.
    #[arg(long, default_value = "24h")]
    pub expires: String,
}

#[derive(Args, Debug)]
pub struct RevokeArgs {
    /// Token id (jti) — printed by `capability issue`.
    pub token_id: String,
}

#[derive(Args, Debug, Default)]
pub struct ListArgs {
    /// Include rows with `revoked_at` set.
    #[arg(long)]
    pub include_revoked: bool,
    /// Include rows past `expires_at`.
    #[arg(long)]
    pub include_expired: bool,
    /// Page size (default 100, max 500).
    #[arg(long)]
    pub limit: Option<u32>,
    /// Which side of the capability table to query: `issued` (tokens
    /// minted by this daemon, default) or `received` (tokens granted
    /// to us by another agent, e.g. via `permission delegate`).
    #[arg(long, value_parser = ["issued", "received"], default_value = "issued")]
    pub direction: String,
}

pub async fn issue(args: IssueArgs, target: &ClientTarget) -> Result<()> {
    let audience = match args.audience.as_deref() {
        None | Some("none") => None,
        Some(s) => Some(AgentId::from_str(s).map_err(|e| invalid("audience agent_id", s, e))?),
    };
    let expires_in = parse_duration(&args.expires)?;
    let mut c = target.connect().await?;
    let r = c
        .capability_issue(CapabilityIssueParams {
            audience,
            scope: args.scope,
            target: args.target,
            expires_in_secs: Some(expires_in as u64),
        })
        .await?;
    let hex_token = hex::encode(r.token.as_bytes());
    println!(
        "{}",
        serde_json::json!({
            "id": r.id,
            "token_hex": hex_token,
        })
    );
    Ok(())
}

pub async fn revoke(args: RevokeArgs, target: &ClientTarget) -> Result<()> {
    let mut c = target.connect().await?;
    let r = c
        .capability_revoke(CapabilityRevokeParams {
            token_id: args.token_id,
        })
        .await?;
    println!("{}", serde_json::to_string_pretty(&r)?);
    Ok(())
}

pub async fn list(args: ListArgs, target: &ClientTarget) -> Result<()> {
    // clap's `value_parser` already restricts this to `issued|received`,
    // so the CapabilityDirection parse is infallible at runtime —
    // unwrap is a programmer-error backstop, not a user-facing path.
    let direction = hermod_core::CapabilityDirection::from_str(&args.direction)
        .expect("clap value_parser guarantees `issued|received`");
    let mut c = target.connect().await?;
    let r = c
        .capability_list(CapabilityListParams {
            include_revoked: args.include_revoked,
            include_expired: args.include_expired,
            limit: args.limit,
            after_id: None,
            direction: Some(direction),
        })
        .await?;
    println!("{}", serde_json::to_string_pretty(&r)?);
    Ok(())
}

fn parse_duration(s: &str) -> Result<u32> {
    if let Ok(n) = s.parse::<u32>() {
        return Ok(n);
    }
    let bytes = s.as_bytes();
    let (num_part, suffix) = bytes.split_at(bytes.len().saturating_sub(1));
    let n: u32 = std::str::from_utf8(num_part)?
        .parse()
        .map_err(|e| invalid("duration", s, e))?;
    let mult: u32 = match std::str::from_utf8(suffix)? {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        other => return Err(invalid("duration suffix", other, "expected s|m|h|d")),
    };
    Ok(n.saturating_mul(mult))
}
