//! `hermod permission …` — operator surface for the permission relay.
//!
//! Two paths into this module:
//!
//!   * `permission list` — show what the daemon currently has open. The
//!     operator might use this to triage what's waiting after stepping
//!     away from the terminal.
//!   * `permission allow <id>` / `permission deny <id>` — apply a verdict
//!     to an open prompt. The verdict short id (5 lowercase letters
//!     drawn from `[a-km-z]`) is the one the host's Channels prompt told
//!     the operator to type.
//!
//! These commands are deliberately read/write-narrow. Federation-driven
//! approval (a remote peer answering on the operator's behalf) layers on
//! top of `permission.respond` without changes here.

use anyhow::{Context, Result, bail};
use clap::Args;
use hermod_core::{AgentAddress, AgentAlias, AgentId};
use hermod_protocol::ipc::methods::{
    CapabilityDeliverParams, PermissionBehavior, PermissionListParams, PermissionRespondParams,
};
use std::str::FromStr;

use crate::client::ClientTarget;
use crate::error::{invalid, not_found};

#[derive(Args, Debug)]
pub struct ListArgs {
    /// Cap the number of pending requests returned (oldest first).
    #[arg(long)]
    pub limit: Option<u32>,
}

#[derive(Args, Debug)]
pub struct DecideArgs {
    /// Permission request id — 5 lowercase letters from `[a-km-z]`.
    pub id: String,
}

pub async fn list(args: ListArgs, target: &ClientTarget) -> Result<()> {
    let mut c = target.connect().await?;
    let r = c
        .permission_list(PermissionListParams {
            limit: args.limit,
            // Operator CLI is a global view — no session filter,
            // surfaces every prompt for the caller agent.
            session_id: None,
        })
        .await?;
    println!("{}", serde_json::to_string_pretty(&r)?);
    Ok(())
}

pub async fn allow(args: DecideArgs, target: &ClientTarget) -> Result<()> {
    decide(args, PermissionBehavior::Allow, target).await
}

pub async fn deny(args: DecideArgs, target: &ClientTarget) -> Result<()> {
    decide(args, PermissionBehavior::Deny, target).await
}

/// Issue a `permission:respond` capability and ship it to the
/// target agent in one step. Convenience wrapper around
/// `capability.deliver` for the common case of "I want this agent
/// to be able to answer my permission prompts".
#[derive(Args, Debug)]
pub struct DelegateArgs {
    /// Audience: `<agent_id>` or `@alias`.
    pub agent: String,
    /// Restrict the delegation to a specific tool name (e.g. `Bash`).
    /// Omit to delegate for every tool.
    #[arg(long)]
    pub tool: Option<String>,
    /// Expiry duration. Forms: `30d`, `2h`, `15m`. Omit for non-expiring.
    #[arg(long)]
    pub ttl: Option<String>,
}

pub async fn delegate(args: DelegateArgs, target: &ClientTarget) -> Result<()> {
    let mut c = target.connect().await?;
    let audience = resolve_to(&args.agent, &mut c).await?;
    let exp_secs = args.ttl.as_deref().map(parse_duration).transpose()?;
    let r = c
        .capability_deliver(CapabilityDeliverParams {
            audience,
            scope: "permission:respond".into(),
            scope_target: args.tool,
            exp_secs,
        })
        .await?;
    println!("{}", serde_json::to_string_pretty(&r)?);
    Ok(())
}

async fn resolve_to(
    reference: &str,
    client: &mut crate::client::DaemonClient,
) -> Result<AgentAddress> {
    if let Some(alias_raw) = reference.strip_prefix('@') {
        let alias = AgentAlias::from_str(alias_raw).map_err(|e| invalid("alias", alias_raw, e))?;
        let desc = client
            .agent_get(hermod_protocol::ipc::methods::AgentGetParams {
                agent: alias.to_string(),
            })
            .await
            .map_err(|_| not_found("agent", alias.to_string(), "directory"))?;
        return Ok(match desc.endpoint {
            Some(ep) => AgentAddress::with_endpoint(desc.id, ep),
            None => AgentAddress::local(desc.id),
        });
    }
    let id = AgentId::from_str(reference).map_err(|e| invalid("agent_id", reference, e))?;
    match client
        .agent_get(hermod_protocol::ipc::methods::AgentGetParams {
            agent: id.to_string(),
        })
        .await
    {
        Ok(desc) => Ok(match desc.endpoint {
            Some(ep) => AgentAddress::with_endpoint(desc.id, ep),
            None => AgentAddress::local(desc.id),
        }),
        Err(_) => Ok(AgentAddress::local(id)),
    }
}

fn parse_duration(s: &str) -> Result<i64> {
    if let Ok(n) = s.parse::<i64>() {
        return Ok(n);
    }
    let bytes = s.as_bytes();
    let (num_part, suffix) = bytes.split_at(bytes.len().saturating_sub(1));
    let n: i64 = std::str::from_utf8(num_part)
        .context("duration prefix")?
        .parse()
        .map_err(|e| invalid("duration", s, e))?;
    let mult: i64 = match std::str::from_utf8(suffix).context("duration suffix")? {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        other => bail!("unknown duration suffix `{other}` (use s|m|h|d)"),
    };
    Ok(n.saturating_mul(mult))
}

async fn decide(
    args: DecideArgs,
    behavior: PermissionBehavior,
    target: &ClientTarget,
) -> Result<()> {
    let id = args.id;
    let mut c = target.connect().await?;
    let r = c
        .permission_respond(PermissionRespondParams {
            request_id: id.clone(),
            behavior,
        })
        .await?;
    println!("{}", serde_json::to_string_pretty(&r)?);
    // Surface "no live request" as a non-zero exit so operator scripts
    // and `hermod-CI` style runners can react. The verdict was a no-op
    // — typically because the host's local dialog already answered, the
    // request expired, or the id is wrong.
    if !r.matched {
        bail!(
            "no open permission request matching id `{id}` (already answered, expired, or wrong id)"
        );
    }
    Ok(())
}
