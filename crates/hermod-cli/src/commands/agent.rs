use anyhow::Result;
use clap::Args;
use hermod_core::{AgentAlias, Endpoint, TrustLevel};
use hermod_protocol::ipc::methods::{AgentGetParams, AgentListParams, AgentRegisterParams};

use std::str::FromStr;

use crate::client::ClientTarget;

/// `agent list` returns only live agents — see [`AgentListParams`] for the
/// design rationale. There is no `--include-offline` flag.
#[derive(Args, Debug)]
pub struct ListArgs {}

#[derive(Args, Debug)]
pub struct GetArgs {
    /// Agent reference: `<agent_id>` or `@alias`. Returns regardless of
    /// whether the agent is currently live — used for inspection and
    /// audit-trail correlation.
    pub agent: String,
}

#[derive(Args, Debug)]
pub struct RegisterArgs {
    /// Hex-encoded ed25519 public key (64 hex chars).
    #[arg(long)]
    pub pubkey_hex: String,
    #[arg(long)]
    pub alias: Option<String>,
    #[arg(long)]
    pub endpoint: Option<String>,
    /// Trust level: self | verified | tofu | untrusted
    #[arg(long, default_value = "tofu")]
    pub trust: String,
}

pub async fn list(_args: ListArgs, target: &ClientTarget) -> Result<()> {
    let mut c = target.connect().await?;
    let r = c.agent_list(AgentListParams {}).await?;
    println!("{}", serde_json::to_string_pretty(&r)?);
    Ok(())
}

pub async fn get(args: GetArgs, target: &ClientTarget) -> Result<()> {
    let mut c = target.connect().await?;
    let r = c.agent_get(AgentGetParams { agent: args.agent }).await?;
    println!("{}", serde_json::to_string_pretty(&r)?);
    Ok(())
}

pub async fn register(args: RegisterArgs, target: &ClientTarget) -> Result<()> {
    let mut c = target.connect().await?;
    let alias = args
        .alias
        .as_deref()
        .map(AgentAlias::from_str)
        .transpose()?;
    let endpoint = args
        .endpoint
        .as_deref()
        .map(Endpoint::from_str)
        .transpose()?;
    let trust = TrustLevel::from_str(&args.trust)?;
    let r = c
        .agent_register(AgentRegisterParams {
            pubkey_hex: args.pubkey_hex,
            local_alias: alias,
            endpoint,
            trust_level: trust,
        })
        .await?;
    if matches!(
        r.alias_outcome,
        hermod_protocol::ipc::methods::AliasOutcomeView::LocalDropped
    ) {
        eprintln!(
            "warning: requested local_alias was already bound to another agent; \
             registered without alias."
        );
    }
    println!("{}", serde_json::to_string_pretty(&r)?);
    Ok(())
}
