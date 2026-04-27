use anyhow::Result;
use clap::Args;
use hermod_core::PresenceStatus;
use hermod_protocol::ipc::methods::{
    PresenceClearManualParams, PresenceGetParams, PresenceSetManualParams,
};

use std::str::FromStr;

use crate::client::ClientTarget;
use crate::error::invalid;

#[derive(Args, Debug)]
pub struct SetArgs {
    /// Status: online | idle | busy | offline.
    pub status: String,
    /// Optional TTL in seconds. Omit for a permanent override (until next set).
    /// Useful for short statuses like `busy --ttl-secs 1800`.
    #[arg(long)]
    pub ttl_secs: Option<u32>,
}

#[derive(Args, Debug)]
pub struct GetArgs {
    /// agent_id or @alias.
    pub agent: String,
}

pub async fn set(args: SetArgs, target: &ClientTarget) -> Result<()> {
    let status =
        PresenceStatus::from_str(&args.status).map_err(|e| invalid("status", &args.status, e))?;
    let mut c = target.connect().await?;
    let r = c
        .presence_set_manual(PresenceSetManualParams {
            status,
            ttl_secs: args.ttl_secs,
        })
        .await?;
    println!("{}", serde_json::to_string_pretty(&r)?);
    Ok(())
}

pub async fn get(args: GetArgs, target: &ClientTarget) -> Result<()> {
    let mut c = target.connect().await?;
    let r = c
        .presence_get(PresenceGetParams { agent: args.agent })
        .await?;
    println!("{}", serde_json::to_string_pretty(&r)?);
    Ok(())
}

pub async fn clear(target: &ClientTarget) -> Result<()> {
    let mut c = target.connect().await?;
    let r = c
        .presence_clear_manual(PresenceClearManualParams {})
        .await?;
    println!("{}", serde_json::to_string_pretty(&r)?);
    Ok(())
}
