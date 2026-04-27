use anyhow::Result;
use clap::Args;
use hermod_protocol::ipc::methods::{BriefPublishParams, BriefReadParams};

use crate::client::ClientTarget;

#[derive(Args, Debug)]
pub struct PublishArgs {
    /// Self-authored summary of recent activity.
    #[arg(long)]
    pub summary: String,
    /// Optional topic tag (e.g. "release-prep").
    #[arg(long)]
    pub topic: Option<String>,
    /// TTL in seconds (default 1 hour, 0 = no expiry).
    #[arg(long)]
    pub ttl_secs: Option<u32>,
}

#[derive(Args, Debug)]
pub struct ReadArgs {
    /// agent_id or @alias.
    pub agent: String,
    /// Optional topic to filter on.
    #[arg(long)]
    pub topic: Option<String>,
}

pub async fn publish(args: PublishArgs, target: &ClientTarget) -> Result<()> {
    let mut c = target.connect().await?;
    let r = c
        .brief_publish(BriefPublishParams {
            summary: args.summary,
            topic: args.topic,
            ttl_secs: args.ttl_secs,
        })
        .await?;
    println!("{}", serde_json::to_string_pretty(&r)?);
    Ok(())
}

pub async fn read(args: ReadArgs, target: &ClientTarget) -> Result<()> {
    let mut c = target.connect().await?;
    let r = c
        .brief_read(BriefReadParams {
            agent: args.agent,
            topic: args.topic,
        })
        .await?;
    println!("{}", serde_json::to_string_pretty(&r)?);
    Ok(())
}
