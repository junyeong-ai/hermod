use anyhow::Result;
use clap::Args;
use hermod_protocol::ipc::methods::{
    ChannelAdoptParams, ChannelAdvertiseParams, ChannelCreateParams, ChannelDeleteParams,
    ChannelDiscoverParams, ChannelHistoryParams, ChannelListParams, ChannelMuteParams,
};

use crate::client::ClientTarget;
use crate::commands::MuteState;

#[derive(Args, Debug)]
pub struct CreateArgs {
    /// Workspace id (hex) the channel lives in.
    #[arg(long)]
    pub workspace_id: String,
    /// Channel name within the workspace (1..=64 bytes).
    #[arg(long)]
    pub name: String,
}

#[derive(Args, Debug)]
pub struct ListArgs {
    /// Workspace id (hex).
    pub workspace_id: String,
}

#[derive(Args, Debug)]
pub struct HistoryArgs {
    /// Channel id (hex).
    pub channel_id: String,
    #[arg(long)]
    pub limit: Option<u32>,
}

#[derive(Args, Debug)]
pub struct DeleteArgs {
    /// Channel id (hex). Cascades to channel_messages.
    pub id: String,
}

#[derive(Args, Debug)]
pub struct MuteArgs {
    /// Channel id (hex).
    pub id: String,
    /// `on` to mute, `off` to unmute.
    pub muted: MuteState,
}

#[derive(Args, Debug)]
pub struct AdvertiseArgs {
    /// Channel id (hex).
    pub id: String,
}

#[derive(Args, Debug)]
pub struct DiscoverArgs {
    /// Workspace id (hex).
    pub workspace_id: String,
}

#[derive(Args, Debug)]
pub struct AdoptArgs {
    /// Discovered channel id (hex), as listed by `channel discover`.
    pub channel_id: String,
}

pub async fn create(args: CreateArgs, target: &ClientTarget) -> Result<()> {
    let mut c = target.connect().await?;
    let r = c
        .channel_create(ChannelCreateParams {
            workspace_id: args.workspace_id,
            name: args.name,
        })
        .await?;
    println!("{}", serde_json::to_string_pretty(&r)?);
    Ok(())
}

pub async fn list(args: ListArgs, target: &ClientTarget) -> Result<()> {
    let mut c = target.connect().await?;
    let r = c
        .channel_list(ChannelListParams {
            workspace_id: args.workspace_id,
        })
        .await?;
    println!("{}", serde_json::to_string_pretty(&r)?);
    Ok(())
}

pub async fn history(args: HistoryArgs, target: &ClientTarget) -> Result<()> {
    let mut c = target.connect().await?;
    let r = c
        .channel_history(ChannelHistoryParams {
            channel_id: args.channel_id,
            limit: args.limit,
        })
        .await?;
    println!("{}", serde_json::to_string_pretty(&r)?);
    Ok(())
}

pub async fn delete(args: DeleteArgs, target: &ClientTarget) -> Result<()> {
    let mut c = target.connect().await?;
    let r = c
        .channel_delete(ChannelDeleteParams {
            channel_id: args.id,
        })
        .await?;
    println!("{}", serde_json::to_string_pretty(&r)?);
    Ok(())
}

pub async fn mute(args: MuteArgs, target: &ClientTarget) -> Result<()> {
    let mut c = target.connect().await?;
    let r = c
        .channel_mute(ChannelMuteParams {
            channel_id: args.id,
            muted: args.muted.into_bool(),
        })
        .await?;
    println!("{}", serde_json::to_string_pretty(&r)?);
    Ok(())
}

pub async fn advertise(args: AdvertiseArgs, target: &ClientTarget) -> Result<()> {
    let mut c = target.connect().await?;
    let r = c
        .channel_advertise(ChannelAdvertiseParams {
            channel_id: args.id,
        })
        .await?;
    println!("{}", serde_json::to_string_pretty(&r)?);
    Ok(())
}

pub async fn discover(args: DiscoverArgs, target: &ClientTarget) -> Result<()> {
    let mut c = target.connect().await?;
    let r = c
        .channel_discover(ChannelDiscoverParams {
            workspace_id: args.workspace_id,
        })
        .await?;
    println!("{}", serde_json::to_string_pretty(&r)?);
    Ok(())
}

pub async fn adopt(args: AdoptArgs, target: &ClientTarget) -> Result<()> {
    let mut c = target.connect().await?;
    let r = c
        .channel_adopt(ChannelAdoptParams {
            channel_id: args.channel_id,
        })
        .await?;
    println!("{}", serde_json::to_string_pretty(&r)?);
    Ok(())
}
