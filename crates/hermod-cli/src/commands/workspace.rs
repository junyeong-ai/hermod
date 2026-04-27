use anyhow::Result;
use clap::Args;
use hermod_protocol::ipc::methods::{
    WorkspaceChannelsParams, WorkspaceCreateParams, WorkspaceDeleteParams, WorkspaceGetParams,
    WorkspaceInviteParams, WorkspaceJoinParams, WorkspaceMuteParams, WorkspaceRosterParams,
    WorkspaceVisibility,
};

use crate::commands::MuteState;

use crate::client::ClientTarget;

#[derive(Args, Debug)]
pub struct CreateArgs {
    /// Workspace name (1..=64 bytes, human-readable).
    pub name: String,
    /// Public workspaces are openly identifiable; private workspaces require
    /// the secret returned by this command to join.
    #[arg(long, default_value = "private")]
    pub visibility: String,
}

#[derive(Args, Debug)]
pub struct JoinArgs {
    /// Workspace name (must match the creator's chosen name).
    pub name: String,
    /// Hex-encoded 32-byte workspace secret, shared out of band.
    pub secret_hex: String,
}

#[derive(Args, Debug)]
pub struct GetArgs {
    /// Workspace id (hex).
    pub id: String,
}

#[derive(Args, Debug)]
pub struct DeleteArgs {
    /// Workspace id (hex). Cascades to channels, channel_messages, members.
    pub id: String,
}

#[derive(Args, Debug)]
pub struct MuteArgs {
    /// Workspace id (hex).
    pub id: String,
    /// `on` to mute, `off` to unmute.
    pub muted: MuteState,
}

#[derive(Args, Debug)]
pub struct InviteArgs {
    /// Workspace id (hex).
    #[arg(long)]
    pub workspace_id: String,
    /// Invite recipient: `<agent_id>` or `@alias`.
    #[arg(long)]
    pub target: String,
}

pub async fn create(args: CreateArgs, target: &ClientTarget) -> Result<()> {
    let visibility = match args.visibility.as_str() {
        "public" => WorkspaceVisibility::Public,
        "private" => WorkspaceVisibility::Private,
        other => {
            return Err(crate::error::invalid(
                "visibility",
                other,
                "expected public|private",
            ));
        }
    };
    let mut c = target.connect().await?;
    let r = c
        .workspace_create(WorkspaceCreateParams {
            name: args.name,
            visibility,
        })
        .await?;
    println!("{}", serde_json::to_string_pretty(&r)?);
    Ok(())
}

pub async fn join(args: JoinArgs, target: &ClientTarget) -> Result<()> {
    let mut c = target.connect().await?;
    let r = c
        .workspace_join(WorkspaceJoinParams {
            name: args.name,
            secret_hex: args.secret_hex,
        })
        .await?;
    println!("{}", serde_json::to_string_pretty(&r)?);
    Ok(())
}

pub async fn list(target: &ClientTarget) -> Result<()> {
    let mut c = target.connect().await?;
    let r = c.workspace_list().await?;
    println!("{}", serde_json::to_string_pretty(&r)?);
    Ok(())
}

pub async fn get(args: GetArgs, target: &ClientTarget) -> Result<()> {
    let mut c = target.connect().await?;
    let r = c
        .workspace_get(WorkspaceGetParams {
            workspace_id: args.id,
        })
        .await?;
    println!("{}", serde_json::to_string_pretty(&r)?);
    Ok(())
}

pub async fn delete(args: DeleteArgs, target: &ClientTarget) -> Result<()> {
    let mut c = target.connect().await?;
    let r = c
        .workspace_delete(WorkspaceDeleteParams {
            workspace_id: args.id,
        })
        .await?;
    println!("{}", serde_json::to_string_pretty(&r)?);
    Ok(())
}

pub async fn mute(args: MuteArgs, target: &ClientTarget) -> Result<()> {
    let mut c = target.connect().await?;
    let r = c
        .workspace_mute(WorkspaceMuteParams {
            workspace_id: args.id,
            muted: args.muted.into_bool(),
        })
        .await?;
    println!("{}", serde_json::to_string_pretty(&r)?);
    Ok(())
}

pub async fn invite(args: InviteArgs, target: &ClientTarget) -> Result<()> {
    let mut c = target.connect().await?;
    let r = c
        .workspace_invite(WorkspaceInviteParams {
            workspace_id: args.workspace_id,
            target: args.target,
        })
        .await?;
    println!("{}", serde_json::to_string_pretty(&r)?);
    Ok(())
}

#[derive(Args, Debug)]
pub struct MembersArgs {
    /// Hex workspace id (16 bytes = 32 hex chars).
    pub workspace_id: String,
}

pub async fn members(args: MembersArgs, target: &ClientTarget) -> Result<()> {
    let mut c = target.connect().await?;
    let r = c
        .workspace_roster(WorkspaceRosterParams {
            workspace_id: args.workspace_id,
        })
        .await?;
    println!("{}", serde_json::to_string_pretty(&r)?);
    Ok(())
}

#[derive(Args, Debug)]
pub struct ChannelsArgs {
    /// Hex workspace id (16 bytes = 32 hex chars).
    pub workspace_id: String,
}

pub async fn channels(args: ChannelsArgs, target: &ClientTarget) -> Result<()> {
    let mut c = target.connect().await?;
    let r = c
        .workspace_channels(WorkspaceChannelsParams {
            workspace_id: args.workspace_id,
        })
        .await?;
    println!("{}", serde_json::to_string_pretty(&r)?);
    Ok(())
}
