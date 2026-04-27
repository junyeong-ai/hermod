use anyhow::Result;
use clap::Args;
use hermod_protocol::ipc::methods::{
    ConfirmationAcceptParams, ConfirmationListParams, ConfirmationRejectParams,
};

use crate::client::ClientTarget;

#[derive(Args, Debug)]
pub struct ListArgs {
    #[arg(long)]
    pub limit: Option<u32>,
}

#[derive(Args, Debug)]
pub struct DecideArgs {
    /// Confirmation id (ULID, from `confirm list`).
    pub id: String,
}

pub async fn list(args: ListArgs, target: &ClientTarget) -> Result<()> {
    let mut c = target.connect().await?;
    let r = c
        .confirmation_list(ConfirmationListParams {
            limit: args.limit,
            after_id: None,
        })
        .await?;
    println!("{}", serde_json::to_string_pretty(&r)?);
    Ok(())
}

pub async fn accept(args: DecideArgs, target: &ClientTarget) -> Result<()> {
    let mut c = target.connect().await?;
    let r = c
        .confirmation_accept(ConfirmationAcceptParams {
            confirmation_id: args.id,
        })
        .await?;
    println!("{}", serde_json::to_string_pretty(&r)?);
    Ok(())
}

pub async fn reject(args: DecideArgs, target: &ClientTarget) -> Result<()> {
    let mut c = target.connect().await?;
    let r = c
        .confirmation_reject(ConfirmationRejectParams {
            confirmation_id: args.id,
        })
        .await?;
    println!("{}", serde_json::to_string_pretty(&r)?);
    Ok(())
}
