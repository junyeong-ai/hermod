use anyhow::Result;
use clap::Args;
use hermod_protocol::ipc::methods::BroadcastSendParams;

use crate::client::ClientTarget;

#[derive(Args, Debug)]
pub struct SendArgs {
    /// Channel id (hex).
    #[arg(long)]
    pub channel_id: String,
    /// Message text.
    #[arg(long)]
    pub text: String,
}

pub async fn send(args: SendArgs, target: &ClientTarget) -> Result<()> {
    let mut c = target.connect().await?;
    let r = c
        .broadcast_send(BroadcastSendParams {
            channel_id: args.channel_id,
            text: args.text,
        })
        .await?;
    println!("{}", serde_json::to_string_pretty(&r)?);
    Ok(())
}
