use anyhow::Result;
use clap::Args;
use hermod_core::{Endpoint, TrustLevel};
use hermod_protocol::ipc::methods::{
    PeerAddParams, PeerRemoveParams, PeerRepinParams, PeerTrustParams,
};

use std::str::FromStr;

use crate::client::ClientTarget;
use crate::error::{from_underlying, invalid};

#[derive(Args, Debug)]
pub struct AddArgs {
    /// Endpoint URI, e.g. `wss://host:7823`.
    #[arg(long)]
    pub endpoint: String,
    /// 64-char hex of the peer's ed25519 identity pubkey. Required —
    /// federation peers authenticate via Noise XX, so an endpoint without
    /// a known pubkey can't talk to us.
    #[arg(long)]
    pub pubkey_hex: String,
    /// Optional human-readable alias.
    #[arg(long)]
    pub alias: Option<String>,
}

#[derive(Args, Debug)]
pub struct TrustArgs {
    /// Peer id (as returned by `peer add` or `peer list`).
    pub peer: String,
    /// New trust level: self | verified | tofu | untrusted.
    pub level: String,
}

#[derive(Args, Debug)]
pub struct RemoveArgs {
    /// Peer id to forget. The agent row stays so audit references resolve;
    /// the federation endpoint and TLS pin are cleared.
    pub peer: String,
}

#[derive(Args, Debug)]
pub struct RepinArgs {
    /// Peer id whose TLS fingerprint pin should be replaced.
    pub peer: String,
    /// New SHA-256 fingerprint, lowercase hex with colons (`aa:bb:…:ff`).
    /// Confirm out-of-band before submitting.
    #[arg(long)]
    pub fingerprint: String,
}

pub async fn add(args: AddArgs, target: &ClientTarget) -> Result<()> {
    let endpoint =
        Endpoint::from_str(&args.endpoint).map_err(|e| from_underlying("endpoint", e))?;
    let mut c = target.connect().await?;
    let r = c
        .peer_add(PeerAddParams {
            endpoint,
            pubkey_hex: Some(args.pubkey_hex),
            local_alias: args
                .alias
                .as_deref()
                .map(hermod_core::AgentAlias::from_str)
                .transpose()
                .map_err(|e| from_underlying("alias", e))?,
        })
        .await?;
    if matches!(
        r.alias_outcome,
        hermod_protocol::ipc::methods::AliasOutcomeView::LocalDropped
    ) {
        eprintln!(
            "warning: requested local_alias was already bound to another peer; \
             added without alias. The peer's self-asserted alias will arrive on \
             first federation contact (visible as `peer_asserted_alias`). Either \
             rename the existing peer or pick a different alias."
        );
    }
    println!("{}", serde_json::to_string_pretty(&r)?);
    Ok(())
}

pub async fn list(target: &ClientTarget) -> Result<()> {
    let mut c = target.connect().await?;
    let r = c.peer_list().await?;
    println!("{}", serde_json::to_string_pretty(&r)?);
    Ok(())
}

pub async fn trust(args: TrustArgs, target: &ClientTarget) -> Result<()> {
    let level =
        TrustLevel::from_str(&args.level).map_err(|e| invalid("trust level", &args.level, e))?;
    let mut c = target.connect().await?;
    let r = c
        .peer_trust(PeerTrustParams {
            peer: args.peer,
            level,
        })
        .await?;
    println!("{}", serde_json::to_string_pretty(&r)?);
    Ok(())
}

pub async fn remove(args: RemoveArgs, target: &ClientTarget) -> Result<()> {
    let mut c = target.connect().await?;
    let r = c.peer_remove(PeerRemoveParams { peer: args.peer }).await?;
    println!("{}", serde_json::to_string_pretty(&r)?);
    Ok(())
}

pub async fn repin(args: RepinArgs, target: &ClientTarget) -> Result<()> {
    let mut c = target.connect().await?;
    let r = c
        .peer_repin(PeerRepinParams {
            peer: args.peer,
            fingerprint: args.fingerprint,
        })
        .await?;
    println!("{}", serde_json::to_string_pretty(&r)?);
    Ok(())
}
