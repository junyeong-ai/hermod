use anyhow::Result;
use clap::Args;
use hermod_core::{Endpoint, TrustLevel};
use hermod_protocol::ipc::methods::{
    PeerAddParams, PeerAdvertiseParams, PeerReach, PeerRemoveParams, PeerRepinParams,
    PeerTrustParams,
};

use std::str::FromStr;

use crate::client::ClientTarget;
use crate::error::{from_underlying, invalid};

#[derive(Args, Debug)]
pub struct AddArgs {
    /// Direct endpoint, e.g. `wss://host:7823`. Mutually exclusive
    /// with `--via` — pick one.
    #[arg(long, conflicts_with = "via", required_unless_present = "via")]
    pub endpoint: Option<String>,
    /// Reach this peer through a broker that's already in the
    /// directory (`agent_id` or `@<local_alias>`). The broker's
    /// `BrokerMode::RelayOnly` fall-through forwards the envelope.
    /// Mutually exclusive with `--endpoint`.
    #[arg(long)]
    pub via: Option<String>,
    /// 64-char hex of the remote daemon's host identity pubkey. Pinned
    /// for the Noise XX handshake when this daemon dials the peer.
    #[arg(long)]
    pub host_pubkey_hex: String,
    /// 64-char hex of the peer agent's identity pubkey. Envelopes
    /// addressed `--to <alias>` resolve to this agent's id; signature
    /// verification uses this pubkey.
    #[arg(long)]
    pub agent_pubkey_hex: String,
    /// Optional human-readable alias for the peer agent.
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
    // clap's `conflicts_with` + `required_unless_present` combo
    // guarantees exactly one of `--endpoint` / `--via` is set; the
    // match is exhaustive for the operator's mental model and the
    // wire enum.
    let reach = match (args.endpoint, args.via) {
        (Some(ep), None) => PeerReach::Direct {
            endpoint: Endpoint::from_str(&ep).map_err(|e| from_underlying("endpoint", e))?,
        },
        (None, Some(via)) => PeerReach::Via { via },
        _ => unreachable!("clap enforces XOR"),
    };
    let mut c = target.connect().await?;
    let r = c
        .peer_add(PeerAddParams {
            reach,
            host_pubkey_hex: args.host_pubkey_hex,
            agent_pubkey_hex: args.agent_pubkey_hex,
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

#[derive(Args, Debug)]
pub struct AdvertiseArgs {
    /// Target peer (`agent_id` or `@<local_alias>`). Omit to advertise
    /// to every federated peer once per distinct host.
    #[arg(long)]
    pub target: Option<String>,
}

pub async fn advertise(args: AdvertiseArgs, target: &ClientTarget) -> Result<()> {
    let mut c = target.connect().await?;
    let r = c
        .peer_advertise(PeerAdvertiseParams {
            target: args.target,
        })
        .await?;
    println!("{}", serde_json::to_string_pretty(&r)?);
    // Honesty contract: at least one target failed to deliver →
    // exit non-zero so scripts react. Operators reading the JSON
    // see the per-target rows; CI pipelines key off `$?`.
    let any_failed = r
        .outcomes
        .iter()
        .any(|o| o.status == hermod_core::MessageStatus::Failed);
    if any_failed {
        anyhow::bail!("one or more advertise targets failed; see outcomes[].status");
    }
    Ok(())
}
