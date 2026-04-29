//! `hermod local` — operator commands for the daemon's hosted local
//! agents.
//!
//! All mutating commands (`add`, `rm`, `rotate`) call into the
//! daemon via IPC: the daemon writes the on-disk state, updates the
//! `local_agents` + `agents` DB rows, swaps the in-memory registry
//! entry, and force-closes any active session pinned to a removed
//! or rotated bearer. The daemon must be running.
//!
//! Read commands (`list`, `show`) work directly off the on-disk
//! `$HERMOD_HOME/agents/<id>/` material — no daemon required, useful
//! for offline troubleshooting.
//!
//! `setup-mcp` writes a `.mcp.json` next to a project root pointing
//! at the agent's bearer file, so Claude Code launching from that
//! project connects to the daemon as the project's agent.

use anyhow::{Context, Result};
use clap::Args;
use hermod_core::{AgentAlias, AgentId};
use hermod_daemon::local_agent;
use hermod_protocol::ipc::methods::{LocalAddParams, LocalRemoveParams, LocalRotateParams};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use crate::client::ClientTarget;

#[derive(Args, Debug)]
pub struct AddArgs {
    /// Operator label for the new agent (stored in the agent's
    /// on-disk `alias` file). Optional — agents without an alias are
    /// addressable by `agent_id` only.
    #[arg(long)]
    pub alias: Option<String>,
}

#[derive(Args, Debug)]
pub struct ShowArgs {
    /// Either the agent_id (26-char base32) or the alias.
    pub reference: String,
    /// Print the bearer token instead of a masked prefix.
    #[arg(long, default_value_t = false)]
    pub full: bool,
}

#[derive(Args, Debug)]
pub struct RemoveArgs {
    /// Either the agent_id or the alias.
    pub reference: String,
    /// Required confirmation — without it, `rm` refuses to delete.
    #[arg(long, default_value_t = false)]
    pub force: bool,
}

#[derive(Args, Debug)]
pub struct RotateArgs {
    /// Either the agent_id or the alias.
    pub reference: String,
}

#[derive(Args, Debug)]
pub struct SetupMcpArgs {
    /// Either the agent_id or the alias of the local agent the
    /// project should authenticate as.
    pub reference: String,
    /// Project root — `.mcp.json` is written here.
    #[arg(long)]
    pub project: PathBuf,
}

pub async fn list(home: &Path) -> Result<()> {
    let agents = local_agent::scan_disk(home)?;
    if agents.is_empty() {
        println!("(no local agents — run `hermod init` to provision the bootstrap)");
        return Ok(());
    }
    println!(
        "{:<26}  {:<20}  {:<10}  secret",
        "agent_id", "alias", "bearer"
    );
    for a in &agents {
        let alias = a
            .local_alias
            .as_ref()
            .map(|s| s.as_str().to_string())
            .unwrap_or_default();
        println!(
            "{:<26}  {:<20}  {:<10}  {}",
            a.agent_id.as_str(),
            alias,
            mask(a.bearer_token.expose_secret()),
            local_agent::secret_path(home, &a.agent_id).display(),
        );
    }
    Ok(())
}

pub async fn show(args: ShowArgs, home: &Path) -> Result<()> {
    let agent = resolve(home, &args.reference)?;
    println!("agent_id:        {}", agent.agent_id);
    println!(
        "alias:           {}",
        agent
            .local_alias
            .as_ref()
            .map(|a| a.as_str())
            .unwrap_or("(unset)")
    );
    println!(
        "ed25519_secret:  {}",
        local_agent::secret_path(home, &agent.agent_id).display()
    );
    let bearer_path = local_agent::bearer_token_path(home, &agent.agent_id);
    println!("bearer_token:    {}", bearer_path.display());
    let token = agent.bearer_token.expose_secret();
    if args.full {
        println!("token:           {token}");
    } else {
        println!("token:           {} (--full to print)", mask(token));
    }
    Ok(())
}

pub async fn add(args: AddArgs, target: &ClientTarget) -> Result<()> {
    let alias = args
        .alias
        .as_deref()
        .map(AgentAlias::from_str)
        .transpose()
        .context("parse --alias")?;
    let mut client = target.connect().await?;
    let res = client.local_add(LocalAddParams { alias }).await?;
    println!("provisioned local agent");
    println!("  agent_id:     {}", res.agent.agent_id);
    println!(
        "  alias:        {}",
        res.agent
            .alias
            .as_ref()
            .map(|a| a.as_str())
            .unwrap_or("(unset)"),
    );
    println!("  bearer_file:  {}", res.agent.bearer_file);
    println!("  secret_file:  {}", res.agent.secret_file);
    println!("  bearer_token: {}", res.bearer_token);
    Ok(())
}

pub async fn remove(args: RemoveArgs, target: &ClientTarget) -> Result<()> {
    let mut client = target.connect().await?;
    let res = client
        .local_remove(LocalRemoveParams {
            reference: args.reference,
            force: args.force,
        })
        .await?;
    println!("archived local agent {}", res.agent_id);
    println!("  archive: {}", res.archive_path);
    Ok(())
}

pub async fn rotate(args: RotateArgs, target: &ClientTarget) -> Result<()> {
    let mut client = target.connect().await?;
    let res = client
        .local_rotate(LocalRotateParams {
            reference: args.reference,
        })
        .await?;
    println!("rotated bearer for {}", res.agent_id);
    println!("  new token: {}", res.bearer_token);
    Ok(())
}

pub async fn setup_mcp(args: SetupMcpArgs, home: &Path) -> Result<()> {
    let agent = resolve(home, &args.reference)?;
    let bearer_path = local_agent::bearer_token_path(home, &agent.agent_id);
    let project = args
        .project
        .canonicalize()
        .with_context(|| format!("canonicalize project root {}", args.project.display()))?;
    let mcp_path = project.join(".mcp.json");
    let json = serde_json::json!({
        "mcpServers": {
            "hermod": {
                "command": "hermod",
                "args": ["mcp"],
                "env": {
                    "HERMOD_HOME": home.display().to_string(),
                    "HERMOD_BEARER_FILE": bearer_path.display().to_string(),
                }
            }
        }
    });
    let body = serde_json::to_string_pretty(&json).expect("serde_json round-trip");
    std::fs::write(&mcp_path, body).with_context(|| format!("write {}", mcp_path.display()))?;
    println!("wrote {}", mcp_path.display());
    println!("  agent_id:    {}", agent.agent_id);
    println!(
        "  alias:       {}",
        agent
            .local_alias
            .as_ref()
            .map(|a| a.as_str())
            .unwrap_or("(unset)")
    );
    println!(
        "  bearer_file: {}",
        local_agent::bearer_token_path(home, &agent.agent_id).display()
    );
    Ok(())
}

/// Look up an agent by `agent_id` (26-char base32) or by alias. Returns
/// the loaded `LocalAgent` so callers can inspect the bearer / keypair
/// without re-walking the disk.
fn resolve(home: &Path, reference: &str) -> Result<local_agent::LocalAgent> {
    let agents = local_agent::scan_disk(home)?;
    if let Ok(id) = AgentId::from_str(reference)
        && let Some(found) = agents.iter().find(|a| a.agent_id == id)
    {
        return Ok(found.clone());
    }
    let matches: Vec<&local_agent::LocalAgent> = agents
        .iter()
        .filter(|a| {
            a.local_alias
                .as_ref()
                .map(|al| al.as_str() == reference)
                .unwrap_or(false)
        })
        .collect();
    match matches.as_slice() {
        [] => anyhow::bail!(
            "no local agent matches `{reference}` — \
             either an agent_id (26-char base32) or an exact alias"
        ),
        [single] => Ok((*single).clone()),
        _ => anyhow::bail!(
            "alias `{reference}` matches {} local agents — disambiguate with the agent_id",
            matches.len()
        ),
    }
}

fn mask(s: &str) -> String {
    let n = s.len();
    if n <= 8 {
        return "*".repeat(n);
    }
    format!("{}…{}", &s[..4], &s[n - 4..])
}
