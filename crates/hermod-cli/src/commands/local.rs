//! `hermod local` — operator commands for the daemon's hosted local
//! agents.
//!
//! Read commands (`list`, `show`) work directly off the on-disk
//! `$HERMOD_HOME/agents/<id>/` material, no daemon required. Mutating
//! commands (`add`, `rm`, `rotate`) write the on-disk authoritative
//! state and prompt the operator to restart the daemon so the new
//! state is picked up — H3.5 will replace the prompt with a live IPC
//! handler that updates the registry, DB row, bearer authenticator,
//! and active sessions atomically.
//!
//! `setup-mcp` writes a `.mcp.json` next to a project root pointing
//! at the agent's bearer file, so Claude Code launching from that
//! project connects to the daemon as the project's agent.

use anyhow::{Context, Result};
use clap::Args;
use hermod_core::{AgentAlias, AgentId};
use hermod_daemon::local_agent;
use std::path::{Path, PathBuf};
use std::str::FromStr;

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

pub async fn add(args: AddArgs, home: &Path) -> Result<()> {
    let alias = args
        .alias
        .as_deref()
        .map(AgentAlias::from_str)
        .transpose()
        .context("parse --alias")?;
    let agent = local_agent::create_additional(home, alias)?;
    println!("provisioned local agent");
    println!("  agent_id:     {}", agent.agent_id);
    println!(
        "  alias:        {}",
        agent
            .local_alias
            .as_ref()
            .map(|a| a.as_str())
            .unwrap_or("(unset)")
    );
    println!(
        "  bearer_token: {}",
        local_agent::bearer_token_path(home, &agent.agent_id).display()
    );
    println!();
    println!("restart hermodd so the new agent enters the registry.");
    Ok(())
}

pub async fn remove(args: RemoveArgs, home: &Path) -> Result<()> {
    let agent = resolve(home, &args.reference)?;
    if !args.force {
        anyhow::bail!(
            "refusing to remove agent {} without --force; the keypair is unrecoverable once archived",
            agent.agent_id
        );
    }
    let archive = local_agent::archive_agent(home, &agent.agent_id)?;
    println!("archived local agent {}", agent.agent_id);
    println!("  archive: {}", archive.display());
    println!();
    println!("restart hermodd so the registry forgets this agent.");
    Ok(())
}

pub async fn rotate(args: RotateArgs, home: &Path) -> Result<()> {
    let agent = resolve(home, &args.reference)?;
    let new_token = local_agent::rotate_bearer_on_disk(home, &agent.agent_id)?;
    println!("rotated bearer for {}", agent.agent_id);
    println!("  new token: {}", new_token.expose_secret());
    println!();
    println!("restart hermodd so the registry picks up the new bearer hash.");
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
