use anyhow::{Context, Result};
use clap::Args;
use std::path::Path;
use std::str::FromStr;

use hermod_core::AgentAlias;
use hermod_daemon::{config::Config, home_layout, host_identity, local_agent};

#[derive(Args, Debug)]
pub struct InitArgs {
    /// Operator label for the bootstrap local agent — peers see it as
    /// `local_alias` in the agents directory. Stored as the bootstrap
    /// agent's on-disk `alias` file (operator-managed, mode 0644).
    #[arg(long)]
    pub alias: Option<String>,

    /// Replace the existing host + local-agent identities. Both the
    /// host Ed25519 secret (Noise XX static key + TLS leaf) and every
    /// per-agent keypair under `agents/<id>/` are wiped, so federation
    /// peers will need to re-pin the new pubkeys + TLS fingerprint.
    /// To make this irreversible-by-accident, the existing
    /// `hermod.db`, host material, and per-agent material are
    /// archived under `<home>/archive/<timestamp>/` before the new
    /// identities are generated.
    #[arg(long, default_value_t = false)]
    pub force: bool,
}

pub async fn run(args: InitArgs, home: &Path) -> Result<()> {
    home_layout::prepare_dirs(home).context("prepare $HERMOD_HOME layout")?;
    let config_path = Config::write_template(home)?;

    let host_secret = host_identity::secret_path(home);
    let existing_agent_ids = local_agent::scan_disk_ids(home)?;
    if (host_secret.exists() || !existing_agent_ids.is_empty()) && !args.force {
        let host_kp = host_identity::load(home)?;
        println!("identity already exists");
        println!("  host_id:        {}", host_kp.agent_id());
        println!(
            "  host_fp:        {}",
            host_kp.fingerprint().to_human_prefix(8)
        );
        if existing_agent_ids.is_empty() {
            println!("  local agents:   (none — re-run `hermod init --force` to provision)");
        } else {
            for id in &existing_agent_ids {
                println!("  local agent:    {id}");
            }
        }
        println!("  config:         {}", config_path.display());
        return Ok(());
    }
    if args.force {
        archive_existing_state(home)?;
    }

    let alias = args
        .alias
        .as_deref()
        .map(AgentAlias::from_str)
        .transpose()
        .context("parse --alias")?;
    let (host_kp, _) = host_identity::ensure_exists(home)?;
    let tls = host_identity::ensure_tls(home, &host_kp)?;
    let bootstrap = local_agent::create_bootstrap(home, alias)?;

    println!("initialized hermod at {}", home.display());
    println!("  host_id:         {}", host_kp.agent_id());
    println!(
        "  host_fp:         {}",
        host_kp.fingerprint().to_human_prefix(8)
    );
    println!("  tls_fingerprint: {}", tls.fingerprint);
    println!("  local agent:     {}", bootstrap.agent_id);
    println!(
        "  bearer_token:    {}",
        local_agent::bearer_token_path(home, &bootstrap.agent_id).display()
    );
    println!("  config:          {}", config_path.display());
    println!();
    println!("next: start the daemon with `hermodd`, then `hermod status`");
    Ok(())
}

/// Move every piece of state that's tied to the current host or
/// per-agent identities into a timestamped archive subdirectory.
/// Items that survive (e.g. config.toml, remote_pins.json) are not
/// identity-bound. The archive is never read by hermod at runtime;
/// it exists for forensic recovery only.
fn archive_existing_state(home: &Path) -> Result<()> {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|_| "0".to_string());
    let archive_root = home.join("archive");
    let archive = archive_root.join(&stamp);
    std::fs::create_dir_all(&archive).with_context(|| format!("create {}", archive.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&archive_root, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("chmod {}", archive_root.display()))?;
        std::fs::set_permissions(&archive, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("chmod {}", archive.display()))?;
    }

    let host_dir = host_identity::host_dir(home);
    if host_dir.exists() {
        move_path(&host_dir, &archive.join("host"))?;
    }

    let agents_dir = local_agent::agents_dir(home);
    if agents_dir.exists() {
        move_path(&agents_dir, &archive.join("agents"))?;
    }

    for tail in ["hermod.db", "hermod.db-wal", "hermod.db-shm"] {
        let p = home.join(tail);
        if p.exists() {
            move_path(&p, &archive.join(tail))?;
        }
    }

    println!("archived previous identity state to {}", archive.display());
    println!("  (recovery: copy files back to {})", home.display());
    Ok(())
}

fn move_path(src: &Path, dst: &Path) -> Result<()> {
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    std::fs::rename(src, dst)
        .with_context(|| format!("move {} → {}", src.display(), dst.display()))?;
    Ok(())
}
