use anyhow::{Context, Result};
use clap::Args;
use std::path::Path;

use hermod_daemon::{config::Config, home_layout, identity};

#[derive(Args, Debug)]
pub struct InitArgs {
    /// Optional human-readable alias for this identity (stored in config.toml).
    #[arg(long)]
    pub alias: Option<String>,

    /// Replace the existing identity. The Ed25519 secret key *is* the agent
    /// identity in Hermod, so rotating it means becoming a brand-new agent.
    /// To make this irreversible-by-accident, the existing `hermod.db`,
    /// TLS material, and bearer token are archived under
    /// `<home>/archive/<timestamp>/` before the new identity is generated;
    /// federation peers will need to re-pin the new pubkey + TLS fingerprint.
    #[arg(long, default_value_t = false)]
    pub force: bool,
}

pub async fn run(args: InitArgs, home: &Path) -> Result<()> {
    // Bring `$HERMOD_HOME` and `identity/` to the canonical 0o700
    // mode. Init is the explicit operator-driven bootstrap, so it
    // chmods existing dirs down (the daemon's strict `ensure_dirs`
    // refuses to touch existing modes — see `home_layout` docs).
    home_layout::prepare_dirs(home).context("prepare $HERMOD_HOME layout")?;
    let config_path = Config::write_template(home)?;

    let id_path = identity::secret_path(home);
    if id_path.exists() {
        if args.force {
            archive_existing_state(home)?;
        } else {
            let kp = identity::load(home)?;
            println!("identity already exists");
            println!("  agent_id:    {}", kp.agent_id());
            println!("  fingerprint: {}", kp.fingerprint().to_human_prefix(8));
            println!("  config:      {}", config_path.display());
            return Ok(());
        }
    }

    let (kp, _) = identity::ensure_exists(home)?;
    let tls = identity::ensure_tls(home, &kp)?;
    let _ = identity::ensure_bearer_token(home)?;

    if let Some(alias) = args.alias {
        apply_alias(&config_path, &alias)?;
    }

    println!("initialized hermod at {}", home.display());
    println!("  agent_id:        {}", kp.agent_id());
    println!("  fingerprint:     {}", kp.fingerprint().to_human_prefix(8));
    println!("  tls_fingerprint: {}", tls.fingerprint);
    println!(
        "  bearer_token:    {}",
        identity::bearer_token_path(home).display()
    );
    println!("  config:          {}", config_path.display());
    println!();
    println!("next: start the daemon with `hermodd`, then `hermod status`");
    Ok(())
}

fn apply_alias(config_path: &Path, alias: &str) -> Result<()> {
    let text = std::fs::read_to_string(config_path)?;
    let mut cfg: Config = toml::from_str(&text)?;
    cfg.identity.alias = Some(alias.to_string());
    std::fs::write(config_path, toml::to_string_pretty(&cfg)?)?;
    Ok(())
}

/// Move every piece of state that's tied to the current identity into a
/// timestamped archive subdirectory. Items that survive (e.g. config.toml,
/// remote_pins.json) are not identity-bound. The archive is never read by
/// hermod at runtime; it exists for forensic recovery only.
fn archive_existing_state(home: &Path) -> Result<()> {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|_| "0".to_string());
    let archive_root = home.join("archive");
    let archive = archive_root.join(&stamp);
    std::fs::create_dir_all(&archive).with_context(|| format!("create {}", archive.display()))?;
    // Lock the archive root and the timestamped subdir to operator-
    // only access — they hold former identity material and DB
    // contents. Matches the rest of the $HERMOD_HOME mode policy
    // (`hermod_daemon::home_layout`). Fail loud if chmod fails.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&archive_root, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("chmod {}", archive_root.display()))?;
        std::fs::set_permissions(&archive, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("chmod {}", archive.display()))?;
    }

    // Identity material (key, TLS, bearer token).
    let identity_dir = home.join("identity");
    if identity_dir.exists() {
        move_path(&identity_dir, &archive.join("identity"))?;
    }

    // SQLite store + WAL/SHM siblings.
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
