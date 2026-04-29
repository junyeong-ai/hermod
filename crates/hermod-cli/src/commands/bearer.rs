//! Operator commands for per-agent IPC bearer tokens.
//!
//! Each local agent has a bearer at
//! `$HERMOD_HOME/agents/<agent_id>/bearer_token` (mode 0600). H2
//! single-tenant: when the daemon hosts exactly one local agent,
//! `hermod bearer show` / `hermod bearer rotate` operate on that
//! agent's bearer without further qualification. Multi-agent
//! dispatch (with explicit `--alias <name>`) lands in H5.
//!
//! After `rotate`, restart the daemon (or wait for systemd to do so)
//! so the new token takes effect — there is no in-process hot-reload
//! yet (Phase H3 will introduce per-agent bearer rotation that
//! invalidates active sessions atomically).

use anyhow::{Context, Result};
use clap::Args;
use std::path::Path;

use hermod_crypto::SecretString;
use hermod_daemon::local_agent;

#[derive(Args, Debug)]
pub struct ShowArgs {
    /// Print the full token instead of a masked prefix.
    #[arg(long, default_value_t = false)]
    pub full: bool,
}

pub async fn show(args: ShowArgs, home: &Path) -> Result<()> {
    let agent = solo_agent(home)?;
    let path = local_agent::bearer_token_path(home, &agent.agent_id);
    println!("agent: {}", agent.agent_id);
    println!("path:  {}", path.display());
    let token = agent.bearer_token.as_ref();
    if args.full {
        println!("token: {}", token.expose_secret());
    } else {
        let masked = mask(token.expose_secret());
        println!("token: {} (--full to print)", masked);
    }
    Ok(())
}

pub async fn rotate(home: &Path) -> Result<()> {
    let agent = solo_agent(home)?;
    let new_token = local_agent::generate_bearer_token();
    let path = local_agent::bearer_token_path(home, &agent.agent_id);
    write_bearer_token_file(&path, &new_token)?;
    println!("agent: {}", agent.agent_id);
    println!("rotated. new token: {}", new_token.expose_secret());
    println!("restart hermodd so the new token takes effect on the WSS+Bearer listener.");
    Ok(())
}

fn solo_agent(home: &Path) -> Result<local_agent::LocalAgent> {
    let agents = local_agent::scan_disk(home)
        .with_context(|| format!("scan {}", local_agent::agents_dir(home).display()))?;
    match agents.len() {
        0 => anyhow::bail!(
            "no local agents at {} — run `hermod init` to provision the bootstrap",
            local_agent::agents_dir(home).display()
        ),
        1 => Ok(agents.into_iter().next().expect("len == 1")),
        n => anyhow::bail!(
            "this daemon hosts {n} local agents — multi-agent bearer dispatch (with \
             explicit --alias) lands in phase H5; for now, manage tokens via the \
             on-disk file at $HERMOD_HOME/agents/<id>/bearer_token directly"
        ),
    }
}

/// Atomically replace the on-disk bearer file with `token`. Same
/// crash-safe rename + 0600 discipline as `local_agent::create_bootstrap`'s
/// initial write.
fn write_bearer_token_file(path: &Path, token: &SecretString) -> Result<()> {
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = parent.join(format!(
        ".{}.tmp.{}",
        path.file_name().and_then(|s| s.to_str()).unwrap_or("file"),
        std::process::id()
    ));

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let mut f = opts
        .open(&tmp)
        .with_context(|| format!("open {}", tmp.display()))?;
    f.write_all(token.expose_secret().as_bytes())
        .with_context(|| format!("write {}", tmp.display()))?;
    f.sync_all()
        .with_context(|| format!("fsync {}", tmp.display()))?;
    drop(f);
    #[cfg(unix)]
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod {}", tmp.display()))?;
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("rename → {}", path.display()));
    }
    Ok(())
}

fn mask(s: &str) -> String {
    let n = s.len();
    if n <= 8 {
        return "*".repeat(n);
    }
    format!("{}…{}", &s[..4], &s[n - 4..])
}
