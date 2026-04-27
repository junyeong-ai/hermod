//! Operator commands for the Remote IPC bearer token.
//!
//! The token at `$HERMOD_HOME/identity/api_token` (mode 0600) is the
//! credential thin clients present to the daemon's WSS+Bearer endpoint.
//! These commands let an operator inspect or rotate it without manually
//! editing the file. After `rotate`, restart the daemon (or wait for
//! systemd to do so) so the new token takes effect — there is no
//! in-process hot-reload yet.

use anyhow::Result;
use clap::Args;
use std::path::Path;

use hermod_daemon::identity;

#[derive(Args, Debug)]
pub struct ShowArgs {
    /// Print the full token instead of a masked prefix.
    #[arg(long, default_value_t = false)]
    pub full: bool,
}

pub async fn show(args: ShowArgs, home: &Path) -> Result<()> {
    let token = identity::ensure_api_token(home)?;
    println!("path:  {}", identity::api_token_path(home).display());
    if args.full {
        println!("token: {}", token);
    } else {
        let masked = mask(&token);
        println!("token: {} (--full to print)", masked);
    }
    Ok(())
}

pub async fn rotate(home: &Path) -> Result<()> {
    let token = identity::rotate_api_token(home)?;
    println!("rotated. new token: {}", token);
    println!("restart hermodd so the new token takes effect on the WSS+Bearer listener.");
    Ok(())
}

fn mask(s: &str) -> String {
    let n = s.len();
    if n <= 8 {
        return "*".repeat(n);
    }
    format!("{}…{}", &s[..4], &s[n - 4..])
}
