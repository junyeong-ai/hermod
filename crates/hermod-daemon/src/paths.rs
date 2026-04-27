use anyhow::{Context, Result, anyhow};
use std::path::{Path, PathBuf};

/// Resolve the Hermod home dir: explicit `--home`, else `$HERMOD_HOME`, else `~/.hermod`.
///
/// The result is **always absolute**. Relative inputs are resolved against
/// the current working directory at startup and then canonicalised — this
/// matters because the daemon may later be re-launched from a different
/// CWD (launchd / systemd / manual restart) and must keep pointing at the
/// same files. Canonicalisation also collapses `..` segments and follows
/// symlinks, so behaviour is stable regardless of how the operator wrote
/// the path. If the directory doesn't exist yet (fresh install before
/// `hermod init`), absolutise without canonicalising; the `init` step
/// creates the directory and subsequent calls see a real path.
pub fn resolve_home(explicit: Option<&Path>) -> Result<PathBuf> {
    let raw = if let Some(p) = explicit {
        p.to_path_buf()
    } else if let Ok(env) = std::env::var("HERMOD_HOME") {
        PathBuf::from(env)
    } else {
        let base = directories::BaseDirs::new().ok_or_else(|| anyhow!("no HOME detected"))?;
        base.home_dir().join(".hermod")
    };

    let absolute = if raw.is_absolute() {
        raw
    } else {
        let cwd = std::env::current_dir().context("HERMOD_HOME is relative but cwd unreadable")?;
        cwd.join(&raw)
    };
    // Canonicalise if the path exists; otherwise accept the absolute form
    // as-is (init will create it on first run).
    Ok(absolute.canonicalize().unwrap_or(absolute))
}

/// Expand `~` and `$HERMOD_HOME` prefixes in a config path string.
pub fn expand(input: &str, home: &Path) -> PathBuf {
    if let Some(rest) = input.strip_prefix("~/") {
        return directories::BaseDirs::new()
            .map(|b| b.home_dir().join(rest))
            .unwrap_or_else(|| PathBuf::from(input));
    }
    if let Some(rest) = input.strip_prefix("$HERMOD_HOME/") {
        return home.join(rest);
    }
    PathBuf::from(input)
}

/// Expand `$HERMOD_HOME` inside a backend DSN. The token may appear
/// anywhere in the URL — typically embedded in the path component
/// (`sqlite://$HERMOD_HOME/hermod.db`). We textually substitute the
/// resolved home directory before the URL is parsed; downstream
/// (`hermod_storage::connect`) sees a fully-qualified DSN.
pub fn expand_url(input: &str, home: &Path) -> String {
    input.replace("$HERMOD_HOME", &home.display().to_string())
}
