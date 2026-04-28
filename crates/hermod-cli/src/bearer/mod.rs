//! Bearer credential providers for the Remote IPC client.
//!
//! Every outbound `--remote wss://…` connection presents an
//! `Authorization: Bearer <token>` header. This module abstracts where the
//! token comes from (env var, file on disk, mint-on-demand shell command)
//! behind a single trait so the connect path stays source-agnostic.
//!
//! ## Refresh model
//!
//! Two methods, no boolean flags:
//!
//!   * [`BearerProvider::current`] — return the cached token, minting once
//!     if the cache is empty.
//!   * [`BearerProvider::refresh`] — guarantee a token strictly newer than
//!     `stale.epoch`. If a concurrent caller already refreshed, the cached
//!     token is returned without spawning another mint (single-flight).
//!
//! [`TokenEpoch`] is the cookie the connect path passes when retrying after
//! a 401 — it tells the provider "the token I just used was rejected;
//! mint a new one unless you already have a newer one".
//!
//! ## Source taxonomy
//!
//!   * [`StaticBearerProvider`] — value handed in at startup
//!     (`HERMOD_BEARER_TOKEN`). Never expires; refresh returns the same
//!     value (callers escalate to fatal).
//!   * [`FileBearerProvider`] — reads `--bearer-file` once on the cold
//!     path; subsequent reads happen only via `refresh`. Same
//!     deterministic model as the command source — no time-based
//!     heuristic that could silently advance the epoch under an
//!     in-flight 401-retry.
//!   * [`CommandBearerProvider`] — runs `--bearer-command` under `sh -c`
//!     and treats stdout as the token. Single-flight via
//!     [`TokenEpoch`]; the inner mutex means concurrent 401s collapse
//!     into a single subprocess invocation.
//!
//! New sources are added by implementing the trait and adding an arm to
//! [`from_env_and_args`]; nothing else in the codebase needs to change.

mod command;
mod file;
mod static_provider;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Result, bail};
use async_trait::async_trait;
use hermod_crypto::SecretString;

pub use command::CommandBearerProvider;
pub use file::FileBearerProvider;
pub use static_provider::StaticBearerProvider;

/// Monotonically increasing per-provider counter. Used as a cookie by the
/// connect path's 401-retry: `refresh(stale)` only mints fresh material if
/// the cached token's epoch is `<= stale.epoch`. This is the single-flight
/// dedup primitive — N concurrent 401s collapse into one subprocess.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TokenEpoch(u64);

impl TokenEpoch {
    /// Sentinel returned by sources that have no notion of refresh
    /// (env-supplied static tokens). A `refresh(epoch_zero)` from a
    /// `StaticBearerProvider` returns the same `TokenEpoch::ZERO`, which
    /// the connect path uses to detect "provider can't refresh" and
    /// escalate the error to fatal.
    pub const ZERO: TokenEpoch = TokenEpoch(0);
    /// First epoch a refreshable provider hands out.
    pub const FIRST: TokenEpoch = TokenEpoch(1);

    pub fn next(self) -> TokenEpoch {
        TokenEpoch(self.0.saturating_add(1))
    }
}

/// One immutable lease on a bearer token. Cloning shares the underlying
/// secret via `Arc` — no string re-allocation, no extra zeroize on drop
/// of the cloned handle.
#[derive(Clone, Debug)]
pub struct BearerToken {
    secret: Arc<SecretString>,
    epoch: TokenEpoch,
}

impl BearerToken {
    pub fn new(secret: SecretString, epoch: TokenEpoch) -> Self {
        Self {
            secret: Arc::new(secret),
            epoch,
        }
    }

    pub fn secret(&self) -> &SecretString {
        &self.secret
    }

    pub fn epoch(&self) -> TokenEpoch {
        self.epoch
    }
}

/// Errors a provider can surface. Distinguished so the connect path
/// (and operator-facing error messages) can react sensibly — e.g.
/// `CommandFailed` propagates the auth provider's stderr verbatim,
/// because that's what the user needs to debug a broken `gcloud auth`.
#[derive(thiserror::Error, Debug)]
pub enum BearerError {
    #[error("bearer source produced empty output")]
    Empty,
    #[error(
        "bearer command `{command}` failed (exit {code})\n--- stderr ---\n{stderr}\n--- end stderr ---"
    )]
    CommandFailed {
        code: i32,
        command: String,
        stderr: String,
    },
    #[error("bearer command timed out after {0:?}")]
    CommandTimedOut(std::time::Duration),
    #[error("bearer command spawn failed: {0}")]
    CommandSpawn(std::io::Error),
    #[error("bearer file {path}: {source}")]
    FileRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

#[async_trait]
pub trait BearerProvider: Send + Sync + std::fmt::Debug {
    /// Return the current cached token, minting once on the cold path.
    async fn current(&self) -> Result<BearerToken, BearerError>;

    /// Return a token strictly newer than `stale.epoch`. If another caller
    /// already advanced the cache past `stale`, the cached token is
    /// returned without re-minting (single-flight). If this provider has
    /// no notion of refresh (e.g. a static env-supplied token), the
    /// returned token's epoch will equal `stale.epoch` — the caller should
    /// escalate to fatal.
    async fn refresh(&self, stale: TokenEpoch) -> Result<BearerToken, BearerError>;
}

/// Operator-supplied bearer source declarations. Captured from CLI args
/// and environment by [`from_env_and_args`] before any IPC happens; the
/// connect path never re-inspects env vars.
#[derive(Debug, Default)]
pub struct BearerArgs {
    pub bearer_file: Option<PathBuf>,
    pub bearer_command: Option<String>,
}

/// Resolve "where does the bearer come from" exactly once at startup.
///
/// Precedence is **explicit > implicit**: any of `--bearer-file`,
/// `--bearer-command`, or `HERMOD_BEARER_TOKEN` is treated as an
/// explicit declaration, and at most one may be set. With no explicit
/// declaration `default_path` (when `Some`) is opened via
/// [`FileBearerProvider`] — the "just works" path when the CLI runs on
/// the same host as the daemon and inherits its `bearer_token` file.
/// `None` plus zero explicit declarations is a configuration error.
///
/// Returning a trait object means the connect path doesn't know (or
/// care) which source it got. Adding a fourth source (e.g. an OS
/// keyring lookup) is a new arm here and a new module — no other call
/// sites change.
pub fn from_env_and_args(
    args: &BearerArgs,
    env_token: Option<SecretString>,
    default_path: Option<PathBuf>,
) -> Result<Arc<dyn BearerProvider>> {
    let mut declared: Vec<&'static str> = Vec::new();
    if args.bearer_file.is_some() {
        declared.push("--bearer-file");
    }
    if args.bearer_command.is_some() {
        declared.push("--bearer-command");
    }
    if env_token.is_some() {
        declared.push("HERMOD_BEARER_TOKEN");
    }

    match declared.len() {
        0 => match default_path {
            // Implicit fallback. Using FileBearerProvider (not Static)
            // means a `hermod bearer rotate` followed by a
            // `hermod --remote ...` in the same shell sees the new
            // token via 401-trigger refresh.
            Some(path) => Ok(Arc::new(FileBearerProvider::new(path))),
            None => bail!(
                "no bearer source — specify one of --bearer-file, \
                 --bearer-command, or HERMOD_BEARER_TOKEN"
            ),
        },
        1 => {
            if let Some(path) = &args.bearer_file {
                Ok(Arc::new(FileBearerProvider::new(path.clone())))
            } else if let Some(cmd) = &args.bearer_command {
                Ok(Arc::new(CommandBearerProvider::new(cmd.clone())))
            } else if let Some(secret) = env_token {
                Ok(Arc::new(StaticBearerProvider::new(secret)))
            } else {
                unreachable!("declared.len()==1 but no source matched")
            }
        }
        _ => bail!(
            "bearer source ambiguous — specify exactly one of: {}",
            declared.join(", ")
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn no_source_falls_back_to_default_path() {
        let dir = tempdir().unwrap();
        let default_path = dir.path().join("bearer_token");
        std::fs::write(&default_path, "default-tok").unwrap();
        let provider = from_env_and_args(&BearerArgs::default(), None, Some(default_path)).unwrap();
        let t = provider.current().await.unwrap();
        assert_eq!(t.secret().expose_secret(), "default-tok");
    }

    #[test]
    fn no_source_and_no_default_is_an_error() {
        let result = from_env_and_args(&BearerArgs::default(), None, None);
        let err = result.unwrap_err().to_string();
        assert!(err.contains("no bearer source"), "got: {err}");
    }

    #[tokio::test]
    async fn explicit_file_wins() {
        let dir = tempdir().unwrap();
        let explicit = dir.path().join("explicit");
        std::fs::write(&explicit, "from-flag").unwrap();
        let provider = from_env_and_args(
            &BearerArgs {
                bearer_file: Some(explicit),
                bearer_command: None,
            },
            None,
            None,
        )
        .unwrap();
        let t = provider.current().await.unwrap();
        assert_eq!(t.secret().expose_secret(), "from-flag");
    }

    #[tokio::test]
    async fn env_token_dispatches_static_provider() {
        let provider = from_env_and_args(
            &BearerArgs::default(),
            Some(SecretString::new("env-tok".to_string())),
            None,
        )
        .unwrap();
        let t = provider.current().await.unwrap();
        assert_eq!(t.secret().expose_secret(), "env-tok");
        assert_eq!(t.epoch(), TokenEpoch::ZERO);
    }

    #[test]
    fn two_sources_is_ambiguous() {
        let dir = tempdir().unwrap();
        let result = from_env_and_args(
            &BearerArgs {
                bearer_file: Some(dir.path().join("a")),
                bearer_command: Some("echo b".into()),
            },
            None,
            None,
        );
        let err = result.unwrap_err().to_string();
        assert!(err.contains("ambiguous"), "got: {err}");
        assert!(err.contains("--bearer-file"));
        assert!(err.contains("--bearer-command"));
    }

    #[test]
    fn three_sources_lists_all() {
        let dir = tempdir().unwrap();
        let result = from_env_and_args(
            &BearerArgs {
                bearer_file: Some(dir.path().join("a")),
                bearer_command: Some("echo b".into()),
            },
            Some(SecretString::new("c".to_string())),
            None,
        );
        let err = result.unwrap_err().to_string();
        assert!(err.contains("--bearer-file"));
        assert!(err.contains("--bearer-command"));
        assert!(err.contains("HERMOD_BEARER_TOKEN"));
    }
}
