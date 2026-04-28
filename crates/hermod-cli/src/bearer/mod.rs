//! Bearer credential providers for the Remote IPC client.
//!
//! Every outbound `--remote wss://…` connection presents one or two
//! `Bearer` headers:
//!
//! * `Authorization: Bearer <daemon-token>` — always set; validated by
//!   the hermod daemon.
//! * `Proxy-Authorization: Bearer <proxy-token>` — set when the CLI is
//!   running behind an SSO reverse proxy (Google Cloud IAP,
//!   oauth2-proxy, Cloudflare Access, ALB+Cognito, …) that demands its
//!   own bearer alongside the daemon's. Per RFC 7235 §4.4 the proxy
//!   strips this header before forwarding to the backend.
//!
//! The two headers are independent; the same provider taxonomy backs
//! both. A connect path holds an [`Arc<dyn BearerProvider>`] for the
//! daemon side and an `Option<Arc<dyn BearerProvider>>` for the proxy.
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
//! an auth failure — it tells the provider "the token I just used was
//! rejected; mint a new one unless you already have a newer one".
//!
//! ## Source taxonomy
//!
//!   * [`StaticBearerProvider`] — value handed in at startup
//!     (`HERMOD_BEARER_TOKEN` / `HERMOD_PROXY_BEARER_TOKEN`). Never
//!     expires; refresh returns the same value (callers escalate to
//!     fatal).
//!   * [`FileBearerProvider`] — reads `--bearer-file` / `--proxy-bearer-file`
//!     once on the cold path; subsequent reads happen only via `refresh`.
//!     Same deterministic model as the command source — no time-based
//!     heuristic that could silently advance the epoch under an
//!     in-flight retry.
//!   * [`CommandBearerProvider`] — runs the configured shell command
//!     under `sh -c` and treats stdout as the token. Single-flight via
//!     [`TokenEpoch`]; the inner mutex means concurrent retries collapse
//!     into a single subprocess invocation.
//!
//! New sources are added by implementing the trait and adding an arm in
//! [`resolve_source`]; nothing else in the codebase needs to change.

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
/// connect path's auth-failure retry: `refresh(stale)` only mints fresh
/// material if the cached token's epoch is `<= stale.epoch`. This is the
/// single-flight dedup primitive — N concurrent retries collapse into one
/// subprocess.
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
/// and environment by [`daemon_from_env_and_args`] /
/// [`proxy_from_env_and_args`] before any IPC happens; the connect path
/// never re-inspects env vars.
///
/// The same shape backs both header families — the daemon's
/// `Authorization` and the SSO proxy's `Proxy-Authorization` — because
/// they share the file/command/env source axis. The flag-name strings
/// surfaced in error messages live in the family-specific factory, not
/// in this struct.
#[derive(Debug, Default)]
pub struct BearerArgs {
    pub file: Option<PathBuf>,
    pub command: Option<String>,
}

/// Flag names surfaced when the source is ambiguous. One per bearer
/// family — daemon-bearer flags vs proxy-bearer flags — so the operator
/// sees the names they actually typed.
struct FamilyFlags {
    file: &'static str,
    command: &'static str,
    env: &'static str,
}

const DAEMON_FLAGS: FamilyFlags = FamilyFlags {
    file: "--bearer-file",
    command: "--bearer-command",
    env: "HERMOD_BEARER_TOKEN",
};

const PROXY_FLAGS: FamilyFlags = FamilyFlags {
    file: "--proxy-bearer-file",
    command: "--proxy-bearer-command",
    env: "HERMOD_PROXY_BEARER_TOKEN",
};

/// Resolve "where does the daemon-layer bearer come from" exactly once
/// at startup.
///
/// Precedence is **explicit > implicit**: any of `--bearer-file`,
/// `--bearer-command`, or `HERMOD_BEARER_TOKEN` is treated as an
/// explicit declaration, and at most one may be set. With no explicit
/// declaration `default_path` is opened via [`FileBearerProvider`] —
/// the "just works" path when the CLI runs on the same host as the
/// daemon and inherits its `bearer_token` file.
///
/// Returning a trait object means the connect path doesn't know (or
/// care) which source it got. Adding a fourth source (e.g. an OS
/// keyring lookup) is one new arm in [`resolve_source`] — no other
/// call sites change.
pub fn daemon_from_env_and_args(
    args: &BearerArgs,
    env_token: Option<SecretString>,
    default_path: PathBuf,
) -> Result<Arc<dyn BearerProvider>> {
    match resolve_source(args, env_token, &DAEMON_FLAGS)? {
        Some(p) => Ok(p),
        // Implicit fallback. Using FileBearerProvider (not Static)
        // means a `hermod bearer rotate` followed by a
        // `hermod --remote ...` in the same shell sees the new
        // token via 401-trigger refresh.
        None => Ok(Arc::new(FileBearerProvider::new(default_path))),
    }
}

/// Resolve "where does the proxy-layer bearer come from", or return
/// `None` if no source is configured.
///
/// Unlike the daemon side, there is no implicit fallback: SSO proxy
/// credentials never live at a canonical disk location. Zero sources
/// is the "no proxy in front of me" deployment shape and yields
/// `Ok(None)`; the connect path then sends only the `Authorization`
/// header.
pub fn proxy_from_env_and_args(
    args: &BearerArgs,
    env_token: Option<SecretString>,
) -> Result<Option<Arc<dyn BearerProvider>>> {
    resolve_source(args, env_token, &PROXY_FLAGS)
}

/// Shared dispatch: at most one source set, picked into a provider.
/// Returns `None` when no source is set at all (callers decide whether
/// that is an error or a valid no-source state).
fn resolve_source(
    args: &BearerArgs,
    env_token: Option<SecretString>,
    flags: &FamilyFlags,
) -> Result<Option<Arc<dyn BearerProvider>>> {
    let mut declared: Vec<&'static str> = Vec::new();
    if args.file.is_some() {
        declared.push(flags.file);
    }
    if args.command.is_some() {
        declared.push(flags.command);
    }
    if env_token.is_some() {
        declared.push(flags.env);
    }

    match declared.len() {
        0 => Ok(None),
        1 => {
            if let Some(path) = &args.file {
                Ok(Some(Arc::new(FileBearerProvider::new(path.clone()))))
            } else if let Some(cmd) = &args.command {
                Ok(Some(Arc::new(CommandBearerProvider::new(cmd.clone()))))
            } else if let Some(secret) = env_token {
                Ok(Some(Arc::new(StaticBearerProvider::new(secret))))
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

    // ---- daemon family -----------------------------------------------------

    #[tokio::test]
    async fn daemon_no_source_falls_back_to_default_path() {
        let dir = tempdir().unwrap();
        let default_path = dir.path().join("bearer_token");
        std::fs::write(&default_path, "default-tok").unwrap();
        let provider =
            daemon_from_env_and_args(&BearerArgs::default(), None, default_path).unwrap();
        let t = provider.current().await.unwrap();
        assert_eq!(t.secret().expose_secret(), "default-tok");
    }

    #[tokio::test]
    async fn daemon_explicit_file_wins() {
        let dir = tempdir().unwrap();
        let explicit = dir.path().join("explicit");
        std::fs::write(&explicit, "from-flag").unwrap();
        let unused_default = dir.path().join("unused");
        let provider = daemon_from_env_and_args(
            &BearerArgs {
                file: Some(explicit),
                command: None,
            },
            None,
            unused_default,
        )
        .unwrap();
        let t = provider.current().await.unwrap();
        assert_eq!(t.secret().expose_secret(), "from-flag");
    }

    #[tokio::test]
    async fn daemon_env_token_dispatches_static_provider() {
        let dir = tempdir().unwrap();
        let provider = daemon_from_env_and_args(
            &BearerArgs::default(),
            Some(SecretString::new("env-tok".to_string())),
            dir.path().join("unused"),
        )
        .unwrap();
        let t = provider.current().await.unwrap();
        assert_eq!(t.secret().expose_secret(), "env-tok");
        assert_eq!(t.epoch(), TokenEpoch::ZERO);
    }

    #[test]
    fn daemon_two_sources_is_ambiguous() {
        let dir = tempdir().unwrap();
        let result = daemon_from_env_and_args(
            &BearerArgs {
                file: Some(dir.path().join("a")),
                command: Some("echo b".into()),
            },
            None,
            dir.path().join("default"),
        );
        let err = result.unwrap_err().to_string();
        assert!(err.contains("ambiguous"), "got: {err}");
        assert!(err.contains("--bearer-file"));
        assert!(err.contains("--bearer-command"));
    }

    #[test]
    fn daemon_three_sources_lists_all() {
        let dir = tempdir().unwrap();
        let result = daemon_from_env_and_args(
            &BearerArgs {
                file: Some(dir.path().join("a")),
                command: Some("echo b".into()),
            },
            Some(SecretString::new("c".to_string())),
            dir.path().join("default"),
        );
        let err = result.unwrap_err().to_string();
        assert!(err.contains("--bearer-file"));
        assert!(err.contains("--bearer-command"));
        assert!(err.contains("HERMOD_BEARER_TOKEN"));
    }

    // ---- proxy family ------------------------------------------------------

    #[test]
    fn proxy_no_source_yields_none() {
        let provider = proxy_from_env_and_args(&BearerArgs::default(), None).unwrap();
        assert!(provider.is_none());
    }

    #[tokio::test]
    async fn proxy_explicit_file_wins() {
        let dir = tempdir().unwrap();
        let explicit = dir.path().join("proxy");
        std::fs::write(&explicit, "proxy-tok").unwrap();
        let provider = proxy_from_env_and_args(
            &BearerArgs {
                file: Some(explicit),
                command: None,
            },
            None,
        )
        .unwrap()
        .expect("Some");
        let t = provider.current().await.unwrap();
        assert_eq!(t.secret().expose_secret(), "proxy-tok");
    }

    #[tokio::test]
    async fn proxy_env_token_dispatches_static_provider() {
        let provider = proxy_from_env_and_args(
            &BearerArgs::default(),
            Some(SecretString::new("proxy-env".to_string())),
        )
        .unwrap()
        .expect("Some");
        let t = provider.current().await.unwrap();
        assert_eq!(t.secret().expose_secret(), "proxy-env");
        assert_eq!(t.epoch(), TokenEpoch::ZERO);
    }

    #[test]
    fn proxy_two_sources_is_ambiguous_with_proxy_flag_names() {
        let dir = tempdir().unwrap();
        let result = proxy_from_env_and_args(
            &BearerArgs {
                file: Some(dir.path().join("a")),
                command: Some("echo b".into()),
            },
            None,
        );
        let err = result.unwrap_err().to_string();
        assert!(err.contains("ambiguous"), "got: {err}");
        assert!(err.contains("--proxy-bearer-file"));
        assert!(err.contains("--proxy-bearer-command"));
        // Critical: must NOT mention the daemon-family flag names — operators
        // would chase the wrong flag.
        assert!(!err.contains("HERMOD_BEARER_TOKEN"));
    }

    #[test]
    fn proxy_three_sources_lists_all_proxy_names() {
        let dir = tempdir().unwrap();
        let result = proxy_from_env_and_args(
            &BearerArgs {
                file: Some(dir.path().join("a")),
                command: Some("echo b".into()),
            },
            Some(SecretString::new("c".to_string())),
        );
        let err = result.unwrap_err().to_string();
        assert!(err.contains("--proxy-bearer-file"));
        assert!(err.contains("--proxy-bearer-command"));
        assert!(err.contains("HERMOD_PROXY_BEARER_TOKEN"));
    }
}
