//! Subprocess-backed bearer source.
//!
//! Backs `--bearer-command <SHELL>`. The command runs under `sh -c`,
//! inherits the caller's environment, has 30 s to print its token to
//! stdout, then is reaped. Stdout is trimmed and treated as the bearer.
//! Non-zero exit, empty stdout, or timeout each surface a typed
//! [`BearerError`] so the operator sees the auth provider's actual
//! failure mode (`gcloud auth login` expired, network down, …).
//!
//! ## Single-flight refresh
//!
//! 100 concurrent connects that all 401 must collapse into one
//! subprocess invocation. The token cache is `Mutex<Option<BearerToken>>`
//! and `refresh(stale)` only mints fresh material if the cached token's
//! epoch is `<= stale`. Callers that arrive after the lock holder has
//! already advanced the epoch get the freshly-cached value.
//!
//! ## Why not parse `exp` from the token?
//!
//! Best-effort JWT parsing is the textbook flimsy heuristic: opaque
//! OAuth bearers aren't JWTs at all, and a parse-failure either pins
//! the cache forever or pessimistically re-mints on every connect.
//! 401-trigger refresh is source-agnostic, deterministic, and
//! sufficient for any OAuth/OIDC-shaped credential.

use std::time::Duration;

use async_trait::async_trait;
use hermod_crypto::SecretString;
use tokio::process::Command;
use tokio::sync::Mutex;
use tokio::time::timeout;
use zeroize::Zeroizing;

use super::{BearerError, BearerProvider, BearerToken, TokenEpoch};

/// Hard ceiling on a single mint. `gcloud auth print-identity-token`
/// finishes in ~hundreds of ms in steady state; 30 s is generous enough
/// for a slow auth provider on a cold cache, short enough that a hung
/// command doesn't pin the CLI indefinitely.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

pub struct CommandBearerProvider {
    command: String,
    cache: Mutex<Option<BearerToken>>,
}

/// Hand-rolled `Debug` so the operator-supplied command — which can
/// legitimately embed credentials (e.g. `curl -u user:pass …`) — never
/// shows up in trace logs or panic backtraces. The cache value is also
/// elided; `BearerToken`'s own `Debug` already redacts the secret, but
/// surfacing it here would gratuitously leak the epoch via tracing.
impl std::fmt::Debug for CommandBearerProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommandBearerProvider")
            .field("command", &"<elided>")
            .finish_non_exhaustive()
    }
}

impl CommandBearerProvider {
    pub fn new(command: String) -> Self {
        Self {
            command,
            cache: Mutex::new(None),
        }
    }

    async fn run_once(&self) -> Result<SecretString, BearerError> {
        // `kill_on_drop(true)` is load-bearing: when the timeout fires
        // and the future is dropped, tokio reaps the child via SIGKILL
        // instead of letting it run detached. Without this, a wedged
        // auth provider (`gcloud` stuck on a 2FA prompt, `curl
        // --connect-timeout never`) leaks one zombie process per
        // refresh attempt over the lifetime of a long-running MCP
        // session.
        let fut = Command::new("sh")
            .arg("-c")
            .arg(&self.command)
            .kill_on_drop(true)
            .output();
        let output = match timeout(COMMAND_TIMEOUT, fut).await {
            Ok(Ok(o)) => o,
            Ok(Err(e)) => return Err(BearerError::CommandSpawn(e)),
            Err(_) => return Err(BearerError::CommandTimedOut(COMMAND_TIMEOUT)),
        };
        if !output.status.success() {
            return Err(BearerError::CommandFailed {
                code: output.status.code().unwrap_or(-1),
                command: self.command.clone(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            });
        }
        // Wrap the stdout buffer in `Zeroizing` so the secret bytes are
        // wiped when this function returns, regardless of whether
        // `from_utf8_lossy` borrows or allocates.
        let stdout_bytes = Zeroizing::new(output.stdout);
        let stdout_str = String::from_utf8_lossy(&stdout_bytes);
        let trimmed = stdout_str.trim();
        if trimmed.is_empty() {
            return Err(BearerError::Empty);
        }
        Ok(SecretString::new(trimmed.to_owned()))
    }
}

#[async_trait]
impl BearerProvider for CommandBearerProvider {
    async fn current(&self) -> Result<BearerToken, BearerError> {
        let mut guard = self.cache.lock().await;
        if let Some(t) = guard.as_ref() {
            return Ok(t.clone());
        }
        let secret = self.run_once().await?;
        let token = BearerToken::new(secret, TokenEpoch::FIRST);
        *guard = Some(token.clone());
        Ok(token)
    }

    async fn refresh(&self, stale: TokenEpoch) -> Result<BearerToken, BearerError> {
        let mut guard = self.cache.lock().await;
        if let Some(t) = guard.as_ref()
            && t.epoch() > stale
        {
            return Ok(t.clone());
        }
        let secret = self.run_once().await?;
        let next_epoch = guard
            .as_ref()
            .map(|t| t.epoch().next())
            .unwrap_or(TokenEpoch::FIRST);
        let token = BearerToken::new(secret, next_epoch);
        *guard = Some(token.clone());
        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn echo(token: &str) -> CommandBearerProvider {
        CommandBearerProvider::new(format!("printf '%s' '{token}'"))
    }

    #[tokio::test]
    async fn current_runs_command_and_caches() {
        let p = echo("abc");
        let a = p.current().await.unwrap();
        let b = p.current().await.unwrap();
        assert_eq!(a.secret().expose_secret(), "abc");
        assert_eq!(a.epoch(), b.epoch()); // cached, not re-run
    }

    #[tokio::test]
    async fn nonzero_exit_surfaces_stderr() {
        let p = CommandBearerProvider::new("echo something-broke 1>&2; exit 7".into());
        match p.current().await {
            Err(BearerError::CommandFailed { code, stderr, .. }) => {
                assert_eq!(code, 7);
                assert!(stderr.contains("something-broke"));
            }
            other => panic!("expected CommandFailed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn empty_stdout_is_rejected() {
        let p = CommandBearerProvider::new("printf ''".into());
        match p.current().await {
            Err(BearerError::Empty) => {}
            other => panic!("expected Empty, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn refresh_advances_epoch() {
        let dir = tempfile::tempdir().unwrap();
        let counter_file = dir.path().join("count");
        std::fs::write(&counter_file, "0").unwrap();
        let cmd = format!(
            r#"n=$(cat '{p}'); printf '%s' "$((n+1))" > '{p}'; printf 'tok-%s' "$((n+1))""#,
            p = counter_file.display()
        );
        let p = CommandBearerProvider::new(cmd);
        let a = p.current().await.unwrap();
        let b = p.refresh(a.epoch()).await.unwrap();
        assert!(b.epoch() > a.epoch());
        assert_eq!(a.secret().expose_secret(), "tok-1");
        assert_eq!(b.secret().expose_secret(), "tok-2");
    }

    /// Single-flight: N concurrent `refresh(epoch_zero)` calls must
    /// collapse into ≤ 1 subprocess (the second caller sees the cache
    /// already advanced past `stale`). Without the epoch check this
    /// would spawn N subprocesses serialised behind the mutex.
    #[tokio::test]
    async fn concurrent_refresh_dedups_into_one_subprocess() {
        let dir = tempfile::tempdir().unwrap();
        let counter_file = dir.path().join("count");
        std::fs::write(&counter_file, "0").unwrap();
        // Each invocation increments the counter file. Sleep 50 ms to
        // make racing invocations actually race.
        let cmd = format!(
            r#"n=$(cat '{p}'); n=$((n+1)); printf '%s' "$n" > '{p}'; sleep 0.05; printf 'tok-%s' "$n""#,
            p = counter_file.display()
        );
        let provider = Arc::new(CommandBearerProvider::new(cmd));
        // Prime the cache with epoch FIRST.
        let primed = provider.current().await.unwrap();
        // Fire 16 concurrent refreshes against the same `stale` epoch.
        let stale = primed.epoch();
        let mut handles = Vec::new();
        let observed = Arc::new(AtomicUsize::new(0));
        for _ in 0..16 {
            let p = provider.clone();
            let observed = observed.clone();
            handles.push(tokio::spawn(async move {
                let _ = p.refresh(stale).await.unwrap();
                observed.fetch_add(1, Ordering::SeqCst);
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        // The first refresh that wins the lock advances the cache;
        // every subsequent caller sees the new epoch and skips spawn.
        let final_count: usize = std::fs::read_to_string(&counter_file)
            .unwrap()
            .parse()
            .unwrap();
        // 1 prime + 1 single-flight refresh = 2 subprocess runs.
        // Allow one extra in case the very first refresh contender
        // also raced with the prime check; never more.
        assert!(
            final_count <= 2,
            "expected ≤2 subprocess runs (single-flight), got {final_count}"
        );
        assert_eq!(observed.load(Ordering::SeqCst), 16);
    }
}
