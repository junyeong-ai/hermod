//! File-backed bearer source.
//!
//! Reads the token from a path on disk. Used by:
//!
//!   * `--bearer-file <PATH>` / `--proxy-bearer-file <PATH>` —
//!     explicit operator-supplied path for the daemon and proxy
//!     bearer families respectively.
//!   * Implicit default (daemon family only) —
//!     `$HERMOD_HOME/identity/bearer_token` when no explicit
//!     daemon-bearer source is declared. The proxy family has no
//!     implicit fallback (no canonical disk location for SSO proxy
//!     credentials).
//!
//! The cold path reads the file once and caches the result for the rest
//! of the process lifetime. Re-reads happen only via [`refresh`], which
//! the connect path triggers exactly once per HTTP 401 / 407 (see
//! [`crate::remote::connect_remote_with_refresh`]). This matches the
//! [`CommandBearerProvider`] model: deterministic, source-agnostic
//! refresh, no time-based heuristics that could silently advance the
//! epoch out from under an in-flight retry.
//!
//! `hermod bearer rotate` followed by an in-shell `hermod --remote …`
//! still works: the new connect 401s on the old cached token, refresh
//! re-reads the file, the retry succeeds.
//!
//! [`refresh`]: BearerProvider::refresh
//! [`CommandBearerProvider`]: super::CommandBearerProvider

use std::path::PathBuf;

use async_trait::async_trait;
use hermod_crypto::SecretString;
use tokio::sync::Mutex;

use super::{BearerError, BearerProvider, BearerToken, TokenEpoch};

#[derive(Debug)]
pub struct FileBearerProvider {
    path: PathBuf,
    cache: Mutex<Option<BearerToken>>,
}

impl FileBearerProvider {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            cache: Mutex::new(None),
        }
    }

    fn read_disk(&self) -> Result<SecretString, BearerError> {
        // Routes through the hermod-crypto helper so the intermediate
        // String buffer holding the file bytes is wiped via `Zeroizing`
        // when this returns — the secret never lives in unzeroed
        // memory beyond this function.
        hermod_crypto::secret::read_secret_file(&self.path)
            .map_err(|e| BearerError::FileRead {
                path: self.path.clone(),
                source: e,
            })?
            .ok_or(BearerError::Empty)
    }
}

#[async_trait]
impl BearerProvider for FileBearerProvider {
    async fn current(&self) -> Result<BearerToken, BearerError> {
        let mut guard = self.cache.lock().await;
        if let Some(t) = guard.as_ref() {
            return Ok(t.clone());
        }
        let secret = self.read_disk()?;
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
        let secret = self.read_disk()?;
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
    use tempfile::tempdir;

    #[tokio::test]
    async fn reads_trimmed_file_contents() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("bt");
        std::fs::write(&p, "  abc-token\n").unwrap();
        let prov = FileBearerProvider::new(p);
        let t = prov.current().await.unwrap();
        assert_eq!(t.secret().expose_secret(), "abc-token");
        assert_eq!(t.epoch(), TokenEpoch::FIRST);
    }

    #[tokio::test]
    async fn current_caches_and_does_not_re_read_on_external_change() {
        // Long-running processes (mcp) expect current() to be stable —
        // only refresh() should re-read disk. Otherwise a 401-retry
        // could observe a silently-advanced epoch and skip the re-mint.
        let dir = tempdir().unwrap();
        let p = dir.path().join("bt");
        std::fs::write(&p, "first").unwrap();
        let prov = FileBearerProvider::new(p.clone());
        let a = prov.current().await.unwrap();

        std::fs::write(&p, "second").unwrap();
        let b = prov.current().await.unwrap();
        assert_eq!(a.secret().expose_secret(), "first");
        assert_eq!(b.secret().expose_secret(), "first");
        assert_eq!(a.epoch(), b.epoch());
    }

    #[tokio::test]
    async fn refresh_reads_new_value_and_advances_epoch() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("bt");
        std::fs::write(&p, "first").unwrap();
        let prov = FileBearerProvider::new(p.clone());
        let a = prov.current().await.unwrap();

        std::fs::write(&p, "second").unwrap();
        let b = prov.refresh(a.epoch()).await.unwrap();

        assert_eq!(a.secret().expose_secret(), "first");
        assert_eq!(b.secret().expose_secret(), "second");
        assert!(b.epoch() > a.epoch());
    }

    #[tokio::test]
    async fn refresh_returns_cached_when_already_advanced() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("bt");
        std::fs::write(&p, "first").unwrap();
        let prov = FileBearerProvider::new(p.clone());
        let a = prov.current().await.unwrap();

        std::fs::write(&p, "second").unwrap();
        let b = prov.refresh(a.epoch()).await.unwrap();

        // Second caller sees the already-advanced cache; no re-read.
        std::fs::write(&p, "third").unwrap();
        let c = prov.refresh(a.epoch()).await.unwrap();
        assert_eq!(b.epoch(), c.epoch());
        assert_eq!(c.secret().expose_secret(), "second");
    }

    #[tokio::test]
    async fn missing_file_surfaces_typed_error() {
        let prov = FileBearerProvider::new(PathBuf::from("/nonexistent/bearer"));
        let err = prov.current().await.unwrap_err();
        match err {
            BearerError::FileRead { .. } => {}
            other => panic!("expected FileRead, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn empty_file_is_rejected() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("bt");
        std::fs::write(&p, "   \n  ").unwrap();
        let prov = FileBearerProvider::new(p);
        match prov.current().await {
            Err(BearerError::Empty) => {}
            other => panic!("expected Empty, got {other:?}"),
        }
    }

    /// Single-flight: N concurrent `refresh(stale)` calls dedup into
    /// exactly one disk re-read past the lock holder, mirroring the
    /// `CommandBearerProvider` invariant. Without the epoch check every
    /// caller would `read_disk()` even though only the first needs to.
    #[tokio::test]
    async fn concurrent_refresh_dedups_into_one_re_read() {
        use std::collections::HashSet;
        use std::sync::Arc;

        let dir = tempdir().unwrap();
        let p = dir.path().join("bt");
        std::fs::write(&p, "first").unwrap();
        let prov = Arc::new(FileBearerProvider::new(p.clone()));

        let primed = prov.current().await.unwrap();
        let stale = primed.epoch();
        std::fs::write(&p, "second").unwrap();

        let mut handles = Vec::new();
        for _ in 0..16 {
            let prov = prov.clone();
            handles.push(tokio::spawn(
                async move { prov.refresh(stale).await.unwrap() },
            ));
        }
        let mut epochs = HashSet::new();
        for h in handles {
            epochs.insert(h.await.unwrap().epoch());
        }
        // Every racer ends up with the same advanced epoch — one disk
        // read collapsed N concurrent refreshes.
        assert_eq!(
            epochs.len(),
            1,
            "single-flight broken — got distinct epochs: {epochs:?}"
        );
        assert_eq!(*epochs.iter().next().unwrap(), stale.next());
    }
}
