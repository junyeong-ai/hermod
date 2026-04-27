use std::path::{Path, PathBuf};
use tokio::net::{UnixListener, UnixStream};
use tracing::warn;

use crate::error::TransportError;

/// Convenience wrapper over `tokio::net::UnixStream`.
pub type UnixIpcStream = UnixStream;

/// Unix-socket listener that manages socket-file lifecycle:
/// - On `bind`, removes any stale socket file at the path first.
/// - On drop, removes the socket file.
#[derive(Debug)]
pub struct UnixIpcListener {
    listener: UnixListener,
    path: PathBuf,
}

impl UnixIpcListener {
    /// Bind a new listener, replacing any stale socket file at `path`.
    /// The parent directory must already exist.
    ///
    /// On Unix the socket file is forced to mode 0600 immediately after
    /// bind so a peer process can't connect by virtue of being on the
    /// same machine — the operator's UID owns the socket, full stop.
    /// We use the umask-temp pattern (set umask, bind, restore umask)
    /// rather than `chmod` after bind so there is no window during which
    /// the socket exists with looser permissions.
    pub async fn bind(path: impl AsRef<Path>) -> Result<Self, TransportError> {
        let path = path.as_ref().to_path_buf();
        if path.exists() {
            // If it's a socket and we can connect, refuse to clobber.
            if try_ping_existing(&path).await {
                return Err(TransportError::AddrInUse(format!("{}", path.display())));
            }
            // Otherwise assume stale; remove.
            let _ = std::fs::remove_file(&path);
        }
        let listener = bind_locked_down(&path)?;
        Ok(Self { listener, path })
    }

    pub async fn accept(&self) -> Result<UnixIpcStream, TransportError> {
        let (stream, _addr) = self.listener.accept().await?;
        Ok(stream)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for UnixIpcListener {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_file(&self.path) {
            // ENOENT is fine (already gone).
            if e.kind() != std::io::ErrorKind::NotFound {
                warn!(path = %self.path.display(), error = %e, "removing socket on drop");
            }
        }
    }
}

pub async fn connect(path: impl AsRef<Path>) -> Result<UnixIpcStream, TransportError> {
    let stream = UnixStream::connect(path.as_ref()).await?;
    Ok(stream)
}

/// Bind a Unix listener with mode 0600. We use a per-thread umask flip
/// rather than chmod-after-bind: the latter leaves a window during which
/// another process could `connect()`, which on some kernels survives the
/// later mode-tightening. Note: `umask` is process-global, so this is
/// briefly visible to other threads in this process; in practice nothing
/// else in `hermodd`'s startup is racing socket creation.
#[cfg(unix)]
fn bind_locked_down(path: &Path) -> Result<UnixListener, TransportError> {
    use std::os::unix::fs::PermissionsExt;
    // 0o077 strips group + world bits, so umask(0o077) ANDed with the
    // 0o666 default yields 0o600. Restore whatever the operator had.
    let prior = libc_umask(0o077);
    // The single legitimate `UnixListener::bind` site — every other path
    // is gated to `UnixIpcListener` by clippy.toml.
    #[allow(clippy::disallowed_methods)]
    let result = UnixListener::bind(path);
    libc_umask(prior);
    let listener = result?;
    // Belt and braces: enforce mode after the fact too. If the FS doesn't
    // honor umask (rare; some tmpfs / overlay setups), this catches it.
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    Ok(listener)
}

#[cfg(not(unix))]
fn bind_locked_down(path: &Path) -> Result<UnixListener, TransportError> {
    #[allow(clippy::disallowed_methods)]
    Ok(UnixListener::bind(path)?)
}

/// FFI wrapper for `umask(2)`. The crate denies `unsafe_code` globally;
/// this single call is allow-listed because there is no safe equivalent
/// in `std` for atomically narrowing the file-creation mask before bind.
/// The function is process-global by definition (POSIX), so no Rust
/// invariant can be violated.
#[cfg(unix)]
#[allow(unsafe_code)]
fn libc_umask(mask: u32) -> u32 {
    unsafe extern "C" {
        fn umask(mask: u32) -> u32;
    }
    unsafe { umask(mask) }
}

async fn try_ping_existing(path: &Path) -> bool {
    // Quick check: can we connect? If yes, a live daemon owns this path.
    tokio::time::timeout(
        std::time::Duration::from_millis(200),
        UnixStream::connect(path),
    )
    .await
    .ok()
    .and_then(|r| r.ok())
    .is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn listener_accepts_connection() {
        let mut p = std::env::temp_dir();
        p.push(format!("hermod-unix-test-{}.sock", ulid::Ulid::new()));
        let listener = UnixIpcListener::bind(&p).await.unwrap();

        let server = tokio::spawn(async move {
            let mut s = listener.accept().await.unwrap();
            s.write_all(b"hi").await.unwrap();
            s.shutdown().await.unwrap();
        });

        let mut c = connect(&p).await.unwrap();
        let mut buf = Vec::new();
        c.read_to_end(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hi");
        server.await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn socket_file_is_locked_to_owner() {
        use std::os::unix::fs::PermissionsExt;
        let mut p = std::env::temp_dir();
        p.push(format!("hermod-unix-perms-{}.sock", ulid::Ulid::new()));
        let _listener = UnixIpcListener::bind(&p).await.unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "daemon socket must be owner-only (got {mode:o})"
        );
    }
}
