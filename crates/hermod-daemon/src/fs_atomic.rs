//! Atomic file write helpers shared by `host_identity` and
//! `local_agent`. Both layers persist secret material under
//! `$HERMOD_HOME` and need the same crash-safe rename + explicit-mode
//! discipline; pulling the helpers up here keeps the policy in one
//! place.
//!
//! ```text
//! Secret  → mode 0600
//! Public  → mode 0644 (overrides the daemon's 0o077 umask explicitly)
//! ```
//!
//! Both writers go through [`write_atomic_with_mode`]: open a sibling
//! temp file with the restrictive mode, write, fsync, then `rename`
//! over the target. A partial write or a crash mid-write leaves the
//! previous file in place, never a half-populated secret.

use std::fs;
use std::path::Path;

#[cfg(unix)]
pub(crate) fn write_secret_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    write_atomic_with_mode(path, bytes, 0o600)
}

#[cfg(not(unix))]
pub(crate) fn write_secret_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    fs::write(path, bytes)
}

/// Atomically write `bytes` to `path` with mode 0644 — the public-file
/// equivalent of [`write_secret_atomic`]. Used for `tls.crt`, which
/// peers fetch and which the daemon must guarantee remains canonical
/// regardless of the inherited umask (the daemon installs `umask
/// 0o077`, which would otherwise mask `0o644` → `0o600`).
#[cfg(unix)]
pub(crate) fn write_public_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    write_atomic_with_mode(path, bytes, 0o644)
}

#[cfg(not(unix))]
pub(crate) fn write_public_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    fs::write(path, bytes)
}

#[cfg(unix)]
fn write_atomic_with_mode(path: &Path, bytes: &[u8], mode: u32) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = parent.join(format!(
        ".{}.tmp.{}",
        path.file_name().and_then(|s| s.to_str()).unwrap_or("file"),
        std::process::id()
    ));

    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);

    // Explicit set_permissions overrides any process umask that may
    // have masked the OpenOptions::mode at create time. Critical for
    // public files (`tls.crt` at 0o644) under the daemon's
    // `umask 0o077`.
    fs::set_permissions(&tmp, fs::Permissions::from_mode(mode))?;

    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}
