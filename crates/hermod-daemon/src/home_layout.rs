//! Single source of truth for `$HERMOD_HOME/` filesystem layout and the
//! modes its files are required to carry.
//!
//! Every entry in [`spec`] is authoritative — boot-time enforcement,
//! `hermod doctor` output, and the `chmod` hint a failed check
//! prints all derive from the same list. Adding a new file in
//! `$HERMOD_HOME` is one new entry here; no other call site changes.
//!
//! ## Policy
//!
//! Two complementary mechanisms enforce the modes:
//!
//! 1. **Umask** — [`set_secure_umask`] sets the daemon process umask
//!    to `0o077` at the very start of `main`, so every subsequent file
//!    create defaults to mode `0o600` (and every directory create to
//!    `0o700`). Mirrors systemd `UMask=0077` and OpenSSH's startup
//!    discipline. This catches files Hermod doesn't write directly
//!    (SQLite's `hermod.db-wal`, blob payloads, …).
//!
//! 2. **Boot-time enforce** — [`enforce`] verifies every spec'd file
//!    has the exact required mode after init, and refuses to start on
//!    a breach. Catches existing files an operator may have
//!    chmod-relaxed before boot (the umask only governs *new* file
//!    creates).
//!
//! ## File kinds
//!
//! - **Directory** (`$HERMOD_HOME/`, `identity/`, `blob-store/`,
//!   `archive/`): mode `0o700`. Boot fails loud on any other mode.
//!   Exposing the file *names* underneath is information leakage even
//!   if files themselves are `0o600`.
//! - **Secret** (`ed25519_secret`, `tls.key`, `bearer_token`,
//!   `hermod.db*`): mode `0o600`. Boot fails loud on permissive mode.
//!   Strict equality, not a `mode & 0o077 == 0` mask — uniform
//!   requirement removes "works on my box" surprises.
//! - **Public** (`tls.crt`): mode `0o644`. Reported by [`audit`] for
//!   hygiene; not enforced at boot since a permissive cert mode does
//!   not breach confidentiality.
//! - **OperatorManaged** (`config.toml`): the operator owns mode policy
//!   for files they edit by hand. Hermod creates it at `0o600` (the
//!   safe default for files that may carry `webhook_bearer_token`),
//!   but doesn't enforce on boot — operators who deliberately chmod
//!   `0o644` for visibility shouldn't have the daemon refuse to start.
//!
//! ## No silent repair
//!
//! [`enforce`] never modifies the filesystem. A mode breach is a
//! fail-loud signal — auto-repair would mask an intrusion (an attacker
//! who'd chmod-relaxed a file to read it would see the daemon "fix"
//! the mode and get away with the read). Operators chmod manually;
//! the audit trail is in shell history, not in silent daemon
//! behavior. Mirrors sshd's `StrictModes`.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::identity::{bearer_token_path, identity_dir, secret_path, tls_cert_path, tls_key_path};

/// Set the process umask to `0o077` so every subsequent file create
/// defaults to mode `0o600` and every directory create to `0o700`.
/// Called once at the very top of `main()` before any I/O or thread
/// spawn. Mirrors systemd `UMask=0077`. No-op on non-Unix platforms,
/// where the file-mode model doesn't apply.
#[cfg(unix)]
#[allow(unsafe_code)]
pub fn set_secure_umask() {
    // SAFETY: libc::umask is process-global but the call itself is
    // an atomic write of a single word — thread-safe by definition.
    // The daemon calls this once at the start of main() before any
    // file I/O or thread spawn, so the new value is visible to every
    // subsequent open() call without further synchronisation.
    unsafe {
        libc::umask(0o077);
    }
}

#[cfg(not(unix))]
pub fn set_secure_umask() {}

/// One `$HERMOD_HOME` entry. The full set lives in [`spec`].
#[derive(Clone, Debug)]
pub struct HomeFile {
    /// Operator-facing name (e.g. `"hermod database"`). Shown in
    /// boot-time error messages and `hermod doctor` output.
    pub label: &'static str,
    pub path: PathBuf,
    /// Required Unix mode bits. Strict equality.
    pub required_mode: u32,
    pub kind: HomeFileKind,
    pub presence: Presence,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HomeFileKind {
    /// Directory expected to be `0o700`. Boot fails loud.
    Directory,
    /// Confidential file content. Boot fails loud on permissive mode.
    Secret,
    /// Public file (advertised to peers, e.g. TLS cert). Reported by
    /// [`audit`]; not enforced at boot.
    Public,
    /// File the operator owns by hand (e.g. `config.toml`). Hermod
    /// creates it with a safe default mode but does not enforce on
    /// boot — operators may chmod for their own visibility needs.
    OperatorManaged,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Presence {
    /// Boot refuses to start if the file is missing.
    Required,
    /// File may not exist (e.g. `hermod.db-wal` before any write,
    /// `archive/` before any `--force` rotation). [`enforce`] skips
    /// missing entries; [`audit`] reports them as informational.
    Optional,
}

#[derive(Debug, thiserror::Error)]
pub enum LayoutError {
    #[error("{label} ({path}) is missing — run `hermod init`")]
    Missing { label: &'static str, path: PathBuf },
    #[error(
        "{label} ({path}) has insecure mode {observed:#o} — required {required:#o}. Run `chmod {required_octal} {path}` and retry."
    )]
    ModeMismatch {
        label: &'static str,
        path: PathBuf,
        observed: u32,
        required: u32,
        required_octal: String,
    },
    #[error("{label} ({path}): {source}")]
    Io {
        label: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

impl HomeFile {
    fn dir_required(label: &'static str, path: PathBuf) -> Self {
        Self {
            label,
            path,
            required_mode: 0o700,
            kind: HomeFileKind::Directory,
            presence: Presence::Required,
        }
    }
    fn dir_optional(label: &'static str, path: PathBuf) -> Self {
        Self {
            label,
            path,
            required_mode: 0o700,
            kind: HomeFileKind::Directory,
            presence: Presence::Optional,
        }
    }
    fn secret(label: &'static str, path: PathBuf) -> Self {
        Self {
            label,
            path,
            required_mode: 0o600,
            kind: HomeFileKind::Secret,
            presence: Presence::Required,
        }
    }
    fn secret_optional(label: &'static str, path: PathBuf) -> Self {
        Self {
            label,
            path,
            required_mode: 0o600,
            kind: HomeFileKind::Secret,
            presence: Presence::Optional,
        }
    }
    fn public(label: &'static str, path: PathBuf, mode: u32) -> Self {
        Self {
            label,
            path,
            required_mode: mode,
            kind: HomeFileKind::Public,
            presence: Presence::Required,
        }
    }
    fn operator_managed(label: &'static str, path: PathBuf, mode: u32) -> Self {
        Self {
            label,
            path,
            required_mode: mode,
            kind: HomeFileKind::OperatorManaged,
            presence: Presence::Optional,
        }
    }
}

/// Single source of truth for `$HERMOD_HOME` layout.
///
/// Adding a new file ⇒ one new entry here; boot enforcement,
/// `hermod doctor` audit, and `chmod` hints all stay in sync
/// automatically.
pub fn spec(home: &Path) -> Vec<HomeFile> {
    vec![
        // $HERMOD_HOME itself.
        HomeFile::dir_required("home directory", home.to_path_buf()),
        // Operator-managed config.
        HomeFile::operator_managed("config.toml", home.join("config.toml"), 0o600),
        // identity/ — secrets backing this agent's identity.
        HomeFile::dir_required("identity directory", identity_dir(home)),
        HomeFile::secret("identity secret", secret_path(home)),
        HomeFile::secret("TLS private key", tls_key_path(home)),
        HomeFile::secret("bearer token", bearer_token_path(home)),
        HomeFile::public("TLS certificate", tls_cert_path(home), 0o644),
        // Storage layer — SQLite database + WAL/SHM frames.
        HomeFile::secret("hermod database", home.join("hermod.db")),
        HomeFile::secret_optional("hermod database WAL", home.join("hermod.db-wal")),
        HomeFile::secret_optional("hermod database SHM", home.join("hermod.db-shm")),
        // Blob store (LocalFs backend; cloud backends have no on-disk
        // root and skip naturally via `Optional`).
        HomeFile::dir_optional("blob store directory", home.join("blob-store")),
        // Archived state (created by `hermod init --force`).
        HomeFile::dir_optional("archive directory", home.join("archive")),
    ]
}

/// Create `$HERMOD_HOME` and `identity/` with their required modes if
/// missing; verify if existing. Called early at daemon boot, before
/// any storage / identity work runs.
///
/// **Boot semantics — fail-loud.** If the directories already exist
/// with a permissive mode, returns `LayoutError::ModeMismatch` rather
/// than silently chmod'ing them. The daemon must surface the breach
/// to the operator (sshd `StrictModes` model). For the explicit
/// operator-driven bootstrap path see [`prepare_dirs`].
#[cfg(unix)]
pub fn ensure_dirs(home: &Path) -> Result<(), LayoutError> {
    use std::os::unix::fs::PermissionsExt;
    for label_path in [
        ("home directory", home.to_path_buf()),
        ("identity directory", identity_dir(home)),
    ] {
        let (label, path) = label_path;
        if !path.exists() {
            fs::create_dir_all(&path).map_err(|source| LayoutError::Io {
                label,
                path: path.clone(),
                source,
            })?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).map_err(|source| {
                LayoutError::Io {
                    label,
                    path: path.clone(),
                    source,
                }
            })?;
        } else {
            check_one(&HomeFile::dir_required(label, path))?;
        }
    }
    Ok(())
}

/// `hermod init` — explicit operator bootstrap. Creates
/// `$HERMOD_HOME` and `identity/` at mode `0o700`, **chmod'ing them
/// down if they already exist with a wider mode**. This is the
/// init-time mirror of [`ensure_dirs`]: the operator is actively
/// asking Hermod to bring the layout to a canonical state, so silent
/// repair is the right thing. Daemon boot uses the strict
/// [`ensure_dirs`] instead.
#[cfg(unix)]
pub fn prepare_dirs(home: &Path) -> Result<(), LayoutError> {
    use std::os::unix::fs::PermissionsExt;
    for (label, path) in [
        ("home directory", home.to_path_buf()),
        ("identity directory", identity_dir(home)),
    ] {
        fs::create_dir_all(&path).map_err(|source| LayoutError::Io {
            label,
            path: path.clone(),
            source,
        })?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).map_err(|source| {
            LayoutError::Io {
                label,
                path: path.clone(),
                source,
            }
        })?;
    }
    Ok(())
}

/// Verify every fail-loud entry in [`spec`] conforms.
///
/// Called from `daemon/main.rs` after `ensure_tls` / `ensure_bearer_token`
/// / `open_database` / `open_blob_store` have run, so every required
/// secret file exists and was written with the canonical mode.
/// `OperatorManaged` and `Public` entries are not enforced — see
/// [`audit`] for the doctor-visible report that includes them.
#[cfg(unix)]
pub fn enforce(home: &Path) -> Result<(), LayoutError> {
    for file in spec(home) {
        match file.kind {
            HomeFileKind::Directory | HomeFileKind::Secret => {}
            HomeFileKind::Public | HomeFileKind::OperatorManaged => continue,
        }
        match check_one(&file) {
            Ok(()) => {}
            Err(LayoutError::Missing { .. }) if file.presence == Presence::Optional => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Doctor-friendly per-file audit. Returns one entry per spec'd file
/// with its conformance status, including `Public` and
/// `OperatorManaged` files. The doctor renders the result without
/// exiting on non-fatal findings.
#[cfg(unix)]
pub fn audit(home: &Path) -> Vec<(HomeFile, Result<(), LayoutError>)> {
    spec(home)
        .into_iter()
        .map(|file| {
            let result = check_one(&file);
            (file, result)
        })
        .collect()
}

#[cfg(unix)]
fn check_one(file: &HomeFile) -> Result<(), LayoutError> {
    use std::os::unix::fs::PermissionsExt;
    let meta = match fs::metadata(&file.path) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Err(LayoutError::Missing {
                label: file.label,
                path: file.path.clone(),
            });
        }
        Err(source) => {
            return Err(LayoutError::Io {
                label: file.label,
                path: file.path.clone(),
                source,
            });
        }
    };
    let observed = meta.permissions().mode() & 0o777;
    if observed != file.required_mode {
        return Err(LayoutError::ModeMismatch {
            label: file.label,
            path: file.path.clone(),
            observed,
            required: file.required_mode,
            required_octal: format!("{:o}", file.required_mode),
        });
    }
    Ok(())
}

// Non-Unix platforms have a different ACL model — the daemon can't
// enforce the equivalent invariant from `metadata`.
#[cfg(not(unix))]
pub fn ensure_dirs(home: &Path) -> Result<(), LayoutError> {
    for path in [home.to_path_buf(), identity_dir(home)] {
        if !path.exists() {
            fs::create_dir_all(&path).map_err(|source| LayoutError::Io {
                label: "directory",
                path,
                source,
            })?;
        }
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn prepare_dirs(home: &Path) -> Result<(), LayoutError> {
    ensure_dirs(home)
}

#[cfg(not(unix))]
pub fn enforce(_home: &Path) -> Result<(), LayoutError> {
    Ok(())
}

#[cfg(not(unix))]
pub fn audit(home: &Path) -> Vec<(HomeFile, Result<(), LayoutError>)> {
    spec(home).into_iter().map(|f| (f, Ok(()))).collect()
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    fn write_file(path: &Path, mode: u32) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, b"x").unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    fn make_dir(path: &Path, mode: u32) {
        fs::create_dir_all(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    /// Bootstrap a tempdir as a fully-conformant Hermod home — every
    /// `Required` spec'd file present with its required mode and every
    /// `Optional` directory created.
    fn populate_conformant(home: &Path) {
        for file in spec(home) {
            match (file.kind, file.presence) {
                (HomeFileKind::Directory, _) => make_dir(&file.path, file.required_mode),
                (_, Presence::Required) => write_file(&file.path, file.required_mode),
                (_, Presence::Optional) => {} // skip optional non-dirs
            }
        }
    }

    #[test]
    fn ensure_dirs_creates_home_and_identity_with_correct_modes() {
        let parent = TempDir::new().unwrap();
        let home = parent.path().join("hermod");
        ensure_dirs(&home).unwrap();
        for d in [&home, &identity_dir(&home)] {
            let mode = fs::metadata(d).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "{d:?} should be 0o700, got {mode:o}");
        }
    }

    #[test]
    fn ensure_dirs_rejects_existing_permissive_home() {
        let tmp = TempDir::new().unwrap();
        // The TempDir on macOS comes back at 0o700 already; force
        // permissive to exercise the rejection path.
        fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o755)).unwrap();
        match ensure_dirs(tmp.path()) {
            Err(LayoutError::ModeMismatch {
                observed, required, ..
            }) => {
                assert_eq!(observed, 0o755);
                assert_eq!(required, 0o700);
            }
            other => panic!("expected ModeMismatch, got {other:?}"),
        }
    }

    /// `prepare_dirs` is the init-time mirror of `ensure_dirs` —
    /// it chmods existing permissive dirs *down* rather than failing.
    /// This is the operator-driven bootstrap path and silent repair
    /// is the right thing here.
    #[test]
    fn prepare_dirs_chmods_existing_permissive_dirs_down() {
        let tmp = TempDir::new().unwrap();
        // Force home + identity dirs to be permissive.
        fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let id_dir = identity_dir(tmp.path());
        fs::create_dir_all(&id_dir).unwrap();
        fs::set_permissions(&id_dir, fs::Permissions::from_mode(0o755)).unwrap();

        prepare_dirs(tmp.path()).unwrap();

        for d in [tmp.path().to_path_buf(), id_dir] {
            let mode = fs::metadata(&d).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "{d:?} should be 0o700, got {mode:o}");
        }
    }

    #[test]
    fn prepare_dirs_creates_when_missing() {
        let parent = TempDir::new().unwrap();
        let home = parent.path().join("hermod");
        prepare_dirs(&home).unwrap();
        assert_eq!(
            fs::metadata(&home).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(identity_dir(&home))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }

    #[test]
    fn enforce_passes_on_conformant_layout() {
        let tmp = TempDir::new().unwrap();
        populate_conformant(tmp.path());
        enforce(tmp.path()).unwrap();
    }

    #[test]
    fn enforce_rejects_secret_mode_breach() {
        let tmp = TempDir::new().unwrap();
        populate_conformant(tmp.path());
        let db = tmp.path().join("hermod.db");
        fs::set_permissions(&db, fs::Permissions::from_mode(0o644)).unwrap();
        match enforce(tmp.path()) {
            Err(LayoutError::ModeMismatch {
                label,
                observed,
                required,
                ..
            }) => {
                assert_eq!(label, "hermod database");
                assert_eq!(observed, 0o644);
                assert_eq!(required, 0o600);
            }
            other => panic!("expected ModeMismatch, got {other:?}"),
        }
    }

    #[test]
    fn enforce_rejects_dir_mode_breach() {
        let tmp = TempDir::new().unwrap();
        populate_conformant(tmp.path());
        let bs = tmp.path().join("blob-store");
        fs::set_permissions(&bs, fs::Permissions::from_mode(0o755)).unwrap();
        match enforce(tmp.path()) {
            Err(LayoutError::ModeMismatch {
                label,
                observed,
                required,
                ..
            }) => {
                assert_eq!(label, "blob store directory");
                assert_eq!(observed, 0o755);
                assert_eq!(required, 0o700);
            }
            other => panic!("expected ModeMismatch, got {other:?}"),
        }
    }

    #[test]
    fn enforce_skips_missing_optional_secret() {
        let tmp = TempDir::new().unwrap();
        populate_conformant(tmp.path());
        // hermod.db-wal is Optional — its absence should not fail.
        assert!(!tmp.path().join("hermod.db-wal").exists());
        enforce(tmp.path()).unwrap();
    }

    #[test]
    fn enforce_rejects_missing_required_secret() {
        let tmp = TempDir::new().unwrap();
        populate_conformant(tmp.path());
        fs::remove_file(tmp.path().join("hermod.db")).unwrap();
        match enforce(tmp.path()) {
            Err(LayoutError::Missing { label, .. }) => {
                assert_eq!(label, "hermod database");
            }
            other => panic!("expected Missing, got {other:?}"),
        }
    }

    #[test]
    fn enforce_ignores_public_and_operator_managed() {
        let tmp = TempDir::new().unwrap();
        populate_conformant(tmp.path());
        // tls.crt: Public — wrong mode is OK at boot.
        let cert = tls_cert_path(tmp.path());
        fs::set_permissions(&cert, fs::Permissions::from_mode(0o600)).unwrap();
        // config.toml: OperatorManaged — wrong mode is OK at boot.
        write_file(&tmp.path().join("config.toml"), 0o644);
        enforce(tmp.path()).unwrap();
        // …but audit() still reports the discrepancies.
        let findings = audit(tmp.path());
        let cert_finding = findings
            .iter()
            .find(|(f, _)| f.label == "TLS certificate")
            .unwrap();
        assert!(matches!(
            cert_finding.1,
            Err(LayoutError::ModeMismatch { .. })
        ));
        let cfg_finding = findings
            .iter()
            .find(|(f, _)| f.label == "config.toml")
            .unwrap();
        assert!(matches!(
            cfg_finding.1,
            Err(LayoutError::ModeMismatch { .. })
        ));
    }

    #[test]
    fn audit_returns_one_entry_per_spec() {
        let tmp = TempDir::new().unwrap();
        populate_conformant(tmp.path());
        let findings = audit(tmp.path());
        assert_eq!(findings.len(), spec(tmp.path()).len());
    }

    #[test]
    fn error_message_includes_chmod_hint() {
        let err = LayoutError::ModeMismatch {
            label: "hermod database",
            path: PathBuf::from("/tmp/x"),
            observed: 0o644,
            required: 0o600,
            required_octal: "600".into(),
        };
        let s = err.to_string();
        assert!(s.contains("chmod 600 /tmp/x"), "got: {s}");
    }

    /// Verify `set_secure_umask` actually moves the process umask to
    /// `0o077`. The umask is process-global; the inner RAII wrapper
    /// restores the prior value on panic so sibling tests aren't
    /// affected.
    #[test]
    #[allow(unsafe_code)]
    fn set_secure_umask_changes_umask() {
        let prior = unsafe { libc::umask(0o022) };
        let _restore = scopeguard::Restore(prior);

        set_secure_umask();
        // libc::umask returns the *previous* value, so calling it
        // with a sentinel reveals the umask we just installed.
        let observed = unsafe { libc::umask(prior) };
        assert_eq!(observed, 0o077);
    }

    mod scopeguard {
        pub struct Restore(pub libc::mode_t);
        impl Drop for Restore {
            fn drop(&mut self) {
                #[allow(unsafe_code)]
                unsafe {
                    libc::umask(self.0);
                }
            }
        }
    }
}
