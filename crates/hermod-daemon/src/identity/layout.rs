//! Single source of truth for `$HERMOD_HOME/identity/` filesystem layout
//! and the modes its files are required to carry.
//!
//! Every entry in [`spec`] is authoritative — boot-time enforcement,
//! `hermod doctor` output, and the `chmod` hint a failed check
//! prints all derive from the same list. Adding a new identity file is
//! one new entry here; no other call site changes.
//!
//! ## Policy
//!
//! - **Directory** (`identity/`): mode 0o700. Boot fails loud on any
//!   other mode. Exposing the file *names* of secrets is information
//!   leakage even if the files themselves are 0o600.
//! - **Secret** files (`ed25519_secret`, `tls.key`, `bearer_token`):
//!   mode 0o600. Boot fails loud on any other mode. Strict equality —
//!   not a `mode & 0o077 == 0` mask — because the daemon's own writes
//!   always produce exactly 0o600 (`write_secret_atomic`). An operator
//!   who chmodded to 0o400 explicitly is still required to `chmod 0o600`
//!   to match what the daemon will produce on the next rotation; the
//!   uniform requirement removes a class of "works on my box" surprises.
//! - **Public** files (`tls.crt`): mode 0o644. Reported by `audit` for
//!   hygiene; not enforced at boot since a permissive cert mode does
//!   not breach confidentiality.
//!
//! ## No silent repair
//!
//! `enforce` never modifies the filesystem. A mode breach is a fail-loud
//! signal — auto-repair would mask an intrusion (an attacker who'd
//! chmod-relaxed a file to read it would see the daemon "fix" the mode
//! and get away with the read). Operators chmod manually; the audit
//! trail is in shell history, not in silent daemon behavior. Mirrors
//! sshd's `StrictModes`.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use super::{bearer_token_path, identity_dir, secret_path, tls_cert_path, tls_key_path};

/// One `$HERMOD_HOME/identity/` entry. The full set lives in [`spec`].
#[derive(Clone, Debug)]
pub struct IdentityFile {
    /// Operator-facing name (e.g. `"identity secret"`). Shown in
    /// boot-time error messages and `hermod doctor` output.
    pub label: &'static str,
    pub path: PathBuf,
    /// Required Unix mode bits. Strict equality.
    pub required_mode: u32,
    pub kind: IdentityFileKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityFileKind {
    /// `identity/` itself — the parent of all secret files.
    Directory,
    /// File whose contents are confidential. Boot refuses to start on
    /// permissive modes.
    Secret,
    /// File whose contents are public (advertised to peers, e.g. a
    /// TLS cert). Reported by [`audit`] for hygiene; not enforced.
    Public,
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
        /// Octal without the `0o` prefix, ready for `chmod` (e.g. `"600"`).
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

/// Single source of truth for `$HERMOD_HOME/identity/` layout.
///
/// Adding a new identity file ⇒ one new entry here; boot enforcement,
/// `hermod doctor` audit, and `chmod` hints all stay in sync
/// automatically.
pub fn spec(home: &Path) -> Vec<IdentityFile> {
    vec![
        IdentityFile {
            label: "identity directory",
            path: identity_dir(home),
            required_mode: 0o700,
            kind: IdentityFileKind::Directory,
        },
        IdentityFile {
            label: "identity secret",
            path: secret_path(home),
            required_mode: 0o600,
            kind: IdentityFileKind::Secret,
        },
        IdentityFile {
            label: "TLS private key",
            path: tls_key_path(home),
            required_mode: 0o600,
            kind: IdentityFileKind::Secret,
        },
        IdentityFile {
            label: "bearer token",
            path: bearer_token_path(home),
            required_mode: 0o600,
            kind: IdentityFileKind::Secret,
        },
        IdentityFile {
            label: "TLS certificate",
            path: tls_cert_path(home),
            required_mode: 0o644,
            kind: IdentityFileKind::Public,
        },
    ]
}

/// Create `identity/` with mode 0o700 if missing; otherwise verify.
/// Called once at the start of daemon boot, before any identity load.
#[cfg(unix)]
pub fn ensure_dir(home: &Path) -> Result<(), LayoutError> {
    use std::os::unix::fs::PermissionsExt;
    let dir = identity_dir(home);
    if !dir.exists() {
        fs::create_dir_all(&dir).map_err(|source| LayoutError::Io {
            label: "identity directory",
            path: dir.clone(),
            source,
        })?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).map_err(|source| {
            LayoutError::Io {
                label: "identity directory",
                path: dir.clone(),
                source,
            }
        })?;
        return Ok(());
    }
    check_one(&IdentityFile {
        label: "identity directory",
        path: dir,
        required_mode: 0o700,
        kind: IdentityFileKind::Directory,
    })
}

/// Verify every fail-loud entry in [`spec`] conforms.
///
/// Called from `daemon/main.rs` after `ensure_tls` / `ensure_bearer_token`
/// have run, so every secret file exists and was written with the
/// canonical mode. Public files (TLS cert) are not enforced — see
/// [`audit`] for the doctor-visible report that includes them.
#[cfg(unix)]
pub fn enforce(home: &Path) -> Result<(), LayoutError> {
    for file in spec(home) {
        if matches!(file.kind, IdentityFileKind::Public) {
            continue;
        }
        check_one(&file)?;
    }
    Ok(())
}

/// Doctor-friendly per-file audit. Returns one entry per spec'd file
/// with its conformance status, including public files. The doctor
/// renders the result without exiting.
#[cfg(unix)]
pub fn audit(home: &Path) -> Vec<(IdentityFile, Result<(), LayoutError>)> {
    spec(home)
        .into_iter()
        .map(|file| {
            let result = check_one(&file);
            (file, result)
        })
        .collect()
}

#[cfg(unix)]
fn check_one(file: &IdentityFile) -> Result<(), LayoutError> {
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
// enforce the equivalent invariant from `metadata`. Operators on those
// platforms are expected to confine `$HERMOD_HOME` via the platform's
// native ACL tooling.
#[cfg(not(unix))]
pub fn ensure_dir(home: &Path) -> Result<(), LayoutError> {
    let dir = identity_dir(home);
    if !dir.exists() {
        fs::create_dir_all(&dir).map_err(|source| LayoutError::Io {
            label: "identity directory",
            path: dir,
            source,
        })?;
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn enforce(_home: &Path) -> Result<(), LayoutError> {
    Ok(())
}

#[cfg(not(unix))]
pub fn audit(home: &Path) -> Vec<(IdentityFile, Result<(), LayoutError>)> {
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

    /// Bootstrap a tempdir as a fully-conformant identity layout —
    /// every spec'd file present with its required mode.
    fn populate_conformant(home: &Path) {
        let dir = identity_dir(home);
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        for file in spec(home) {
            if matches!(file.kind, IdentityFileKind::Directory) {
                continue;
            }
            write_file(&file.path, file.required_mode);
        }
    }

    #[test]
    fn ensure_dir_creates_with_correct_mode() {
        let tmp = TempDir::new().unwrap();
        ensure_dir(tmp.path()).unwrap();
        let mode = fs::metadata(identity_dir(tmp.path()))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn ensure_dir_rejects_existing_permissive_dir() {
        let tmp = TempDir::new().unwrap();
        let dir = identity_dir(tmp.path());
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        match ensure_dir(tmp.path()) {
            Err(LayoutError::ModeMismatch {
                observed, required, ..
            }) => {
                assert_eq!(observed, 0o755);
                assert_eq!(required, 0o700);
            }
            other => panic!("expected ModeMismatch, got {other:?}"),
        }
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
        let bearer = bearer_token_path(tmp.path());
        fs::set_permissions(&bearer, fs::Permissions::from_mode(0o644)).unwrap();
        match enforce(tmp.path()) {
            Err(LayoutError::ModeMismatch {
                label,
                observed,
                required,
                ..
            }) => {
                assert_eq!(label, "bearer token");
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
        fs::set_permissions(identity_dir(tmp.path()), fs::Permissions::from_mode(0o755)).unwrap();
        match enforce(tmp.path()) {
            Err(LayoutError::ModeMismatch {
                label,
                observed,
                required,
                ..
            }) => {
                assert_eq!(label, "identity directory");
                assert_eq!(observed, 0o755);
                assert_eq!(required, 0o700);
            }
            other => panic!("expected ModeMismatch, got {other:?}"),
        }
    }

    #[test]
    fn enforce_rejects_missing_required_secret() {
        let tmp = TempDir::new().unwrap();
        populate_conformant(tmp.path());
        fs::remove_file(secret_path(tmp.path())).unwrap();
        match enforce(tmp.path()) {
            Err(LayoutError::Missing { label, .. }) => {
                assert_eq!(label, "identity secret");
            }
            other => panic!("expected Missing, got {other:?}"),
        }
    }

    /// Public file mode mismatch is reported by `audit` but does not
    /// fail `enforce`. Verifies the kind-aware policy split.
    #[test]
    fn enforce_ignores_public_file_mode_mismatch() {
        let tmp = TempDir::new().unwrap();
        populate_conformant(tmp.path());
        fs::set_permissions(tls_cert_path(tmp.path()), fs::Permissions::from_mode(0o600)).unwrap();
        // enforce passes — TLS cert is Public kind
        enforce(tmp.path()).unwrap();
        // audit reports the discrepancy
        let findings = audit(tmp.path());
        let cert_finding = findings
            .iter()
            .find(|(f, _)| f.label == "TLS certificate")
            .expect("TLS cert in spec");
        match &cert_finding.1 {
            Err(LayoutError::ModeMismatch {
                observed, required, ..
            }) => {
                assert_eq!(*observed, 0o600);
                assert_eq!(*required, 0o644);
            }
            other => panic!("expected ModeMismatch in audit, got {other:?}"),
        }
    }

    #[test]
    fn audit_returns_one_entry_per_spec() {
        let tmp = TempDir::new().unwrap();
        populate_conformant(tmp.path());
        let findings = audit(tmp.path());
        assert_eq!(findings.len(), spec(tmp.path()).len());
        for (_, result) in &findings {
            result.as_ref().unwrap();
        }
    }

    /// The chmod hint embedded in the error must be operator-pasteable
    /// — the octal mode has no leading `0o` and the path is unquoted.
    #[test]
    fn error_message_includes_chmod_hint() {
        let err = LayoutError::ModeMismatch {
            label: "bearer token",
            path: PathBuf::from("/tmp/x"),
            observed: 0o644,
            required: 0o600,
            required_octal: "600".into(),
        };
        let s = err.to_string();
        assert!(s.contains("chmod 600 /tmp/x"), "got: {s}");
    }
}
