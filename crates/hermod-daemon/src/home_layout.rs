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
//! - **Directory** (`$HERMOD_HOME/`, `host/`, `agents/`,
//!   `agents/<id>/`, `blob-store/`, `archive/`): mode `0o700`. Boot
//!   fails loud on any other mode. Exposing the file *names*
//!   underneath is information leakage even if files themselves are
//!   `0o600`.
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

use hermod_core::AgentId;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::host_identity::{
    host_dir, secret_path as host_secret_path, tls_cert_path, tls_key_path,
};
use crate::local_agent::{
    agent_dir, agents_dir, alias_path as agent_alias_path, bearer_token_path as agent_bearer_path,
    secret_path as agent_secret_path,
};

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
    /// boot-time error messages and `hermod doctor` output. Owned to
    /// accommodate per-agent labels (e.g. `"local agent <id> bearer
    /// token"`) that can't be `&'static str`.
    pub label: String,
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
    Missing { label: String, path: PathBuf },
    #[error(
        "{label} ({path}) has insecure mode {observed:#o} — required {required:#o}. Run `chmod {required_octal} {path}` and retry."
    )]
    ModeMismatch {
        label: String,
        path: PathBuf,
        observed: u32,
        required: u32,
        required_octal: String,
    },
    #[error("{label} ({path}): {source}")]
    Io {
        label: String,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

impl HomeFile {
    fn dir_required(label: impl Into<String>, path: PathBuf) -> Self {
        Self {
            label: label.into(),
            path,
            required_mode: 0o700,
            kind: HomeFileKind::Directory,
            presence: Presence::Required,
        }
    }
    fn dir_optional(label: impl Into<String>, path: PathBuf) -> Self {
        Self {
            label: label.into(),
            path,
            required_mode: 0o700,
            kind: HomeFileKind::Directory,
            presence: Presence::Optional,
        }
    }
    fn secret(label: impl Into<String>, path: PathBuf) -> Self {
        Self {
            label: label.into(),
            path,
            required_mode: 0o600,
            kind: HomeFileKind::Secret,
            presence: Presence::Required,
        }
    }
    fn secret_optional(label: impl Into<String>, path: PathBuf) -> Self {
        Self {
            label: label.into(),
            path,
            required_mode: 0o600,
            kind: HomeFileKind::Secret,
            presence: Presence::Optional,
        }
    }
    fn public(label: impl Into<String>, path: PathBuf, mode: u32) -> Self {
        Self {
            label: label.into(),
            path,
            required_mode: mode,
            kind: HomeFileKind::Public,
            presence: Presence::Required,
        }
    }
    fn operator_managed(label: impl Into<String>, path: PathBuf, mode: u32) -> Self {
        Self {
            label: label.into(),
            path,
            required_mode: mode,
            kind: HomeFileKind::OperatorManaged,
            presence: Presence::Optional,
        }
    }
}

/// Single source of truth for `$HERMOD_HOME` layout.
///
/// Adding a new daemon-owned file ⇒ one new entry here. Storage-
/// owned files (database, WAL/SHM, blob store root) are declared by
/// `hermod_storage::{database_local_files, blob_store_local_files}`
/// and folded in below; adding a new backend or backend-local file
/// is one new entry in the storage layer, no change here.
///
/// `local_agents` is the list of agent IDs the daemon hosts (resolved
/// from `local_agent::scan_disk` at boot, or from the same scan at
/// `hermod doctor` time). For each agent, the spec emits a per-agent
/// directory entry plus its keypair + bearer token. Empty list ⇒ no
/// per-agent entries; the parent `agents/` directory is then Optional.
///
/// Both DSNs should already have `$HERMOD_HOME` expanded
/// (via [`crate::paths::expand_dsn`]) so they describe the canonical
/// on-disk paths the daemon will actually write. DSN errors are
/// deferred to `hermod_storage::open_database` /
/// `hermod_storage::open_blob_store`, which run a moment later at
/// boot and report the same error with full backend context.
pub fn spec(
    home: &Path,
    storage_dsn: &str,
    blob_dsn: &str,
    local_agents: &[AgentId],
) -> Vec<HomeFile> {
    let mut files = vec![
        // $HERMOD_HOME itself.
        HomeFile::dir_required("home directory", home.to_path_buf()),
        // Operator-managed config.
        HomeFile::operator_managed("config.toml", home.join("config.toml"), 0o600),
        // host/ — daemon's network-level identity (Noise XX static + TLS).
        HomeFile::dir_required("host directory", host_dir(home)),
        HomeFile::secret("host secret", host_secret_path(home)),
        HomeFile::secret("TLS private key", tls_key_path(home)),
        HomeFile::public("TLS certificate", tls_cert_path(home), 0o644),
    ];
    // agents/ — per-tenant identity material. Required when the
    // daemon hosts at least one local agent; Optional in the
    // pre-bootstrap window between `hermod init` running prepare_dirs
    // and the daemon actually generating its first agent.
    if local_agents.is_empty() {
        files.push(HomeFile::dir_optional("agents directory", agents_dir(home)));
    } else {
        files.push(HomeFile::dir_required("agents directory", agents_dir(home)));
        for id in local_agents {
            files.push(HomeFile::dir_required(
                format!("local agent {id} directory"),
                agent_dir(home, id),
            ));
            files.push(HomeFile::secret(
                format!("local agent {id} secret"),
                agent_secret_path(home, id),
            ));
            files.push(HomeFile::secret(
                format!("local agent {id} bearer token"),
                agent_bearer_path(home, id),
            ));
            files.push(HomeFile::operator_managed(
                format!("local agent {id} alias"),
                agent_alias_path(home, id),
                0o644,
            ));
        }
    }
    files.extend(
        hermod_storage::database_local_files(storage_dsn)
            .unwrap_or_default()
            .into_iter()
            .map(HomeFile::from),
    );
    files.extend(
        hermod_storage::blob_store_local_files(blob_dsn)
            .unwrap_or_default()
            .into_iter()
            .map(HomeFile::from),
    );
    // Archived state (created by `hermod init --force`).
    files.push(HomeFile::dir_optional(
        "archive directory",
        home.join("archive"),
    ));
    files
}

impl From<hermod_storage::LocalFile> for HomeFile {
    fn from(lf: hermod_storage::LocalFile) -> Self {
        use hermod_storage::{LocalFileKind, LocalFilePresence};
        match (lf.kind, lf.presence) {
            (LocalFileKind::Secret, LocalFilePresence::Required) => {
                HomeFile::secret(lf.label, lf.path)
            }
            (LocalFileKind::Secret, LocalFilePresence::Optional) => {
                HomeFile::secret_optional(lf.label, lf.path)
            }
            (LocalFileKind::Directory, LocalFilePresence::Required) => {
                HomeFile::dir_required(lf.label, lf.path)
            }
            (LocalFileKind::Directory, LocalFilePresence::Optional) => {
                HomeFile::dir_optional(lf.label, lf.path)
            }
        }
    }
}

/// Create `$HERMOD_HOME` and `host/` with their required modes if
/// missing; verify if existing. Called early at daemon boot, before
/// any storage / identity work runs. The agents/ parent and per-agent
/// subdirectories are managed lazily by [`crate::local_agent`] —
/// they're created when the bootstrap agent is provisioned, not at
/// generic layout-prep time.
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
        ("host directory", host_dir(home)),
    ] {
        let (label, path) = label_path;
        if !path.exists() {
            fs::create_dir_all(&path).map_err(|source| LayoutError::Io {
                label: label.to_string(),
                path: path.clone(),
                source,
            })?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).map_err(|source| {
                LayoutError::Io {
                    label: label.to_string(),
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
/// `$HERMOD_HOME` and `host/` at mode `0o700`, **chmod'ing them
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
        ("host directory", host_dir(home)),
    ] {
        fs::create_dir_all(&path).map_err(|source| LayoutError::Io {
            label: label.to_string(),
            path: path.clone(),
            source,
        })?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).map_err(|source| {
            LayoutError::Io {
                label: label.to_string(),
                path: path.clone(),
                source,
            }
        })?;
    }
    Ok(())
}

/// Verify every fail-loud entry in [`spec`] conforms.
///
/// Called from `daemon/main.rs` after `ensure_tls` /
/// `ensure_local_agents` / `open_database` / `open_blob_store` have
/// run, so every required secret file exists and was written with
/// the canonical mode. `OperatorManaged` and `Public` entries are
/// not enforced — see [`audit`] for the doctor-visible report that
/// includes them.
#[cfg(unix)]
pub fn enforce(
    home: &Path,
    storage_dsn: &str,
    blob_dsn: &str,
    local_agents: &[AgentId],
) -> Result<(), LayoutError> {
    for file in spec(home, storage_dsn, blob_dsn, local_agents) {
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
pub fn audit(
    home: &Path,
    storage_dsn: &str,
    blob_dsn: &str,
    local_agents: &[AgentId],
) -> Vec<(HomeFile, Result<(), LayoutError>)> {
    spec(home, storage_dsn, blob_dsn, local_agents)
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
                label: file.label.clone(),
                path: file.path.clone(),
            });
        }
        Err(source) => {
            return Err(LayoutError::Io {
                label: file.label.clone(),
                path: file.path.clone(),
                source,
            });
        }
    };
    let observed = meta.permissions().mode() & 0o777;
    if observed != file.required_mode {
        return Err(LayoutError::ModeMismatch {
            label: file.label.clone(),
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
    for path in [home.to_path_buf(), host_dir(home)] {
        if !path.exists() {
            fs::create_dir_all(&path).map_err(|source| LayoutError::Io {
                label: "directory".to_string(),
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
pub fn enforce(
    _home: &Path,
    _storage_dsn: &str,
    _blob_dsn: &str,
    _local_agents: &[AgentId],
) -> Result<(), LayoutError> {
    Ok(())
}

#[cfg(not(unix))]
pub fn audit(
    home: &Path,
    storage_dsn: &str,
    blob_dsn: &str,
    local_agents: &[AgentId],
) -> Vec<(HomeFile, Result<(), LayoutError>)> {
    spec(home, storage_dsn, blob_dsn, local_agents)
        .into_iter()
        .map(|f| (f, Ok(())))
        .collect()
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::local_agent;
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

    fn sqlite_dsn(home: &Path) -> String {
        format!("sqlite://{}/hermod.db", home.display())
    }
    fn local_blob_dsn(home: &Path) -> String {
        format!("file://{}/blob-store", home.display())
    }

    /// Bootstrap a tempdir as a fully-conformant Hermod home — every
    /// `Required` spec'd file present with its required mode and every
    /// `Optional` directory created. Provisions one local agent so
    /// the agents/ block is part of the spec.
    fn populate_conformant(home: &Path) -> Vec<AgentId> {
        let agent = local_agent::create_bootstrap(home, None).unwrap();
        let ids = vec![agent.agent_id.clone()];
        for file in spec(home, &sqlite_dsn(home), &local_blob_dsn(home), &ids) {
            match (file.kind, file.presence) {
                (HomeFileKind::Directory, _) => {
                    if !file.path.exists() {
                        make_dir(&file.path, file.required_mode);
                    } else {
                        fs::set_permissions(
                            &file.path,
                            fs::Permissions::from_mode(file.required_mode),
                        )
                        .unwrap();
                    }
                }
                (_, Presence::Required) => {
                    if !file.path.exists() {
                        write_file(&file.path, file.required_mode);
                    } else {
                        fs::set_permissions(
                            &file.path,
                            fs::Permissions::from_mode(file.required_mode),
                        )
                        .unwrap();
                    }
                }
                (_, Presence::Optional) => {} // skip optional non-dirs
            }
        }
        ids
    }

    #[test]
    fn ensure_dirs_creates_home_and_host_with_correct_modes() {
        let parent = TempDir::new().unwrap();
        let home = parent.path().join("hermod");
        ensure_dirs(&home).unwrap();
        for d in [&home, &host_dir(&home)] {
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

    #[test]
    fn prepare_dirs_chmods_existing_permissive_dirs_down() {
        let tmp = TempDir::new().unwrap();
        fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let host = host_dir(tmp.path());
        fs::create_dir_all(&host).unwrap();
        fs::set_permissions(&host, fs::Permissions::from_mode(0o755)).unwrap();

        prepare_dirs(tmp.path()).unwrap();

        for d in [tmp.path().to_path_buf(), host] {
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
            fs::metadata(host_dir(&home)).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    #[test]
    fn enforce_passes_on_conformant_layout() {
        let tmp = TempDir::new().unwrap();
        let ids = populate_conformant(tmp.path());
        enforce(
            tmp.path(),
            &sqlite_dsn(tmp.path()),
            &local_blob_dsn(tmp.path()),
            &ids,
        )
        .unwrap();
    }

    #[test]
    fn enforce_rejects_secret_mode_breach() {
        let tmp = TempDir::new().unwrap();
        let ids = populate_conformant(tmp.path());
        let db = tmp.path().join("hermod.db");
        fs::set_permissions(&db, fs::Permissions::from_mode(0o644)).unwrap();
        match enforce(
            tmp.path(),
            &sqlite_dsn(tmp.path()),
            &local_blob_dsn(tmp.path()),
            &ids,
        ) {
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
        let ids = populate_conformant(tmp.path());
        let bs = tmp.path().join("blob-store");
        fs::set_permissions(&bs, fs::Permissions::from_mode(0o755)).unwrap();
        match enforce(
            tmp.path(),
            &sqlite_dsn(tmp.path()),
            &local_blob_dsn(tmp.path()),
            &ids,
        ) {
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
    fn enforce_rejects_per_agent_secret_breach() {
        let tmp = TempDir::new().unwrap();
        let ids = populate_conformant(tmp.path());
        let id = &ids[0];
        let secret = local_agent::secret_path(tmp.path(), id);
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o644)).unwrap();
        match enforce(
            tmp.path(),
            &sqlite_dsn(tmp.path()),
            &local_blob_dsn(tmp.path()),
            &ids,
        ) {
            Err(LayoutError::ModeMismatch {
                label,
                observed,
                required,
                ..
            }) => {
                assert!(
                    label.contains(id.as_str()) && label.contains("secret"),
                    "label was {label}"
                );
                assert_eq!(observed, 0o644);
                assert_eq!(required, 0o600);
            }
            other => panic!("expected ModeMismatch, got {other:?}"),
        }
    }

    #[test]
    fn enforce_skips_missing_optional_secret() {
        let tmp = TempDir::new().unwrap();
        let ids = populate_conformant(tmp.path());
        // hermod.db-wal is Optional — its absence should not fail.
        assert!(!tmp.path().join("hermod.db-wal").exists());
        enforce(
            tmp.path(),
            &sqlite_dsn(tmp.path()),
            &local_blob_dsn(tmp.path()),
            &ids,
        )
        .unwrap();
    }

    #[test]
    fn enforce_rejects_missing_required_secret() {
        let tmp = TempDir::new().unwrap();
        let ids = populate_conformant(tmp.path());
        fs::remove_file(tmp.path().join("hermod.db")).unwrap();
        match enforce(
            tmp.path(),
            &sqlite_dsn(tmp.path()),
            &local_blob_dsn(tmp.path()),
            &ids,
        ) {
            Err(LayoutError::Missing { label, .. }) => {
                assert_eq!(label, "hermod database");
            }
            other => panic!("expected Missing, got {other:?}"),
        }
    }

    #[test]
    fn enforce_ignores_public_and_operator_managed() {
        let tmp = TempDir::new().unwrap();
        let ids = populate_conformant(tmp.path());
        // tls.crt: Public — wrong mode is OK at boot.
        let cert = tls_cert_path(tmp.path());
        fs::set_permissions(&cert, fs::Permissions::from_mode(0o600)).unwrap();
        // config.toml: OperatorManaged — wrong mode is OK at boot.
        write_file(&tmp.path().join("config.toml"), 0o644);
        enforce(
            tmp.path(),
            &sqlite_dsn(tmp.path()),
            &local_blob_dsn(tmp.path()),
            &ids,
        )
        .unwrap();
        // …but audit() still reports the discrepancies.
        let findings = audit(
            tmp.path(),
            &sqlite_dsn(tmp.path()),
            &local_blob_dsn(tmp.path()),
            &ids,
        );
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
        let ids = populate_conformant(tmp.path());
        let storage = sqlite_dsn(tmp.path());
        let blob = local_blob_dsn(tmp.path());
        let findings = audit(tmp.path(), &storage, &blob, &ids);
        assert_eq!(
            findings.len(),
            spec(tmp.path(), &storage, &blob, &ids).len()
        );
    }

    #[test]
    fn spec_includes_sqlite_triplet_for_sqlite_dsn() {
        let tmp = TempDir::new().unwrap();
        let labels: Vec<String> = spec(
            tmp.path(),
            &sqlite_dsn(tmp.path()),
            &local_blob_dsn(tmp.path()),
            &[],
        )
        .into_iter()
        .map(|f| f.label)
        .collect();
        assert!(labels.iter().any(|l| l == "hermod database"));
        assert!(labels.iter().any(|l| l == "hermod database WAL"));
        assert!(labels.iter().any(|l| l == "hermod database SHM"));
    }

    #[test]
    fn spec_omits_sqlite_triplet_for_postgres_dsn() {
        let tmp = TempDir::new().unwrap();
        let labels: Vec<String> = spec(
            tmp.path(),
            "postgres://hermod@db/hermod",
            &local_blob_dsn(tmp.path()),
            &[],
        )
        .into_iter()
        .map(|f| f.label)
        .collect();
        assert!(!labels.iter().any(|l| l == "hermod database"));
        assert!(!labels.iter().any(|l| l == "hermod database WAL"));
        assert!(!labels.iter().any(|l| l == "hermod database SHM"));
    }

    #[test]
    fn spec_includes_blob_dir_for_local_blob_dsn() {
        let tmp = TempDir::new().unwrap();
        let labels: Vec<String> = spec(
            tmp.path(),
            &sqlite_dsn(tmp.path()),
            &local_blob_dsn(tmp.path()),
            &[],
        )
        .into_iter()
        .map(|f| f.label)
        .collect();
        assert!(labels.iter().any(|l| l == "blob store directory"));
    }

    #[test]
    fn spec_omits_blob_dir_for_memory_blob_dsn() {
        let tmp = TempDir::new().unwrap();
        let labels: Vec<String> = spec(tmp.path(), &sqlite_dsn(tmp.path()), "memory://", &[])
            .into_iter()
            .map(|f| f.label)
            .collect();
        assert!(!labels.iter().any(|l| l == "blob store directory"));
    }

    #[test]
    fn spec_emits_one_block_per_local_agent() {
        let tmp = TempDir::new().unwrap();
        // No on-disk material needed — spec works off the agent_id
        // list alone. Two fresh keypairs give two distinct ids.
        let a = hermod_crypto::Keypair::generate().agent_id();
        let b = hermod_crypto::Keypair::generate().agent_id();
        let ids = vec![a, b];
        let labels: Vec<String> = spec(
            tmp.path(),
            &sqlite_dsn(tmp.path()),
            &local_blob_dsn(tmp.path()),
            &ids,
        )
        .into_iter()
        .map(|f| f.label)
        .collect();
        for id in &ids {
            assert!(
                labels
                    .iter()
                    .any(|l| l.contains(id.as_str()) && l.ends_with("directory")),
                "missing directory entry for {id}"
            );
            assert!(
                labels
                    .iter()
                    .any(|l| l.contains(id.as_str()) && l.ends_with("secret")),
                "missing secret entry for {id}"
            );
            assert!(
                labels
                    .iter()
                    .any(|l| l.contains(id.as_str()) && l.ends_with("bearer token")),
                "missing bearer token entry for {id}"
            );
        }
    }

    #[test]
    fn spec_marks_agents_dir_optional_when_no_local_agents() {
        let tmp = TempDir::new().unwrap();
        let entry = spec(
            tmp.path(),
            &sqlite_dsn(tmp.path()),
            &local_blob_dsn(tmp.path()),
            &[],
        )
        .into_iter()
        .find(|f| f.label == "agents directory")
        .unwrap();
        assert_eq!(entry.presence, Presence::Optional);
    }

    /// A Postgres-backed daemon with cloud-blob backend must boot
    /// cleanly even when no `$HERMOD_HOME/hermod.db` and no
    /// `$HERMOD_HOME/blob-store/` exist. Both axes drop their entries
    /// from the spec, leaving only the identity-managed files.
    #[test]
    fn enforce_passes_postgres_with_memory_blob_layout() {
        let tmp = TempDir::new().unwrap();
        let agent = local_agent::create_bootstrap(tmp.path(), None).unwrap();
        let ids = vec![agent.agent_id.clone()];
        for file in spec(tmp.path(), "postgres://hermod@db/hermod", "memory://", &ids) {
            match (file.kind, file.presence) {
                (HomeFileKind::Directory, _) => {
                    if !file.path.exists() {
                        make_dir(&file.path, file.required_mode);
                    } else {
                        fs::set_permissions(
                            &file.path,
                            fs::Permissions::from_mode(file.required_mode),
                        )
                        .unwrap();
                    }
                }
                (_, Presence::Required) => {
                    if !file.path.exists() {
                        write_file(&file.path, file.required_mode);
                    } else {
                        fs::set_permissions(
                            &file.path,
                            fs::Permissions::from_mode(file.required_mode),
                        )
                        .unwrap();
                    }
                }
                (_, Presence::Optional) => {}
            }
        }
        assert!(!tmp.path().join("hermod.db").exists());
        assert!(!tmp.path().join("blob-store").exists());
        enforce(tmp.path(), "postgres://hermod@db/hermod", "memory://", &ids).unwrap();
    }

    #[test]
    fn error_message_includes_chmod_hint() {
        let err = LayoutError::ModeMismatch {
            label: "hermod database".to_string(),
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
