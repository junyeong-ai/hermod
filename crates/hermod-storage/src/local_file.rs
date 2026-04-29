//! Backend-declared on-disk files under `$HERMOD_HOME`.
//!
//! Storage backends know which local files they own (SQLite has
//! `hermod.db` + `-wal` + `-shm`; LocalFs blob store has its root
//! directory; cloud backends own no local files). The daemon's
//! `home_layout` consumes this declaration to derive its boot-time
//! enforcement and `hermod doctor` audit — keeping the
//! "what files exist on disk" knowledge in the layer that defines
//! them.
//!
//! Returned by [`crate::database_local_files`] and
//! [`crate::blob_store_local_files`]; both functions resolve from a
//! DSN before any backend is opened, so home-layout enforcement
//! runs before storage construction.
//!
//! Mode policy (Secret → 0o600, Directory → 0o700) is owned by
//! `home_layout`, not here — backends declare *what* they write,
//! the home layout decides *how* it must be protected.

use std::path::PathBuf;

/// One on-disk artefact a storage backend writes under
/// `$HERMOD_HOME`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalFile {
    /// Operator-facing label. Rendered in boot-time errors and
    /// `hermod doctor` rows.
    pub label: &'static str,
    /// Absolute path. The DSN-resolution functions
    /// ([`crate::database_local_files`],
    /// [`crate::blob_store_local_files`]) return paths already
    /// expanded from the DSN — callers do not re-expand.
    pub path: PathBuf,
    pub kind: LocalFileKind,
    pub presence: LocalFilePresence,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalFileKind {
    /// File whose content is confidential (database, WAL frames,
    /// blob payloads). `home_layout` maps this to mode 0o600.
    Secret,
    /// Directory carrying secret children. `home_layout` maps this
    /// to mode 0o700.
    Directory,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalFilePresence {
    /// Boot enforcement refuses to start if the file is missing.
    /// Used for the primary database file — its absence means the
    /// backend cannot serve.
    Required,
    /// File may legitimately not exist yet (SQLite WAL/SHM frames
    /// before any write, blob-store root before any payload).
    /// Audit reports as informational; enforcement skips.
    Optional,
}

impl LocalFile {
    pub fn secret_required(label: &'static str, path: PathBuf) -> Self {
        Self {
            label,
            path,
            kind: LocalFileKind::Secret,
            presence: LocalFilePresence::Required,
        }
    }

    pub fn secret_optional(label: &'static str, path: PathBuf) -> Self {
        Self {
            label,
            path,
            kind: LocalFileKind::Secret,
            presence: LocalFilePresence::Optional,
        }
    }

    pub fn directory_optional(label: &'static str, path: PathBuf) -> Self {
        Self {
            label,
            path,
            kind: LocalFileKind::Directory,
            presence: LocalFilePresence::Optional,
        }
    }
}
