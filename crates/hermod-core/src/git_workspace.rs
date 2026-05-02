//! Git-remote URL → deterministic workspace name + fingerprint.
//!
//! Two inputs operators have on hand:
//!
//!   * `git remote get-url origin` — a git URL in one of three
//!     shapes (HTTPS, SSH alias, scp-like path). Different shapes
//!     of the same repo are *equivalent* but only by string
//!     identity if normalised to one canonical form.
//!   * `git rev-list --max-parents=0 HEAD` — the initial-commit
//!     SHA. Stable across `git push --force` / branch resets,
//!     unique per repo lineage.
//!
//! `workspace_name_from_url` produces a normalised name (the
//! human-readable label operators see in `hermod workspace list`).
//! [`ProjectFingerprint::from_canonical_url`] derives an opaque
//! 32-byte fingerprint from canonical URL + initial commit. The
//! fingerprint is **discovery hint only** — never trust-bearing,
//! never derived from a workspace secret. Operators who want to
//! confirm two clones are talking about the same repo compare
//! fingerprints; the secret stays out-of-band.
//!
//! ## Heuristic discipline
//!
//! Normalisation is deterministic and lossless on canonical
//! forms. Unrecognised forms produce a typed error rather than
//! a fuzzy "best guess" — operators see "unsupported URL form,
//! pass --name explicitly" instead of a workspace name that
//! doesn't match what their teammate's clone produced. No
//! probabilistic / heuristic matching anywhere.
//!
//! ## What's NOT here
//!
//! * No I/O — `hermod-core` has no fs / process deps. The CLI
//!   layer reads `.git/config` and feeds the strings here.
//! * No workspace-secret derivation. URLs are public knowledge;
//!   secrets stay out-of-band (decision archived in PR-M memory).

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

use crate::error::HermodError;

/// Canonical workspace name derived from a git remote URL. Format:
/// `<host>/<owner>/<repo>`, all lowercase, `.git` stripped, no
/// userinfo, no port-in-path. Operators see this in `hermod
/// workspace list`; it's the human-readable label.
///
/// Length-bounded (1..=128) to fit comfortably in TOML / IPC and
/// keep the audit log readable.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WorkspaceName(String);

impl WorkspaceName {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Construct without re-validation — used by
    /// [`workspace_name_from_url`] after it has produced a
    /// normalised string.
    fn from_validated(s: String) -> Self {
        Self(s)
    }
}

impl fmt::Display for WorkspaceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for WorkspaceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WorkspaceName({})", self.0)
    }
}

/// Hard cap on the resulting name. Long enough for typical
/// `host/owner/repo` paths; short enough to surface in CLI tables.
const WORKSPACE_NAME_MAX_BYTES: usize = 128;

/// Discovery-only fingerprint. Derived from canonical URL +
/// initial-commit SHA via blake3. Two clones of the same repo
/// produce identical fingerprints; forks share the *same* initial
/// commit (so they share fingerprints — fork-vs-original is not
/// authoritative here, by design). Trust gate is the workspace
/// secret; this is only a hint.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProjectFingerprint(pub [u8; 32]);

impl ProjectFingerprint {
    /// Derive `blake3(canonical_url || 0x00 || initial_commit)`.
    /// `initial_commit` is the SHA-1 hex of the repo's first
    /// parentless commit (or `None` for a fresh repo with no
    /// commits — fingerprint then reflects URL alone).
    pub fn from_canonical_url(canonical_url: &str, initial_commit: Option<&str>) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(canonical_url.as_bytes());
        hasher.update(&[0x00]);
        if let Some(sha) = initial_commit {
            hasher.update(sha.as_bytes());
        }
        let out = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(out.as_bytes());
        Self(bytes)
    }

    /// Hex form for human display + `.hermod-workspace` TOML.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(hex: &str) -> Result<Self, HermodError> {
        let bytes = hex::decode(hex).map_err(|e| {
            HermodError::InvalidGitWorkspaceUrl(format!("fingerprint hex decode: {e}"))
        })?;
        if bytes.len() != 32 {
            return Err(HermodError::InvalidGitWorkspaceUrl(format!(
                "fingerprint must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(Self(out))
    }
}

impl fmt::Debug for ProjectFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ProjectFingerprint({})", self.to_hex())
    }
}

/// URL-normalisation errors. Each variant fails-loud so
/// `workspace create --from-git` surfaces a clear "I don't know
/// this URL form" rather than producing a name the operator's
/// teammate's clone wouldn't reproduce.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum GitWorkspaceError {
    #[error("git url is empty")]
    Empty,
    #[error(
        "git url `{0}` does not match a recognised form (https://, ssh://, or scp-like host:path)"
    )]
    UnsupportedForm(String),
    #[error("git url `{url}` is missing path component (host: `{host}`)")]
    MissingPath { url: String, host: String },
    #[error(
        "git url `{url}` produced workspace name longer than {WORKSPACE_NAME_MAX_BYTES} bytes \
         ({got} bytes); pass --name explicitly"
    )]
    NameTooLong { url: String, got: usize },
}

/// Normalise a git remote URL to the canonical
/// `<host>/<owner>/<repo>` form. Lowercased, `.git` stripped, no
/// userinfo, no port. Three input shapes are accepted:
///
///   * `https://github.com/foo/bar.git`
///   * `https://user@github.com/foo/bar.git` (userinfo dropped)
///   * `ssh://git@github.com/foo/bar.git`
///   * `git@github.com:foo/bar.git` (scp-like — colon = path sep)
///
/// All produce `github.com/foo/bar`. Anything that doesn't match
/// these forms returns [`GitWorkspaceError::UnsupportedForm`] so
/// the operator picks `--name` manually rather than getting a
/// silently-different name.
pub fn workspace_name_from_url(url: &str) -> Result<WorkspaceName, GitWorkspaceError> {
    let url = url.trim();
    if url.is_empty() {
        return Err(GitWorkspaceError::Empty);
    }

    let (host, path) = parse_url(url)?;
    let host = host.to_ascii_lowercase();
    // Strip leading `/`s, trailing `/`s, and the conventional
    // `.git` suffix.
    let path = path.trim_start_matches('/').trim_end_matches('/');
    let path = path.strip_suffix(".git").unwrap_or(path).to_string();
    if path.is_empty() {
        return Err(GitWorkspaceError::MissingPath {
            url: url.to_string(),
            host,
        });
    }
    let path = path.to_ascii_lowercase();
    let name = format!("{host}/{path}");
    if name.len() > WORKSPACE_NAME_MAX_BYTES {
        return Err(GitWorkspaceError::NameTooLong {
            url: url.to_string(),
            got: name.len(),
        });
    }
    Ok(WorkspaceName::from_validated(name))
}

/// Split a git URL into `(host, path)`. Returns
/// `UnsupportedForm` for inputs that don't match a known shape.
fn parse_url(url: &str) -> Result<(String, String), GitWorkspaceError> {
    // 1. Explicit scheme: `https://`, `http://`, `ssh://`, `git://`.
    for scheme in &["https://", "http://", "ssh://", "git://"] {
        if let Some(rest) = url.strip_prefix(scheme) {
            return parse_authority_path(rest, url);
        }
    }
    // 2. scp-like: `[user@]host:path`. Colon must come BEFORE any
    //    `/`, otherwise it's a port spec or just text.
    if let Some(colon_idx) = url.find(':') {
        let slash_idx = url.find('/').unwrap_or(usize::MAX);
        if colon_idx < slash_idx {
            let (left, right) = url.split_at(colon_idx);
            let path = &right[1..]; // drop the leading colon
            let host = strip_userinfo(left);
            return Ok((host.to_string(), path.to_string()));
        }
    }
    Err(GitWorkspaceError::UnsupportedForm(url.to_string()))
}

/// `[user@]host[:port]/path` → `(host_no_port, path)`. The port,
/// if present, is dropped — workspace name doesn't depend on it
/// (two clones from `:443` and unspecified port are the same repo).
fn parse_authority_path(rest: &str, original: &str) -> Result<(String, String), GitWorkspaceError> {
    let (authority, path) = match rest.find('/') {
        Some(idx) => rest.split_at(idx),
        None => {
            return Err(GitWorkspaceError::MissingPath {
                url: original.to_string(),
                host: rest.to_string(),
            });
        }
    };
    let authority = strip_userinfo(authority);
    let host = match authority.find(':') {
        Some(idx) => &authority[..idx],
        None => authority,
    };
    Ok((host.to_string(), path.to_string()))
}

/// Drop `user@` prefix if present.
fn strip_userinfo(s: &str) -> &str {
    match s.rfind('@') {
        Some(idx) => &s[idx + 1..],
        None => s,
    }
}

impl FromStr for WorkspaceName {
    type Err = HermodError;
    /// Parse a *pre-normalised* name (e.g. from `.hermod-workspace`'s
    /// `name` field). The `<host>/<owner>/<repo>` shape is checked but
    /// not re-derived — operators editing the file by hand can pass any
    /// string that satisfies the length + alphabet rules, but a fresh
    /// `--from-git` produces only canonical names.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() || s.len() > WORKSPACE_NAME_MAX_BYTES {
            return Err(HermodError::InvalidGitWorkspaceUrl(format!(
                "workspace name length must be 1..={WORKSPACE_NAME_MAX_BYTES}, got {}",
                s.len()
            )));
        }
        for c in s.chars() {
            if !(c.is_ascii_lowercase()
                || c.is_ascii_digit()
                || c == '/'
                || c == '.'
                || c == '_'
                || c == '-')
            {
                return Err(HermodError::InvalidGitWorkspaceUrl(format!(
                    "workspace name char {c:?} invalid (allowed: a-z 0-9 / . _ -)"
                )));
            }
        }
        Ok(Self(s.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_canonical_form() {
        let n = workspace_name_from_url("https://github.com/foo/bar.git").unwrap();
        assert_eq!(n.as_str(), "github.com/foo/bar");
    }

    #[test]
    fn https_no_dot_git_suffix() {
        let n = workspace_name_from_url("https://github.com/foo/bar").unwrap();
        assert_eq!(n.as_str(), "github.com/foo/bar");
    }

    #[test]
    fn https_with_userinfo_drops_userinfo() {
        let n = workspace_name_from_url("https://user@github.com/foo/bar.git").unwrap();
        assert_eq!(n.as_str(), "github.com/foo/bar");
    }

    #[test]
    fn https_with_token_userinfo_drops_secret() {
        // Tokens-as-username are common in CI configs; we MUST NOT
        // bake the secret into the workspace name.
        let n =
            workspace_name_from_url("https://oauth2:ghp_secret@github.com/foo/bar.git").unwrap();
        assert_eq!(n.as_str(), "github.com/foo/bar");
    }

    #[test]
    fn https_with_port_drops_port() {
        let n = workspace_name_from_url("https://gitlab.example.com:8443/group/repo.git").unwrap();
        assert_eq!(n.as_str(), "gitlab.example.com/group/repo");
    }

    #[test]
    fn ssh_explicit_scheme() {
        let n = workspace_name_from_url("ssh://git@github.com/foo/bar.git").unwrap();
        assert_eq!(n.as_str(), "github.com/foo/bar");
    }

    #[test]
    fn scp_like_form() {
        let n = workspace_name_from_url("git@github.com:foo/bar.git").unwrap();
        assert_eq!(n.as_str(), "github.com/foo/bar");
    }

    #[test]
    fn scp_like_without_user() {
        // `host:path` even without explicit user is still scp-like.
        let n = workspace_name_from_url("github.com:foo/bar.git").unwrap();
        assert_eq!(n.as_str(), "github.com/foo/bar");
    }

    #[test]
    fn case_normalisation_lowercases_host_and_path() {
        let n = workspace_name_from_url("https://GitHub.com/Foo/Bar.git").unwrap();
        assert_eq!(n.as_str(), "github.com/foo/bar");
    }

    #[test]
    fn equivalent_forms_produce_same_name() {
        let n1 = workspace_name_from_url("https://github.com/foo/bar.git").unwrap();
        let n2 = workspace_name_from_url("git@github.com:foo/bar.git").unwrap();
        let n3 = workspace_name_from_url("ssh://git@github.com/foo/bar.git").unwrap();
        assert_eq!(n1, n2);
        assert_eq!(n2, n3);
    }

    #[test]
    fn empty_url_rejected() {
        assert!(matches!(
            workspace_name_from_url(""),
            Err(GitWorkspaceError::Empty)
        ));
    }

    #[test]
    fn unsupported_form_rejected() {
        // No scheme, no scp-colon — operator must pass --name.
        assert!(matches!(
            workspace_name_from_url("github.com_foo_bar"),
            Err(GitWorkspaceError::UnsupportedForm(_))
        ));
    }

    #[test]
    fn missing_path_rejected() {
        assert!(matches!(
            workspace_name_from_url("https://github.com"),
            Err(GitWorkspaceError::MissingPath { .. })
        ));
        assert!(matches!(
            workspace_name_from_url("https://github.com/"),
            Err(GitWorkspaceError::MissingPath { .. })
        ));
    }

    #[test]
    fn fingerprint_is_deterministic_on_canonical_input() {
        let canon = "github.com/foo/bar";
        let sha = "abcd1234";
        let f1 = ProjectFingerprint::from_canonical_url(canon, Some(sha));
        let f2 = ProjectFingerprint::from_canonical_url(canon, Some(sha));
        assert_eq!(f1, f2);
        // Different commit → different fingerprint.
        let f3 = ProjectFingerprint::from_canonical_url(canon, Some("dead0000"));
        assert_ne!(f1, f3);
        // None vs Some → different.
        let f4 = ProjectFingerprint::from_canonical_url(canon, None);
        assert_ne!(f1, f4);
    }

    #[test]
    fn fingerprint_hex_round_trip() {
        let f = ProjectFingerprint::from_canonical_url("github.com/x/y", Some("abc"));
        let hex = f.to_hex();
        let back = ProjectFingerprint::from_hex(&hex).unwrap();
        assert_eq!(f, back);
    }

    #[test]
    fn workspace_name_parse_accepts_canonical() {
        for s in [
            "github.com/foo/bar",
            "gitlab.com/team.platform/repo",
            "host_internal/owner/repo-name",
        ] {
            let n: WorkspaceName = s.parse().unwrap();
            assert_eq!(n.as_str(), s);
        }
    }

    #[test]
    fn workspace_name_parse_rejects_uppercase() {
        assert!("Github.com/foo/bar".parse::<WorkspaceName>().is_err());
    }
}
