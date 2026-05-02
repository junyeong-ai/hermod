//! Per-MCP-instance identity primitives.
//!
//! When Claude Code spawns, it starts an MCP server process that
//! attaches to the daemon. Multiple Claude Code windows of the same
//! agent must each be addressable independently — for inbox cursors,
//! permission queue isolation, and operator visibility. Two newtypes
//! encode that addressability:
//!
//! * [`McpSessionId`] — daemon-minted opaque handle. Stable for the
//!   lifetime of an attach. Used as the FK for cursors and the
//!   permission queue's `owner_session`.
//! * [`SessionLabel`] — operator-supplied stable name (e.g. via
//!   `HERMOD_SESSION_LABEL`). When provided, the daemon resumes
//!   the existing session row keyed by `(agent_id, session_label)`
//!   on re-attach — so cursors survive MCP process restart. At most
//!   one live session per `(agent, label)`: a fresh attach with a
//!   matching label evicts the prior session via the live-registry
//!   force-close channel.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

use crate::error::HermodError;

/// Maximum length of a [`SessionLabel`] — short enough to render in
/// `hermod local sessions` tabular output, long enough to encode
/// host + role (`vscode-review`, `terminal-1`, `claude-mobile`).
pub const SESSION_LABEL_MAX_LEN: usize = 32;

/// Daemon-minted MCP session handle. Opaque to clients; the daemon
/// generates a UUIDv4 string on attach and clients echo it on
/// heartbeat / detach / cursor advance.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct McpSessionId(String);

impl McpSessionId {
    /// Construct without validation. Used by the daemon when minting
    /// fresh handles or replaying persisted ones from `mcp_sessions`.
    pub fn from_raw(s: String) -> Self {
        Self(s)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for McpSessionId {
    type Err = HermodError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() || s.len() > 64 {
            return Err(HermodError::InvalidMcpSessionId(format!(
                "length must be 1..=64, got {}",
                s.len()
            )));
        }
        for c in s.chars() {
            if !(c.is_ascii_alphanumeric() || c == '-') {
                return Err(HermodError::InvalidMcpSessionId(format!(
                    "invalid char {c:?}"
                )));
            }
        }
        Ok(Self(s.to_string()))
    }
}

impl fmt::Display for McpSessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for McpSessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "McpSessionId({})", self.0)
    }
}

/// Operator-supplied stable nickname for an MCP attach. When provided,
/// the daemon keys session resumption on `(agent_id, session_label)`
/// — restarting the MCP process with the same label resumes the same
/// session row, preserving inbox / confirmation / resolved cursors.
///
/// Wire form: bare string. Validates `^[A-Za-z0-9_.-]{1,32}$` —
/// human-typeable, file-system-safe, terminal-safe. Disallows
/// whitespace and shell metacharacters so labels can be surfaced in
/// CLI tables and audit details without escaping.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SessionLabel(String);

impl From<SessionLabel> for String {
    fn from(l: SessionLabel) -> String {
        l.0
    }
}

impl TryFrom<String> for SessionLabel {
    type Error = HermodError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl SessionLabel {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for SessionLabel {
    type Err = HermodError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() || s.len() > SESSION_LABEL_MAX_LEN {
            return Err(HermodError::InvalidSessionLabel(format!(
                "length must be 1..={SESSION_LABEL_MAX_LEN}, got {}",
                s.len()
            )));
        }
        for c in s.chars() {
            if !(c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.') {
                return Err(HermodError::InvalidSessionLabel(format!(
                    "invalid char {c:?}"
                )));
            }
        }
        Ok(Self(s.to_string()))
    }
}

impl fmt::Display for SessionLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for SessionLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SessionLabel({})", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_label_accepts_typical_shapes() {
        for s in ["vscode-review", "terminal_1", "claude.mobile", "a", "Z9-_."] {
            let l: SessionLabel = s.parse().unwrap();
            assert_eq!(l.as_str(), s);
        }
    }

    #[test]
    fn session_label_rejects_bad_shapes() {
        for s in ["", " ", "label with space", "a/b", "a;b", "a*"] {
            let r: Result<SessionLabel, _> = s.parse();
            assert!(r.is_err(), "{s:?} should be rejected");
        }
        // Boundary
        let too_long = "x".repeat(SESSION_LABEL_MAX_LEN + 1);
        assert!(too_long.parse::<SessionLabel>().is_err());
    }

    #[test]
    fn session_label_round_trips_through_serde() {
        let original: SessionLabel = "vscode-1".parse().unwrap();
        let json = serde_json::to_string(&original).unwrap();
        let back: SessionLabel = serde_json::from_str(&json).unwrap();
        assert_eq!(original, back);
        // Bare string on the wire.
        assert_eq!(json, "\"vscode-1\"");
    }

    #[test]
    fn session_label_serde_rejects_invalid() {
        let bad = serde_json::from_str::<SessionLabel>("\"a b\"");
        assert!(bad.is_err());
    }

    #[test]
    fn mcp_session_id_accepts_uuid_and_typical() {
        for s in ["a", "abc-123", "01234567-89ab-cdef-0123-456789abcdef"] {
            let id: McpSessionId = s.parse().unwrap();
            assert_eq!(id.as_str(), s);
        }
    }

    #[test]
    fn mcp_session_id_rejects_bad() {
        for s in ["", "a b", "a/b", "a.b"] {
            let r: Result<McpSessionId, _> = s.parse();
            assert!(r.is_err(), "{s:?} should be rejected");
        }
        let too_long = "x".repeat(65);
        assert!(too_long.parse::<McpSessionId>().is_err());
    }
}
