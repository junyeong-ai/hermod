use crate::error::HermodError;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// Workspace visibility — `public` workspaces are identified by
/// `(creator_pubkey, name)` and authenticate broadcasts via ed25519 alone;
/// `private` workspaces carry a 32-byte secret that gates membership and
/// derives per-channel HMAC keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceVisibility {
    Public,
    Private,
}

impl WorkspaceVisibility {
    pub fn as_str(&self) -> &'static str {
        match self {
            WorkspaceVisibility::Public => "public",
            WorkspaceVisibility::Private => "private",
        }
    }
}

impl FromStr for WorkspaceVisibility {
    type Err = HermodError;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "public" => Ok(WorkspaceVisibility::Public),
            "private" => Ok(WorkspaceVisibility::Private),
            other => Err(HermodError::InvalidEnvelope(format!(
                "unknown workspace visibility {other:?}"
            ))),
        }
    }
}
