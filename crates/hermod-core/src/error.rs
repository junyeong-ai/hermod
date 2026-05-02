use thiserror::Error;

#[derive(Debug, Error)]
pub enum HermodError {
    #[error("invalid agent id: {0}")]
    InvalidAgentId(String),

    #[error("invalid agent alias: {0}")]
    InvalidAgentAlias(String),

    #[error("invalid endpoint: {0}")]
    InvalidEndpoint(String),

    #[error("invalid agent address: {0}")]
    InvalidAgentAddress(String),

    #[error("invalid timestamp: {0}")]
    InvalidTimestamp(String),

    #[error("invalid envelope: {0}")]
    InvalidEnvelope(String),

    #[error("invalid fingerprint: {0}")]
    InvalidFingerprint(String),

    #[error("invalid capability token: {0}")]
    InvalidCapabilityToken(String),

    #[error("invalid mcp session id: {0}")]
    InvalidMcpSessionId(String),

    #[error("invalid session label: {0}")]
    InvalidSessionLabel(String),

    #[error("invalid capability tag: {0}")]
    InvalidCapabilityTag(String),

    #[error("invalid git workspace url: {0}")]
    InvalidGitWorkspaceUrl(String),
}

pub type Result<T, E = HermodError> = std::result::Result<T, E>;
