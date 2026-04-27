use serde::{Deserialize, Serialize};
use thiserror::Error;

/// JSON-RPC 2.0 error codes used by Hermod.
pub mod code {
    pub const PARSE_ERROR: i32 = -32700;
    pub const INVALID_REQUEST: i32 = -32600;
    pub const METHOD_NOT_FOUND: i32 = -32601;
    pub const INVALID_PARAMS: i32 = -32602;
    pub const INTERNAL_ERROR: i32 = -32603;

    // Hermod-specific (server-defined, -32000..-32099).
    pub const UNAUTHORIZED: i32 = -32000;
    pub const RATE_LIMITED: i32 = -32001;
    pub const NOT_FOUND: i32 = -32002;
    pub const STORAGE: i32 = -32003;
    pub const CRYPTO: i32 = -32004;
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub data: Option<serde_json::Value>,
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "rpc {}: {}", self.code, self.message)
    }
}

impl std::error::Error for RpcError {}

impl RpcError {
    pub fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    pub fn with_data(mut self, data: serde_json::Value) -> Self {
        self.data = Some(data);
        self
    }
}

#[derive(Debug, Error)]
pub enum IpcError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    #[error("connection closed")]
    Closed,

    #[error("frame too large: {0} bytes")]
    FrameTooLarge(usize),

    #[error("remote error ({code}): {message}")]
    Remote { code: i32, message: String },

    #[error("id mismatch: expected {expected:?}, got {actual:?}")]
    IdMismatch { expected: String, actual: String },
}

impl From<RpcError> for IpcError {
    fn from(e: RpcError) -> Self {
        IpcError::Remote {
            code: e.code,
            message: e.message,
        }
    }
}
