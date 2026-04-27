use thiserror::Error;

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("endpoint {0:?} has unsupported scheme")]
    UnsupportedScheme(String),

    #[error("connection closed by peer")]
    Closed,

    #[error("address already in use: {0}")]
    AddrInUse(String),

    #[error("websocket: {0}")]
    WebSocket(String),

    #[error("expected binary frame, got non-binary")]
    NotBinary,
}
