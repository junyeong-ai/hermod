use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::Framed;

use super::codec::ServerCodec;
use super::error::IpcError;
use super::message::{Request, Response};

/// Wraps an async read/write half-pair and speaks the IPC codec.
///
/// Server-side semantics: yields `Request`s, accepts `Response`s.
#[derive(Debug)]
pub struct IpcServer<S: AsyncRead + AsyncWrite + Unpin> {
    framed: Framed<S, ServerCodec>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> IpcServer<S> {
    pub fn new(io: S) -> Self {
        Self {
            framed: Framed::new(io, ServerCodec::default()),
        }
    }

    pub async fn next_request(&mut self) -> Result<Option<Request>, IpcError> {
        match self.framed.next().await {
            Some(Ok(req)) => Ok(Some(req)),
            Some(Err(e)) => Err(e),
            None => Ok(None),
        }
    }

    pub async fn send_response(&mut self, resp: Response) -> Result<(), IpcError> {
        self.framed.send(resp).await
    }
}
