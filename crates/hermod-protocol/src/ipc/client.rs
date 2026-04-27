use futures::{SinkExt, StreamExt};
use hermod_transport::{UnixIpcStream, unix};
use serde::{Serialize, de::DeserializeOwned};
use std::path::Path;
use tokio_util::codec::Framed;

use super::codec::ClientCodec;
use super::error::IpcError;
use super::message::{Id, Request, Response, ResponsePayload};

/// Half-duplex IPC client. Not pipeline-aware: one call in flight at a time.
#[derive(Debug)]
pub struct IpcClient {
    framed: Framed<UnixIpcStream, ClientCodec>,
}

impl IpcClient {
    pub async fn connect_unix(path: impl AsRef<Path>) -> Result<Self, IpcError> {
        let stream = unix::connect(path).await.map_err(|e| match e {
            hermod_transport::TransportError::Io(e) => IpcError::Io(e),
            other => IpcError::Io(std::io::Error::other(other.to_string())),
        })?;
        Ok(Self {
            framed: Framed::new(stream, ClientCodec::default()),
        })
    }

    pub async fn call<P: Serialize, R: DeserializeOwned>(
        &mut self,
        method: &str,
        params: P,
    ) -> Result<R, IpcError> {
        let id = Id::from_ulid();
        let params = serde_json::to_value(params)?;
        let req = Request::new(
            id.clone(),
            method,
            if params.is_null() { None } else { Some(params) },
        );

        self.framed.send(req).await?;

        let resp: Response = match self.framed.next().await {
            Some(Ok(r)) => r,
            Some(Err(e)) => return Err(e),
            None => return Err(IpcError::Closed),
        };

        if resp.id != id {
            return Err(IpcError::IdMismatch {
                expected: format!("{id:?}"),
                actual: format!("{:?}", resp.id),
            });
        }

        match resp.payload {
            ResponsePayload::Ok { result } => Ok(serde_json::from_value::<R>(result)?),
            ResponsePayload::Err { error } => Err(IpcError::Remote {
                code: error.code,
                message: error.message,
            }),
        }
    }

    /// Call a method with unit params `()`.
    pub async fn call_noparams<R: DeserializeOwned>(
        &mut self,
        method: &str,
    ) -> Result<R, IpcError> {
        self.call(method, serde_json::Value::Null).await
    }
}
