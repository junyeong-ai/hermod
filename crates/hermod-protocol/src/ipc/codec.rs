use bytes::{Bytes, BytesMut};
use tokio_util::codec::{Decoder, Encoder, LengthDelimitedCodec};

use super::error::IpcError;
use super::message::{Request, Response};

/// 16 MB max IPC frame.
pub const MAX_FRAME_LEN: usize = 16 * 1024 * 1024;

fn length_delimited() -> LengthDelimitedCodec {
    LengthDelimitedCodec::builder()
        .length_field_length(4)
        .max_frame_length(MAX_FRAME_LEN)
        .new_codec()
}

/// Codec used on the server side:
///  - decodes incoming `Request`
///  - encodes outgoing `Response`
#[derive(Debug)]
pub struct ServerCodec {
    inner: LengthDelimitedCodec,
}

impl Default for ServerCodec {
    fn default() -> Self {
        Self {
            inner: length_delimited(),
        }
    }
}

impl Decoder for ServerCodec {
    type Item = Request;
    type Error = IpcError;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let frame = match self.inner.decode(buf)? {
            Some(f) => f,
            None => return Ok(None),
        };
        Ok(Some(serde_json::from_slice(&frame)?))
    }
}

impl Encoder<Response> for ServerCodec {
    type Error = IpcError;

    fn encode(&mut self, item: Response, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let bytes = serde_json::to_vec(&item)?;
        self.inner.encode(Bytes::from(bytes), dst)?;
        Ok(())
    }
}

/// Codec used on the client side:
///  - encodes outgoing `Request`
///  - decodes incoming `Response`
#[derive(Debug)]
pub struct ClientCodec {
    inner: LengthDelimitedCodec,
}

impl Default for ClientCodec {
    fn default() -> Self {
        Self {
            inner: length_delimited(),
        }
    }
}

impl Decoder for ClientCodec {
    type Item = Response;
    type Error = IpcError;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let frame = match self.inner.decode(buf)? {
            Some(f) => f,
            None => return Ok(None),
        };
        Ok(Some(serde_json::from_slice(&frame)?))
    }
}

impl Encoder<Request> for ClientCodec {
    type Error = IpcError;

    fn encode(&mut self, item: Request, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let bytes = serde_json::to_vec(&item)?;
        self.inner.encode(Bytes::from(bytes), dst)?;
        Ok(())
    }
}
