//! JSON-RPC 2.0 IPC between `hermodd` and clients (CLI, MCP server).
//!
//! Wire format: `LengthDelimitedCodec` with 4-byte big-endian length prefix,
//! carrying UTF-8 JSON payloads. Max frame length: 16 MB.

pub mod client;
pub mod codec;
pub mod error;
pub mod message;
pub mod methods;
pub mod server;

pub use client::IpcClient;
pub use codec::{ClientCodec, MAX_FRAME_LEN, ServerCodec};
pub use error::{IpcError, RpcError};
pub use message::{Id, JsonRpc2, Request, Response, ResponsePayload};
pub use server::IpcServer;
