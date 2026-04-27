//! Core types for Hermod.
//!
//! This crate has no I/O and minimal dependencies. Every other crate builds on top of
//! these types. Signing, storage, networking live in sibling crates.

pub mod bytes;
pub mod capability;
pub mod envelope;
pub mod error;
pub mod identity;
pub mod time;
pub mod workspace;

pub use bytes::{FingerprintBytes, PubkeyBytes, SignatureBytes};
pub use capability::{CapabilityDirection, CapabilityScope, CapabilityToken};
pub use envelope::{
    Envelope, MAX_CAPS_PER_ENVELOPE, MAX_FILE_PAYLOAD_BYTES, MessageBody, MessageId, MessageKind,
    MessagePriority, MessageStatus, PROTOCOL_VERSION, PresenceStatus, RosterMember,
    WorkspaceChannelEntry,
};
pub use error::HermodError;
pub use identity::{AgentAddress, AgentAlias, AgentId, Endpoint, TrustLevel, WssEndpoint};
pub use time::Timestamp;
pub use workspace::WorkspaceVisibility;
