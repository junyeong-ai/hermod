//! Core types for Hermod.
//!
//! This crate has no I/O and minimal dependencies. Every other crate builds on top of
//! these types. Signing, storage, networking live in sibling crates.

pub mod bytes;
pub mod capability;
pub mod capability_tag;
pub mod envelope;
pub mod error;
pub mod git_workspace;
pub mod identity;
pub mod mcp_session;
pub mod time;
pub mod workspace;

pub use bytes::{FingerprintBytes, PubkeyBytes, SignatureBytes};
pub use capability::{CapabilityDirection, CapabilityScope, CapabilityToken};
pub use capability_tag::{
    CapabilityTag, CapabilityTagSet, MAX_TAG_BYTES, MAX_TAGS_PER_SET, effective_tags,
};
pub use envelope::{
    AdvertisedAgent, Envelope, MAX_CAPS_PER_ENVELOPE, MAX_FILE_PAYLOAD_BYTES, MessageBody,
    MessageDisposition, MessageId, MessageKind, MessagePriority, MessageStatus, NotificationStatus,
    PROTOCOL_VERSION, PresenceStatus, RosterMember, WorkspaceChannelEntry,
};
pub use error::HermodError;
pub use git_workspace::{
    GitWorkspaceError, ProjectFingerprint, WorkspaceName, workspace_name_from_url,
};
pub use identity::{AgentAddress, AgentAlias, AgentId, Endpoint, TrustLevel, WssEndpoint};
pub use mcp_session::{McpSessionId, SESSION_LABEL_MAX_LEN, SessionLabel};
pub use time::Timestamp;
pub use workspace::WorkspaceVisibility;
