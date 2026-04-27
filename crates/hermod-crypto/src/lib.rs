//! Cryptographic primitives for Hermod: ed25519 signing, blake3-based identifiers,
//! capability tokens, TLS material, and canonical CBOR for envelope signing.

pub mod canonical;
pub mod capability;
pub mod error;
pub mod identity;
pub mod keypair;
pub mod noise_key;
pub mod public_key;
pub mod short_id;
pub mod signer;
pub mod tls;
pub mod workspace;

pub use canonical::{canonical_envelope_bytes, canonical_mdns_beacon_bytes};
pub use capability::{
    CAPABILITY_VERSION, CapabilityClaim, parse_claim_unverified, verify_capability,
};
pub use error::CryptoError;
pub use identity::{agent_id_from_pubkey, fingerprint_from_pubkey};
pub use keypair::Keypair;
pub use noise_key::NoiseStaticKey;
pub use public_key::PublicKey;
pub use signer::{LocalKeySigner, Signer};
pub use tls::{TlsError, TlsMaterial, sha256_fingerprint};
pub use workspace::{
    ChannelId, ChannelMacKey, WorkspaceId, WorkspaceMacKey, WorkspaceSecret, public_channel_id,
    public_workspace_id,
};
