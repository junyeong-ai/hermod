//! Workspace + channel key derivation.
//!
//! A workspace is either:
//! - **Private**: identified by a 32-byte secret. Members hold the secret;
//!   anyone with it can derive the workspace id, every channel id, and every
//!   channel HMAC key. Outsiders see opaque ids on the wire and cannot forge
//!   broadcasts.
//! - **Public**: identified by `(creator_pubkey, name)`. There is no secret;
//!   broadcasts authenticate by ed25519 signature alone.
//!
//! Derivations use `blake3::derive_key` (a proper KDF — domain-separated and
//! constant-time), not raw concatenation. The 16-byte ids are truncations of
//! the 32-byte derived key. v1 is fixed by the domain strings below; rotating
//! to v2 means changing all five strings.

use crate::error::CryptoError;
use hermod_core::PubkeyBytes;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// 32-byte workspace secret (the PSK). Zeroed on drop so it doesn't linger in
/// memory after the daemon stops referencing it.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct WorkspaceSecret([u8; 32]);

impl WorkspaceSecret {
    /// Generate a fresh secret from the OS RNG.
    pub fn generate() -> Self {
        let mut b = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut b);
        Self(b)
    }

    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self, CryptoError> {
        let bytes = hex::decode(s)
            .map_err(|e| CryptoError::Encoding(format!("workspace secret hex: {e}")))?;
        if bytes.len() != 32 {
            return Err(CryptoError::Encoding(format!(
                "workspace secret must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    /// Derive this workspace's id from the secret.
    pub fn workspace_id(&self) -> WorkspaceId {
        let key = blake3::derive_key(DOMAIN_WS_PRIV_ID_V1, &self.0);
        WorkspaceId(truncate16(&key))
    }

    /// Derive a channel id within this workspace.
    pub fn channel_id(&self, name: &str) -> ChannelId {
        // Two-step derive: first derive a channel-namespacing subkey from
        // (workspace secret, "ch-priv"), then mix in the channel name. This
        // way, swapping the workspace secret rotates every channel id even if
        // names are reused.
        let subkey = blake3::derive_key(DOMAIN_CH_PRIV_ID_V1, &self.0);
        let mut hasher = blake3::Hasher::new_keyed(&subkey);
        hasher.update(name.as_bytes());
        let out = hasher.finalize();
        ChannelId(truncate16(out.as_bytes()))
    }

    /// Derive a channel's HMAC-MAC key. Used to authenticate channel
    /// broadcasts under blake3 keyed mode (peers without the workspace secret
    /// cannot forge broadcasts).
    pub fn channel_mac_key(&self, name: &str) -> ChannelMacKey {
        let subkey = blake3::derive_key(DOMAIN_CH_MAC_V1, &self.0);
        let mut hasher = blake3::Hasher::new_keyed(&subkey);
        hasher.update(name.as_bytes());
        ChannelMacKey(*hasher.finalize().as_bytes())
    }

    /// Derive the workspace-level HMAC key. Used to authenticate
    /// workspace-scoped RPC envelopes (roster query, channel listing)
    /// where channel-level keys aren't appropriate. Possessing the
    /// workspace secret = membership = authorisation to query/respond;
    /// the MAC just makes membership cryptographically provable on
    /// each individual envelope without needing a stored membership
    /// table on the receiver side.
    pub fn workspace_mac_key(&self) -> WorkspaceMacKey {
        let key = blake3::derive_key(DOMAIN_WS_MAC_V1, &self.0);
        WorkspaceMacKey(key)
    }
}

impl std::fmt::Debug for WorkspaceSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("WorkspaceSecret")
            .field(&"<redacted>")
            .finish()
    }
}

/// 16-byte workspace identifier. Hex-encoded on the wire and in storage.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WorkspaceId(#[serde(with = "hex_array16")] pub [u8; 16]);

impl WorkspaceId {
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self, CryptoError> {
        let bytes =
            hex::decode(s).map_err(|e| CryptoError::Encoding(format!("workspace id hex: {e}")))?;
        if bytes.len() != 16 {
            return Err(CryptoError::Encoding(format!(
                "workspace id must be 16 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

impl std::fmt::Debug for WorkspaceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WorkspaceId({})", self.to_hex())
    }
}

impl std::fmt::Display for WorkspaceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// 16-byte channel identifier.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ChannelId(#[serde(with = "hex_array16")] pub [u8; 16]);

impl ChannelId {
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self, CryptoError> {
        let bytes =
            hex::decode(s).map_err(|e| CryptoError::Encoding(format!("channel id hex: {e}")))?;
        if bytes.len() != 16 {
            return Err(CryptoError::Encoding(format!(
                "channel id must be 16 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

impl std::fmt::Debug for ChannelId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ChannelId({})", self.to_hex())
    }
}

impl std::fmt::Display for ChannelId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// 32-byte channel HMAC key. Zeroed on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ChannelMacKey([u8; 32]);

impl ChannelMacKey {
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Compute the channel HMAC over `msg`.
    pub fn mac(&self, msg: &[u8]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_keyed(&self.0);
        hasher.update(msg);
        *hasher.finalize().as_bytes()
    }

    /// Constant-time comparison of `expected` (computed locally) against
    /// `received` (claimed in the envelope).
    pub fn verify(&self, msg: &[u8], received: &[u8; 32]) -> bool {
        let computed = self.mac(msg);
        constant_time_eq(&computed, received)
    }
}

impl std::fmt::Debug for ChannelMacKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ChannelMacKey").field(&"<redacted>").finish()
    }
}

/// 32-byte workspace-level HMAC key. Zeroed on drop. Derived from
/// [`WorkspaceSecret::workspace_mac_key`] and used to MAC workspace-
/// scoped RPC envelopes (roster, channel list).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct WorkspaceMacKey([u8; 32]);

impl WorkspaceMacKey {
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Compute the workspace-level HMAC over `msg`.
    pub fn mac(&self, msg: &[u8]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_keyed(&self.0);
        hasher.update(msg);
        *hasher.finalize().as_bytes()
    }

    /// Constant-time comparison of `expected` (computed locally)
    /// against `received` (claimed in the envelope).
    pub fn verify(&self, msg: &[u8], received: &[u8; 32]) -> bool {
        let computed = self.mac(msg);
        constant_time_eq(&computed, received)
    }
}

impl std::fmt::Debug for WorkspaceMacKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("WorkspaceMacKey")
            .field(&"<redacted>")
            .finish()
    }
}

/// Compute a public workspace's id from `(creator_pubkey, name)`. Pure derivation,
/// no secret. Two creators choosing the same name end up with distinct ids.
pub fn public_workspace_id(creator: &PubkeyBytes, name: &str) -> WorkspaceId {
    let mut input = Vec::with_capacity(32 + 1 + name.len());
    input.extend_from_slice(creator.as_slice());
    input.push(0);
    input.extend_from_slice(name.as_bytes());
    let key = blake3::derive_key(DOMAIN_WS_PUB_ID_V1, &input);
    WorkspaceId(truncate16(&key))
}

/// Compute a public channel's id from `(workspace_id, name)`.
pub fn public_channel_id(workspace_id: &WorkspaceId, name: &str) -> ChannelId {
    let mut input = Vec::with_capacity(16 + 1 + name.len());
    input.extend_from_slice(&workspace_id.0);
    input.push(0);
    input.extend_from_slice(name.as_bytes());
    let key = blake3::derive_key(DOMAIN_CH_PUB_ID_V1, &input);
    ChannelId(truncate16(&key))
}

// Domain separators. Changing any of these means a wire-incompatible v2 of the
// derivation scheme — every existing workspace/channel id changes.
const DOMAIN_WS_PRIV_ID_V1: &str = "hermod-ws-priv-id-v1";
const DOMAIN_WS_PUB_ID_V1: &str = "hermod-ws-pub-id-v1";
const DOMAIN_CH_PRIV_ID_V1: &str = "hermod-ch-priv-id-v1";
const DOMAIN_CH_PUB_ID_V1: &str = "hermod-ch-pub-id-v1";
const DOMAIN_CH_MAC_V1: &str = "hermod-ch-mac-v1";
const DOMAIN_WS_MAC_V1: &str = "hermod-ws-mac-v1";

fn truncate16(bytes: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes[..16]);
    out
}

fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut acc = 0u8;
    for i in 0..32 {
        acc |= a[i] ^ b[i];
    }
    acc == 0
}

mod hex_array16 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 16], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(v)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 16], D::Error> {
        let bytes: serde_bytes::ByteBuf = Deserialize::deserialize(d)?;
        let slice: &[u8] = bytes.as_ref();
        if slice.len() != 16 {
            return Err(serde::de::Error::custom(format!(
                "expected 16 bytes, got {}",
                slice.len()
            )));
        }
        let mut arr = [0u8; 16];
        arr.copy_from_slice(slice);
        Ok(arr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_workspace_derivation_is_deterministic() {
        let s = WorkspaceSecret::from_bytes([7u8; 32]);
        assert_eq!(s.workspace_id(), s.workspace_id());
        assert_eq!(s.channel_id("general"), s.channel_id("general"));
        assert_ne!(s.channel_id("general"), s.channel_id("random"));
    }

    #[test]
    fn distinct_secrets_yield_distinct_ids() {
        let a = WorkspaceSecret::from_bytes([1u8; 32]);
        let b = WorkspaceSecret::from_bytes([2u8; 32]);
        assert_ne!(a.workspace_id(), b.workspace_id());
        assert_ne!(a.channel_id("ch"), b.channel_id("ch"));
        assert_ne!(
            a.channel_mac_key("ch").as_bytes(),
            b.channel_mac_key("ch").as_bytes()
        );
    }

    #[test]
    fn public_ids_depend_on_creator_and_name() {
        let pk1 = PubkeyBytes([1u8; 32]);
        let pk2 = PubkeyBytes([2u8; 32]);
        assert_ne!(
            public_workspace_id(&pk1, "team"),
            public_workspace_id(&pk2, "team")
        );
        assert_ne!(
            public_workspace_id(&pk1, "team"),
            public_workspace_id(&pk1, "other")
        );
    }

    #[test]
    fn mac_round_trip() {
        let s = WorkspaceSecret::from_bytes([3u8; 32]);
        let key = s.channel_mac_key("general");
        let msg = b"hello broadcast";
        let tag = key.mac(msg);
        assert!(key.verify(msg, &tag));
        // Tampered message rejects.
        assert!(!key.verify(b"hello broadcast!", &tag));
        // Different key rejects.
        let other = WorkspaceSecret::from_bytes([4u8; 32]).channel_mac_key("general");
        assert!(!other.verify(msg, &tag));
    }

    #[test]
    fn hex_roundtrip_secret() {
        let s = WorkspaceSecret::generate();
        let hex = s.to_hex();
        let back = WorkspaceSecret::from_hex(&hex).unwrap();
        assert_eq!(s.as_bytes(), back.as_bytes());
    }

    #[test]
    fn hex_roundtrip_ids() {
        let id = WorkspaceSecret::from_bytes([5u8; 32]).workspace_id();
        let hex = id.to_hex();
        let back = WorkspaceId::from_hex(&hex).unwrap();
        assert_eq!(id, back);

        let cid = ChannelId([6u8; 16]);
        assert_eq!(ChannelId::from_hex(&cid.to_hex()).unwrap(), cid);
    }

    #[test]
    fn rejects_short_hex() {
        assert!(WorkspaceSecret::from_hex(&hex::encode([1u8; 8])).is_err());
        assert!(WorkspaceId::from_hex(&hex::encode([1u8; 8])).is_err());
        assert!(ChannelId::from_hex(&hex::encode([1u8; 8])).is_err());
    }
}
