//! Fixed-size byte arrays for crypto primitives.
//!
//! These live in `hermod-core` so that types like `Envelope` can reference them without
//! pulling in `hermod-crypto`. The crypto crate converts to/from these when signing
//! or verifying.
//!
//! Serialization:
//! - Human-readable formats (JSON, TOML): hex-encoded strings
//! - Binary formats (CBOR): raw bytes (CBOR major type 2)

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

use crate::error::HermodError;

/// Ed25519 signature (64 bytes).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SignatureBytes(pub [u8; Self::LEN]);

impl SignatureBytes {
    pub const LEN: usize = 64;

    pub fn zero() -> Self {
        Self([0u8; Self::LEN])
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SignatureBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SignatureBytes({})", hex::encode(self.0))
    }
}

impl Serialize for SignatureBytes {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        serialize_fixed_bytes(&self.0, ser)
    }
}

impl<'de> Deserialize<'de> for SignatureBytes {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        Ok(Self(deserialize_fixed_bytes::<{ Self::LEN }, D>(de)?))
    }
}

/// Ed25519 public key (32 bytes).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PubkeyBytes(pub [u8; Self::LEN]);

impl PubkeyBytes {
    pub const LEN: usize = 32;

    /// All-zero placeholder for unsigned envelope drafts. The signer
    /// overwrites this with the real pubkey at sign time, identical to
    /// how `SignatureBytes::zero()` is later overwritten with the real
    /// signature.
    pub fn zero() -> Self {
        Self([0u8; Self::LEN])
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for PubkeyBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PubkeyBytes({})", hex::encode(self.0))
    }
}

impl Serialize for PubkeyBytes {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        serialize_fixed_bytes(&self.0, ser)
    }
}

impl<'de> Deserialize<'de> for PubkeyBytes {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        Ok(Self(deserialize_fixed_bytes::<{ Self::LEN }, D>(de)?))
    }
}

/// Blake3 hash of a pubkey (32 bytes). Used as source material for `AgentId` and for
/// human-readable fingerprint display.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct FingerprintBytes(pub [u8; Self::LEN]);

impl FingerprintBytes {
    pub const LEN: usize = 32;

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Format as `ab:cd:ef:...` truncated to `n_bytes`.
    pub fn to_human_prefix(&self, n_bytes: usize) -> String {
        let n = n_bytes.min(Self::LEN);
        let mut out = String::with_capacity(n * 3);
        for (i, b) in self.0.iter().take(n).enumerate() {
            if i > 0 {
                out.push(':');
            }
            out.push_str(&format!("{b:02x}"));
        }
        out
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self, HermodError> {
        let bytes = hex::decode(s.replace(':', ""))
            .map_err(|e| HermodError::InvalidFingerprint(e.to_string()))?;
        if bytes.len() != Self::LEN {
            return Err(HermodError::InvalidFingerprint(format!(
                "expected {} bytes, got {}",
                Self::LEN,
                bytes.len()
            )));
        }
        let mut arr = [0u8; Self::LEN];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

impl fmt::Debug for FingerprintBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FingerprintBytes({})", self.to_hex())
    }
}

impl Serialize for FingerprintBytes {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        serialize_fixed_bytes(&self.0, ser)
    }
}

impl<'de> Deserialize<'de> for FingerprintBytes {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        Ok(Self(deserialize_fixed_bytes::<{ Self::LEN }, D>(de)?))
    }
}

// --- shared serde helpers ---

fn serialize_fixed_bytes<S: Serializer>(bytes: &[u8], ser: S) -> Result<S::Ok, S::Error> {
    if ser.is_human_readable() {
        ser.serialize_str(&hex::encode(bytes))
    } else {
        ser.serialize_bytes(bytes)
    }
}

fn deserialize_fixed_bytes<'de, const N: usize, D: Deserializer<'de>>(
    de: D,
) -> Result<[u8; N], D::Error> {
    struct FixedBytesVisitor<const M: usize>;
    impl<'de, const M: usize> serde::de::Visitor<'de> for FixedBytesVisitor<M> {
        type Value = [u8; M];

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{M} bytes (raw or hex-encoded)")
        }

        fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
            if v.len() != M {
                return Err(E::custom(format!("expected {M} bytes, got {}", v.len())));
            }
            let mut arr = [0u8; M];
            arr.copy_from_slice(v);
            Ok(arr)
        }

        fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<Self::Value, E> {
            self.visit_bytes(&v)
        }

        fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
            let bytes = hex::decode(v).map_err(E::custom)?;
            self.visit_bytes(&bytes)
        }

        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> Result<Self::Value, A::Error> {
            let mut arr = [0u8; M];
            for (i, slot) in arr.iter_mut().enumerate() {
                *slot = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(i, &format!("{M}").as_str()))?;
            }
            Ok(arr)
        }
    }

    if de.is_human_readable() {
        de.deserialize_str(FixedBytesVisitor::<N>)
    } else {
        de.deserialize_bytes(FixedBytesVisitor::<N>)
    }
}
