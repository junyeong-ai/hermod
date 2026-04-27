use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

use crate::error::HermodError;

/// Opaque capability token bytes (length-prefixed CBOR claim + 64-byte
/// ed25519 signature). Interpretation and verification live in
/// `hermod-crypto::capability` and `hermod-routing::AccessController`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityToken {
    #[serde(with = "serde_bytes_wrapper")]
    bytes: Vec<u8>,
}

impl CapabilityToken {
    pub fn from_bytes(b: Vec<u8>) -> Self {
        Self { bytes: b }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl fmt::Debug for CapabilityToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CapabilityToken(len={})", self.bytes.len())
    }
}

/// Direction of a capability row from this agent's perspective.
/// `Issued` — minted locally, audience is some other agent (or wildcard).
/// `Received` — minted by a remote issuer, this agent is the audience.
/// Lives in core (not storage) so it can ride along IPC params and CLI
/// surface without dragging the storage crate into protocol/CLI builds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityDirection {
    Issued,
    Received,
}

impl CapabilityDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            CapabilityDirection::Issued => "issued",
            CapabilityDirection::Received => "received",
        }
    }
}

impl FromStr for CapabilityDirection {
    type Err = HermodError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "issued" => Ok(CapabilityDirection::Issued),
            "received" => Ok(CapabilityDirection::Received),
            other => Err(HermodError::InvalidCapabilityToken(format!(
                "invalid capability direction `{other}`; expected `issued` or `received`"
            ))),
        }
    }
}

/// Scope of a capability. Text form: `<resource>:<action>` or `<resource>:<action>:<target>`.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CapabilityScope(String);

impl CapabilityScope {
    pub const MESSAGE_SEND: &'static str = "message:send";
    pub const MESSAGE_READ: &'static str = "message:read";
    pub const MESSAGE_ACK: &'static str = "message:ack";
    pub const BRIEF_PUBLISH: &'static str = "brief:publish";
    pub const BRIEF_READ: &'static str = "brief:read";
    pub const PRESENCE_SET: &'static str = "presence:set";
    pub const PRESENCE_READ: &'static str = "presence:read";
    pub const AGENT_LIST: &'static str = "agent:list";
    pub const AGENT_BLOCK: &'static str = "agent:block";
    pub const PEER_ADMIN: &'static str = "peer:admin";
    pub const CAPABILITY_ISSUE: &'static str = "capability:issue";

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for CapabilityScope {
    type Err = HermodError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();
        if !(2..=3).contains(&parts.len()) {
            return Err(HermodError::InvalidCapabilityToken(format!(
                "expected 2-3 colon-separated parts, got {s:?}"
            )));
        }
        for p in &parts {
            if p.is_empty() {
                return Err(HermodError::InvalidCapabilityToken(format!(
                    "empty scope part in {s:?}"
                )));
            }
        }
        Ok(Self(s.to_string()))
    }
}

impl fmt::Debug for CapabilityScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CapabilityScope({})", self.0)
    }
}

impl fmt::Display for CapabilityScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// Serde adapter for Vec<u8>:
// - human-readable formats (JSON / TOML): hex-encoded string
// - binary formats (CBOR): byte string (CBOR major type 2)
//
// We do not trust `is_human_readable()` for dispatch — ciborium reports `false` on
// the Serializer side and `true` on the Deserializer side. Instead, the serialize
// path branches on `is_human_readable()` to choose its representation, and the
// deserialize path uses a single visitor that accepts BOTH a hex string and raw
// bytes, returning the raw byte content in either case.
mod serde_bytes_wrapper {
    use serde::{Deserializer, Serializer};
    use std::fmt;

    pub fn serialize<S: Serializer>(bytes: &Vec<u8>, ser: S) -> Result<S::Ok, S::Error> {
        if ser.is_human_readable() {
            ser.serialize_str(&hex::encode(bytes))
        } else {
            ser.serialize_bytes(bytes)
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Vec<u8>, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = Vec<u8>;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "bytes (raw or hex-encoded)")
            }
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                Ok(v.to_vec())
            }
            fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<Self::Value, E> {
                Ok(v)
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                hex::decode(v).map_err(E::custom)
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut out: Vec<u8> = Vec::new();
                while let Some(b) = seq.next_element::<u8>()? {
                    out.push(b);
                }
                Ok(out)
            }
        }
        // Ask for "any" so the underlying format dispatches to the right visit_* method.
        de.deserialize_any(V)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_parse_roundtrip() {
        let s: CapabilityScope = "message:send".parse().unwrap();
        assert_eq!(s.as_str(), "message:send");
    }

    #[test]
    fn scope_parse_three_parts() {
        let s: CapabilityScope = "brief:read:@alice".parse().unwrap();
        assert_eq!(s.as_str(), "brief:read:@alice");
    }

    #[test]
    fn scope_reject_malformed() {
        assert!("noop".parse::<CapabilityScope>().is_err());
        assert!("a::b".parse::<CapabilityScope>().is_err());
    }
}
