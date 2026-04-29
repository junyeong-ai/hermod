use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;

use crate::error::HermodError;

/// Length of the base32-encoded `AgentId` (26 characters).
pub const AGENT_ID_LEN: usize = 26;

/// Self-certifying agent identifier: `base32-unpadded(blake3(pubkey))[:26]`.
///
/// The `hermod-crypto` crate constructs instances from public keys. This crate only
/// validates that a string has the right shape.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AgentId(String);

impl AgentId {
    /// Construct without validation. For use inside `hermod-crypto`.
    pub fn from_raw(s: String) -> Self {
        Self(s)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for AgentId {
    type Err = HermodError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        validate_agent_id_shape(s)?;
        Ok(Self(s.to_string()))
    }
}

impl fmt::Display for AgentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for AgentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AgentId({})", self.0)
    }
}

fn validate_agent_id_shape(s: &str) -> Result<(), HermodError> {
    if s.len() != AGENT_ID_LEN {
        return Err(HermodError::InvalidAgentId(format!(
            "expected {AGENT_ID_LEN} chars, got {}",
            s.len()
        )));
    }
    // RFC 4648 §6 base32 unpadded lowercase alphabet: a-z 2-7. Note that
    // 0/1/8/9 are explicitly NOT in the base32 alphabet — they look too
    // much like O/I/B/g for safe transcription.
    for c in s.chars() {
        let is_letter = c.is_ascii_lowercase();
        let is_digit = matches!(c, '2'..='7');
        if !is_letter && !is_digit {
            return Err(HermodError::InvalidAgentId(format!(
                "invalid char {c:?} in agent id"
            )));
        }
    }
    Ok(())
}

/// Human-readable alias for an agent. Stored without the `@` prefix.
///
/// Serializes as a bare string for wire compactness. Deserialization goes
/// through [`AgentAlias::from_str`] via `try_from` so a malformed alias on
/// the wire (or in a config file) fails at the deserializer boundary
/// rather than smuggling an invariant violation deeper into the system.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct AgentAlias(String);

impl From<AgentAlias> for String {
    fn from(a: AgentAlias) -> String {
        a.0
    }
}

impl TryFrom<String> for AgentAlias {
    type Error = HermodError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl AgentAlias {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for AgentAlias {
    type Err = HermodError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let stripped = s.strip_prefix('@').unwrap_or(s);
        if stripped.is_empty() || stripped.len() > 64 {
            return Err(HermodError::InvalidAgentAlias(format!(
                "length must be 1..=64, got {}",
                stripped.len()
            )));
        }
        let valid_start = stripped
            .chars()
            .next()
            .map(|c| c.is_ascii_alphabetic())
            .unwrap_or(false);
        if !valid_start {
            return Err(HermodError::InvalidAgentAlias(
                "must start with a letter".into(),
            ));
        }
        for c in stripped.chars() {
            if !(c.is_ascii_alphanumeric() || c == '-' || c == '_') {
                return Err(HermodError::InvalidAgentAlias(format!(
                    "invalid char {c:?}"
                )));
            }
        }
        Ok(Self(stripped.to_string()))
    }
}

impl fmt::Display for AgentAlias {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "@{}", self.0)
    }
}

impl fmt::Debug for AgentAlias {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AgentAlias(@{})", self.0)
    }
}

/// Transport endpoint for an agent's daemon.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "scheme", rename_all = "lowercase")]
pub enum Endpoint {
    /// Unix domain socket (local).
    Unix { path: PathBuf },
    /// TLS-terminated WebSocket (remote).
    Wss(WssEndpoint),
}

impl Endpoint {
    pub fn is_local(&self) -> bool {
        matches!(self, Endpoint::Unix { .. })
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Endpoint::Unix { path } => write!(f, "unix://{}", path.display()),
            Endpoint::Wss(w) => write!(f, "wss://{}:{}", w.host, w.port),
        }
    }
}

impl FromStr for Endpoint {
    type Err = HermodError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(rest) = s.strip_prefix("unix://") {
            Ok(Endpoint::Unix {
                path: PathBuf::from(rest),
            })
        } else if let Some(rest) = s.strip_prefix("wss://") {
            let (host, port) = rest
                .rsplit_once(':')
                .ok_or_else(|| HermodError::InvalidEndpoint(format!("missing port in {s:?}")))?;
            let port: u16 = port
                .parse()
                .map_err(|e| HermodError::InvalidEndpoint(format!("invalid port: {e}")))?;
            Ok(Endpoint::Wss(WssEndpoint {
                host: host.to_string(),
                port,
            }))
        } else {
            Err(HermodError::InvalidEndpoint(format!(
                "unknown scheme in {s:?}"
            )))
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WssEndpoint {
    pub host: String,
    pub port: u16,
}

/// Routable agent address: `AgentId` + optional `Endpoint` hint.
///
/// `None` endpoint means the address must be resolved via the local registry or
/// discovery before reaching.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentAddress {
    pub id: AgentId,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub endpoint: Option<Endpoint>,
}

impl AgentAddress {
    pub fn local(id: AgentId) -> Self {
        Self { id, endpoint: None }
    }

    pub fn with_endpoint(id: AgentId, endpoint: Endpoint) -> Self {
        Self {
            id,
            endpoint: Some(endpoint),
        }
    }
}

impl fmt::Display for AgentAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.endpoint {
            Some(ep) => write!(f, "{}@{ep}", self.id),
            None => write!(f, "{}", self.id),
        }
    }
}

impl FromStr for AgentAddress {
    type Err = HermodError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.split_once('@') {
            None => Ok(AgentAddress::local(AgentId::from_str(s)?)),
            Some((id_part, ep_part)) => Ok(AgentAddress::with_endpoint(
                AgentId::from_str(id_part)?,
                Endpoint::from_str(ep_part)?,
            )),
        }
    }
}

/// Trust level for a known agent. `Local` marks agents this daemon
/// hosts (private key in the `local_agents` table) — multi-tenant,
/// so multiple `Local` rows are normal. The other three apply to
/// remote peer agents observed in our directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustLevel {
    /// Hosted on this daemon — we hold the keypair.
    Local,
    /// Out-of-band fingerprint verification completed.
    Verified,
    /// Trust on first use. Fingerprint memorised.
    Tofu,
    /// New, unknown, or fingerprint changed.
    Untrusted,
}

impl TrustLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            TrustLevel::Local => "local",
            TrustLevel::Verified => "verified",
            TrustLevel::Tofu => "tofu",
            TrustLevel::Untrusted => "untrusted",
        }
    }
}

impl FromStr for TrustLevel {
    type Err = HermodError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "local" => Ok(TrustLevel::Local),
            "verified" => Ok(TrustLevel::Verified),
            "tofu" => Ok(TrustLevel::Tofu),
            "untrusted" => Ok(TrustLevel::Untrusted),
            other => Err(HermodError::InvalidAgentId(format!(
                "unknown trust level {other:?}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alias_parse_strips_at() {
        let a: AgentAlias = "@alice".parse().unwrap();
        assert_eq!(a.as_str(), "alice");
        assert_eq!(format!("{a}"), "@alice");
    }

    #[test]
    fn alias_without_at() {
        let a: AgentAlias = "bob".parse().unwrap();
        assert_eq!(a.as_str(), "bob");
    }

    #[test]
    fn alias_invalid_start() {
        assert!("9zero".parse::<AgentAlias>().is_err());
    }

    #[test]
    fn endpoint_unix() {
        let e: Endpoint = "unix:///tmp/hermod.sock".parse().unwrap();
        match e {
            Endpoint::Unix { path } => assert_eq!(path.to_str().unwrap(), "/tmp/hermod.sock"),
            _ => panic!(),
        }
    }

    #[test]
    fn endpoint_wss() {
        let e: Endpoint = "wss://hermod.example.com:443".parse().unwrap();
        match e {
            Endpoint::Wss(w) => {
                assert_eq!(w.host, "hermod.example.com");
                assert_eq!(w.port, 443);
            }
            _ => panic!(),
        }
    }
}
