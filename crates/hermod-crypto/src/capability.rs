//! Ed25519-signed capability tokens.
//!
//! A capability says "the holder may perform `<scope>` against `<target>` until
//! `<exp>`." Tokens are minted by an issuer (the daemon of the resource being
//! protected) and presented in `Envelope.caps[]` by the bearer.
//!
//! Wire format (binary, not JSON):
//!
//! ```text
//! +--------+---------------+----------------+
//! | u32 BE | claim (CBOR)  | sig (64 bytes) |
//! | length |               | ed25519        |
//! +--------+---------------+----------------+
//! ```
//!
//! The full bytes form the opaque `CapabilityToken` carried on the wire. The
//! issuer's ed25519 pubkey is *not* embedded — verifiers must look it up by
//! `claim.iss` (which is the issuer's `AgentId`, derivable from the pubkey).

use hermod_core::{AgentId, SignatureBytes};
use serde::{Deserialize, Serialize};

use crate::error::CryptoError;
use crate::public_key::PublicKey;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct CapabilityClaim {
    /// Format version (currently 1).
    pub v: u16,
    /// Issuer agent id — must match the pubkey used to verify the token.
    pub iss: AgentId,
    /// Audience: the agent permitted to bear this token. `None` = bearer = anyone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aud: Option<AgentId>,
    /// Permitted scope, e.g. `"message:send"`, `"brief:read"`.
    pub scope: String,
    /// Optional target identifier (e.g. specific agent id). `None` = any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// Issued-at unix-millis.
    pub iat: i64,
    /// Expires-at unix-millis. `None` = no expiry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    /// Unique token id (ULID string) — used by revocation.
    pub jti: String,
}

pub const CAPABILITY_VERSION: u16 = 1;

/// Inspect token bytes and verify the signature against `issuer_pk`. Returns the
/// embedded claim on success.
pub fn verify_capability(
    issuer_pk: &PublicKey,
    token_bytes: &[u8],
) -> Result<CapabilityClaim, CryptoError> {
    if token_bytes.len() < 4 + SignatureBytes::LEN {
        return Err(CryptoError::InvalidSignature("token too short".into()));
    }
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&token_bytes[..4]);
    let claim_len = u32::from_be_bytes(len_bytes) as usize;
    let total_expected = 4 + claim_len + SignatureBytes::LEN;
    if token_bytes.len() != total_expected {
        return Err(CryptoError::InvalidSignature(format!(
            "token length mismatch: {} != {}",
            token_bytes.len(),
            total_expected
        )));
    }
    let claim_bytes = &token_bytes[4..4 + claim_len];
    let sig_bytes_slice = &token_bytes[4 + claim_len..];
    let mut sig_arr = [0u8; SignatureBytes::LEN];
    sig_arr.copy_from_slice(sig_bytes_slice);
    let sig = SignatureBytes(sig_arr);
    issuer_pk.verify_bytes(claim_bytes, &sig)?;
    let claim: CapabilityClaim = ciborium::from_reader(claim_bytes)
        .map_err(|e| CryptoError::Serialization(e.to_string()))?;
    if claim.v != CAPABILITY_VERSION {
        return Err(CryptoError::InvalidSignature(format!(
            "unsupported capability version {}",
            claim.v
        )));
    }
    Ok(claim)
}

/// Read just the claim — without verifying the signature — for inspection.
/// **Do not use this for authorization decisions.**
pub fn parse_claim_unverified(token_bytes: &[u8]) -> Result<CapabilityClaim, CryptoError> {
    if token_bytes.len() < 4 + SignatureBytes::LEN {
        return Err(CryptoError::InvalidSignature("token too short".into()));
    }
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&token_bytes[..4]);
    let claim_len = u32::from_be_bytes(len_bytes) as usize;
    if token_bytes.len() < 4 + claim_len + SignatureBytes::LEN {
        return Err(CryptoError::InvalidSignature(
            "token length mismatch".into(),
        ));
    }
    let claim_bytes = &token_bytes[4..4 + claim_len];
    ciborium::from_reader(claim_bytes).map_err(|e| CryptoError::Serialization(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Keypair, LocalKeySigner, Signer};
    use std::sync::Arc;

    fn fresh() -> (LocalKeySigner, PublicKey) {
        let kp = Arc::new(Keypair::generate());
        let pk = kp.public_key();
        (LocalKeySigner::new(kp), pk)
    }

    fn claim_for(issuer: AgentId) -> CapabilityClaim {
        CapabilityClaim {
            v: CAPABILITY_VERSION,
            iss: issuer,
            aud: None,
            scope: "message:send".into(),
            target: None,
            iat: 1_700_000_000_000,
            exp: Some(1_800_000_000_000),
            jti: "01J9X0000000000000000000000".into(),
        }
    }

    #[tokio::test]
    async fn sign_then_verify_roundtrip() {
        let (signer, pk) = fresh();
        let claim = claim_for(signer.agent_id());
        let token = signer.sign_capability(&claim).await.unwrap();
        let parsed = verify_capability(&pk, &token).unwrap();
        assert_eq!(parsed, claim);
    }

    #[tokio::test]
    async fn tampered_claim_fails() {
        let (signer, pk) = fresh();
        let claim = claim_for(signer.agent_id());
        let mut token = signer.sign_capability(&claim).await.unwrap();
        // Flip one byte in the claim payload (after the 4-byte length).
        token[5] ^= 0x80;
        assert!(verify_capability(&pk, &token).is_err());
    }

    #[tokio::test]
    async fn wrong_signer_fails() {
        let (signer_a, _) = fresh();
        let (_, pk_b) = fresh();
        let claim = claim_for(signer_a.agent_id());
        let token = signer_a.sign_capability(&claim).await.unwrap();
        assert!(verify_capability(&pk_b, &token).is_err());
    }

    #[tokio::test]
    async fn unverified_parse_works_on_modified_sig() {
        let (signer, _pk) = fresh();
        let claim = claim_for(signer.agent_id());
        let mut token = signer.sign_capability(&claim).await.unwrap();
        let len = token.len();
        token[len - 1] ^= 0xff; // corrupt sig only
        let parsed = parse_claim_unverified(&token).unwrap();
        assert_eq!(parsed.scope, "message:send");
    }
}
