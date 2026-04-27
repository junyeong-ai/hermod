//! Envelope-level protocol helpers.

use hermod_core::{Envelope, HermodError, PROTOCOL_VERSION};
use hermod_crypto::{CryptoError, PublicKey};

pub use hermod_crypto::canonical_envelope_bytes;

/// Serialize the *full* envelope (including `sig`) as CBOR. Used for storage and
/// peer forwarding; canonical bytes (sig-stripped) are used only at sign/verify time.
pub fn serialize_envelope(envelope: &Envelope) -> Result<Vec<u8>, EnvelopeError> {
    let mut buf = Vec::with_capacity(256);
    ciborium::into_writer(envelope, &mut buf)
        .map_err(|e| EnvelopeError::Crypto(CryptoError::Serialization(e.to_string())))?;
    Ok(buf)
}

pub fn deserialize_envelope(bytes: &[u8]) -> Result<Envelope, EnvelopeError> {
    ciborium::from_reader(bytes)
        .map_err(|e| EnvelopeError::Crypto(CryptoError::Serialization(e.to_string())))
}

#[derive(Debug, thiserror::Error)]
pub enum EnvelopeError {
    #[error("unsupported protocol version {actual}, expected <= {supported}")]
    UnsupportedVersion { actual: u16, supported: u16 },

    #[error(transparent)]
    Core(#[from] HermodError),

    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

/// Validate an incoming envelope and verify its signature.
///
/// Steps:
///  1. Check protocol version is supported.
///  2. Check kind/body invariant.
///  3. Verify signature against the sender's `PublicKey`.
pub fn verify_incoming(env: &Envelope, sender_key: &PublicKey) -> Result<(), EnvelopeError> {
    if env.v > PROTOCOL_VERSION {
        return Err(EnvelopeError::UnsupportedVersion {
            actual: env.v,
            supported: PROTOCOL_VERSION,
        });
    }
    env.validate_kind_body()?;
    sender_key.verify_envelope(env)?;
    Ok(())
}
