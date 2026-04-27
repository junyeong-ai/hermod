//! Application-level signing abstraction.
//!
//! Hermod separates two distinct uses of the daemon's identity material:
//!
//! - **Application signing** — envelopes, capability tokens, audit-log
//!   rows, signed mDNS beacons. Goes through this `Signer` trait so a
//!   future deployment can swap the local file-backed key for a
//!   KMS-backed one (`KmsSigner` against AWS KMS / GCP KMS / HashiCorp
//!   Vault Transit). Every callsite is a trait method on `Arc<dyn Signer>`.
//!
//! - **Transport material** — the X25519 static key derived for Noise
//!   handshake, the ed25519 cert chain for self-signed TLS. These stay
//!   on the concrete [`Keypair`] type and are consumed inside the
//!   transport layer (Noise + rustls). They aren't operations a KMS
//!   would gate; they're handshake-time key derivations.
//!
//! Async: every signing operation returns a future even when the local
//! impl is infallible/instant — KMS round-trips are network-bound, and
//! making the trait sync would force every callsite to refactor when a
//! KMS backend is added later.

use async_trait::async_trait;
use std::sync::Arc;

use hermod_core::{AgentId, Envelope, PubkeyBytes, SignatureBytes};

use crate::canonical::canonical_envelope_bytes;
use crate::capability::CapabilityClaim;
use crate::error::CryptoError;
use crate::keypair::Keypair;
use crate::public_key::PublicKey;

/// Signs payloads on behalf of one agent identity.
///
/// Implementations must be cheap to `Arc::clone`; the daemon hands one
/// `Arc<dyn Signer>` to every service that needs to sign.
#[async_trait]
pub trait Signer: Send + Sync + std::fmt::Debug + 'static {
    /// The agent_id this signer mints signatures under. Constant for the
    /// lifetime of the signer; rotation = constructing a new Signer.
    fn agent_id(&self) -> AgentId;

    /// The verifying half of this signer's identity. Receivers use this
    /// to authenticate signed payloads.
    fn public_key(&self) -> PublicKey;

    /// Raw 32-byte ed25519 pubkey — the bytes that hash to `agent_id`.
    /// Embedded in `Hello` frames and capability claims so peers can
    /// verify our signatures.
    fn pubkey_bytes(&self) -> PubkeyBytes;

    /// Sign arbitrary bytes. The fundamental primitive — every other
    /// trait method composes this. Used by the audit hash chain
    /// (`row_hash` → signature) and by signed mDNS beacons.
    async fn sign_bytes(&self, bytes: &[u8]) -> Result<SignatureBytes, CryptoError>;

    /// Stamp the signer's pubkey onto the envelope, compute canonical
    /// bytes, sign them, and store the signature. Refuses to sign for
    /// any identity other than the signer's own. After this call the
    /// envelope is fully self-verifying — receivers can authenticate
    /// it from the bytes alone (`blake3(from_pubkey)[:26] == from.id`
    /// + sig verification) without consulting any external directory.
    async fn sign_envelope(&self, envelope: &mut Envelope) -> Result<(), CryptoError> {
        if envelope.from.id.as_str() != self.agent_id().as_str() {
            return Err(CryptoError::SignerMismatch);
        }
        envelope.from_pubkey = self.pubkey_bytes();
        let bytes = canonical_envelope_bytes(envelope)?;
        envelope.sig = self.sign_bytes(&bytes).await?;
        Ok(())
    }

    /// Serialize a capability claim to canonical CBOR, sign it, and
    /// concatenate `[len|claim|sig]` into the opaque token bytes.
    /// Default impl handles the framing — backends only customise
    /// `sign_bytes`.
    async fn sign_capability(&self, claim: &CapabilityClaim) -> Result<Vec<u8>, CryptoError> {
        let mut claim_bytes = Vec::with_capacity(96);
        ciborium::into_writer(claim, &mut claim_bytes)
            .map_err(|e| CryptoError::Serialization(e.to_string()))?;
        let sig = self.sign_bytes(&claim_bytes).await?;
        let mut out = Vec::with_capacity(4 + claim_bytes.len() + SignatureBytes::LEN);
        out.extend_from_slice(&(claim_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&claim_bytes);
        out.extend_from_slice(sig.as_slice());
        Ok(out)
    }
}

/// Local file-backed signer — wraps a `Keypair` loaded from
/// `$HERMOD_HOME/identity/ed25519_secret`. The default implementation;
/// a future `KmsSigner` slots into the same `Arc<dyn Signer>` consumer
/// surface without daemon changes.
#[derive(Debug)]
pub struct LocalKeySigner {
    keypair: Arc<Keypair>,
}

impl LocalKeySigner {
    pub fn new(keypair: Arc<Keypair>) -> Self {
        Self { keypair }
    }

    /// Borrow the underlying keypair. Reserved for the transport layer
    /// (Noise X25519 key derivation, TLS cert generation) — application
    /// services must use the `Signer` trait methods instead.
    pub fn keypair(&self) -> &Arc<Keypair> {
        &self.keypair
    }
}

#[async_trait]
impl Signer for LocalKeySigner {
    fn agent_id(&self) -> AgentId {
        self.keypair.agent_id()
    }

    fn public_key(&self) -> PublicKey {
        self.keypair.public_key()
    }

    fn pubkey_bytes(&self) -> PubkeyBytes {
        self.keypair.to_pubkey_bytes()
    }

    async fn sign_bytes(&self, bytes: &[u8]) -> Result<SignatureBytes, CryptoError> {
        Ok(self.keypair.sign_bytes(bytes))
    }
}
