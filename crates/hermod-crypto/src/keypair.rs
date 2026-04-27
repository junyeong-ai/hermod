use ed25519_dalek::{Signer, SigningKey};
use hermod_core::{AgentId, Envelope, FingerprintBytes, PubkeyBytes, SignatureBytes};
use zeroize::ZeroizeOnDrop;

use crate::canonical::canonical_envelope_bytes;
use crate::error::CryptoError;
use crate::identity::{agent_id_from_pubkey, fingerprint_from_pubkey};
use crate::noise_key::NoiseStaticKey;
use crate::public_key::PublicKey;

/// Ed25519 signing keypair.
///
/// `SigningKey` is wired with `ZeroizeOnDrop` (ed25519-dalek's
/// `zeroize` feature is enabled in the workspace `Cargo.toml`), so
/// the secret bytes are scrubbed when the keypair leaves scope.
/// `#[derive(ZeroizeOnDrop)]` here propagates the guarantee to
/// callers that hold an `Arc<Keypair>` — the inner buffer is wiped
/// at the last `Arc::drop`. No `Zeroize` derive: the only field
/// already self-zeroizes and we want `Drop` to fire exactly once.
#[derive(Debug, ZeroizeOnDrop)]
pub struct Keypair {
    signing: SigningKey,
}

impl Keypair {
    /// Generate a fresh keypair using OS randomness.
    pub fn generate() -> Self {
        let mut rng = rand::rngs::OsRng;
        Self {
            signing: SigningKey::generate(&mut rng),
        }
    }

    /// Construct from a 32-byte seed.
    pub fn from_secret_seed(seed: &[u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(seed),
        }
    }

    /// Export the 32-byte seed. Treat as highly sensitive.
    pub fn to_secret_seed(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey::from_verifying(self.signing.verifying_key())
    }

    pub fn to_pubkey_bytes(&self) -> PubkeyBytes {
        PubkeyBytes(self.signing.verifying_key().to_bytes())
    }

    pub fn agent_id(&self) -> AgentId {
        agent_id_from_pubkey(&self.to_pubkey_bytes())
    }

    pub fn fingerprint(&self) -> FingerprintBytes {
        fingerprint_from_pubkey(&self.to_pubkey_bytes())
    }

    /// Sign arbitrary bytes.
    pub fn sign_bytes(&self, bytes: &[u8]) -> SignatureBytes {
        SignatureBytes(self.signing.sign(bytes).to_bytes())
    }

    /// Derive the Noise XX static key (x25519) from this keypair's seed.
    pub fn noise_static_key(&self) -> NoiseStaticKey {
        NoiseStaticKey::derive_from_seed(&self.to_secret_seed())
    }

    /// Compute canonical bytes for an envelope, sign them, and store the signature
    /// into `envelope.sig`. The `envelope.from` id must match this keypair's agent id.
    pub fn sign_envelope(&self, envelope: &mut Envelope) -> Result<(), CryptoError> {
        if envelope.from.id.as_str() != self.agent_id().as_str() {
            return Err(CryptoError::SignerMismatch);
        }
        let bytes = canonical_envelope_bytes(envelope)?;
        envelope.sig = self.sign_bytes(&bytes);
        Ok(())
    }
}
