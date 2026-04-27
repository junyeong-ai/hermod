//! Noise XX static key derivation.
//!
//! Each Hermod agent has one ed25519 identity key (used to sign envelopes). For the
//! Noise XX handshake we need an x25519 keypair. Rather than store a second secret
//! on disk, we *derive* the noise key deterministically from the ed25519 seed plus
//! a domain separator. Anyone who knows the agent's ed25519 secret can produce the
//! same noise secret; the public key is therefore a function of identity.

use blake3::Hasher;
use x25519_dalek::{PublicKey, StaticSecret};

const DOMAIN: &[u8] = b"hermod-noise-static-v1\0";

#[derive(Clone, Debug)]
pub struct NoiseStaticKey {
    secret: [u8; 32],
    public: [u8; 32],
}

impl NoiseStaticKey {
    /// Derive both halves from a 32-byte ed25519 seed.
    pub fn derive_from_seed(ed25519_seed: &[u8; 32]) -> Self {
        let mut hasher = Hasher::new();
        hasher.update(DOMAIN);
        hasher.update(ed25519_seed);
        let raw: [u8; 32] = hasher.finalize().into();

        let secret = StaticSecret::from(raw);
        let public = PublicKey::from(&secret);
        Self {
            secret: secret.to_bytes(),
            public: public.to_bytes(),
        }
    }

    pub fn private_bytes(&self) -> &[u8; 32] {
        &self.secret
    }

    pub fn public_bytes(&self) -> &[u8; 32] {
        &self.public
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_is_deterministic() {
        let seed = [42u8; 32];
        let a = NoiseStaticKey::derive_from_seed(&seed);
        let b = NoiseStaticKey::derive_from_seed(&seed);
        assert_eq!(a.public_bytes(), b.public_bytes());
        assert_eq!(a.private_bytes(), b.private_bytes());
    }

    #[test]
    fn different_seeds_yield_different_keys() {
        let a = NoiseStaticKey::derive_from_seed(&[1u8; 32]);
        let b = NoiseStaticKey::derive_from_seed(&[2u8; 32]);
        assert_ne!(a.public_bytes(), b.public_bytes());
    }
}
