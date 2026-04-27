use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hermod_core::{AgentId, Envelope, FingerprintBytes, PubkeyBytes, SignatureBytes};

use crate::canonical::canonical_envelope_bytes;
use crate::error::CryptoError;
use crate::identity::{agent_id_from_pubkey, fingerprint_from_pubkey, verify_agent_id};

/// Ed25519 verifying (public) key.
#[derive(Clone, Debug)]
pub struct PublicKey {
    verifying: VerifyingKey,
}

impl PublicKey {
    pub(crate) fn from_verifying(v: VerifyingKey) -> Self {
        Self { verifying: v }
    }

    pub fn from_bytes(b: &PubkeyBytes) -> Result<Self, CryptoError> {
        let v = VerifyingKey::from_bytes(&b.0)
            .map_err(|e| CryptoError::InvalidPublicKey(e.to_string()))?;
        Ok(Self { verifying: v })
    }

    pub fn to_bytes(&self) -> PubkeyBytes {
        PubkeyBytes(self.verifying.to_bytes())
    }

    pub fn agent_id(&self) -> AgentId {
        agent_id_from_pubkey(&self.to_bytes())
    }

    pub fn fingerprint(&self) -> FingerprintBytes {
        fingerprint_from_pubkey(&self.to_bytes())
    }

    /// Verify a signature over raw bytes.
    pub fn verify_bytes(&self, bytes: &[u8], sig: &SignatureBytes) -> Result<(), CryptoError> {
        let sig = Signature::from_bytes(&sig.0);
        self.verifying
            .verify(bytes, &sig)
            .map_err(|_| CryptoError::SignatureVerificationFailed)
    }

    /// Verify an envelope: recomputes canonical bytes and checks `sig` against them.
    /// Also checks that the envelope `from` agent id matches this key.
    pub fn verify_envelope(&self, envelope: &Envelope) -> Result<(), CryptoError> {
        verify_agent_id(&envelope.from.id, &self.to_bytes())?;
        envelope.validate_kind_body()?;
        let bytes = canonical_envelope_bytes(envelope)?;
        self.verify_bytes(&bytes, &envelope.sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keypair::Keypair;
    use hermod_core::{AgentAddress, MessageBody, MessagePriority};

    #[test]
    fn sign_and_verify_roundtrip() {
        let kp = Keypair::generate();
        let pk = kp.public_key();
        let me = AgentAddress::local(kp.agent_id());
        let mut env = Envelope::draft(
            me.clone(),
            me,
            MessageBody::Direct { text: "hi".into() },
            MessagePriority::Normal,
            60,
        );
        kp.sign_envelope(&mut env).unwrap();
        pk.verify_envelope(&env).unwrap();
    }

    #[test]
    fn tampered_envelope_fails_verification() {
        let kp = Keypair::generate();
        let pk = kp.public_key();
        let me = AgentAddress::local(kp.agent_id());
        let mut env = Envelope::draft(
            me.clone(),
            me,
            MessageBody::Direct { text: "hi".into() },
            MessagePriority::Normal,
            60,
        );
        kp.sign_envelope(&mut env).unwrap();
        if let MessageBody::Direct { text } = &mut env.body {
            text.push_str(" extra");
        }
        assert!(pk.verify_envelope(&env).is_err());
    }

    #[test]
    fn wrong_key_fails_verification() {
        let kp1 = Keypair::generate();
        let kp2 = Keypair::generate();
        let me1 = AgentAddress::local(kp1.agent_id());
        let mut env = Envelope::draft(
            me1.clone(),
            me1,
            MessageBody::Direct { text: "hi".into() },
            MessagePriority::Normal,
            60,
        );
        kp1.sign_envelope(&mut env).unwrap();
        assert!(kp2.public_key().verify_envelope(&env).is_err());
    }
}
