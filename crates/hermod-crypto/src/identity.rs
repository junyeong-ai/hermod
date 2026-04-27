use data_encoding::BASE32_NOPAD;
use hermod_core::{AgentId, FingerprintBytes, PubkeyBytes};

use crate::error::CryptoError;

/// Blake3 hash of the 32-byte public key.
pub fn fingerprint_from_pubkey(pk: &PubkeyBytes) -> FingerprintBytes {
    FingerprintBytes(*blake3::hash(pk.as_slice()).as_bytes())
}

/// Derive `AgentId = base32-unpadded-lowercase(blake3(pubkey))[:26]`.
pub fn agent_id_from_pubkey(pk: &PubkeyBytes) -> AgentId {
    let digest = blake3::hash(pk.as_slice());
    let encoded = BASE32_NOPAD.encode(digest.as_bytes()).to_lowercase();
    let mut id = encoded;
    id.truncate(hermod_core::identity::AGENT_ID_LEN);
    AgentId::from_raw(id)
}

/// Re-derive an `AgentId` from raw pubkey bytes and check it matches a claimed id.
pub fn verify_agent_id(claimed: &AgentId, pk: &PubkeyBytes) -> Result<(), CryptoError> {
    let derived = agent_id_from_pubkey(pk);
    if derived.as_str() != claimed.as_str() {
        return Err(CryptoError::InvalidPublicKey(format!(
            "agent id mismatch: claimed {claimed}, derived {derived}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hermod_core::identity::AGENT_ID_LEN;

    #[test]
    fn agent_id_is_deterministic_and_valid_length() {
        let pk = PubkeyBytes([7u8; 32]);
        let a = agent_id_from_pubkey(&pk);
        let b = agent_id_from_pubkey(&pk);
        assert_eq!(a.as_str(), b.as_str());
        assert_eq!(a.as_str().len(), AGENT_ID_LEN);
    }

    #[test]
    fn fingerprint_human_prefix() {
        let pk = PubkeyBytes([0xab; 32]);
        let fp = fingerprint_from_pubkey(&pk);
        let p = fp.to_human_prefix(4);
        assert_eq!(p.matches(':').count(), 3);
    }

    #[test]
    fn verify_agent_id_detects_mismatch() {
        let pk_a = PubkeyBytes([1u8; 32]);
        let pk_b = PubkeyBytes([2u8; 32]);
        let id_a = agent_id_from_pubkey(&pk_a);
        assert!(verify_agent_id(&id_a, &pk_a).is_ok());
        assert!(verify_agent_id(&id_a, &pk_b).is_err());
    }
}
