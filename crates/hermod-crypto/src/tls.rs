//! TLS material for the federation layer.
//!
//! Hermod's federation runs Noise XX *inside* TLS (defence-in-depth). The TLS
//! layer here is intentionally minimal:
//!
//! - Each daemon owns one self-signed cert (subject CN = its agent_id, with
//!   `localhost`, `127.0.0.1`, and `::1` as subject-alternative-names so plain
//!   loopback peering works without DNS).
//! - The cert is regenerated only at `hermod init`; rotation and CA-issued
//!   certs are out of scope for v1.
//! - Authentication of the *peer* is not at the TLS layer — Noise XX provides
//!   it. The TLS verifier in `hermod-transport` therefore accepts any cert,
//!   captures its SHA-256 fingerprint, and `hermod-routing` performs TOFU
//!   pinning against the `agents.tls_fingerprint` column.

use hermod_core::AgentId;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TlsError {
    #[error("rcgen: {0}")]
    Rcgen(#[from] rcgen::Error),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// One self-signed cert + its private key, plus the SHA-256 fingerprint of the
/// cert DER (used for TOFU pinning).
#[derive(Clone, Debug)]
pub struct TlsMaterial {
    pub cert_pem: String,
    pub key_pem: String,
    pub cert_der: Vec<u8>,
    pub fingerprint: String,
}

impl TlsMaterial {
    /// Generate a fresh self-signed cert for this `agent_id`.
    pub fn generate(agent_id: &AgentId) -> Result<Self, TlsError> {
        let mut params = CertificateParams::new(vec![
            "localhost".to_string(),
            "127.0.0.1".to_string(),
            "::1".to_string(),
        ])?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, agent_id.as_str());
        dn.push(DnType::OrganizationName, "Hermod");
        params.distinguished_name = dn;

        let key = KeyPair::generate()?;
        let cert = params.self_signed(&key)?;
        let cert_pem = cert.pem();
        let key_pem = key.serialize_pem();
        let cert_der = cert.der().to_vec();
        let fingerprint = sha256_fingerprint(&cert_der);

        Ok(TlsMaterial {
            cert_pem,
            key_pem,
            cert_der,
            fingerprint,
        })
    }

    /// Reconstruct from PEM-on-disk (loaded by `hermod-daemon::identity`).
    pub fn from_pem(cert_pem: String, key_pem: String) -> Result<Self, TlsError> {
        let cert_der = pem_to_der(&cert_pem);
        let fingerprint = sha256_fingerprint(&cert_der);
        Ok(TlsMaterial {
            cert_pem,
            key_pem,
            cert_der,
            fingerprint,
        })
    }

    /// Parse the cert's `notAfter` validity bound and return it as a
    /// Unix timestamp in seconds. Returns `None` if the DER doesn't
    /// parse — the cert is unreadable in that case anyway, so the
    /// caller (`hermod doctor`) escalates to a separate "cert
    /// readable" check rather than treating "no expiry" as a soft
    /// signal.
    pub fn not_after_unix_secs(&self) -> Option<i64> {
        let (_, parsed) = x509_parser::parse_x509_certificate(&self.cert_der).ok()?;
        Some(parsed.validity().not_after.timestamp())
    }
}

/// Lowercase, colon-separated SHA-256 of the DER cert (e.g. `ab:cd:…:00`).
pub fn sha256_fingerprint(cert_der: &[u8]) -> String {
    let digest = Sha256::digest(cert_der);
    digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn pem_to_der(pem: &str) -> Vec<u8> {
    // Strip header / footer / newlines, base64-decode the body. We accept the
    // cert in standard `-----BEGIN CERTIFICATE-----` framing.
    let body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    use data_encoding::BASE64;
    BASE64.decode(body.as_bytes()).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Keypair;

    fn agent_id() -> AgentId {
        let kp = Keypair::generate();
        kp.agent_id()
    }

    #[test]
    fn generate_yields_consistent_fingerprint() {
        let aid = agent_id();
        let m = TlsMaterial::generate(&aid).expect("generate");
        let recomputed = sha256_fingerprint(&m.cert_der);
        assert_eq!(m.fingerprint, recomputed);
        assert_eq!(m.fingerprint.matches(':').count(), 31);
    }

    #[test]
    fn pem_roundtrip_preserves_fingerprint() {
        let aid = agent_id();
        let original = TlsMaterial::generate(&aid).unwrap();
        let restored =
            TlsMaterial::from_pem(original.cert_pem.clone(), original.key_pem.clone()).unwrap();
        assert_eq!(original.fingerprint, restored.fingerprint);
        assert_eq!(original.cert_der, restored.cert_der);
    }

    #[test]
    fn distinct_certs_have_distinct_fingerprints() {
        let a = TlsMaterial::generate(&agent_id()).unwrap();
        let b = TlsMaterial::generate(&agent_id()).unwrap();
        assert_ne!(a.fingerprint, b.fingerprint);
    }

    #[test]
    fn not_after_is_in_the_future() {
        // rcgen's default validity puts notAfter ~1 year out. The
        // exact horizon isn't specified — we only assert that a
        // freshly-generated cert has a future expiry. This pins the
        // contract `hermod doctor` depends on: a present cert never
        // reports as already-expired.
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let m = TlsMaterial::generate(&agent_id()).unwrap();
        let not_after = m
            .not_after_unix_secs()
            .expect("freshly-generated cert must parse");
        assert!(
            not_after > now_secs,
            "notAfter {} must be after now {}",
            not_after,
            now_secs
        );
    }

    #[test]
    fn not_after_round_trips_through_pem() {
        // PEM-on-disk → from_pem → still parseable. Catches any
        // base64 decoding drift between `generate` and `from_pem`
        // that would silently break the doctor warning.
        let original = TlsMaterial::generate(&agent_id()).unwrap();
        let restored =
            TlsMaterial::from_pem(original.cert_pem.clone(), original.key_pem.clone()).unwrap();
        assert_eq!(
            original.not_after_unix_secs(),
            restored.not_after_unix_secs()
        );
    }
}
