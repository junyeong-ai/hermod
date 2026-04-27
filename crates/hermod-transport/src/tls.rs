//! TLS plumbing for `WsListener::bind_tls` and `connect_tls`.
//!
//! Peer authentication is the Noise-layer's responsibility. The TLS layer
//! therefore accepts any cert and just exposes the cert fingerprint
//! upstream for TOFU pinning at the routing layer.

use rustls::{
    DigitallySignedStruct, SignatureScheme, SupportedProtocolVersion,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{CryptoProvider, ring::default_provider},
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime, pem::PemObject},
};
use std::sync::{Arc, Once};

use crate::error::TransportError;

/// rustls protocol versions accepted by Hermod's federation transport.
///
/// Pinned to TLS 1.3 only. Every Hermod peer is another Hermod
/// daemon — there is no compatibility floor to preserve. TLS 1.3
/// gives stronger forward secrecy (ephemeral-only key exchange),
/// removes the renegotiation surface, and is downgrade-resistant
/// in a way TLS 1.2 is not. Enforced both server-side and
/// client-side via [`PROTOCOL_VERSIONS`] passed to every rustls
/// builder in this workspace.
pub static PROTOCOL_VERSIONS: &[&SupportedProtocolVersion] = &[&rustls::version::TLS13];

static CRYPTO_PROVIDER_INSTALLED: Once = Once::new();

/// Idempotently install the ring-based default crypto provider for rustls.
/// Safe to call from any thread; `Once` ensures exactly one registration.
pub fn install_default_crypto_provider() {
    CRYPTO_PROVIDER_INSTALLED.call_once(|| {
        // Returns Err if a provider is already installed — we ignore that case.
        let _ = CryptoProvider::install_default(default_provider());
    });
}

pub fn parse_cert_chain(pem: &str) -> Result<Vec<CertificateDer<'static>>, TransportError> {
    CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TransportError::WebSocket(format!("parse cert pem: {e}")))
}

pub fn parse_private_key(pem: &str) -> Result<PrivateKeyDer<'static>, TransportError> {
    PrivateKeyDer::from_pem_slice(pem.as_bytes())
        .map_err(|e| TransportError::WebSocket(format!("parse key pem: {e}")))
}

/// Custom `ServerCertVerifier` that accepts every cert. The peer is authenticated
/// at the Noise layer; this verifier exists only to make TLS itself permissive.
#[derive(Debug)]
pub(crate) struct InsecureCertVerifier {
    supported: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl InsecureCertVerifier {
    fn new() -> Self {
        Self {
            supported: default_provider().signature_verification_algorithms,
        }
    }
}

impl ServerCertVerifier for InsecureCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported.supported_schemes()
    }
}

/// Build a `rustls::ClientConfig` that accepts any server cert. Pair this with
/// fingerprint TOFU at the routing layer.
pub fn client_config_with_insecure_verifier() -> rustls::ClientConfig {
    rustls::ClientConfig::builder_with_protocol_versions(PROTOCOL_VERSIONS)
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(InsecureCertVerifier::new()))
        .with_no_client_auth()
}
