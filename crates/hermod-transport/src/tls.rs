//! TLS plumbing for `WsListener::bind_tls` and `connect_tls`.
//!
//! Server-side TLS material loading + the workspace-wide TLS-version
//! pin live here. Client-side cert verification is delegated to
//! [`crate::pin`], which exposes the four-policy
//! [`TlsPinPolicy`](crate::pin::TlsPinPolicy) used by federation and IPC.

use rustls::{
    SupportedProtocolVersion,
    crypto::{CryptoProvider, ring::default_provider},
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
};
use std::sync::Once;

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
