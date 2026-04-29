//! TLS pin policy + verifier for outbound TLS connections.
//!
//! Hermod authenticates the *peer identity* at the application layer
//! (Noise XX for federation, bearer token for IPC). The TLS layer
//! exists to provide confidentiality and to recognise the same peer
//! across reconnects. [`TlsPinPolicy`] picks how the cert chain is
//! validated:
//!
//! | mode | use case |
//! |------|----------|
//! | `tofu` (default) | self-signed daemon cert, federation peer-to-peer, LAN |
//! | `<sha256>` | explicit fingerprint pin (production federation, audited) |
//! | `public-ca` | broker behind a public-CA-trusted reverse proxy (Cloud Run, IAP, Cloudflare) |
//! | `none` | tests / fully-trusted LAN; skip TLS validation entirely |
//!
//! TOFU records the first-seen fingerprint to a JSON map keyed by
//! `host:port`. Subsequent connects fail loud on mismatch — exactly the
//! semantics SSH host-key pinning has used for decades.
//!
//! `public-ca` skips the TOFU store and delegates chain validation to
//! `rustls`'s production `WebPkiServerVerifier` over the OS trust
//! store, so an LB rotating its cert under a stable hostname keeps
//! working without operator intervention.

use crate::error::TransportError;
use crate::tls::PROTOCOL_VERSIONS;
use rustls::{
    ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::ring::default_provider,
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

/// Policy for verifying a TLS server certificate. Variants are
/// exhaustive and cover both the "we own both ends" world (TOFU /
/// fingerprint) and the "we go through a hosted reverse proxy" world
/// (public-CA).
#[derive(Debug, Clone)]
pub enum TlsPinPolicy {
    /// First-connect: record the observed fingerprint to `store`. Subsequent
    /// connects: fail loud on mismatch. `host_port` is the lookup key.
    Tofu {
        store: TlsPinStore,
        host_port: String,
    },
    /// Validate the daemon's TLS chain via the OS trust store (system
    /// root CAs). The right answer when a public-CA-trusted reverse
    /// proxy (Cloud Run, IAP, Cloudflare Access, ALB+Cognito) sits in
    /// front of the daemon and presents the user-facing cert — pinning
    /// the LB's cert fingerprint would break on every cert rotation.
    PublicCa,
    /// Skip TLS validation entirely. Strictly opt-in for tests / known-LAN.
    Insecure,
    /// Cert SHA-256 must equal this fingerprint (lowercase, colon-separated).
    Fingerprint(String),
}

impl TlsPinPolicy {
    /// Normalise a hex fingerprint for storage / comparison.
    /// Accepts colon-separated, space-separated, or unseparated; lowercases.
    pub fn normalize_fingerprint(s: &str) -> Result<String, TransportError> {
        let cleaned: String = s
            .chars()
            .filter(|c| !c.is_whitespace() && *c != ':')
            .map(|c| c.to_ascii_lowercase())
            .collect();
        if cleaned.len() != 64 || !cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(TransportError::WebSocket(format!(
                "TLS fingerprint must be SHA-256 (64 hex chars), got {} chars",
                cleaned.len()
            )));
        }
        let mut out = String::with_capacity(95);
        for (i, ch) in cleaned.chars().enumerate() {
            if i > 0 && i % 2 == 0 {
                out.push(':');
            }
            out.push(ch);
        }
        Ok(out)
    }

    /// Build the rustls `ClientConfig` enforcing this policy.
    /// `PublicCa` uses the production `WebPkiServerVerifier` from rustls;
    /// the other three install a custom verifier that delegates the
    /// cryptographic-signature check to ring while overriding chain
    /// validation per the policy.
    pub fn build_client_config(&self) -> Result<ClientConfig, TransportError> {
        let base = ClientConfig::builder_with_protocol_versions(PROTOCOL_VERSIONS);
        Ok(match self {
            TlsPinPolicy::PublicCa => base
                .with_root_certificates(load_native_roots()?)
                .with_no_client_auth(),
            TlsPinPolicy::Insecure => base
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(InsecureVerifier::new()))
                .with_no_client_auth(),
            TlsPinPolicy::Fingerprint(expected) => base
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(PinningVerifier::fingerprint(
                    expected.clone(),
                )))
                .with_no_client_auth(),
            TlsPinPolicy::Tofu { store, host_port } => base
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(PinningVerifier::tofu(
                    store.clone(),
                    host_port.clone(),
                )))
                .with_no_client_auth(),
        })
    }
}

/// Parsed CLI / config form of a pin policy. Distinct from [`TlsPinPolicy`]
/// because `Tofu` carries a runtime store + host_port that can't be
/// expressed in a configuration string. Operator-supplied strings parse
/// into [`PinSpec`]; the daemon (which knows `$HERMOD_HOME` and the URL)
/// resolves them to [`TlsPinPolicy`] at dial-construction time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinSpec {
    Tofu,
    PublicCa,
    Insecure,
    Fingerprint(String),
}

impl PinSpec {
    /// Resolve to a runtime [`TlsPinPolicy`]. `tofu_store` and
    /// `host_port` are consulted only for the `Tofu` arm.
    pub fn resolve(self, tofu_store: TlsPinStore, host_port: String) -> TlsPinPolicy {
        match self {
            Self::Tofu => TlsPinPolicy::Tofu {
                store: tofu_store,
                host_port,
            },
            Self::PublicCa => TlsPinPolicy::PublicCa,
            Self::Insecure => TlsPinPolicy::Insecure,
            Self::Fingerprint(fp) => TlsPinPolicy::Fingerprint(fp),
        }
    }
}

impl FromStr for PinSpec {
    type Err = TransportError;
    fn from_str(s: &str) -> Result<Self, TransportError> {
        match s {
            "tofu" => Ok(Self::Tofu),
            "public-ca" => Ok(Self::PublicCa),
            "none" => Ok(Self::Insecure),
            other => TlsPinPolicy::normalize_fingerprint(other)
                .map(Self::Fingerprint)
                .map_err(|e| {
                    TransportError::WebSocket(format!(
                        "TLS pin must be one of `tofu`, `public-ca`, `none`, or a SHA-256 \
                         hex fingerprint (64 hex chars, optional `:` separators); got \
                         {other:?} ({e})"
                    ))
                }),
        }
    }
}

/// Persistent store of TOFU-pinned TLS fingerprints, keyed by `host:port`.
/// Same on-disk shape as the IPC pin store — the file path picks the
/// usage domain (`remote_pins.json` for IPC, `federation_pins.json`
/// for daemon-to-daemon).
#[derive(Debug, Clone)]
pub struct TlsPinStore {
    path: PathBuf,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct PinFile {
    /// `host:port` → SHA-256 fingerprint (lowercase, colon-separated).
    #[serde(default)]
    pins: BTreeMap<String, String>,
}

impl TlsPinStore {
    pub fn at(path: PathBuf) -> Self {
        Self { path }
    }

    /// Convenience: store at `<home>/<file_name>`. The file is created
    /// lazily on first pin write, so the home directory just needs to
    /// already exist (it does — `home_layout::ensure_dirs` runs at boot).
    pub fn at_home(home: &Path, file_name: &str) -> Self {
        Self {
            path: home.join(file_name),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn load(&self) -> Result<PinFile, TransportError> {
        if !self.path.exists() {
            return Ok(PinFile::default());
        }
        let raw = std::fs::read_to_string(&self.path)
            .map_err(|e| TransportError::WebSocket(format!("read {}: {e}", self.path.display())))?;
        serde_json::from_str(&raw)
            .map_err(|e| TransportError::WebSocket(format!("parse {}: {e}", self.path.display())))
    }

    fn save(&self, file: &PinFile) -> Result<(), TransportError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let serialized = serde_json::to_string_pretty(file)
            .map_err(|e| TransportError::WebSocket(format!("serialize pin file: {e}")))?;
        std::fs::write(&self.path, serialized).map_err(|e| {
            TransportError::WebSocket(format!("write {}: {e}", self.path.display()))
        })?;
        Ok(())
    }

    pub fn lookup(&self, host_port: &str) -> Result<Option<String>, TransportError> {
        Ok(self.load()?.pins.get(host_port).cloned())
    }

    pub fn pin(&self, host_port: &str, fingerprint: &str) -> Result<(), TransportError> {
        let mut file = self.load()?;
        file.pins
            .insert(host_port.to_string(), fingerprint.to_string());
        self.save(&file)
    }
}

/// `aa:bb:…:ff` lowercase, matching `hermod_crypto::sha256_fingerprint`.
fn sha256_fp(cert_der: &[u8]) -> String {
    let digest = Sha256::digest(cert_der);
    digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn signature_schemes() -> Vec<SignatureScheme> {
    vec![
        SignatureScheme::ECDSA_NISTP256_SHA256,
        SignatureScheme::ECDSA_NISTP384_SHA384,
        SignatureScheme::ED25519,
        SignatureScheme::RSA_PSS_SHA256,
        SignatureScheme::RSA_PKCS1_SHA256,
    ]
}

#[derive(Debug)]
struct InsecureVerifier {
    supported: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl InsecureVerifier {
    fn new() -> Self {
        Self {
            supported: default_provider().signature_verification_algorithms,
        }
    }
}

impl ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
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
        signature_schemes()
    }
}

#[derive(Debug)]
struct PinningVerifier {
    mode: PinningMode,
}

#[derive(Debug)]
enum PinningMode {
    Fingerprint {
        expected: String,
    },
    Tofu {
        store: TlsPinStore,
        host_port: String,
    },
}

impl PinningVerifier {
    fn fingerprint(expected: String) -> Self {
        Self {
            mode: PinningMode::Fingerprint { expected },
        }
    }
    fn tofu(store: TlsPinStore, host_port: String) -> Self {
        Self {
            mode: PinningMode::Tofu { store, host_port },
        }
    }
}

impl ServerCertVerifier for PinningVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let observed = sha256_fp(end_entity.as_ref());
        match &self.mode {
            PinningMode::Fingerprint { expected } => {
                if &observed == expected {
                    Ok(ServerCertVerified::assertion())
                } else {
                    Err(rustls::Error::General(format!(
                        "TLS pin mismatch: expected {expected}, got {observed}"
                    )))
                }
            }
            PinningMode::Tofu { store, host_port } => match store.lookup(host_port) {
                Ok(Some(stored)) if stored == observed => Ok(ServerCertVerified::assertion()),
                Ok(Some(stored)) => Err(rustls::Error::General(format!(
                    "TLS pin mismatch for {host_port}: stored {stored}, presented {observed}. \
                     If the peer was re-initialised, remove this entry from {} and retry.",
                    store.path().display()
                ))),
                Ok(None) => match store.pin(host_port, &observed) {
                    Ok(()) => Ok(ServerCertVerified::assertion()),
                    Err(e) => Err(rustls::Error::General(format!(
                        "TLS pin write failed for {host_port}: {e}"
                    ))),
                },
                Err(e) => Err(rustls::Error::General(format!(
                    "TLS pin lookup failed for {host_port}: {e}"
                ))),
            },
        }
    }
    fn verify_tls12_signature(
        &self,
        _msg: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _msg: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        signature_schemes()
    }
}

/// Load the OS trust store via `rustls-native-certs` and return the
/// populated `RootCertStore`. Distinguishes loader-stage failures
/// (system store unreadable) from parser-stage failures (bytes
/// present but unparseable).
fn load_native_roots() -> Result<RootCertStore, TransportError> {
    let mut roots = RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    let load_error_count = native.errors.len();
    if !native.errors.is_empty() {
        tracing::debug!(
            errors = ?native.errors,
            "rustls-native-certs reported {} non-fatal load error(s)",
            load_error_count,
        );
    }
    let (added, ignored) = roots.add_parsable_certificates(native.certs);
    if added == 0 {
        return Err(TransportError::WebSocket(format!(
            "TLS pin policy `public-ca` requested but no usable root CAs were loaded \
             from the OS trust store (loader errors: {load_error_count}, parsed-but-\
             rejected: {ignored}). Install/repair the system CA bundle, or use an \
             explicit fingerprint pin."
        )));
    }
    Ok(roots)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_accepts_colon_form() {
        let fp = "ab:cd:".to_string() + &"00:".repeat(28) + "00:ff";
        let cleaned = TlsPinPolicy::normalize_fingerprint(&fp).unwrap();
        assert!(cleaned.starts_with("ab:cd:"));
        assert_eq!(cleaned.matches(':').count(), 31);
    }

    #[test]
    fn normalize_accepts_unseparated_lowercase() {
        let fp = "AB".to_string() + &"00".repeat(31);
        let cleaned = TlsPinPolicy::normalize_fingerprint(&fp).unwrap();
        assert!(cleaned.starts_with("ab:00:"));
    }

    #[test]
    fn normalize_rejects_short_fp() {
        assert!(TlsPinPolicy::normalize_fingerprint("abcd").is_err());
    }

    #[test]
    fn pin_spec_parses_keywords() {
        assert_eq!(PinSpec::from_str("tofu").unwrap(), PinSpec::Tofu);
        assert_eq!(PinSpec::from_str("public-ca").unwrap(), PinSpec::PublicCa);
        assert_eq!(PinSpec::from_str("none").unwrap(), PinSpec::Insecure);
    }

    #[test]
    fn pin_spec_parses_fingerprint() {
        let fp = "AB".to_string() + &"00".repeat(31);
        let parsed = PinSpec::from_str(&fp).unwrap();
        match parsed {
            PinSpec::Fingerprint(s) => assert!(s.starts_with("ab:00:")),
            other => panic!("expected Fingerprint, got {other:?}"),
        }
    }

    #[test]
    fn pin_spec_rejects_garbage() {
        assert!(PinSpec::from_str("foo").is_err());
        assert!(PinSpec::from_str("Tofu").is_err()); // case-sensitive
    }

    #[test]
    fn store_round_trips_via_disk() {
        let dir = tempfile::tempdir().unwrap();
        let store = TlsPinStore::at_home(dir.path(), "federation_pins.json");
        let fp = "ab:cd:".to_string() + &"ef:".repeat(29) + "00";
        let cleaned = TlsPinPolicy::normalize_fingerprint(&fp).unwrap();

        assert!(store.lookup("broker.example:443").unwrap().is_none());
        store.pin("broker.example:443", &cleaned).unwrap();
        assert_eq!(
            store.lookup("broker.example:443").unwrap().as_deref(),
            Some(cleaned.as_str())
        );

        // Re-instantiate to confirm persistence.
        let store2 = TlsPinStore::at_home(dir.path(), "federation_pins.json");
        assert_eq!(
            store2.lookup("broker.example:443").unwrap().as_deref(),
            Some(cleaned.as_str())
        );
    }
}
