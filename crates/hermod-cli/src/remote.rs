//! WSS+Bearer remote IPC client.
//!
//! Speaks JSON-RPC 2.0 over a single WebSocket frame per request/response.
//!
//! ## Auth
//!
//! Two header families, one transport:
//!
//! * `Authorization: Bearer <daemon-token>` — always sent; validated by
//!   the hermod daemon's `ipc_remote::serve`.
//! * `Proxy-Authorization: Bearer <proxy-token>` — sent when the
//!   [`crate::client::RemoteAuth::proxy`] slot is `Some`. RFC 7235 §4.4
//!   reserves this header for the SSO reverse proxy fronting the
//!   broker (Google Cloud IAP, oauth2-proxy, Cloudflare Access,
//!   ALB+Cognito, …). Real proxies strip the header before forwarding,
//!   so the daemon never sees it.
//!
//! ## TLS verification
//!
//! Four policies, picked by `--pin`:
//!
//!   * `tofu` (default) — record the daemon's SHA-256 fingerprint to
//!     `$HERMOD_HOME/remote_pins.json` on first connect; fail loud on
//!     mismatch thereafter.
//!   * `<sha256>` — explicit fingerprint pin.
//!   * `public-ca` — validate the chain via the OS root CA store
//!     (`rustls-native-certs`). Use when a public-CA-trusted reverse
//!     proxy fronts the daemon (Cloud Run, Google IAP, Cloudflare
//!     Access, ALB+Cognito); pinning the LB cert would break on every
//!     rotation.
//!   * `none` — skip TLS validation. Strictly opt-in for tests /
//!     known-LAN.
//!
//! ## Auth-failure refresh
//!
//! The connect path is [`connect_remote_with_refresh`]:
//!
//!   * HTTP 401 → daemon-bearer rejected (or proxy-bearer rejected with
//!     a 401-emitting reverse proxy; the wire is ambiguous). Refresh
//!     both providers concurrently and retry once.
//!   * HTTP 407 → RFC 7235 Proxy-Authentication-Required. Refresh the
//!     proxy provider only and retry once.
//!   * Two consecutive auth failures → fatal.
//!   * A provider that returns the same epoch from `refresh` (e.g.
//!     [`crate::bearer::StaticBearerProvider`]) signals "no notion of
//!     refresh"; if no provider advanced, the failure is fatal.

use anyhow::{Context, Result, anyhow};
use futures::{SinkExt, StreamExt};
use hermod_protocol::ipc::message::{Id, JsonRpc2, Request, Response, ResponsePayload};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::StatusCode;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::{Connector, MaybeTlsStream, WebSocketStream};
use url::Url;
use zeroize::Zeroizing;

use crate::bearer::{BearerError, BearerToken, TokenEpoch};
use crate::client::RemoteAuth;

/// Mirrors the daemon's `MAX_REMOTE_IPC_BYTES` cap. Generous enough for
/// any legitimate JSON-RPC reply, small enough that a misbehaving server
/// can't pin client memory.
const MAX_REMOTE_IPC_BYTES: usize = 1024 * 1024;

use crate::pins::{PinPolicy, RemotePinStore};

/// Outcome of a single WSS handshake. Two of the variants drive the
/// refresh state machine in [`connect_remote_with_refresh`]; everything
/// else folds into `Other` and propagates as fatal.
#[derive(thiserror::Error, Debug)]
pub enum RemoteConnectError {
    /// HTTP 401 — daemon (or 401-emitting reverse proxy) rejected the
    /// presented bearer.
    #[error("server returned HTTP 401 (bearer rejected)")]
    Unauthorized,
    /// HTTP 407 — RFC 7235 Proxy-Authentication-Required from the
    /// reverse proxy. Distinct from 401 so the retry refreshes only
    /// the proxy provider.
    #[error("server returned HTTP 407 (proxy authentication required)")]
    ProxyAuthRequired,
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub struct RemoteIpcClient {
    ws: WebSocketStream<MaybeTlsStream<TcpStream>>,
}

/// Minted leases for one connect attempt — never reused across retries.
/// Lifetime ends with the `connect` call that consumes them.
struct RemoteAuthLeases {
    daemon: BearerToken,
    proxy: Option<BearerToken>,
}

impl RemoteAuthLeases {
    /// Mint both tokens concurrently. Daemon and proxy providers are
    /// independent — running them in parallel halves wall-clock time
    /// when both are subprocess-backed (e.g. `gcloud auth
    /// print-identity-token` for both).
    async fn mint(auth: &RemoteAuth) -> Result<Self, BearerError> {
        let daemon_fut = auth.daemon.current();
        let proxy_fut = async {
            match &auth.proxy {
                Some(p) => Ok::<_, BearerError>(Some(p.current().await?)),
                None => Ok(None),
            }
        };
        let (daemon, proxy) = tokio::join!(daemon_fut, proxy_fut);
        Ok(Self {
            daemon: daemon?,
            proxy: proxy?,
        })
    }

    /// Refresh the proxy provider only — used after HTTP 407.
    /// If `auth.proxy` is `None`, the lease is returned unchanged
    /// (the caller has already decided that case is fatal before
    /// invoking us, but defensive: never invent a refresh that didn't
    /// happen).
    async fn refresh_proxy(self, auth: &RemoteAuth) -> Result<Self, BearerError> {
        let Self { daemon, proxy } = self;
        let proxy = match (&auth.proxy, proxy) {
            (Some(p), Some(stale)) => Some(p.refresh(stale.epoch()).await?),
            (Some(p), None) => Some(p.current().await?),
            (None, original) => original,
        };
        Ok(Self { daemon, proxy })
    }

    /// Refresh both providers concurrently — used after HTTP 401, where
    /// we cannot tell which layer rejected. Single-flight inside each
    /// provider; this top-level concurrency is purely to overlap two
    /// independent subprocess invocations.
    async fn refresh_both(self, auth: &RemoteAuth) -> Result<Self, BearerError> {
        let Self { daemon, proxy } = self;
        let daemon_stale = daemon.epoch();
        let daemon_fut = auth.daemon.refresh(daemon_stale);
        let proxy_fut = async {
            match (&auth.proxy, proxy) {
                (Some(p), Some(stale)) => {
                    Ok::<_, BearerError>(Some(p.refresh(stale.epoch()).await?))
                }
                (Some(p), None) => Ok(Some(p.current().await?)),
                (None, original) => Ok(original),
            }
        };
        let (daemon, proxy) = tokio::join!(daemon_fut, proxy_fut);
        Ok(Self {
            daemon: daemon?,
            proxy: proxy?,
        })
    }

    /// Snapshot the epochs in a `Copy`-able value so callers can compare
    /// before/after even though `refresh_*` consume `self`.
    fn epochs(&self) -> AuthEpochs {
        AuthEpochs {
            daemon: self.daemon.epoch(),
            proxy: self.proxy.as_ref().map(|t| t.epoch()),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct AuthEpochs {
    daemon: TokenEpoch,
    proxy: Option<TokenEpoch>,
}

impl RemoteIpcClient {
    /// Open one WSS connection presenting the minted leases. A 401/407
    /// surfaces as the matching variant of [`RemoteConnectError`];
    /// every other failure folds into `Other`.
    async fn connect(
        url: &Url,
        leases: &RemoteAuthLeases,
        policy: PinPolicy,
    ) -> Result<Self, RemoteConnectError> {
        let scheme = url.scheme();
        if scheme != "wss" && scheme != "ws" {
            return Err(RemoteConnectError::Other(anyhow!(
                "remote IPC URL must be wss:// or ws://, got {scheme}"
            )));
        }

        let mut req = url
            .as_str()
            .into_client_request()
            .context("build ws request")
            .map_err(RemoteConnectError::Other)?;
        // Wrap the formatted "Bearer <secret>" String in Zeroizing so
        // its heap buffer is wiped after the HeaderValue takes its own
        // copy. We can't control tungstenite's HeaderValue allocation,
        // but we can ensure no extra unzeroed copy lingers in our
        // stack frame for every connect.
        let auth = Zeroizing::new(format!("Bearer {}", leases.daemon.secret().expose_secret()));
        req.headers_mut().insert(
            "Authorization",
            auth.parse()
                .map_err(|e| RemoteConnectError::Other(anyhow!("invalid daemon token: {e}")))?,
        );
        if let Some(proxy) = &leases.proxy {
            let proxy_auth = Zeroizing::new(format!("Bearer {}", proxy.secret().expose_secret()));
            req.headers_mut().insert(
                "Proxy-Authorization",
                proxy_auth
                    .parse()
                    .map_err(|e| RemoteConnectError::Other(anyhow!("invalid proxy token: {e}")))?,
            );
        }

        let connector = if scheme == "wss" {
            install_default_crypto_provider();
            Some(Connector::Rustls(Arc::new(build_client_tls_config(
                policy,
            )?)))
        } else {
            None
        };

        let ws_config = WebSocketConfig::default()
            .max_message_size(Some(MAX_REMOTE_IPC_BYTES))
            .max_frame_size(Some(MAX_REMOTE_IPC_BYTES));

        let (ws, _resp) = match tokio_tungstenite::connect_async_tls_with_config(
            req,
            Some(ws_config),
            false,
            connector,
        )
        .await
        {
            Ok(v) => v,
            Err(e) => {
                if let Some(specific) = classify_handshake_error(&e) {
                    return Err(specific);
                }
                return Err(RemoteConnectError::Other(
                    anyhow::Error::new(e).context("ws handshake"),
                ));
            }
        };
        Ok(Self { ws })
    }

    pub async fn call_typed(&mut self, method: &str, params: Option<Value>) -> Result<Value> {
        let req = Request {
            jsonrpc: JsonRpc2,
            id: Id::from_ulid(),
            method: method.to_string(),
            params,
        };
        let frame = serde_json::to_string(&req)?;
        self.ws.send(Message::Text(frame.into())).await?;

        loop {
            let msg = self
                .ws
                .next()
                .await
                .ok_or_else(|| anyhow!("ws closed before response"))??;
            match msg {
                Message::Text(text) => {
                    let resp: Response = serde_json::from_str(&text)
                        .with_context(|| format!("decode response: {text}"))?;
                    return match resp.payload {
                        ResponsePayload::Ok { result } => Ok(result),
                        ResponsePayload::Err { error } => {
                            Err(anyhow!("rpc error {}: {}", error.code, error.message))
                        }
                    };
                }
                Message::Binary(_) | Message::Ping(_) | Message::Pong(_) => continue,
                Message::Close(_) => return Err(anyhow!("ws closed mid-request")),
                _ => continue,
            }
        }
    }
}

/// Connect with one automatic re-mint on auth failure.
///
/// 1. Mint both leases via [`RemoteAuthLeases::mint`], attempt connect.
/// 2. On `ProxyAuthRequired` (HTTP 407) — refresh the proxy provider
///    only; retry exactly once.
/// 3. On `Unauthorized` (HTTP 401) — the wire is ambiguous about which
///    layer rejected, so refresh both providers concurrently and retry
///    exactly once.
/// 4. If no provider advanced its epoch, the source(s) have no notion
///    of refresh (e.g. a static env-supplied token rejected by the
///    daemon) — escalate to fatal so the operator sees the actual cause.
/// 5. A second consecutive auth failure after refresh is fatal.
pub async fn connect_remote_with_refresh(
    url: &Url,
    auth: &RemoteAuth,
    pin: PinPolicy,
) -> Result<RemoteIpcClient> {
    let leases = RemoteAuthLeases::mint(auth).await?;
    match RemoteIpcClient::connect(url, &leases, pin.clone()).await {
        Ok(c) => Ok(c),
        Err(RemoteConnectError::Other(other)) => Err(other),
        Err(RemoteConnectError::ProxyAuthRequired) => {
            if auth.proxy.is_none() {
                anyhow::bail!(
                    "remote returned HTTP 407 (proxy authentication required) but \
                     no --proxy-bearer-* source is configured — set \
                     --proxy-bearer-file, --proxy-bearer-command, or \
                     HERMOD_PROXY_BEARER_TOKEN to authenticate against the \
                     fronting proxy"
                );
            }
            let before = leases.epochs();
            let renewed = leases.refresh_proxy(auth).await?;
            if renewed.epochs() == before {
                anyhow::bail!(
                    "proxy auth rejected and the proxy bearer source declined \
                     to renew (cannot recover; check --proxy-bearer-command \
                     output, --proxy-bearer-file contents, or \
                     HERMOD_PROXY_BEARER_TOKEN)"
                );
            }
            RemoteIpcClient::connect(url, &renewed, pin)
                .await
                .map_err(escalate_after_refresh)
        }
        Err(RemoteConnectError::Unauthorized) => {
            let before = leases.epochs();
            let renewed = leases.refresh_both(auth).await?;
            if renewed.epochs() == before {
                anyhow::bail!(
                    "bearer rejected by remote daemon and the bearer source(s) declined \
                     to renew (cannot recover; check `hermod bearer show` against the \
                     daemon's $HERMOD_HOME/identity/bearer_token, or rotate via \
                     `hermod bearer rotate`)"
                );
            }
            RemoteIpcClient::connect(url, &renewed, pin)
                .await
                .map_err(escalate_after_refresh)
        }
    }
}

/// Map a second-attempt failure to a clear operator-facing message.
/// `Other` propagates verbatim (TLS / pin / IO failures aren't
/// auth-related and shouldn't be reframed as auth issues).
/// Build the rustls `ClientConfig` for the chosen [`PinPolicy`].
/// Three policies hand a custom verifier to the same dangerous-mode
/// builder; `PublicCa` is the one branch that uses rustls'
/// production-blessed `WebPkiServerVerifier` over the OS trust store
/// (`with_root_certificates`), enforcing SAN / expiry / EKU correctly.
/// `connect_async_tls_with_config` forwards the URL host as the SNI /
/// verification target, so cert rotation on the LB just works.
fn build_client_tls_config(policy: PinPolicy) -> Result<ClientConfig, RemoteConnectError> {
    let base =
        ClientConfig::builder_with_protocol_versions(hermod_transport::tls::PROTOCOL_VERSIONS);
    match policy {
        PinPolicy::PublicCa => Ok(base
            .with_root_certificates(load_native_roots()?)
            .with_no_client_auth()),
        PinPolicy::Insecure => Ok(base
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth()),
        PinPolicy::Fingerprint(expected) => Ok(base
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinningVerifier::fingerprint(expected)))
            .with_no_client_auth()),
        PinPolicy::Tofu { store, host_port } => Ok(base
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinningVerifier::tofu(store, host_port)))
            .with_no_client_auth()),
    }
}

/// Load the OS trust store via `rustls-native-certs` and return the
/// populated `RootCertStore`. Distinguishes loader-stage failures
/// (system store unreadable) from parser-stage failures (bytes
/// present but unparseable) so the error message can point at the
/// actual cause — an operator with a broken CA bundle gets a
/// different remediation hint than one whose SDK rejected the certs.
fn load_native_roots() -> Result<rustls::RootCertStore, RemoteConnectError> {
    let mut roots = rustls::RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    // `rustls_native_certs::Error` is not `Clone`, so we capture the
    // count up front and let `?`-debug borrow `native.errors`
    // immutably before moving `native.certs` into the parser below.
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
        return Err(RemoteConnectError::Other(anyhow!(
            "--pin public-ca requested but no usable root CAs were loaded \
             from the OS trust store (loader errors: {load_errs}, parsed-but-\
             rejected: {ignored}). Install/repair the system CA bundle \
             (`update-ca-certificates` on Debian, `security` keychain on \
             macOS, …), or use `--pin <sha256>` with an explicitly-\
             provisioned fingerprint",
            load_errs = load_error_count,
            ignored = ignored,
        )));
    }
    Ok(roots)
}

fn escalate_after_refresh(e: RemoteConnectError) -> anyhow::Error {
    match e {
        RemoteConnectError::Unauthorized => anyhow!(
            "bearer rejected after refresh — the renewed daemon token is also \
             invalid (auth provider misconfigured)"
        ),
        RemoteConnectError::ProxyAuthRequired => anyhow!(
            "proxy auth rejected after refresh — the renewed proxy token is also \
             invalid (proxy auth provider misconfigured)"
        ),
        RemoteConnectError::Other(other) => other,
    }
}

/// Best-effort detection of "the server told us our credentials are
/// wrong" from a tungstenite handshake error. The library exposes the
/// rejected HTTP response on `Error::Http`; we match purely on its
/// status code, not on the body, so a daemon or proxy that customises
/// the WWW-Authenticate / Proxy-Authenticate payload still gets
/// recognised.
fn classify_handshake_error(
    err: &tokio_tungstenite::tungstenite::Error,
) -> Option<RemoteConnectError> {
    if let tokio_tungstenite::tungstenite::Error::Http(resp) = err {
        return match resp.status() {
            StatusCode::UNAUTHORIZED => Some(RemoteConnectError::Unauthorized),
            StatusCode::PROXY_AUTHENTICATION_REQUIRED => {
                Some(RemoteConnectError::ProxyAuthRequired)
            }
            _ => None,
        };
    }
    None
}

/// Computes the SHA-256 of the cert DER and either matches against the
/// expected pin (Explicit) or pins-on-first-use (Tofu). Signature checks are
/// trivially accepted because hermod authenticates the *peer identity* via
/// the bearer token, not via TLS — TLS only provides confidentiality and
/// the cert pin guarantees we're talking to the same daemon as last time.
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
        store: RemotePinStore,
        host_port: String,
    },
}

impl PinningVerifier {
    fn fingerprint(expected: String) -> Self {
        Self {
            mode: PinningMode::Fingerprint { expected },
        }
    }
    fn tofu(store: RemotePinStore, host_port: String) -> Self {
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
                         If the daemon was re-initialised, remove this entry from \
                         $HERMOD_HOME/remote_pins.json and retry."
                ))),
                Ok(None) => match store.pin(host_port, &observed) {
                    Ok(()) => Ok(ServerCertVerified::assertion()),
                    Err(e) => Err(rustls::Error::General(format!(
                        "TOFU pin write failed: {e}"
                    ))),
                },
                Err(e) => Err(rustls::Error::General(format!(
                    "TOFU pin store unreadable: {e}"
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

#[derive(Debug)]
struct NoVerify;

impl ServerCertVerifier for NoVerify {
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

fn signature_schemes() -> Vec<SignatureScheme> {
    vec![
        SignatureScheme::ECDSA_NISTP256_SHA256,
        SignatureScheme::ECDSA_NISTP384_SHA384,
        SignatureScheme::ED25519,
        SignatureScheme::RSA_PSS_SHA256,
        SignatureScheme::RSA_PKCS1_SHA256,
    ]
}

/// `aa:bb:…:ff` lowercase, matching `hermod_crypto::tls::sha256_fingerprint`.
fn sha256_fp(cert_der: &[u8]) -> String {
    let digest = Sha256::digest(cert_der);
    digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn install_default_crypto_provider() {
    // Idempotent — multiple calls / threads safe.
    let _ = rustls::crypto::ring::default_provider().install_default();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bearer::BearerProvider;
    use async_trait::async_trait;
    use hermod_crypto::SecretString;
    use std::sync::Mutex;

    /// Lightweight provider that the auth-flow tests can drive
    /// deterministically. `refreshable=false` mimics a static
    /// env-supplied source — `refresh()` returns the same epoch the
    /// caller already holds, which the connect path recognises as
    /// "declined to renew".
    #[derive(Debug)]
    struct StubProvider {
        state: Mutex<StubState>,
        token_prefix: &'static str,
        refreshable: bool,
    }

    #[derive(Debug)]
    struct StubState {
        epoch: TokenEpoch,
        mints: u64,
    }

    impl StubProvider {
        fn new(prefix: &'static str, refreshable: bool) -> Arc<Self> {
            Arc::new(Self {
                state: Mutex::new(StubState {
                    epoch: TokenEpoch::FIRST,
                    mints: 1,
                }),
                token_prefix: prefix,
                refreshable,
            })
        }

        fn snapshot(&self) -> BearerToken {
            let s = self.state.lock().expect("mutex");
            let secret = SecretString::new(format!("{}-{}", self.token_prefix, s.mints));
            BearerToken::new(secret, s.epoch)
        }
    }

    #[async_trait]
    impl BearerProvider for StubProvider {
        async fn current(&self) -> Result<BearerToken, BearerError> {
            Ok(self.snapshot())
        }
        async fn refresh(&self, stale: TokenEpoch) -> Result<BearerToken, BearerError> {
            if self.refreshable {
                let mut s = self.state.lock().expect("mutex");
                if s.epoch <= stale {
                    s.epoch = s.epoch.next();
                    s.mints += 1;
                }
            }
            Ok(self.snapshot())
        }
    }

    fn make_auth(daemon_refresh: bool, proxy: Option<bool>) -> RemoteAuth {
        RemoteAuth {
            daemon: StubProvider::new("daemon", daemon_refresh),
            proxy: proxy.map(|r| StubProvider::new("proxy", r) as _),
        }
    }

    #[tokio::test]
    async fn mint_returns_both_when_proxy_set() {
        let auth = make_auth(true, Some(true));
        let leases = RemoteAuthLeases::mint(&auth).await.expect("mint");
        let proxy = leases.proxy.as_ref().expect("proxy lease");
        assert_eq!(leases.daemon.secret().expose_secret(), "daemon-1");
        assert_eq!(proxy.secret().expose_secret(), "proxy-1");
        assert_eq!(leases.daemon.epoch(), TokenEpoch::FIRST);
    }

    #[tokio::test]
    async fn mint_omits_proxy_when_unset() {
        let auth = make_auth(true, None);
        let leases = RemoteAuthLeases::mint(&auth).await.expect("mint");
        assert!(leases.proxy.is_none());
    }

    #[tokio::test]
    async fn refresh_proxy_only_advances_proxy() {
        let auth = make_auth(true, Some(true));
        let leases = RemoteAuthLeases::mint(&auth).await.expect("mint");
        let before = leases.epochs();
        let renewed = leases.refresh_proxy(&auth).await.expect("refresh_proxy");
        assert_eq!(renewed.daemon.epoch(), before.daemon);
        assert_ne!(
            renewed.proxy.as_ref().expect("proxy").epoch(),
            before.proxy.expect("had proxy"),
        );
    }

    #[tokio::test]
    async fn refresh_both_advances_both_when_refreshable() {
        let auth = make_auth(true, Some(true));
        let leases = RemoteAuthLeases::mint(&auth).await.expect("mint");
        let before = leases.epochs();
        let renewed = leases.refresh_both(&auth).await.expect("refresh_both");
        assert_ne!(renewed.daemon.epoch(), before.daemon);
        assert_ne!(
            renewed.proxy.as_ref().expect("proxy").epoch(),
            before.proxy.expect("had proxy"),
        );
    }

    #[tokio::test]
    async fn refresh_both_with_static_providers_advances_neither() {
        let auth = make_auth(false, Some(false));
        let leases = RemoteAuthLeases::mint(&auth).await.expect("mint");
        let before = leases.epochs();
        let renewed = leases.refresh_both(&auth).await.expect("refresh_both");
        assert_eq!(renewed.epochs(), before);
    }

    #[tokio::test]
    async fn epochs_snapshot_detects_partial_progress() {
        let auth = make_auth(true, Some(false));
        let leases = RemoteAuthLeases::mint(&auth).await.expect("mint");
        let before = leases.epochs();
        let renewed = leases.refresh_both(&auth).await.expect("refresh_both");
        // daemon refreshable, proxy not — daemon advanced, proxy stayed.
        assert_ne!(renewed.daemon.epoch(), before.daemon);
        assert_eq!(
            renewed.proxy.as_ref().expect("proxy").epoch(),
            before.proxy.expect("had proxy"),
        );
        // overall snapshot differs because daemon component changed.
        assert_ne!(renewed.epochs(), before);
    }
}
