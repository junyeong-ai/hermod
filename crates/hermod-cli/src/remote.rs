//! WSS+Bearer remote IPC client.
//!
//! Speaks JSON-RPC 2.0 over a single WebSocket frame per request/response.
//! Auth: `Authorization: Bearer <token>` on the upgrade request.
//!
//! TLS pinning matches the federation model — the daemon presents a
//! self-signed cert and the client compares its SHA-256 fingerprint to
//! either an explicit pin (`--pin <hex>`) or a TOFU pin recorded at
//! `$HERMOD_HOME/remote_pins.json`. Use `PinPolicy::InsecureNoVerify` only
//! for tests / fully-trusted LAN deployments.
//!
//! ## Bearer refresh
//!
//! The connect path goes through [`connect_remote_with_refresh`]: on a
//! 401 from the upgrade, the bearer provider is asked to mint a fresh
//! token (single-flight via [`crate::bearer::TokenEpoch`]) and the
//! handshake is retried exactly once. Two consecutive 401s — or a
//! provider that declines to advance the epoch — escalate to fatal.

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

use crate::bearer::{BearerProvider, BearerToken};

/// Mirrors the daemon's `MAX_REMOTE_IPC_BYTES` cap. Generous enough for
/// any legitimate JSON-RPC reply, small enough that a misbehaving server
/// can't pin client memory.
const MAX_REMOTE_IPC_BYTES: usize = 1024 * 1024;

use crate::pins::{PinPolicy, RemotePinStore};

/// Outcome of a single WSS handshake. The `Unauthorized` arm is the only
/// signal the connect path acts on — every other failure (TLS, pin, IO,
/// protocol) is `Other` and propagates as fatal.
#[derive(thiserror::Error, Debug)]
pub enum RemoteConnectError {
    #[error("server returned HTTP 401 (bearer rejected)")]
    Unauthorized,
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub struct RemoteIpcClient {
    ws: WebSocketStream<MaybeTlsStream<TcpStream>>,
}

impl RemoteIpcClient {
    /// Open one WSS connection presenting `token` as the bearer. A 401
    /// surfaces as [`RemoteConnectError::Unauthorized`]; other failures
    /// fold into `Other`.
    pub async fn connect(
        url: &Url,
        token: &BearerToken,
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
        let auth = Zeroizing::new(format!("Bearer {}", token.secret().expose_secret()));
        req.headers_mut().insert(
            "Authorization",
            auth.parse()
                .map_err(|e| RemoteConnectError::Other(anyhow!("invalid token: {e}")))?,
        );

        let connector = if scheme == "wss" {
            install_default_crypto_provider();
            let verifier: Arc<dyn ServerCertVerifier> = match policy {
                PinPolicy::InsecureNoVerify => Arc::new(NoVerify),
                PinPolicy::Explicit(expected) => Arc::new(PinningVerifier::explicit(expected)),
                PinPolicy::Tofu { store, host_port } => {
                    Arc::new(PinningVerifier::tofu(store, host_port))
                }
            };
            let config = ClientConfig::builder_with_protocol_versions(
                hermod_transport::tls::PROTOCOL_VERSIONS,
            )
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
            Some(Connector::Rustls(Arc::new(config)))
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
                if is_unauthorized(&e) {
                    return Err(RemoteConnectError::Unauthorized);
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

/// Connect with one automatic re-mint on 401.
///
/// 1. Mint via `provider.current()`, attempt connect.
/// 2. On `Unauthorized`, ask the provider to advance the epoch and retry
///    exactly once.
/// 3. If the provider returns the same epoch, the source has no notion
///    of refresh (e.g. a static env-supplied token rejected by the
///    daemon) — escalate to fatal so the operator sees the actual cause.
pub async fn connect_remote_with_refresh(
    url: &Url,
    provider: &Arc<dyn BearerProvider>,
    pin: PinPolicy,
) -> Result<RemoteIpcClient> {
    let lease = provider.current().await?;
    match RemoteIpcClient::connect(url, &lease, pin.clone()).await {
        Ok(c) => Ok(c),
        Err(RemoteConnectError::Unauthorized) => {
            let renewed = provider.refresh(lease.epoch()).await?;
            if renewed.epoch() == lease.epoch() {
                anyhow::bail!(
                    "bearer rejected by remote daemon and the bearer source declined \
                     to renew (cannot recover; check `hermod bearer show` against the \
                     daemon's $HERMOD_HOME/identity/bearer_token, or rotate via \
                     `hermod bearer rotate`)"
                );
            }
            RemoteIpcClient::connect(url, &renewed, pin)
                .await
                .map_err(|e| match e {
                    RemoteConnectError::Unauthorized => anyhow!(
                        "bearer rejected after refresh — the renewed token is also \
                         invalid (auth provider misconfigured)"
                    ),
                    RemoteConnectError::Other(other) => other,
                })
        }
        Err(RemoteConnectError::Other(other)) => Err(other),
    }
}

/// Best-effort detection of "the server told us our bearer is wrong"
/// from a tungstenite handshake error. The library exposes the rejected
/// HTTP response on `Error::Http`; we match purely on its status code,
/// not on the body, so a daemon that customises the WWW-Authenticate
/// payload still gets recognised.
fn is_unauthorized(err: &tokio_tungstenite::tungstenite::Error) -> bool {
    matches!(
        err,
        tokio_tungstenite::tungstenite::Error::Http(resp) if resp.status() == StatusCode::UNAUTHORIZED
    )
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
    Explicit {
        expected: String,
    },
    Tofu {
        store: RemotePinStore,
        host_port: String,
    },
}

impl PinningVerifier {
    fn explicit(expected: String) -> Self {
        Self {
            mode: PinningMode::Explicit { expected },
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
            PinningMode::Explicit { expected } => {
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
