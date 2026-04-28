//! Peer discovery for Hermod.
//!
//! Two backends, both feeding into the same [`DiscoveredPeer`] shape:
//! - [`StaticDiscoverer`] — peers configured in `config.federation.peers`.
//! - [`MdnsDiscoverer`] — auto-discovery on `_hermod._tcp.local.`.

use async_trait::async_trait;
use hermod_core::{AgentAlias, Endpoint, PubkeyBytes};
use hermod_crypto::Signer;
use std::str::FromStr;
use std::sync::Arc;
use thiserror::Error;

pub mod mdns;
pub use mdns::MdnsDiscoverer;

#[derive(Debug, Error)]
pub enum DiscoveryError {
    #[error("invalid peer descriptor: {0}")]
    InvalidPeer(String),

    #[error(transparent)]
    Core(#[from] hermod_core::HermodError),

    #[error("mdns: {0}")]
    Mdns(String),
}

/// One discovered peer record.
///
/// `alias` is the publisher's *self-asserted* display name as advertised in
/// mDNS TXT or a static config descriptor. It's advisory only — the daemon
/// stores it as `peer_asserted_alias` and never as `local_alias` (which is
/// reserved for explicit operator action via `peer add --alias`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveredPeer {
    pub id: Option<String>,
    pub endpoint: Endpoint,
    pub pubkey: Option<PubkeyBytes>,
    pub alias: Option<AgentAlias>,
    pub source: &'static str,
}

/// Parameters for [`Discoverer::announce`]. Bundles all fields the
/// publisher needs to broadcast its presence to the discovery backend.
/// The signer is held as `Arc<dyn Signer>` so a future KMS-backed
/// signer slots in without changing announcer code.
#[derive(Debug)]
pub struct AnnounceParams<'a> {
    pub hostname: &'a str,
    pub port: u16,
    pub signer: Arc<dyn Signer>,
    pub validity_secs: u32,
    pub alias: Option<&'a str>,
}

/// Side-channel notifications the discovery layer emits when a beacon
/// is published, observed, or rejected. The discovery crate would
/// otherwise have to depend on `hermod-storage` to write audit rows
/// directly; instead we publish to a callback the daemon adapts to its
/// own audit sink.
///
/// All methods are best-effort and synchronous (no `async`) — the
/// caller MUST NOT block the discovery task waiting for storage. A
/// real implementation queues the event onto a channel or invokes
/// a fire-and-forget audit helper.
pub trait BeaconAuditor: Send + Sync + std::fmt::Debug {
    /// Local daemon successfully registered or refreshed its own beacon
    /// for this LAN.
    fn emitted(&self, port: u16, validity_secs: u32);

    /// Inbound beacon passed signature, freshness, and identity-binding
    /// checks. The agent_id is unverified TXT data — the auditor
    /// records what was claimed; downstream lookup binds it to a
    /// pubkey.
    fn observed(&self, agent_id: &str, endpoint: &Endpoint);

    /// Inbound beacon failed verification. `agent_id` is the claimed
    /// id from the TXT record (or `None` if even that field was
    /// missing). `reason` is a stable short string suitable for
    /// `details.reason` in the audit row.
    fn rejected(&self, agent_id: Option<&str>, reason: &'static str);
}

/// No-op auditor for tests and operators who don't want beacon
/// observability. Returned by [`NoopBeaconAuditor::shared`].
#[derive(Debug, Default)]
pub struct NoopBeaconAuditor;

impl BeaconAuditor for NoopBeaconAuditor {
    fn emitted(&self, _port: u16, _validity_secs: u32) {}
    fn observed(&self, _agent_id: &str, _endpoint: &Endpoint) {}
    fn rejected(&self, _agent_id: Option<&str>, _reason: &'static str) {}
}

impl NoopBeaconAuditor {
    /// Returns a cheap shared no-op auditor — the same `Arc` instance
    /// is fine for every caller because the type is zero-sized.
    pub fn shared() -> Arc<dyn BeaconAuditor> {
        Arc::new(NoopBeaconAuditor)
    }
}

#[async_trait]
pub trait Discoverer: Send + Sync + std::fmt::Debug {
    fn name(&self) -> &'static str;

    /// Snapshot of currently-known peers. Read-only.
    async fn snapshot(&self) -> Result<Vec<DiscoveredPeer>, DiscoveryError>;

    /// Announce this daemon's presence to the backend. Read-only
    /// backends (e.g. `StaticDiscoverer`) treat this as a no-op via the
    /// default impl. Mutating backends (mDNS, Consul, k8s) override.
    async fn announce(&self, params: AnnounceParams<'_>) -> Result<(), DiscoveryError> {
        let _ = params;
        Ok(())
    }

    /// Tear down — unannounce, close sockets, etc. Default no-op.
    /// Idempotent.
    async fn shutdown(&self) {}
}

/// Reads peers from a static configured list.
///
/// Each entry is one of:
/// - `"wss://host:port#<pubkey_hex>"` — endpoint with ed25519 (or noise) pubkey hint
/// - `"wss://host:port"` — endpoint only; pubkey will be learned via TOFU on first connect
#[derive(Clone, Debug, Default)]
pub struct StaticDiscoverer {
    peers: Vec<DiscoveredPeer>,
}

impl StaticDiscoverer {
    pub fn from_strings(entries: &[String]) -> Result<Self, DiscoveryError> {
        let peers = entries
            .iter()
            .map(|s| parse_descriptor(s))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { peers })
    }
}

fn parse_descriptor(s: &str) -> Result<DiscoveredPeer, DiscoveryError> {
    let (endpoint_str, pubkey) = match s.split_once('#') {
        Some((ep, pk)) => {
            let bytes = hex::decode(pk)
                .map_err(|e| DiscoveryError::InvalidPeer(format!("pubkey hex {pk:?}: {e}")))?;
            if bytes.len() != PubkeyBytes::LEN {
                return Err(DiscoveryError::InvalidPeer(format!(
                    "pubkey must be {} bytes, got {}",
                    PubkeyBytes::LEN,
                    bytes.len()
                )));
            }
            let mut arr = [0u8; PubkeyBytes::LEN];
            arr.copy_from_slice(&bytes);
            (ep, Some(PubkeyBytes(arr)))
        }
        None => (s, None),
    };
    let endpoint = Endpoint::from_str(endpoint_str)
        .map_err(|e| DiscoveryError::InvalidPeer(format!("endpoint: {e}")))?;
    Ok(DiscoveredPeer {
        id: None,
        endpoint,
        pubkey,
        alias: None,
        source: "static",
    })
}

#[async_trait]
impl Discoverer for StaticDiscoverer {
    fn name(&self) -> &'static str {
        "static"
    }
    async fn snapshot(&self) -> Result<Vec<DiscoveredPeer>, DiscoveryError> {
        Ok(self.peers.clone())
    }
}

/// Chains several backends behind a single [`Discoverer`].
///
/// Snapshots are concatenated; announce/shutdown are forwarded to every
/// child. Useful when an operator wants both the static config seed and
/// the mDNS auto-browser at once — `MultiDiscoverer::new(vec![static_,
/// mdns])` exposes them as one `Arc<dyn Discoverer>` to the daemon.
///
/// Per-child failures don't poison the whole snapshot — `snapshot`
/// logs each failure but continues with whatever the other children
/// returned. `announce` / `shutdown` errors propagate from the first
/// failing child since those are operational concerns the operator
/// should see.
#[derive(Debug)]
pub struct MultiDiscoverer {
    children: Vec<Arc<dyn Discoverer>>,
}

impl MultiDiscoverer {
    pub fn new(children: Vec<Arc<dyn Discoverer>>) -> Self {
        Self { children }
    }
}

#[async_trait]
impl Discoverer for MultiDiscoverer {
    fn name(&self) -> &'static str {
        "multi"
    }

    async fn snapshot(&self) -> Result<Vec<DiscoveredPeer>, DiscoveryError> {
        let mut out = Vec::new();
        for child in &self.children {
            match child.snapshot().await {
                Ok(mut peers) => out.append(&mut peers),
                Err(e) => {
                    // Best-effort: one backend's failure shouldn't blind
                    // the daemon to peers reported by another.
                    tracing::warn!(
                        backend = child.name(),
                        error = %e,
                        "discoverer snapshot failed; continuing with remaining backends"
                    );
                }
            }
        }
        Ok(out)
    }

    async fn announce(&self, params: AnnounceParams<'_>) -> Result<(), DiscoveryError> {
        // Announce on every child that supports it. Read-only backends
        // (StaticDiscoverer) hit the trait's no-op default impl.
        for child in &self.children {
            // Re-borrow params per child since AnnounceParams holds
            // borrowed references; cheap clones of the &str fields.
            let p = AnnounceParams {
                hostname: params.hostname,
                port: params.port,
                signer: params.signer.clone(),
                validity_secs: params.validity_secs,
                alias: params.alias,
            };
            child.announce(p).await?;
        }
        Ok(())
    }

    async fn shutdown(&self) {
        for child in &self.children {
            child.shutdown().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_endpoint_only() {
        let p = parse_descriptor("wss://example.com:443").unwrap();
        assert!(matches!(p.endpoint, Endpoint::Wss(_)));
        assert!(p.pubkey.is_none());
    }

    #[test]
    fn parses_endpoint_plus_pubkey() {
        let pk = hex::encode([7u8; 32]);
        let p = parse_descriptor(&format!("wss://example.com:7823#{pk}")).unwrap();
        assert!(p.pubkey.is_some());
    }

    #[tokio::test]
    async fn static_snapshot_returns_configured_peers() {
        let d = StaticDiscoverer::from_strings(&[
            "wss://a.example:7823".into(),
            "wss://b.example:7823".into(),
        ])
        .unwrap();
        let snap = d.snapshot().await.unwrap();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].source, "static");
    }
}
