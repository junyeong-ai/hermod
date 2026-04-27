//! mDNS auto-discovery for Hermod.
//!
//! Two halves, both gated by `config.federation.discover_mdns`:
//!
//! 1. **Announce**: register a `_hermod._tcp.local.` service advertising
//!    `(agent_id, pubkey_hex)` as TXT records. Peers on the same subnet
//!    learn our endpoint without manual `peer add`.
//! 2. **Browse**: maintain an in-memory cache of resolved peers fed by an
//!    mDNS browser; `MdnsDiscoverer::snapshot()` returns the current set,
//!    excluding self.
//!
//! Why not store directly in the `peers` table from inside this crate?
//! Because storage isn't a discovery dep — the daemon side reads the
//! snapshot and pipes new entries through the existing `peer.add` path so
//! TOFU + TLS pinning still apply.

use async_trait::async_trait;
use hermod_core::{AgentAlias, Endpoint, PubkeyBytes, SignatureBytes, WssEndpoint};
use hermod_crypto::{PublicKey, Signer, canonical_mdns_beacon_bytes};
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, warn};

use crate::{AnnounceParams, DiscoveredPeer, Discoverer, DiscoveryError};

/// `_hermod._tcp.local.` — the mDNS service type that Hermod daemons advertise.
pub const SERVICE_TYPE: &str = "_hermod._tcp.local.";

/// Maximum permissible clock skew on an inbound beacon's `ts_ms`. A
/// beacon whose timestamp is more than this far in the future is
/// rejected — protects against an attacker pre-signing beacons for
/// future broadcast.
pub const BEACON_FUTURE_SKEW_MS: i64 = 60_000; // 60 s

/// Verdict from [`MdnsDiscoverer::verify_inbound_beacon`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BeaconVerdict {
    /// Signature, freshness, and identity binding all check out.
    Accept,
    /// One of the required TXT records (`ts`, `validity_secs`, `sig`) is
    /// absent or malformed. Caller emits `mdns.beacon_rejected
    /// { reason = "missing_or_malformed_field" }` and ignores the
    /// announcement.
    MalformedFields,
    /// Signature does not verify against the carried `pubkey`. Caller
    /// emits `mdns.beacon_rejected { reason = "invalid_sig" }`.
    InvalidSignature,
    /// `ts` is older than `validity_secs` ago (replay protection).
    Stale { age_ms: i64, validity_ms: i64 },
    /// `ts` is more than [`BEACON_FUTURE_SKEW_MS`] in the future.
    Future { skew_ms: i64 },
}

#[derive(Clone)]
pub struct MdnsDiscoverer {
    daemon: ServiceDaemon,
    own_agent_id: String,
    cache: Arc<Mutex<HashMap<String, DiscoveredPeer>>>,
    auditor: Arc<dyn crate::BeaconAuditor>,
}

impl std::fmt::Debug for MdnsDiscoverer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MdnsDiscoverer")
            .field("own_agent_id", &self.own_agent_id)
            .field(
                "cache_size",
                &self.cache.lock().map(|g| g.len()).unwrap_or(0),
            )
            .finish_non_exhaustive()
    }
}

impl MdnsDiscoverer {
    /// Start the daemon and begin browsing. Failures from the underlying
    /// mDNS stack (typically socket permissions or already-bound port)
    /// surface as `DiscoveryError::Mdns`. Browse runs in a background
    /// task; the receiver is driven by `tokio::spawn`. `auditor`
    /// observes beacon emit / observe / reject events for the
    /// daemon's hash-chained log; pass [`crate::NoopBeaconAuditor::shared`]
    /// when audit observability isn't wanted.
    pub fn start(
        own_agent_id: String,
        auditor: Arc<dyn crate::BeaconAuditor>,
    ) -> Result<Self, DiscoveryError> {
        let daemon =
            ServiceDaemon::new().map_err(|e| DiscoveryError::Mdns(format!("daemon: {e}")))?;
        let receiver = daemon
            .browse(SERVICE_TYPE)
            .map_err(|e| DiscoveryError::Mdns(format!("browse: {e}")))?;
        let cache: Arc<Mutex<HashMap<String, DiscoveredPeer>>> =
            Arc::new(Mutex::new(HashMap::new()));

        // Drive the browse channel until the daemon stops. Each Resolved
        // event refreshes our cache; Removed evicts. Self-resolutions are
        // skipped so we don't try to dial ourselves.
        let cache_for_task = cache.clone();
        let own_for_task = own_agent_id.clone();
        let auditor_for_task = auditor.clone();
        tokio::spawn(async move {
            while let Ok(event) = receiver.recv_async().await {
                match event {
                    ServiceEvent::ServiceResolved(info) => {
                        if let Some(peer) =
                            peer_from_info(&info, &own_for_task, &*auditor_for_task)
                        {
                            let key = info.get_fullname().to_string();
                            if let Ok(mut g) = cache_for_task.lock() {
                                g.insert(key, peer);
                            }
                        }
                    }
                    ServiceEvent::ServiceRemoved(_, fullname) => {
                        if let Ok(mut g) = cache_for_task.lock() {
                            g.remove(&fullname);
                        }
                    }
                    other => debug!(?other, "mdns event"),
                }
            }
            warn!("mdns browse channel closed");
        });

        Ok(Self {
            daemon,
            own_agent_id,
            cache,
            auditor,
        })
    }

    /// Sign and register a beacon for `(self_agent_id, pubkey, optional
    /// alias)` on the LAN. Internal helper — the public surface is
    /// [`Discoverer::announce`].
    async fn announce_inner(
        &self,
        hostname: &str,
        port: u16,
        signer: &dyn Signer,
        validity_secs: u32,
        alias: Option<&str>,
    ) -> Result<(), DiscoveryError> {
        let pubkey_bytes = signer.pubkey_bytes();
        let pubkey_hex = hex::encode(pubkey_bytes.0);
        let ts_ms = now_unix_ms();
        let canonical = canonical_mdns_beacon_bytes(
            self.own_agent_id.as_str(),
            &pubkey_bytes.0,
            port,
            ts_ms,
            validity_secs,
        )
        .map_err(|e| DiscoveryError::Mdns(format!("canonical: {e}")))?;
        let sig = signer
            .sign_bytes(&canonical)
            .await
            .map_err(|e| DiscoveryError::Mdns(format!("sign: {e}")))?;
        let sig_hex = hex::encode(sig.0);
        let ts_string = ts_ms.to_string();
        let validity_string = validity_secs.to_string();

        let instance = format!("hermod-{}", self.own_agent_id);
        // ServiceInfo properties as (key, value) pairs. An empty IP triggers
        // auto-detect across all interfaces.
        let mut props: Vec<(&str, &str)> = vec![
            ("agent_id", self.own_agent_id.as_str()),
            ("pubkey", pubkey_hex.as_str()),
            ("ts_ms", ts_string.as_str()),
            ("validity_secs", validity_string.as_str()),
            ("sig", sig_hex.as_str()),
        ];
        if let Some(a) = alias {
            props.push(("alias", a));
        }
        let info = ServiceInfo::new(
            SERVICE_TYPE,
            &instance,
            hostname,
            "",
            port,
            props.as_slice(),
        )
        .map_err(|e| DiscoveryError::Mdns(format!("service info: {e}")))?
        .enable_addr_auto();
        self.daemon
            .register(info)
            .map_err(|e| DiscoveryError::Mdns(format!("register: {e}")))?;
        self.auditor.emitted(port, validity_secs);
        Ok(())
    }

    /// Strict verification of an inbound beacon's authenticity +
    /// freshness. Pure function over a `ServiceInfo` snapshot so
    /// callers (including `peer_from_info`) share one decision path.
    pub fn verify_inbound_beacon(info: &ServiceInfo, now_ms: i64) -> BeaconVerdict {
        let agent_id = match info.get_property_val_str("agent_id") {
            Some(s) => s,
            None => return BeaconVerdict::MalformedFields,
        };
        let pubkey = match info.get_property_val_str("pubkey").and_then(parse_pubkey_hex) {
            Some(p) => p,
            None => return BeaconVerdict::MalformedFields,
        };
        let ts_ms = match info
            .get_property_val_str("ts_ms")
            .and_then(|s| s.parse::<i64>().ok())
        {
            Some(t) => t,
            None => return BeaconVerdict::MalformedFields,
        };
        let validity_secs = match info
            .get_property_val_str("validity_secs")
            .and_then(|s| s.parse::<u32>().ok())
        {
            Some(v) => v,
            None => return BeaconVerdict::MalformedFields,
        };
        let sig_bytes = match info
            .get_property_val_str("sig")
            .and_then(|s| hex::decode(s).ok())
        {
            Some(b) if b.len() == SignatureBytes::LEN => b,
            _ => return BeaconVerdict::MalformedFields,
        };
        let mut sig_arr = [0u8; SignatureBytes::LEN];
        sig_arr.copy_from_slice(&sig_bytes);
        let sig = SignatureBytes(sig_arr);

        // Freshness: stale OR future are both rejected.
        let age_ms = now_ms - ts_ms;
        let validity_ms = (validity_secs as i64) * 1000;
        if age_ms > validity_ms {
            return BeaconVerdict::Stale { age_ms, validity_ms };
        }
        if age_ms < -BEACON_FUTURE_SKEW_MS {
            return BeaconVerdict::Future { skew_ms: -age_ms };
        }

        // Identity binding: pubkey must hash to the announced agent_id.
        let derived = hermod_crypto::agent_id_from_pubkey(&pubkey);
        if derived.as_str() != agent_id {
            return BeaconVerdict::InvalidSignature;
        }

        // Signature: reconstruct canonical bytes + verify under pubkey.
        let canonical = match canonical_mdns_beacon_bytes(
            agent_id,
            &pubkey.0,
            info.get_port(),
            ts_ms,
            validity_secs,
        ) {
            Ok(c) => c,
            Err(_) => return BeaconVerdict::MalformedFields,
        };
        let pk = match PublicKey::from_bytes(&pubkey) {
            Ok(p) => p,
            Err(_) => return BeaconVerdict::InvalidSignature,
        };
        if pk.verify_bytes(&canonical, &sig).is_err() {
            return BeaconVerdict::InvalidSignature;
        }
        BeaconVerdict::Accept
    }
}

fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[async_trait]
impl Discoverer for MdnsDiscoverer {
    fn name(&self) -> &'static str {
        "mdns"
    }

    async fn snapshot(&self) -> Result<Vec<DiscoveredPeer>, DiscoveryError> {
        let g = self
            .cache
            .lock()
            .map_err(|e| DiscoveryError::Mdns(format!("cache poisoned: {e}")))?;
        Ok(g.values().cloned().collect())
    }

    async fn announce(&self, params: AnnounceParams<'_>) -> Result<(), DiscoveryError> {
        self.announce_inner(
            params.hostname,
            params.port,
            &*params.signer,
            params.validity_secs,
            params.alias,
        )
        .await
    }

    /// Tear down the mDNS daemon. Sends an unannounce so peers immediately
    /// drop us from their caches instead of waiting for the TTL to expire.
    /// Idempotent — calling twice is safe.
    async fn shutdown(&self) {
        let instance = format!("hermod-{}.{}", self.own_agent_id, SERVICE_TYPE);
        let _ = self.daemon.unregister(&instance);
        let _ = self.daemon.shutdown();
    }
}

fn peer_from_info(
    info: &ServiceInfo,
    own_agent_id: &str,
    auditor: &dyn crate::BeaconAuditor,
) -> Option<DiscoveredPeer> {
    let agent_id = match info.get_property_val_str("agent_id") {
        Some(a) => a,
        None => {
            auditor.rejected(None, "missing_agent_id");
            return None;
        }
    };
    if agent_id == own_agent_id {
        return None;
    }
    // Strict-mode beacon authentication: any signature failure, missing
    // field, or freshness violation drops the announcement on the
    // floor. The verdict is forwarded to the auditor so the daemon can
    // record the rejection in its hash-chained audit log.
    match MdnsDiscoverer::verify_inbound_beacon(info, now_unix_ms()) {
        BeaconVerdict::Accept => {}
        BeaconVerdict::MalformedFields => {
            warn!(agent_id, "mdns beacon rejected: malformed fields");
            auditor.rejected(Some(agent_id), "malformed_fields");
            return None;
        }
        BeaconVerdict::InvalidSignature => {
            warn!(agent_id, "mdns beacon rejected: invalid signature");
            auditor.rejected(Some(agent_id), "invalid_sig");
            return None;
        }
        BeaconVerdict::Stale { .. } => {
            warn!(agent_id, "mdns beacon rejected: stale");
            auditor.rejected(Some(agent_id), "stale");
            return None;
        }
        BeaconVerdict::Future { .. } => {
            warn!(agent_id, "mdns beacon rejected: future ts");
            auditor.rejected(Some(agent_id), "future_ts");
            return None;
        }
    }
    let pubkey = info
        .get_property_val_str("pubkey")
        .and_then(parse_pubkey_hex);
    let alias = parse_alias_txt(info.get_property_val_str("alias"));
    let port = info.get_port();
    let host = info
        .get_addresses_v4()
        .iter()
        .next()
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| info.get_hostname().to_string());
    let endpoint = Endpoint::Wss(WssEndpoint { host, port });
    auditor.observed(agent_id, &endpoint);
    Some(DiscoveredPeer {
        id: Some(agent_id.to_string()),
        endpoint,
        pubkey,
        alias,
        source: "mdns",
    })
}

/// Parse the optional `alias` TXT value into an [`AgentAlias`]. Returns
/// `None` for missing OR malformed values — discovery must never panic
/// on a hostile / typo'd broadcast.
fn parse_alias_txt(raw: Option<&str>) -> Option<AgentAlias> {
    raw.and_then(|s| AgentAlias::from_str(s).ok())
}

fn parse_pubkey_hex(s: &str) -> Option<PubkeyBytes> {
    let bytes = hex::decode(s).ok()?;
    if bytes.len() != PubkeyBytes::LEN {
        return None;
    }
    let mut arr = [0u8; PubkeyBytes::LEN];
    arr.copy_from_slice(&bytes);
    Some(PubkeyBytes(arr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alias_txt_present_round_trips() {
        let parsed = parse_alias_txt(Some("alice"));
        assert_eq!(parsed.as_ref().map(|a| a.as_str()), Some("alice"));
    }

    #[test]
    fn alias_txt_absent_is_none() {
        assert!(parse_alias_txt(None).is_none());
    }

    #[test]
    fn alias_txt_invalid_drops_to_none() {
        // Discovery must never panic on a hostile or typo'd broadcast —
        // anything that fails `AgentAlias::from_str` falls to None.
        for hostile in ["@@@", "", "with space", "way-too-long-".repeat(8).as_str()] {
            assert!(
                parse_alias_txt(Some(hostile)).is_none(),
                "invalid alias {hostile:?} should drop, not parse"
            );
        }
    }
}
