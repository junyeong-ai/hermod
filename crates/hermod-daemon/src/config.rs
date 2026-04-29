use anyhow::{Context, Result};
use hermod_crypto::SecretString;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub daemon: DaemonConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub blob: BlobConfig,
    #[serde(default)]
    pub federation: FederationConfig,
    #[serde(default)]
    pub policy: PolicyConfig,
    #[serde(default)]
    pub audit: AuditConfig,
    #[serde(default)]
    pub broker: BrokerConfig,
}

/// Broker daemon role.
///
/// A broker is a federation daemon that **routes envelopes for other
/// peers**. Two independently-toggled sub-roles:
///
/// * `relay` — forward inbound envelopes whose `to.id` is NOT this
///   daemon (mediates traffic between peers). Signature is preserved
///   verbatim — the broker cannot tamper with content (E2E auth).
/// * `witness` — log every routed envelope to the broker's own
///   hash-chained audit log (mandatory audit, not best-effort).
///
/// Default: every flag `false` — a fresh daemon is not a broker.
/// Whether this daemon acts as a relay broker, and if so whether
/// every relayed envelope is witnessed (audited).
///
/// Three exhaustive modes — every legal combination of "do I relay?"
/// and "do I audit each relay?" lives here. The same daemon may
/// simultaneously host its own local agents AND act as a broker for
/// others (envelopes whose `to.id` is one of our hosted agents are
/// processed normally; everything else is relayed).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrokerMode {
    /// No relaying. Inbound envelopes addressed to other peers are
    /// rejected with `not for us`. The default for non-broker daemons.
    #[default]
    Disabled,
    /// Relay inbound envelopes addressed to other peers via the
    /// daemon's own outbound peer pool. No per-relay audit row — the
    /// hash-chained log only sees broker startup / shutdown plus the
    /// daemon's own actions.
    RelayOnly,
    /// Relay AND emit one `broker.relay.{forwarded|rejected}` audit
    /// row per attempt. The audit row goes through the same
    /// hash-chained sink as the daemon's own actions, so an operator
    /// querying the broker has a complete ground-truth log of every
    /// envelope that traversed it.
    RelayAndWitness,
}

impl BrokerMode {
    pub fn relays(self) -> bool {
        matches!(self, Self::RelayOnly | Self::RelayAndWitness)
    }

    pub fn witnesses(self) -> bool {
        matches!(self, Self::RelayAndWitness)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BrokerConfig {
    #[serde(default)]
    pub mode: BrokerMode,
}

/// External audit-shipping sinks. The hash-chained SQLite log is always
/// written; this section only configures *additional* mirror sinks
/// (file, federation, future webhook / OTLP). All fields default to
/// disabled.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AuditConfig {
    /// If set, every audit row is appended (one JSON object per line) to
    /// this path. Operators tail-follow with promtail / vector / fluent-
    /// bit / filebeat to ship to Loki / Splunk / DataDog without the
    /// daemon taking on a network sink dependency. The path's parent
    /// directory must exist (the daemon does not create it). Logrotate-
    /// compatible: the sink reopens the file per write. None disables.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    /// Audit-federation destinations. Every audit row is shipped to
    /// each listed agent as an `AuditFederate` envelope, fanned out in
    /// parallel — primary down does not delay secondary delivery.
    /// Each peer must opt in to ingestion (`accept_federation = true`)
    /// otherwise it rejects every envelope with `unauthorized`. Empty
    /// disables outbound federation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aggregators: Vec<String>,
    /// Operator opt-in to act as an audit-federation aggregator: when
    /// `true`, inbound `AuditFederate` envelopes from authenticated
    /// peers are written to the local hash-chained log under
    /// `audit.federate.<original_action>`. Default `false` — random
    /// peers can't pollute our audit log.
    #[serde(default)]
    pub accept_federation: bool,
    /// HTTP webhook URL. When set, every audit row is POSTed as a
    /// single JSON object to this endpoint by a background worker
    /// (non-blocking; queue overflow drops with a warn). Suitable for
    /// DataDog Logs, Loki HTTP push (via sidecar), OpenTelemetry
    /// collector OTLP/HTTP-JSON, or any generic webhook. None
    /// disables.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webhook_url: Option<String>,
    /// Optional `Authorization: Bearer <token>` for the webhook.
    /// Configure separately so a TOML config file can ship without
    /// secrets when paired with `HERMOD_AUDIT_WEBHOOK_BEARER_TOKEN`.
    /// `skip_serializing` ensures the value never round-trips back to
    /// disk via `Config::write_template` — secrets stay in TOML
    /// only because the operator put them there.
    #[serde(default, skip_serializing)]
    pub webhook_bearer_token: Option<SecretString>,
}

/// Authorization, replay protection, rate limiting, and retention windows.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// When true, federation listener requires `Envelope.caps[]` to contain a
    /// valid self-issued capability matching the operation. False =
    /// permissive: Noise XX auth alone gates inbound.
    #[serde(default)]
    pub require_capability: bool,
    /// Reject envelopes whose `ts` is more than this many seconds off our wall
    /// clock. 0 disables the check.
    #[serde(default = "defaults::replay_window")]
    pub replay_window_secs: u32,
    /// Token-bucket capacity per (sender → us) pair, in messages per minute.
    /// 0 disables rate limiting.
    #[serde(default = "defaults::rate_limit")]
    pub rate_limit_per_sender: u32,
    /// Pending confirmations older than this many seconds are auto-marked
    /// `expired` by the janitor. 0 disables the sweep.
    #[serde(default = "defaults::confirmation_retention")]
    pub confirmation_retention_secs: u64,
    /// Discovered channels not refreshed within this window are dropped
    /// by the janitor. 0 disables the sweep.
    #[serde(default = "defaults::discovery_retention")]
    pub discovery_retention_secs: u64,
    /// `read` / `failed` messages older than this many seconds are deleted
    /// to bound the messages table. 0 disables the sweep (operator-managed
    /// rotation). The envelope TTL (`expires_at`) is honoured separately
    /// regardless of this setting.
    #[serde(default = "defaults::message_terminal_retention")]
    pub message_terminal_retention_secs: u64,
    /// Maximum age of a held envelope at the moment the operator accepts
    /// it. The signature and capability checks already cleared at hold
    /// time, but a multi-day-old action is no longer "this peer is
    /// asking right now" — it's an arbitrary replay decided by the
    /// operator. Envelopes older than this on accept are rejected with
    /// `StaleHeldEnvelope`. 0 disables the check.
    #[serde(default = "defaults::held_envelope_max_age")]
    pub held_envelope_max_age_secs: u64,
    /// Hard cap on simultaneously-pending TLS+WS+Noise handshakes the
    /// federation listener will spawn. Beyond this, new TCP accepts wait
    /// at the semaphore until an in-flight handshake completes or hits
    /// `HANDSHAKE_TIMEOUT`. Tune up for very large peer fleets, down for
    /// tightly-resource-constrained edge nodes.
    #[serde(default = "defaults::max_inflight_handshakes")]
    pub max_inflight_handshakes: u32,
    /// Cap on `MessageBody::File` payload bytes accepted from peers and
    /// emitted by `MessageService::send_file`. Cannot exceed the
    /// compile-time ceiling [`hermod_core::MAX_FILE_PAYLOAD_BYTES`]
    /// (1 MiB) — the daemon clamps silently if a higher value is set.
    /// Lower this in resource-constrained environments to bound the
    /// memory cost of inbox blobs.
    #[serde(default = "defaults::max_file_payload_bytes")]
    pub max_file_payload_bytes: u32,
    /// Live `audit_log` rows older than this are archived into
    /// gzip-JSONL day-buckets in the `BlobStore` and deleted from the
    /// table. Chain continuity is preserved via
    /// `audit_archive_index`. 0 disables archival entirely (operator
    /// manages retention manually).
    #[serde(default = "defaults::audit_retention")]
    pub audit_retention_secs: u64,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            require_capability: false,
            replay_window_secs: defaults::replay_window(),
            rate_limit_per_sender: defaults::rate_limit(),
            confirmation_retention_secs: defaults::confirmation_retention(),
            discovery_retention_secs: defaults::discovery_retention(),
            message_terminal_retention_secs: defaults::message_terminal_retention(),
            held_envelope_max_age_secs: defaults::held_envelope_max_age(),
            max_inflight_handshakes: defaults::max_inflight_handshakes(),
            max_file_payload_bytes: defaults::max_file_payload_bytes(),
            audit_retention_secs: defaults::audit_retention(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DaemonConfig {
    #[serde(default = "defaults::socket_path")]
    pub socket_path: String,
    /// Inbound federation listen address, e.g. `0.0.0.0:7823`. None disables inbound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen_ws: Option<String>,
    /// Optional WSS+Bearer endpoint for remote IPC (`hermod --remote …`).
    /// When set, exposes the same JSON-RPC surface the Unix socket serves,
    /// gated by the bearer token at
    /// `$HERMOD_HOME/agents/<bootstrap_id>/bearer_token`.
    /// Reuses the daemon's TLS material — TLS termination at the daemon
    /// itself. None disables the listener. Mutually exclusive with
    /// [`Self::ipc_listen_ws`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipc_listen_wss: Option<String>,
    /// Optional plaintext WS+Bearer endpoint for remote IPC, intended
    /// for deployments where TLS terminates at an upstream reverse
    /// proxy (Cloud Run, Google IAP, oauth2-proxy, Cloudflare Access,
    /// AWS ALB+Cognito, k8s ingress). The wire-format JSON-RPC surface
    /// is identical to [`Self::ipc_listen_wss`]; the only difference
    /// is that this listener accepts the WebSocket handshake on a raw
    /// TCP stream instead of inside its own TLS envelope.
    ///
    /// The bearer token still gates auth — TLS termination at the
    /// proxy doesn't authenticate the *client*, only the *transport*.
    /// Federation peer-to-peer connections never use this mode (peers
    /// authenticate identity via TLS material, see
    /// [`Self::listen_ws`]). None disables the listener. Mutually
    /// exclusive with [`Self::ipc_listen_wss`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipc_listen_ws: Option<String>,
    /// Optional plaintext HTTP bind for `/healthz` (liveness),
    /// `/readyz` (readiness), and `/metrics` (Prometheus). Bind to
    /// `127.0.0.1:9690` for sidecar use, or to a private interface
    /// for cluster scrape. None disables the listener entirely.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metrics_listen: Option<String>,
    /// Grace budget for the SIGTERM ordered drain (listener stop →
    /// discovery deregister → outbox / janitor / pool flush → DB
    /// shutdown). Cloud Run / Kubernetes default
    /// `terminationGracePeriodSeconds` is 30s; the default 25s here
    /// leaves a 5s margin for the runtime to log + exit. Operators
    /// who raise their platform's grace (slow audit federation drain)
    /// raise this match, and operators who lower it (fast pod
    /// recycle) lower this too.
    #[serde(default = "defaults::shutdown_grace")]
    pub shutdown_grace_secs: u64,
    /// CIDR ranges of reverse proxies whose `X-Forwarded-For` header
    /// the daemon will trust to recover the originating client IP for
    /// audit logging.
    ///
    /// Default: empty — XFF is ignored, the TCP peer IP is the client
    /// IP. The well-established trusted-proxy pattern (nginx
    /// `set_real_ip_from`, Apache `mod_remoteip`, Envoy
    /// `xff_num_trusted_hops`) governs the resolution: see
    /// [`crate::client_ip::resolve_client_ip`].
    ///
    /// Specify upstream **proxy networks** here, never public-internet
    /// ranges — an entry that covers an attacker-reachable IP would
    /// let them forge audit IPs by sending a crafted XFF header. Each
    /// entry is parsed by [`ipnet::IpNet`] (`10.0.0.0/8`,
    /// `172.16.0.0/12`, `2001:db8::/32`, …).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_proxies: Vec<String>,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            socket_path: defaults::socket_path(),
            listen_ws: None,
            ipc_listen_wss: None,
            ipc_listen_ws: None,
            metrics_listen: None,
            shutdown_grace_secs: defaults::shutdown_grace(),
            trusted_proxies: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Backend DSN. Scheme selects the backend:
    ///
    ///   * `sqlite:///$HERMOD_HOME/hermod.db` — file-backed SQLite (default).
    ///   * `postgresql://user@host/db?sslmode=require` — PostgreSQL
    ///     backend (requires `--features postgres`).
    ///
    /// `$HERMOD_HOME` is expanded against the daemon's home directory
    /// before the DSN is parsed, so config files stay portable across
    /// hosts. To swap to a different backend, change the scheme — no
    /// other config touches are needed. Mirrors `[blob] dsn` so the
    /// two pluggable layers share one mental model.
    #[serde(default = "defaults::storage_dsn")]
    pub dsn: String,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            dsn: defaults::storage_dsn(),
        }
    }
}

/// Pluggable blob store. File-message payloads (1 MiB cap) and
/// gzip-compressed audit-archive day-buckets land here. Backends are
/// selected by DSN scheme — see [`hermod_storage::open_blob_store`]
/// for the catalogue. Auth/region for cloud backends come from the
/// SDK's standard env-var chain (ADC for GCS, AWS credential chain
/// for S3); the DSN carries only "where" (bucket + prefix), never
/// secrets.
///
/// `$HERMOD_HOME` is expanded inside the DSN before parsing, so
/// `file://$HERMOD_HOME/blob-store` works portably across hosts.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlobConfig {
    #[serde(default = "defaults::blob_dsn")]
    pub dsn: String,
}

impl Default for BlobConfig {
    fn default() -> Self {
        Self {
            dsn: defaults::blob_dsn(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FederationConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub discover_mdns: bool,
    #[serde(default)]
    pub peers: Vec<String>,
    /// How long an emitted mDNS beacon stays fresh, in seconds.
    /// Receivers in strict mode reject any beacon older than this. Set
    /// shorter for tighter LAN replay protection at the cost of more
    /// re-signs (which are cheap — ed25519 over ~64 bytes).
    #[serde(default = "defaults::mdns_beacon_validity")]
    pub mdns_beacon_validity_secs: u32,
    /// Upstream broker descriptor (`wss://host:port#<pubkey_hex>`).
    /// When set, recipients registered in the local directory without
    /// a remote endpoint route via this broker — the same SMTP
    /// smarthost / Matrix homeserver / IMAP relay pattern. Operators
    /// pair this with a peer the broker registers (so signatures on
    /// inbound replies verify) and never need to learn each peer's
    /// own endpoint. The broker descriptor is registered in this
    /// daemon's directory on startup, just like a static seed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_broker: Option<String>,
    /// Outbound TLS pin policy for federation dials (broker + every
    /// peer this daemon connects to). Mirrors the IPC client's
    /// `--pin` flag; one of `tofu` (default) | `public-ca` | `none`
    /// | a 64-char SHA-256 fingerprint. `tofu` records the first-
    /// seen cert under `$HERMOD_HOME/federation_pins.json` and
    /// fail-loud on subsequent mismatch — the SSH host-key model.
    /// `public-ca` is the right answer when the broker sits behind
    /// Cloud Run / IAP / Cloudflare Access (LB cert rotates under a
    /// stable hostname). `none` skips TLS validation entirely; only
    /// for tests / fully-trusted LAN. Cryptographic peer auth still
    /// happens at the Noise XX layer regardless of this policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_pin: Option<String>,
}

impl Default for FederationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            discover_mdns: false,
            peers: Vec::new(),
            mdns_beacon_validity_secs: defaults::mdns_beacon_validity(),
            upstream_broker: None,
            tls_pin: None,
        }
    }
}

mod defaults {
    pub fn socket_path() -> String {
        "$HERMOD_HOME/sock".into()
    }
    pub fn storage_dsn() -> String {
        "sqlite://$HERMOD_HOME/hermod.db".into()
    }
    pub fn blob_dsn() -> String {
        "file://$HERMOD_HOME/blob-store".into()
    }
    pub fn rate_limit() -> u32 {
        60
    }
    pub fn replay_window() -> u32 {
        300
    }
    pub fn confirmation_retention() -> u64 {
        7 * 24 * 3600
    }
    pub fn discovery_retention() -> u64 {
        24 * 3600
    }
    pub fn message_terminal_retention() -> u64 {
        30 * 24 * 3600
    }
    pub fn held_envelope_max_age() -> u64 {
        24 * 3600 // 1 day — long enough for "looked at it tomorrow"
    }
    pub fn max_inflight_handshakes() -> u32 {
        64
    }
    pub fn max_file_payload_bytes() -> u32 {
        hermod_core::MAX_FILE_PAYLOAD_BYTES as u32
    }
    pub fn mdns_beacon_validity() -> u32 {
        3600
    }
    pub fn audit_retention() -> u64 {
        30 * 24 * 3600
    }
    pub fn shutdown_grace() -> u64 {
        25
    }
}

impl Config {
    /// Read `config.toml` (from `explicit` if provided, otherwise
    /// `<home>/config.toml`), layer `HERMOD_*` env overrides, and
    /// validate. A missing file is fine — the daemon falls back to
    /// `Self::default()` so a fresh install boots without a config.
    /// Any other failure (parse error, malformed env override,
    /// validation breach) returns `Err` so the operator sees the
    /// problem at startup instead of debugging from "wrong default
    /// got applied silently".
    pub fn load(explicit: Option<&Path>, home: &Path) -> Result<Self> {
        let path = match explicit {
            Some(p) => p.to_path_buf(),
            None => home.join("config.toml"),
        };
        let mut cfg = if path.exists() {
            let text = std::fs::read_to_string(&path)
                .with_context(|| format!("read {}", path.display()))?;
            toml::from_str::<Config>(&text).with_context(|| format!("parse {}", path.display()))?
        } else {
            Self::default()
        };
        cfg.apply_env_overrides()
            .context("apply HERMOD_* env overrides")?;
        cfg.validate()
            .with_context(|| format!("validate config from {}", path.display()))?;
        Ok(cfg)
    }

    /// Reject obviously broken config at startup so an operator finds out
    /// before the daemon background-warns and limps along. Currently:
    /// every `*_listen` / `listen_ws` is parsed as a `SocketAddr`. Unset
    /// (`None`) is fine — those listeners are opt-in.
    fn validate(&self) -> Result<()> {
        use std::net::SocketAddr;
        if let Some(s) = &self.daemon.listen_ws {
            s.parse::<SocketAddr>()
                .with_context(|| format!("invalid [daemon] listen_ws = {s:?}"))?;
        }
        if let Some(s) = &self.daemon.ipc_listen_wss {
            s.parse::<SocketAddr>()
                .with_context(|| format!("invalid [daemon] ipc_listen_wss = {s:?}"))?;
        }
        if let Some(s) = &self.daemon.ipc_listen_ws {
            s.parse::<SocketAddr>()
                .with_context(|| format!("invalid [daemon] ipc_listen_ws = {s:?}"))?;
        }
        if self.daemon.ipc_listen_wss.is_some() && self.daemon.ipc_listen_ws.is_some() {
            anyhow::bail!(
                "[daemon] ipc_listen_wss and ipc_listen_ws are mutually exclusive — \
                 the WSS form terminates TLS at the daemon, the WS form expects an \
                 upstream reverse proxy (Cloud Run / IAP / oauth2-proxy) to do TLS \
                 termination. Pick one."
            );
        }
        if let Some(s) = &self.daemon.metrics_listen {
            s.parse::<SocketAddr>()
                .with_context(|| format!("invalid [daemon] metrics_listen = {s:?}"))?;
        }
        // Replay window beyond a day defeats the purpose: an attacker
        // capturing an envelope today could replay it weeks later. Zero
        // disables the window (intentional escape hatch for tests).
        if self.policy.replay_window_secs > 86_400 {
            anyhow::bail!(
                "[policy] replay_window_secs = {} exceeds 86400s (1 day)",
                self.policy.replay_window_secs
            );
        }
        // The token bucket math saturates at f64 well below this, but
        // anything beyond 1M/min isn't a "rate limit" — it's a no-op.
        if self.policy.rate_limit_per_sender > 1_000_000 {
            anyhow::bail!(
                "[policy] rate_limit_per_sender = {} exceeds 1_000_000",
                self.policy.rate_limit_per_sender
            );
        }
        if self.policy.confirmation_retention_secs == 0 {
            anyhow::bail!(
                "[policy] confirmation_retention_secs must be > 0 (use a large value to disable pruning)"
            );
        }
        if self.policy.discovery_retention_secs == 0 {
            anyhow::bail!("[policy] discovery_retention_secs must be > 0");
        }
        // Shutdown grace > 0 (zero means "exit immediately, drop
        // every in-flight envelope") and < 600s (k8s hard ceiling on
        // `terminationGracePeriodSeconds`; beyond that the kernel
        // SIGKILLs us anyway and the wait is dead time).
        if self.daemon.shutdown_grace_secs == 0 {
            anyhow::bail!("[daemon] shutdown_grace_secs must be > 0");
        }
        if self.daemon.shutdown_grace_secs > 600 {
            anyhow::bail!(
                "[daemon] shutdown_grace_secs = {} exceeds 600s (k8s terminationGracePeriodSeconds ceiling)",
                self.daemon.shutdown_grace_secs
            );
        }
        // Pre-parse every CIDR so a typo surfaces at boot, not on the
        // first XFF-bearing request. The parsed values are re-derived
        // at the use site (`crate::client_ip::resolve_client_ip`); the
        // round-trip here is purely a syntactic check against the
        // operator's strings.
        for raw in &self.daemon.trusted_proxies {
            raw.parse::<ipnet::IpNet>().with_context(|| {
                format!("invalid [daemon] trusted_proxies entry {raw:?} (expected CIDR like `10.0.0.0/8`)")
            })?;
        }
        Ok(())
    }

    /// Twelve-factor overrides — every field is settable via
    /// `HERMOD_<SECTION>_<FIELD>=value` so containers / k8s ConfigMaps don't
    /// need to mount a TOML. Returns `Err` on a malformed numeric value so
    /// the daemon refuses to start with silently-defaulted policy.
    fn apply_env_overrides(&mut self) -> Result<()> {
        if let Ok(v) = std::env::var("HERMOD_DAEMON_SOCKET_PATH") {
            self.daemon.socket_path = v;
        }
        if let Ok(v) = std::env::var("HERMOD_DAEMON_LISTEN_WS") {
            self.daemon.listen_ws = Some(v);
        }
        if let Ok(v) = std::env::var("HERMOD_DAEMON_IPC_LISTEN_WSS") {
            self.daemon.ipc_listen_wss = Some(v);
        }
        if let Ok(v) = std::env::var("HERMOD_DAEMON_IPC_LISTEN_WS") {
            self.daemon.ipc_listen_ws = Some(v);
        }
        if let Ok(v) = std::env::var("HERMOD_DAEMON_METRICS_LISTEN") {
            self.daemon.metrics_listen = Some(v);
        }
        if let Ok(v) = std::env::var("HERMOD_DAEMON_SHUTDOWN_GRACE_SECS") {
            self.daemon.shutdown_grace_secs = v
                .parse()
                .with_context(|| format!("invalid HERMOD_DAEMON_SHUTDOWN_GRACE_SECS = {v:?}"))?;
        }
        if let Ok(v) = std::env::var("HERMOD_DAEMON_TRUSTED_PROXIES") {
            // Comma-separated list of CIDR strings; CIDR validity is
            // checked in `validate()` so a single env var carrying a
            // bad entry surfaces with the same message format the TOML
            // path produces.
            self.daemon.trusted_proxies = v
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
        if let Ok(v) = std::env::var("HERMOD_STORAGE_DSN") {
            self.storage.dsn = v;
        }
        if let Ok(v) = std::env::var("HERMOD_BLOB_DSN") {
            self.blob.dsn = v;
        }
        if let Ok(v) = std::env::var("HERMOD_FEDERATION_ENABLED") {
            self.federation.enabled = parse_bool(&v);
        }
        if let Ok(v) = std::env::var("HERMOD_FEDERATION_DISCOVER_MDNS") {
            self.federation.discover_mdns = parse_bool(&v);
        }
        if let Ok(v) = std::env::var("HERMOD_FEDERATION_MDNS_BEACON_VALIDITY_SECS") {
            self.federation.mdns_beacon_validity_secs = v.parse().with_context(|| {
                format!("invalid HERMOD_FEDERATION_MDNS_BEACON_VALIDITY_SECS = {v:?}")
            })?;
        }
        // Comma-separated peer descriptors:
        //   `wss://host:port#<pubkey_hex>,wss://other:port`
        // Splits on `,` so a single env var can carry the full seed list
        // without needing a config file mount in container deployments.
        if let Ok(v) = std::env::var("HERMOD_FEDERATION_PEERS") {
            self.federation.peers = v
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect();
        }
        if let Ok(v) = std::env::var("HERMOD_FEDERATION_UPSTREAM_BROKER") {
            let trimmed = v.trim();
            self.federation.upstream_broker = if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            };
        }
        if let Ok(v) = std::env::var("HERMOD_FEDERATION_TLS_PIN") {
            let trimmed = v.trim();
            self.federation.tls_pin = if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            };
        }
        if let Ok(v) = std::env::var("HERMOD_POLICY_REQUIRE_CAPABILITY") {
            self.policy.require_capability = parse_bool(&v);
        }
        if let Ok(v) = std::env::var("HERMOD_POLICY_REPLAY_WINDOW_SECS") {
            self.policy.replay_window_secs = v
                .parse()
                .with_context(|| format!("invalid HERMOD_POLICY_REPLAY_WINDOW_SECS = {v:?}"))?;
        }
        if let Ok(v) = std::env::var("HERMOD_POLICY_RATE_LIMIT_PER_SENDER") {
            self.policy.rate_limit_per_sender = v
                .parse()
                .with_context(|| format!("invalid HERMOD_POLICY_RATE_LIMIT_PER_SENDER = {v:?}"))?;
        }
        if let Ok(v) = std::env::var("HERMOD_POLICY_CONFIRMATION_RETENTION_SECS") {
            self.policy.confirmation_retention_secs = v.parse().with_context(|| {
                format!("invalid HERMOD_POLICY_CONFIRMATION_RETENTION_SECS = {v:?}")
            })?;
        }
        if let Ok(v) = std::env::var("HERMOD_POLICY_DISCOVERY_RETENTION_SECS") {
            self.policy.discovery_retention_secs = v.parse().with_context(|| {
                format!("invalid HERMOD_POLICY_DISCOVERY_RETENTION_SECS = {v:?}")
            })?;
        }
        if let Ok(v) = std::env::var("HERMOD_POLICY_HELD_ENVELOPE_MAX_AGE_SECS") {
            self.policy.held_envelope_max_age_secs = v.parse().with_context(|| {
                format!("invalid HERMOD_POLICY_HELD_ENVELOPE_MAX_AGE_SECS = {v:?}")
            })?;
        }
        if let Ok(v) = std::env::var("HERMOD_POLICY_MAX_INFLIGHT_HANDSHAKES") {
            self.policy.max_inflight_handshakes = v.parse().with_context(|| {
                format!("invalid HERMOD_POLICY_MAX_INFLIGHT_HANDSHAKES = {v:?}")
            })?;
        }
        if let Ok(v) = std::env::var("HERMOD_POLICY_MAX_FILE_PAYLOAD_BYTES") {
            self.policy.max_file_payload_bytes = v
                .parse()
                .with_context(|| format!("invalid HERMOD_POLICY_MAX_FILE_PAYLOAD_BYTES = {v:?}"))?;
        }
        if let Ok(v) = std::env::var("HERMOD_POLICY_AUDIT_RETENTION_SECS") {
            self.policy.audit_retention_secs = v
                .parse()
                .with_context(|| format!("invalid HERMOD_POLICY_AUDIT_RETENTION_SECS = {v:?}"))?;
        }
        if let Ok(v) = std::env::var("HERMOD_AUDIT_FILE_PATH") {
            self.audit.file_path = Some(v);
        }
        // Comma-separated aggregator agent_ids (mirrors
        // HERMOD_FEDERATION_PEERS' multi-value handling). A single
        // value works without commas; empty entries are dropped.
        if let Ok(v) = std::env::var("HERMOD_AUDIT_AGGREGATORS") {
            self.audit.aggregators = v
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect();
        }
        if let Ok(v) = std::env::var("HERMOD_AUDIT_ACCEPT_FEDERATION") {
            self.audit.accept_federation = parse_bool(&v);
        }
        if let Ok(v) = std::env::var("HERMOD_AUDIT_WEBHOOK_URL") {
            self.audit.webhook_url = Some(v);
        }
        if let Some(v) = hermod_crypto::secret::secret_from_env("HERMOD_AUDIT_WEBHOOK_BEARER_TOKEN")
        {
            self.audit.webhook_bearer_token = Some(v);
        }
        if let Ok(v) = std::env::var("HERMOD_BROKER_MODE") {
            self.broker.mode = match v.trim().to_ascii_lowercase().as_str() {
                "disabled" => BrokerMode::Disabled,
                "relay_only" => BrokerMode::RelayOnly,
                "relay_and_witness" => BrokerMode::RelayAndWitness,
                other => {
                    return Err(anyhow::anyhow!(
                        "HERMOD_BROKER_MODE: unknown mode {other:?} \
                         (expected disabled | relay_only | relay_and_witness)"
                    ));
                }
            };
        }
        Ok(())
    }

    pub fn write_template(home: &Path) -> Result<PathBuf> {
        let path = home.join("config.toml");
        if path.exists() {
            return Ok(path);
        }
        std::fs::create_dir_all(home)?;
        let default = Self::default();
        let text = toml::to_string_pretty(&default)?;
        // Atomic create with mode 0o600 from open(2) — closes the
        // TOCTOU window between `fs::write`'s default-umask create
        // and a follow-up chmod. config.toml may carry
        // `[audit] webhook_bearer_token`; operators who need a wider
        // mode chmod themselves after init.
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)?;
            f.write_all(text.as_bytes())?;
            // Re-assert mode in case the running process's umask
            // masked the create-time mode bit.
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        #[cfg(not(unix))]
        {
            std::fs::write(&path, text)?;
        }
        Ok(path)
    }
}

fn parse_bool(s: &str) -> bool {
    matches!(
        s.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broker_mode_default_is_disabled() {
        assert_eq!(BrokerMode::default(), BrokerMode::Disabled);
    }

    #[test]
    fn broker_mode_relays_matches_intent() {
        // Disabled never relays; the other two do.
        assert!(!BrokerMode::Disabled.relays());
        assert!(BrokerMode::RelayOnly.relays());
        assert!(BrokerMode::RelayAndWitness.relays());
    }

    #[test]
    fn broker_mode_witnesses_only_when_relay_and_witness() {
        // Witnessing without relaying is impossible by construction —
        // there's nothing to witness if no envelope is forwarded. The
        // type encodes that invariant; this test pins it.
        assert!(!BrokerMode::Disabled.witnesses());
        assert!(!BrokerMode::RelayOnly.witnesses());
        assert!(BrokerMode::RelayAndWitness.witnesses());
    }

    #[test]
    fn validate_rejects_both_ipc_listen_keys_set() {
        // The two listener flavours describe mutually-exclusive TLS
        // topologies — `ipc_listen_wss` terminates TLS at the daemon,
        // `ipc_listen_ws` expects an upstream proxy to do it. A
        // config that sets both is incoherent. Reject loud at boot
        // rather than picking one silently and confusing the operator.
        let mut cfg = Config::default();
        cfg.daemon.ipc_listen_wss = Some("0.0.0.0:7824".into());
        cfg.daemon.ipc_listen_ws = Some("0.0.0.0:7825".into());
        let err = cfg
            .validate()
            .expect_err("both listeners set must be rejected");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("mutually exclusive"),
            "error must explain the conflict, got: {msg}"
        );
    }

    #[test]
    fn validate_accepts_either_ipc_listen_key_alone() {
        // Each flavour alone is the supported topology — pin both
        // single-key configurations as accepted so a future change to
        // the validator can't accidentally regress one of them.
        for (label, mutate) in [
            (
                "ipc_listen_wss alone",
                Box::new(|c: &mut Config| {
                    c.daemon.ipc_listen_wss = Some("0.0.0.0:7824".into());
                }) as Box<dyn FnOnce(&mut Config)>,
            ),
            (
                "ipc_listen_ws alone",
                Box::new(|c: &mut Config| {
                    c.daemon.ipc_listen_ws = Some("0.0.0.0:7824".into());
                }),
            ),
        ] {
            let mut cfg = Config::default();
            mutate(&mut cfg);
            cfg.validate().unwrap_or_else(|e| panic!("{label}: {e:#}"));
        }
    }

    #[test]
    fn validate_rejects_malformed_trusted_proxy_cidr() {
        // Catch CIDR typos at boot rather than on the first
        // XFF-bearing request; the runtime resolver is structured to
        // never panic on a bad CIDR, so validation is the single
        // diagnostic surface.
        let mut cfg = Config::default();
        cfg.daemon.trusted_proxies = vec!["not-a-cidr".into()];
        let err = cfg
            .validate()
            .expect_err("malformed trusted_proxies entry must be rejected");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("trusted_proxies entry") && msg.contains("CIDR"),
            "error must point at the field and the expected form, got: {msg}"
        );
    }

    #[test]
    fn validate_accepts_well_formed_trusted_proxy_cidrs() {
        // Mix of IPv4 / IPv6, single-host (`/32`) and network ranges —
        // every combination ipnet accepts must pass.
        let mut cfg = Config::default();
        cfg.daemon.trusted_proxies = vec![
            "10.0.0.0/8".into(),
            "172.16.0.0/12".into(),
            "192.168.1.1/32".into(),
            "fd00::/8".into(),
            "2001:db8::/32".into(),
        ];
        cfg.validate().expect("well-formed CIDRs must validate");
    }

    #[test]
    fn broker_mode_serde_round_trips_each_variant() {
        // Each mode must round-trip through TOML so a config file
        // written by one daemon binary parses on a peer running the
        // same release. The `rename_all = "snake_case"` attribute
        // does the work; this test pins it.
        for (variant, label) in [
            (BrokerMode::Disabled, "disabled"),
            (BrokerMode::RelayOnly, "relay_only"),
            (BrokerMode::RelayAndWitness, "relay_and_witness"),
        ] {
            let toml_str = toml::to_string(&BrokerConfig { mode: variant }).unwrap();
            assert!(
                toml_str.contains(&format!("mode = \"{label}\"")),
                "{variant:?} must serialise to {label}, got:\n{toml_str}"
            );
            let back: BrokerConfig = toml::from_str(&toml_str).unwrap();
            assert_eq!(back.mode, variant);
        }
    }
}
