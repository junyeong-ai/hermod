//! Accept loop: bind Unix socket, dispatch each connection to the RPC dispatcher.

use anyhow::{Context, Result};
use hermod_crypto::{Keypair, SecretString, Signer, TlsMaterial};
use hermod_protocol::ipc::IpcServer;
use hermod_routing::{AccessController, RateLimiter, Router};
use hermod_storage::Database;
use hermod_transport::UnixIpcListener;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Instant;
use tokio::signal;
use tracing::{error, info};

use hermod_daemon::config::Config;
use hermod_routing::{AccessPolicy, RemoteDeliverer, spawn_sweeper};

use crate::dispatcher::Dispatcher;
use crate::federation::FederationServer;
use crate::inbound::InboundProcessor;
use crate::outbox::OutboxWorker;
use crate::services::{
    AgentService, AuditService, BriefService, BroadcastService, CapabilityService, ChannelService,
    ConfirmationService, KeyRef, McpService, MessageService, PeerService, PermissionService,
    PresenceService, StatusService, WorkspaceService,
};

#[allow(clippy::too_many_arguments)]
pub async fn serve(
    socket_path: PathBuf,
    db: Arc<dyn Database>,
    signer: Arc<dyn Signer>,
    keypair: Arc<Keypair>,
    tls: TlsMaterial,
    bearer_token: Arc<SecretString>,
    audit_file_path: Option<PathBuf>,
    home: PathBuf,
    config: Config,
) -> Result<()> {
    if let Some(parent) = socket_path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).ok();
    }

    let listener = UnixIpcListener::bind(&socket_path)
        .await
        .with_context(|| format!("bind {}", socket_path.display()))?;
    info!(socket = %socket_path.display(), "listening");

    let self_id = keypair.agent_id();
    let key_ref = KeyRef::from_keypair(&keypair, None);

    // Audit-sink stack. Built in two phases because `RemoteAuditSink`
    // depends on `MessageService` (to ship federation envelopes), and
    // `MessageService` consumes the same audit_sink it sits inside.
    // Phase 1 (here) returns the unified sink + the optional remote
    // handle; Phase 2 (later, post-MessageService::new) wires the
    // message reference into the remote handle via
    // `RemoteAuditSink::set_messages`.
    let crate::bootstrap::audit_sink::AuditSinkBundle {
        sink: audit_sink,
        remote: remote_audit_sink,
    } = crate::bootstrap::audit_sink::build_audit_sink(db.clone(), audit_file_path, &config.audit)?;

    // Parse `[federation] upstream_broker` once. A malformed value
    // is fatal — the operator should know immediately rather than
    // discovering at first send that the broker silently disabled
    // itself.
    let upstream_broker = match config.federation.upstream_broker.as_deref() {
        Some(raw) if !raw.trim().is_empty() => Some(
            UpstreamBroker::from_descriptor(raw.trim()).context("[federation] upstream_broker")?,
        ),
        _ => None,
    };
    if let Some(ub) = &upstream_broker {
        // Persist the broker as a directory entry so federation auth
        // (TOFU + TLS pin + Noise pubkey check) lights up on first
        // dial — same path `peer add` and the static seeder use.
        crate::federation::record_peer(db.as_ref(), ub.endpoint.clone(), ub.pubkey, None, None)
            .await
            .context("[federation] upstream_broker registration")?;
        info!(
            endpoint = %hermod_core::Endpoint::Wss(ub.endpoint.clone()),
            "[federation] upstream_broker registered"
        );
    }

    let router = match &upstream_broker {
        Some(ub) => Router::new(self_id.clone(), db.clone())
            .with_upstream_broker(hermod_core::Endpoint::Wss(ub.endpoint.clone())),
        None => Router::new(self_id.clone(), db.clone()),
    };
    let access = AccessController::new(
        db.clone(),
        self_id.clone(),
        keypair.public_key(),
        AccessPolicy {
            require_capability: config.policy.require_capability,
        },
    );
    let rate_limit = RateLimiter::new(db.clone(), config.policy.rate_limit_per_sender);
    let started = Instant::now();

    let alias = config
        .identity
        .alias
        .as_deref()
        .and_then(|a| a.parse::<hermod_core::AgentAlias>().ok());

    // Federation transport — currently a single `WssNoiseTransport`.
    // Hold it as `Arc<dyn Transport>` so the daemon never references a
    // concrete backend; future `GrpcMtlsTransport` / `QuicTransport`
    // slot in by changing this one constructor call.
    let transport: Arc<dyn hermod_routing::Transport> =
        Arc::new(hermod_routing::WssNoiseTransport::new(
            keypair.clone(),
            alias.clone(),
            tls.cert_pem.clone().into(),
            tls.key_pem.clone().into(),
        ));

    let remote = RemoteDeliverer::new(transport.clone(), db.clone());

    // Start the pool sweeper task — closes idle outbound connections.
    let (pool_shutdown_tx, pool_shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    spawn_sweeper(remote.pool().as_ref().clone(), pool_shutdown_rx);

    // SIGHUP → re-read TLS material from disk and hot-rotate the
    // federation listener without restarting the daemon. Operators
    // run `mv new.crt $HERMOD_HOME/identity/tls.crt && mv new.key
    // $HERMOD_HOME/identity/tls.key && kill -HUP <pid>`. In-flight
    // connections finish on their pinned acceptor; new accepts use
    // the rotated cert. Lives outside `wait_shutdown` so a HUP never
    // shuts the daemon down by accident.
    #[cfg(unix)]
    spawn_tls_reload_task(transport.clone(), home.clone());

    // Auto-discovery: announce this daemon to the configured discovery
    // backend(s) and poll for peers. The daemon depends only on
    // `Arc<dyn Discoverer>` — concrete backends (mDNS, static config,
    // future K8s / Consul / DNS-SD) slot in via `MultiDiscoverer`
    // composition. Discovered peers flow through the same `record_peer`
    // path as operator-issued `peer add`, so TOFU + TLS pinning still
    // apply downstream.
    let discoverer: Option<Arc<dyn hermod_discovery::Discoverer>> = if config.federation.enabled {
        // Trait imported in scope so `s.name()` resolves on every backend
        // type, not just on the trait object.
        use hermod_discovery::Discoverer as _;
        let mut backends: Vec<Arc<dyn hermod_discovery::Discoverer>> = Vec::new();

        // Static config-driven seed. Operators populate
        // `[federation] peers = ["wss://host:port#<pubkey_hex>", ...]`
        // for known long-lived peers — no manual `peer add` per pair.
        if !config.federation.peers.is_empty() {
            match hermod_discovery::StaticDiscoverer::from_strings(&config.federation.peers) {
                Ok(s) => {
                    info!(
                        backend = s.name(),
                        count = config.federation.peers.len(),
                        "static peer seed loaded"
                    );
                    backends.push(Arc::new(s));
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "[federation] peers parse failed; static discovery disabled"
                    );
                }
            }
        }

        // mDNS LAN auto-browser. Opt-in via `[federation] discover_mdns`.
        if config.federation.discover_mdns {
            // Inject an auditor so beacon emit/observe/reject events
            // land in the same hash-chained audit log as every other
            // operator-meaningful action.
            let beacon_auditor: Arc<dyn hermod_discovery::BeaconAuditor> = Arc::new(
                crate::services::AuditSinkBeaconAuditor::new(audit_sink.clone(), self_id.clone()),
            );
            match hermod_discovery::MdnsDiscoverer::start(self_id.to_string(), beacon_auditor) {
                Ok(m) => {
                    info!(backend = "mdns", "mdns browser started");
                    backends.push(Arc::new(m));
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "mdns init failed; continuing without LAN auto-discovery"
                    );
                }
            }
        }

        if backends.is_empty() {
            None
        } else {
            // Wrap multiple backends in `MultiDiscoverer` so the
            // ingestion loop sees one trait object regardless of how
            // many concrete backends the operator enabled.
            let composite: Arc<dyn hermod_discovery::Discoverer> = if backends.len() == 1 {
                backends.pop().expect("len == 1")
            } else {
                Arc::new(hermod_discovery::MultiDiscoverer::new(backends))
            };

            // Announce ourselves on every backend that supports it
            // (mDNS publishes a signed beacon; static is a no-op).
            if let Some(listen_str) = &config.daemon.listen_ws
                && let Ok(addr) = listen_str.parse::<std::net::SocketAddr>()
            {
                let host = format!("{}.local.", &self_id.to_string()[..8]);
                let alias_str = alias.as_ref().map(|a| a.as_str().to_string());
                let params = hermod_discovery::AnnounceParams {
                    hostname: &host,
                    port: addr.port(),
                    signer: signer.clone(),
                    validity_secs: config.federation.mdns_beacon_validity_secs,
                    alias: alias_str.as_deref(),
                };
                if let Err(e) = composite.announce(params).await {
                    tracing::warn!(error = %e, "discoverer announce failed");
                } else {
                    info!(
                        backend = composite.name(),
                        host = %host,
                        port = addr.port(),
                        validity_secs = config.federation.mdns_beacon_validity_secs,
                        "discoverer announced"
                    );
                }
            }

            Some(composite)
        }
    } else {
        None
    };

    let permissions = PermissionService::new(audit_sink.clone(), self_id.clone());
    let observability = crate::services::WorkspaceObservabilityService::new(
        db.clone(),
        audit_sink.clone(),
        self_id.clone(),
    );

    // Build the InboundProcessor in one consume-on-wire chain so
    // `Clone` on a half-wired instance becomes a compile error.
    // Broker role — when `[broker] mode != "disabled"`, this daemon
    // forwards envelopes whose `to.id` is some other peer. The
    // outbound pool (`remote.clone()`) doubles as the broker's
    // forwarding fabric — the same connections used for our own
    // peers also carry relayed traffic. Off by default; opt-in via
    // config.
    let inbound = {
        let base = InboundProcessor::new(
            db.clone(),
            audit_sink.clone(),
            self_id.clone(),
            access.clone(),
            rate_limit.clone(),
            config.policy.replay_window_secs,
            config.policy.held_envelope_max_age_secs,
            config.policy.max_file_payload_bytes as usize,
            config.audit.accept_federation,
        )
        .with_permission_service(permissions.clone())
        .with_workspace_observability(observability.clone());
        if config.broker.mode != hermod_daemon::config::BrokerMode::Disabled {
            info!(mode = ?config.broker.mode, "broker mode active");
            let broker_svc = crate::services::BrokerService::new(
                db.clone(),
                audit_sink.clone(),
                self_id.clone(),
                remote.clone(),
                config.broker.mode,
            );
            base.with_broker_service(broker_svc)
        } else {
            base
        }
    };

    // Inbound network listener is opt-in. The InboundProcessor stays alive
    // either way so ConfirmationService can replay held envelopes on accept.
    if config.federation.enabled {
        if let Some(listen_str) = &config.daemon.listen_ws {
            let addr: std::net::SocketAddr = listen_str.parse()?;
            let server = FederationServer::new(
                transport.clone(),
                inbound.clone(),
                config.policy.max_inflight_handshakes,
            );
            tokio::spawn(async move {
                if let Err(e) = server.run(addr).await {
                    tracing::error!(error = %e, "federation server exited");
                }
            });
        } else {
            info!("federation enabled but daemon.listen_ws is unset — running outbound-only");
        }
    }

    // Periodic discovery ingestion: every 30s, walk the snapshot and
    // upsert any new peers via the same record_peer path that `peer.add`
    // uses. TOFU semantics apply — first-contact pubkeys are pinned.
    if let Some(d) = discoverer.clone() {
        let ingest_db = db.clone();
        tokio::spawn(async move {
            // Closure shared by the immediate first-pass and the periodic
            // tick — ingestion is the same code path either way. Static
            // peers from `[federation] peers = [...]` get persisted within
            // the first second; mDNS late-arrivers reach the directory on
            // the next tick.
            async fn pass(d: &dyn hermod_discovery::Discoverer, db: &dyn hermod_storage::Database) {
                let snap = match d.snapshot().await {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!(backend = d.name(), error = %e, "discoverer snapshot failed");
                        return;
                    }
                };
                for peer in snap {
                    let endpoint = match peer.endpoint {
                        hermod_core::Endpoint::Wss(w) => w,
                        _ => continue,
                    };
                    let Some(pubkey) = peer.pubkey else {
                        // Records without a pubkey can't be Noise-authenticated.
                        // Skip silently — there's nothing to do with an endpoint alone.
                        continue;
                    };
                    let peer_asserted = peer.alias.clone();
                    match crate::federation::record_peer(db, endpoint, pubkey, peer_asserted, None)
                        .await
                    {
                        Ok(_) => {}
                        Err(e) => {
                            tracing::warn!(backend = d.name(), error = %e, "discoverer peer ingest failed");
                        }
                    }
                }
            }

            // Initial pass — picks up the static seed without waiting
            // 30 s. mDNS may have nothing yet on this first call;
            // subsequent ticks fill it in.
            pass(&*d, &*ingest_db).await;

            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(30));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            ticker.tick().await; // skip the immediate first tick (we already ran one pass)
            loop {
                ticker.tick().await;
                pass(&*d, &*ingest_db).await;
            }
        });
    }

    // Outbox retry worker (always on — harmless if no remote messages exist).
    // The notifier is shared with MessageService so successful enqueues of
    // Pending envelopes wake the worker immediately.
    let outbox_notifier = crate::outbox::OutboxNotifier::new();
    let (outbox_shutdown_tx, outbox_shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let outbox_db = db.clone();
    let outbox_audit = audit_sink.clone();
    let outbox_remote = remote.clone();
    let outbox_notifier_for_worker = outbox_notifier.clone();
    tokio::spawn(async move {
        OutboxWorker::new(
            outbox_db,
            outbox_audit,
            outbox_remote,
            outbox_notifier_for_worker,
        )
        .run(outbox_shutdown_rx)
        .await;
    });

    let (janitor_shutdown_tx, janitor_shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    // Optional plaintext HTTP listener for /healthz + /readyz + /metrics. Bound only
    // when an operator opts in via [daemon] metrics_listen — never on by
    // default since the daemon's only public-facing port is the federation
    // listener.
    if let Some(addr_str) = &config.daemon.metrics_listen {
        match addr_str.parse::<std::net::SocketAddr>() {
            Ok(addr) => {
                let metrics_db = db.clone();
                tokio::spawn(async move {
                    if let Err(e) = crate::observability::serve(
                        addr,
                        metrics_db,
                        started,
                        env!("CARGO_PKG_VERSION"),
                    )
                    .await
                    {
                        tracing::error!(error = %e, "metrics listener exited");
                    }
                });
            }
            Err(e) => {
                tracing::warn!(addr = %addr_str, error = %e, "invalid metrics_listen");
            }
        }
    }

    let messages = MessageService::new(
        db.clone(),
        audit_sink.clone(),
        router.clone(),
        access.clone(),
        rate_limit.clone(),
        signer.clone(),
        remote.clone(),
        outbox_notifier.clone(),
    );

    // Phase 2 of audit-sink wiring: now that MessageService exists,
    // hand it to the RemoteAuditSink so it can ship federation
    // envelopes. See the two-phase comment by the audit_sink
    // construction above.
    if let Some(rs) = &remote_audit_sink {
        rs.set_messages(messages.clone());
    }
    observability.set_messages(messages.clone());

    // Wire the federated-relay responder: PermissionService asks
    // MessageService to ship a `PermissionResponse` envelope back to
    // Permission relay backed by `MessageService`. Production trait
    // impls live in `services::permission_relay`; tests substitute
    // in-memory stand-ins that record verdicts without touching the
    // wire stack.
    permissions.set_relay_responder(std::sync::Arc::new(
        crate::services::MessageRelayResponder::new(db.clone(), messages.clone()),
    ));
    permissions.set_prompt_forwarder(std::sync::Arc::new(
        crate::services::CapabilityPromptForwarder::new(
            db.clone(),
            messages.clone(),
            self_id.clone(),
        ),
    ));

    let presence = PresenceService::new(
        db.clone(),
        audit_sink.clone(),
        self_id.clone(),
        messages.clone(),
    );
    let capabilities = CapabilityService::new(db.clone(), audit_sink.clone(), signer.clone());
    capabilities.set_message_service(messages.clone());
    let dispatcher = Dispatcher {
        status: StatusService::new(db.clone(), key_ref, started),
        messages: messages.clone(),
        agents: AgentService::new(db.clone(), audit_sink.clone(), presence.clone()),
        briefs: BriefService::new(
            db.clone(),
            audit_sink.clone(),
            self_id.clone(),
            messages.clone(),
        ),
        presence: presence.clone(),
        mcp: McpService::new(
            db.clone(),
            audit_sink.clone(),
            self_id.clone(),
            presence.clone(),
        ),
        workspaces: WorkspaceService::new(
            db.clone(),
            audit_sink.clone(),
            self_id.clone(),
            keypair.to_pubkey_bytes(),
            messages.clone(),
        ),
        workspace_observability: observability,
        channels: ChannelService::new(
            db.clone(),
            audit_sink.clone(),
            self_id.clone(),
            messages.clone(),
        ),
        broadcasts: BroadcastService::new(
            db.clone(),
            audit_sink.clone(),
            self_id.clone(),
            messages,
        ),
        confirmations: ConfirmationService::new(
            db.clone(),
            audit_sink.clone(),
            self_id.clone(),
            inbound.clone(),
        ),
        peers: PeerService::new(
            db.clone(),
            audit_sink.clone(),
            self_id.clone(),
            presence.clone(),
            remote.pool(),
        ),
        permissions,
        audit: AuditService::new(db.clone(), config.policy.audit_retention_secs),
        capabilities,
    };

    // Janitor: periodic cleanup of expired briefs / stale confirmations /
    // unrefreshed discoveries / dead MCP sessions. Wired with PresenceService
    // so a session-decay transition (last attached Claude Code session goes
    // away without clean detach) fires a federation broadcast.
    let janitor_config = crate::janitor::JanitorConfig {
        sweep_interval: std::time::Duration::from_secs(5 * 60),
        confirmation_retention: (config.policy.confirmation_retention_secs > 0)
            .then(|| std::time::Duration::from_secs(config.policy.confirmation_retention_secs)),
        discovery_retention: (config.policy.discovery_retention_secs > 0)
            .then(|| std::time::Duration::from_secs(config.policy.discovery_retention_secs)),
        session_ttl: std::time::Duration::from_secs(hermod_storage::SESSION_TTL_SECS),
        message_terminal_retention: (config.policy.message_terminal_retention_secs > 0)
            .then(|| std::time::Duration::from_secs(config.policy.message_terminal_retention_secs)),
        rate_bucket_idle_retention: Some(std::time::Duration::from_secs(24 * 3600)),
        rate_bucket_capacity: config.policy.rate_limit_per_sender,
        audit_retention: (config.policy.audit_retention_secs > 0)
            .then(|| std::time::Duration::from_secs(config.policy.audit_retention_secs)),
    };
    let janitor = crate::janitor::JanitorWorker::new(
        db.clone(),
        audit_sink.clone(),
        self_id.clone(),
        janitor_config,
    )
    .with_presence(presence.clone());
    tokio::spawn(async move {
        janitor.run(janitor_shutdown_rx).await;
    });

    // Optional remote IPC over WebSocket+Bearer. Lets `hermod --remote …`
    // and `hermod mcp --remote …` connect to this daemon over the network
    // with the same JSON-RPC surface the local Unix socket serves. Two
    // mutually-exclusive flavours (config layer enforces exclusivity):
    //   * `ipc_listen_wss` — TLS terminated at the daemon, reuses the
    //     daemon's TLS material. Federation + LAN deployments.
    //   * `ipc_listen_ws`  — plaintext, expects an upstream reverse
    //     proxy (Cloud Run, IAP, oauth2-proxy, …) to terminate TLS.
    if let Some(addr_str) = &config.daemon.ipc_listen_wss {
        match addr_str.parse::<std::net::SocketAddr>() {
            Ok(addr) => {
                let dispatcher_for_ipc = dispatcher.clone();
                let tls_for_ipc = tls.clone();
                let token = bearer_token.clone();
                tokio::spawn(async move {
                    if let Err(e) =
                        crate::ipc_remote::serve_wss(addr, tls_for_ipc, token, dispatcher_for_ipc)
                            .await
                    {
                        tracing::error!(error = %e, "remote IPC (WSS) listener exited");
                    }
                });
            }
            Err(e) => {
                tracing::warn!(addr = %addr_str, error = %e, "invalid ipc_listen_wss");
            }
        }
    } else if let Some(addr_str) = &config.daemon.ipc_listen_ws {
        match addr_str.parse::<std::net::SocketAddr>() {
            Ok(addr) => {
                let dispatcher_for_ipc = dispatcher.clone();
                let token = bearer_token.clone();
                tokio::spawn(async move {
                    if let Err(e) =
                        crate::ipc_remote::serve_ws(addr, token, dispatcher_for_ipc).await
                    {
                        tracing::error!(error = %e, "remote IPC (WS) listener exited");
                    }
                });
            }
            Err(e) => {
                tracing::warn!(addr = %addr_str, error = %e, "invalid ipc_listen_ws");
            }
        }
    }

    // Accept loop until SIGINT or SIGTERM.
    loop {
        tokio::select! {
            biased;
            reason = wait_shutdown() => {
                info!(reason = %reason, "shutting down");
                break;
            }
            accept = listener.accept() => {
                match accept {
                    Ok(stream) => {
                        let dispatcher = dispatcher.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(stream, dispatcher).await {
                                error!(error = %e, "connection terminated with error");
                            }
                        });
                    }
                    Err(e) => {
                        error!(error = %e, "accept failed");
                        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    }
                }
            }
        }
    }

    shutdown_sequence(
        listener,
        discoverer,
        outbox_shutdown_tx,
        janitor_shutdown_tx,
        pool_shutdown_tx,
        remote,
        db,
        config.daemon.shutdown_grace_secs,
    )
    .await;
    Ok(())
}

/// Run the shutdown checklist with bounded waits. Order matters:
///   1. Drop the listener so no new IPC connections accept.
///   2. Discoverer deregister so peers stop hitting us during drain.
///   3. Signal each worker to stop. Workers were spawned with shutdown
///      receivers; sending closes the recv side and the worker drains
///      its in-flight batch on the next loop iteration.
///   4. Close the outbound peer pool — abandons in-flight envelopes
///      that can be retried after restart.
///   5. Close the storage backend (SQLite WAL flush, etc.).
///
/// Steps 3-5 together are bounded by `grace_secs` so a stuck worker
/// can't block the daemon from exiting forever.
#[allow(clippy::too_many_arguments)]
async fn shutdown_sequence(
    listener: UnixIpcListener,
    discoverer: Option<Arc<dyn hermod_discovery::Discoverer>>,
    outbox_shutdown_tx: tokio::sync::oneshot::Sender<()>,
    janitor_shutdown_tx: tokio::sync::oneshot::Sender<()>,
    pool_shutdown_tx: tokio::sync::oneshot::Sender<()>,
    remote: hermod_routing::RemoteDeliverer,
    db: Arc<dyn Database>,
    grace_secs: u64,
) {
    drop(listener);
    if let Some(d) = discoverer {
        d.shutdown().await;
    }
    let _ = outbox_shutdown_tx.send(());
    let _ = janitor_shutdown_tx.send(());
    let _ = pool_shutdown_tx.send(());

    let drain = async {
        remote.pool().close_all().await;
        db.shutdown().await;
    };
    let grace = std::time::Duration::from_secs(grace_secs);
    if tokio::time::timeout(grace, drain).await.is_err() {
        tracing::warn!(secs = grace_secs, "shutdown drain timed out");
    }
}

async fn handle_connection(
    stream: hermod_transport::UnixIpcStream,
    dispatcher: Dispatcher,
) -> Result<()> {
    let mut server = IpcServer::new(stream);
    while let Some(req) = server.next_request().await? {
        let resp = dispatcher.handle(req).await;
        server.send_response(resp).await?;
    }
    Ok(())
}

/// Resolve when either SIGINT or SIGTERM arrives, returning a static label
/// describing which signal triggered the shutdown.
#[cfg(unix)]
async fn wait_shutdown() -> &'static str {
    let mut term = match signal::unix::signal(signal::unix::SignalKind::terminate()) {
        Ok(s) => s,
        Err(_) => return "ctrl_c",
    };
    tokio::select! {
        _ = signal::ctrl_c() => "SIGINT",
        _ = term.recv() => "SIGTERM",
    }
}

#[cfg(not(unix))]
async fn wait_shutdown() -> &'static str {
    let _ = signal::ctrl_c().await;
    "ctrl_c"
}

/// Parsed `[federation] upstream_broker = "wss://host:port#<pubkey_hex>"`
/// descriptor. Both fields are required — without the pubkey, the
/// daemon couldn't TOFU-pin or Noise-authenticate the broker, and
/// silently downgrading to "any peer claiming to be the broker" would
/// be a security regression. Misconfiguration is a fatal startup
/// error: a single-value config has no partial-failure semantics, so
/// silently disabling on parse error would let a typo slip past the
/// operator.
#[derive(Clone, Debug)]
struct UpstreamBroker {
    endpoint: hermod_core::WssEndpoint,
    pubkey: hermod_core::PubkeyBytes,
}

impl UpstreamBroker {
    fn from_descriptor(raw: &str) -> Result<Self> {
        let (endpoint_str, pubkey_hex) = raw.split_once('#').ok_or_else(|| {
            anyhow::anyhow!("missing `#<pubkey_hex>` (expected `wss://host:port#<hex>`)")
        })?;
        let endpoint = match hermod_core::Endpoint::from_str(endpoint_str)
            .with_context(|| format!("endpoint {endpoint_str:?}"))?
        {
            hermod_core::Endpoint::Wss(w) => w,
            other => anyhow::bail!("must be wss://, got {other}"),
        };
        let bytes =
            hex::decode(pubkey_hex).with_context(|| format!("pubkey hex {pubkey_hex:?}"))?;
        if bytes.len() != hermod_core::PubkeyBytes::LEN {
            anyhow::bail!(
                "pubkey must be {} bytes, got {}",
                hermod_core::PubkeyBytes::LEN,
                bytes.len()
            );
        }
        let mut arr = [0u8; hermod_core::PubkeyBytes::LEN];
        arr.copy_from_slice(&bytes);
        Ok(Self {
            endpoint,
            pubkey: hermod_core::PubkeyBytes(arr),
        })
    }
}

/// Spawn a long-lived task that re-reads `$HERMOD_HOME/identity/tls.{crt,key}`
/// on every SIGHUP and asks the federation transport to hot-rotate
/// its acceptor. Failures (parse error, IO error, transport rejected
/// the new material) log a `warn` and leave the previous cert in
/// place — partial state would be worse than the operator getting a
/// clear error to react to.
///
/// Lives in its own task so a SIGHUP never blocks the accept loop and
/// a slow disk read never delays an in-flight rotation. Terminates
/// when the daemon's main task exits (the spawned task is detached;
/// the runtime drops it on shutdown).
#[cfg(unix)]
fn spawn_tls_reload_task(transport: Arc<dyn hermod_routing::Transport>, home: PathBuf) {
    tokio::spawn(async move {
        let mut hup = match signal::unix::signal(signal::unix::SignalKind::hangup()) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "SIGHUP listener init failed; TLS hot-rotate disabled");
                return;
            }
        };
        let cert_path = crate::identity::tls_cert_path(&home);
        let key_path = crate::identity::tls_key_path(&home);
        info!(
            cert = %cert_path.display(),
            key  = %key_path.display(),
            "TLS hot-rotate listener installed (SIGHUP to reload)"
        );
        while hup.recv().await.is_some() {
            let cert_pem = match std::fs::read_to_string(&cert_path) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(
                        path = %cert_path.display(),
                        error = %e,
                        "TLS hot-rotate: read cert failed (keeping previous)"
                    );
                    continue;
                }
            };
            let key_pem = match std::fs::read_to_string(&key_path) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(
                        path = %key_path.display(),
                        error = %e,
                        "TLS hot-rotate: read key failed (keeping previous)"
                    );
                    continue;
                }
            };
            match transport.reload_tls(&cert_pem, &key_pem).await {
                Ok(()) => info!(
                    backend = transport.name(),
                    "TLS hot-rotate: federation listener swapped"
                ),
                Err(e) => tracing::warn!(
                    backend = transport.name(),
                    error = %e,
                    "TLS hot-rotate failed (keeping previous material)"
                ),
            }
        }
    });
}

#[cfg(test)]
mod upstream_broker_tests {
    use super::UpstreamBroker;

    #[test]
    fn parses_canonical_descriptor() {
        let pk_hex = "00".repeat(32);
        let raw = format!("wss://broker.example:7823#{pk_hex}");
        let ub = UpstreamBroker::from_descriptor(&raw).unwrap();
        assert_eq!(ub.endpoint.host, "broker.example");
        assert_eq!(ub.endpoint.port, 7823);
        assert_eq!(ub.pubkey.0, [0u8; 32]);
    }

    #[test]
    fn rejects_missing_hash_separator() {
        let err = UpstreamBroker::from_descriptor("wss://broker:7823").unwrap_err();
        assert!(format!("{err:#}").contains("missing `#<pubkey_hex>`"));
    }

    #[test]
    fn rejects_non_wss_scheme() {
        let pk_hex = "00".repeat(32);
        let raw = format!("unix:///tmp/sock#{pk_hex}");
        let err = UpstreamBroker::from_descriptor(&raw).unwrap_err();
        assert!(format!("{err:#}").contains("must be wss://"));
    }

    #[test]
    fn rejects_short_pubkey() {
        let err = UpstreamBroker::from_descriptor("wss://broker:7823#deadbeef").unwrap_err();
        assert!(format!("{err:#}").contains("pubkey must be 32 bytes"));
    }

    #[test]
    fn rejects_non_hex_pubkey() {
        let raw = "wss://broker:7823#zzzznothex";
        let err = UpstreamBroker::from_descriptor(raw).unwrap_err();
        assert!(format!("{err:#}").contains("pubkey hex"));
    }
}
