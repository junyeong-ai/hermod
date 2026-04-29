//! Accept loop: bind Unix socket, dispatch each connection to the RPC dispatcher.

use anyhow::{Context, Result};
use hermod_crypto::{Keypair, Signer, TlsMaterial};
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
use hermod_daemon::local_agent::LocalAgentRegistry;
use hermod_routing::{AccessPolicy, RemoteDeliverer, spawn_sweeper};
use hermod_storage::AuditSink;

use crate::dispatcher::Dispatcher;
use crate::federation::FederationServer;
use crate::inbound::InboundProcessor;
use crate::outbox::OutboxWorker;
use crate::services::{
    AgentService, AuditService, BriefService, BroadcastService, CapabilityService, ChannelService,
    ConfirmationService, McpService, MessageService, PeerService, PermissionService,
    PresenceService, RemoteAuditSink, StatusService, WorkspaceService,
};

#[allow(clippy::too_many_arguments)]
pub async fn serve(
    socket_path: PathBuf,
    db: Arc<dyn Database>,
    host_signer: Arc<dyn Signer>,
    host_keypair: Arc<Keypair>,
    registry: LocalAgentRegistry,
    tls: TlsMaterial,
    audit_sink: Arc<dyn AuditSink>,
    remote_audit_sink: Option<RemoteAuditSink>,
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

    // Host-level identity used wherever an audit row would otherwise
    // have no caller (background workers, federation accept) — the
    // `audit_or_warn` overlay replaces this with the IPC caller's
    // agent_id when a `CALLER_AGENT` task_local is in scope.
    let host_id = host_keypair.agent_id();
    let host_public_key = host_keypair.public_key();

    // Bearer authentication map for the remote-IPC listeners. Built
    // once from the registry snapshot — a presented bearer's blake3
    // hash resolves to the matching local agent_id (or 401 if no
    // hosted agent owns it). The handshake binds that agent_id as
    // the connection's `CALLER_AGENT` task_local, which audit_or_warn
    // overlays onto every emitted row's `actor` field.
    let bearer_auth = hermod_daemon::local_agent::BearerAuthenticator::from_registry(&registry);

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
        // The broker is identified at the host level: its hosted
        // agents (if any address envelopes through it) get registered
        // separately via inbound TOFU on first envelope.
        crate::federation::record_host_peer(
            db.as_ref(),
            Some(ub.endpoint.clone()),
            ub.pubkey,
            None,
            None,
        )
        .await
        .context("[federation] upstream_broker registration")?;
        info!(
            endpoint = %hermod_core::Endpoint::Wss(ub.endpoint.clone()),
            "[federation] upstream_broker registered"
        );
    }

    let local_ids: Vec<hermod_core::AgentId> =
        registry.list().iter().map(|a| a.agent_id.clone()).collect();
    let local_pubkeys: Vec<(hermod_core::AgentId, hermod_crypto::PublicKey)> = registry
        .list()
        .iter()
        .map(|a| (a.agent_id.clone(), a.keypair.public_key()))
        .collect();
    let router = match &upstream_broker {
        Some(ub) => Router::new(local_ids.clone(), db.clone())
            .with_upstream_broker(hermod_core::Endpoint::Wss(ub.endpoint.clone())),
        None => Router::new(local_ids.clone(), db.clone()),
    };
    let access = AccessController::new(
        db.clone(),
        local_pubkeys,
        AccessPolicy {
            require_capability: config.policy.require_capability,
        },
    );
    let rate_limit = RateLimiter::new(db.clone(), config.policy.rate_limit_per_sender);
    let started = Instant::now();

    // Local Unix-socket IPC binds the lone hosted agent as the
    // connection's caller when there's exactly one (single-tenant
    // convenience for `hermod` operator commands). With N>1 the
    // local socket leaves caller_agent unset and operators reach
    // per-agent methods over remote IPC + bearer instead.
    let local_socket_caller: Option<hermod_core::AgentId> =
        registry.solo().map(|a| a.agent_id.clone());

    // Federation transport — currently a single `WssNoiseTransport`.
    // Hold it as `Arc<dyn Transport>` so the daemon never references a
    // concrete backend; future `GrpcMtlsTransport` / `QuicTransport`
    // slot in by changing this one constructor call. The Noise XX
    // static key is the *host* keypair: federation handshakes
    // authenticate the daemon as a network entity, distinct from any
    // local agent's envelope-signing identity.
    //
    // Outbound TLS pin spec is configurable via `[federation] tls_pin`.
    // Default: `Insecure` (Noise XX already provides cryptographic peer
    // auth). Set to `public-ca` when a hosted broker fronts the
    // daemon, `tofu` for SSH-style first-use pinning, or a 64-char
    // SHA-256 hex for explicit fingerprint pinning.
    let dial_pin =
        parse_federation_pin_spec(&config.federation.tls_pin).context("[federation] tls_pin")?;
    let pin_store = hermod_transport::pin::TlsPinStore::at_home(&home, "federation_pins.json");
    info!(
        spec = parse_federation_pin_label(&dial_pin),
        "federation outbound TLS pin spec",
    );
    let transport: Arc<dyn hermod_routing::Transport> = Arc::new(
        hermod_routing::WssNoiseTransport::new(
            host_keypair.clone(),
            tls.cert_pem.clone().into(),
            tls.key_pem.clone().into(),
            pin_store,
        )
        .with_dial_pin(dial_pin),
    );

    let remote = RemoteDeliverer::new(transport.clone(), db.clone());

    // Start the pool sweeper task — closes idle outbound connections.
    let (pool_shutdown_tx, pool_shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    spawn_sweeper(remote.pool().as_ref().clone(), pool_shutdown_rx);

    // SIGHUP → re-read TLS material from disk and hot-rotate the
    // federation listener without restarting the daemon. Operators
    // run `mv new.crt $HERMOD_HOME/host/tls.crt && mv new.key
    // $HERMOD_HOME/host/tls.key && kill -HUP <pid>`. In-flight
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
            // mDNS speaks at the host level — beacons advertise the
            // daemon's network endpoint, not any one local agent. Audit
            // rows for beacon emit/observe/reject are attributed to the
            // host actor.
            let beacon_auditor: Arc<dyn hermod_discovery::BeaconAuditor> = Arc::new(
                crate::services::AuditSinkBeaconAuditor::new(audit_sink.clone(), host_id.clone()),
            );
            match hermod_discovery::MdnsDiscoverer::start(host_id.to_string(), beacon_auditor) {
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
                let host = format!("{}.local.", &host_id.to_string()[..8]);
                let params = hermod_discovery::AnnounceParams {
                    hostname: &host,
                    port: addr.port(),
                    signer: host_signer.clone(),
                    validity_secs: config.federation.mdns_beacon_validity_secs,
                    alias: None,
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

    let permissions = PermissionService::new(audit_sink.clone(), host_id.clone());
    let observability = crate::services::WorkspaceObservabilityService::new(
        db.clone(),
        audit_sink.clone(),
        host_id.clone(),
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
            host_id.clone(),
            registry.clone(),
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
            // Broker forwards on behalf of the *host* — relay rows are
            // attributed to host_id, not any one local agent.
            let broker_svc = crate::services::BrokerService::new(
                db.clone(),
                audit_sink.clone(),
                host_id.clone(),
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
                    match crate::federation::record_host_peer(
                        db,
                        Some(endpoint),
                        pubkey,
                        peer_asserted,
                        None,
                    )
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
                let metrics_local_agents = registry.len() as u64;
                tokio::spawn(async move {
                    if let Err(e) = crate::observability::serve(
                        addr,
                        metrics_db,
                        started,
                        env!("CARGO_PKG_VERSION"),
                        metrics_local_agents,
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
        registry.clone(),
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
        crate::services::CapabilityPromptForwarder::new(db.clone(), messages.clone()),
    ));

    let presence = PresenceService::new(
        db.clone(),
        audit_sink.clone(),
        host_id.clone(),
        messages.clone(),
    );
    let capabilities = CapabilityService::new(db.clone(), audit_sink.clone(), registry.clone());
    capabilities.set_message_service(messages.clone());
    let dispatcher = Dispatcher {
        status: StatusService::new(db.clone(), registry.clone(), &host_public_key, started),
        messages: messages.clone(),
        agents: AgentService::new(db.clone(), audit_sink.clone(), presence.clone()),
        briefs: BriefService::new(db.clone(), audit_sink.clone(), messages.clone()),
        presence: presence.clone(),
        mcp: McpService::new(
            db.clone(),
            audit_sink.clone(),
            host_id.clone(),
            presence.clone(),
        ),
        workspaces: WorkspaceService::new(
            db.clone(),
            audit_sink.clone(),
            host_id.clone(),
            registry.clone(),
            messages.clone(),
        ),
        workspace_observability: observability,
        channels: ChannelService::new(
            db.clone(),
            audit_sink.clone(),
            host_id.clone(),
            router.clone(),
            messages.clone(),
        ),
        broadcasts: BroadcastService::new(
            db.clone(),
            audit_sink.clone(),
            router.clone(),
            messages.clone(),
        ),
        confirmations: ConfirmationService::new(
            db.clone(),
            audit_sink.clone(),
            host_id.clone(),
            inbound.clone(),
        ),
        peers: PeerService::new(
            db.clone(),
            audit_sink.clone(),
            host_id.clone(),
            presence.clone(),
            remote.pool(),
            registry.clone(),
            host_keypair.to_pubkey_bytes(),
            messages.clone(),
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
    // Janitor sweeps daemon-internal state (outbox claim TTL, audit
    // archive rotation, presence decay) — its `actor` belongs to the
    // host, not any one local agent.
    let janitor = crate::janitor::JanitorWorker::new(
        db.clone(),
        audit_sink.clone(),
        host_id.clone(),
        janitor_config,
    )
    .with_presence(presence.clone(), registry.clone());
    tokio::spawn(async move {
        janitor.run(janitor_shutdown_rx).await;
    });

    // Optional remote IPC over WebSocket+Bearer. Lets `hermod --remote …`
    // and `hermod mcp --remote …` connect to this daemon over the network
    // with the same JSON-RPC surface the local Unix socket serves. Two
    // mutually-exclusive flavours (config layer enforces exclusivity at
    // load time):
    //   * `ipc_listen_wss` — TLS terminated at the daemon, reuses the
    //     daemon's TLS material. Federation + LAN deployments.
    //   * `ipc_listen_ws`  — plaintext, expects an upstream reverse
    //     proxy (Cloud Run, IAP, oauth2-proxy, …) to terminate TLS.
    //
    // Both listeners share the parsed `trusted_proxies` set — any
    // listener that runs behind an L7 reverse proxy benefits from the
    // X-Forwarded-For resolution that recovers the originating client
    // IP. Empty set is a no-op.
    let trusted_proxies =
        std::sync::Arc::new(parse_trusted_proxies(&config.daemon.trusted_proxies));
    if let Some(addr) = parse_listen_addr(&config.daemon.ipc_listen_wss, "ipc_listen_wss") {
        let dispatcher_for_ipc = dispatcher.clone();
        let tls_for_ipc = tls.clone();
        let auth = bearer_auth.clone();
        let trusted = trusted_proxies.clone();
        tokio::spawn(async move {
            if let Err(e) =
                crate::ipc_remote::serve_wss(addr, tls_for_ipc, auth, trusted, dispatcher_for_ipc)
                    .await
            {
                tracing::error!(error = %e, "remote IPC (WSS) listener exited");
            }
        });
    }
    if let Some(addr) = parse_listen_addr(&config.daemon.ipc_listen_ws, "ipc_listen_ws") {
        warn_if_plaintext_exposed(addr);
        let dispatcher_for_ipc = dispatcher.clone();
        let auth = bearer_auth.clone();
        let trusted = trusted_proxies.clone();
        tokio::spawn(async move {
            if let Err(e) =
                crate::ipc_remote::serve_ws(addr, auth, trusted, dispatcher_for_ipc).await
            {
                tracing::error!(error = %e, "remote IPC (WS) listener exited");
            }
        });
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
                        let local_caller = local_socket_caller.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(stream, dispatcher, local_caller).await {
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
    local_caller: Option<hermod_core::AgentId>,
) -> Result<()> {
    // Unix-socket IPC inherits filesystem-permission auth — anyone
    // who can open the socket is already running as the daemon's
    // owning user, so there's no per-connection bearer challenge.
    // When the daemon hosts exactly one local agent we bind it as
    // the connection's `CALLER_AGENT` (single-tenant convenience).
    // With N>1 hosted agents the local socket leaves caller_agent
    // unset — operator IPC methods that don't need a caller still
    // work; per-agent methods (message.send, identity.get, …) must
    // come in over remote IPC where the bearer disambiguates.
    let inner = async {
        let mut server = IpcServer::new(stream);
        while let Some(req) = server.next_request().await? {
            let resp = dispatcher.handle(req).await;
            server.send_response(resp).await?;
        }
        Ok::<_, anyhow::Error>(())
    };
    crate::audit_context::with_caller_agent(local_caller, inner).await
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

/// Spawn a long-lived task that re-reads `$HERMOD_HOME/host/tls.{crt,key}`
/// on every SIGHUP and asks the federation transport to hot-rotate
/// its acceptor. Failures (parse error, IO error, transport rejected
/// the new material) log a `warn` and leave the previous cert in
/// place — partial state would be worse than the operator getting a
/// clear error to react to.
///
/// Lives in its own task so a SIGHUP never blocks the accept loop and
/// Parse an `Option<String>` listen address into a `SocketAddr`,
/// logging at warn-level if the string is present-but-invalid. Returns
/// `None` for both "unset" and "invalid" — the caller treats them
/// identically (don't spawn the listener), but the warn lets the
/// operator see that their config wasn't applied.
fn parse_listen_addr(raw: &Option<String>, label: &str) -> Option<std::net::SocketAddr> {
    let raw = raw.as_ref()?;
    match raw.parse::<std::net::SocketAddr>() {
        Ok(addr) => Some(addr),
        Err(e) => {
            tracing::warn!(addr = %raw, error = %e, "invalid {label}");
            None
        }
    }
}

/// Parse the operator-supplied CIDR strings into the typed
/// representation `client_ip::resolve_client_ip` consumes. Config
/// validation already rejected malformed entries at load time
/// (`Config::validate`), so reaching this with an unparseable string
/// would be a regression in the validation pass — fall back to "drop
/// the bad entry" with a warn rather than panicking, so the daemon
/// keeps running.
fn parse_trusted_proxies(raw: &[String]) -> Vec<ipnet::IpNet> {
    raw.iter()
        .filter_map(|s| match s.parse::<ipnet::IpNet>() {
            Ok(net) => Some(net),
            Err(e) => {
                tracing::warn!(
                    entry = %s,
                    error = %e,
                    "trusted_proxies entry skipped — config.validate should have caught this"
                );
                None
            }
        })
        .collect()
}

/// Plaintext WebSocket exposes the bearer token to anyone on the wire
/// between client and daemon. Operators MAY bind it to a non-loopback
/// interface intentionally (private network, VPN, in-cluster pod IP),
/// but the more common cause of a 0.0.0.0 bind is "forgot to set up
/// the fronting reverse proxy first". Surface a warn so the misuse
/// case is visible without refusing the bind (which would block the
/// intentional case).
fn warn_if_plaintext_exposed(addr: std::net::SocketAddr) {
    if !addr.ip().is_loopback() {
        tracing::warn!(
            addr = %addr,
            "ipc_listen_ws is bound to a non-loopback address — this is \
             plaintext WebSocket. The bearer token rides in the clear unless \
             an upstream TLS-terminating reverse proxy (Cloud Run, IAP, \
             oauth2-proxy, Cloudflare Access, ALB+Cognito, k8s ingress) is in \
             front of this listener. If you intended TLS-at-the-daemon, switch \
             to `ipc_listen_wss` instead."
        );
    }
}

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
        let cert_path = hermod_daemon::host_identity::tls_cert_path(&home);
        let key_path = hermod_daemon::host_identity::tls_key_path(&home);
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

/// Parse the `[federation] tls_pin` config value. `None` (or empty
/// string after trim) defaults to `Insecure` — federation already
/// authenticates peers cryptographically at the Noise XX layer, so
/// the lowest-friction default is "any cert is fine, Noise will
/// catch impersonation". Operators with hosted brokers (Cloud Run /
/// IAP / Cloudflare) opt into `public-ca` for proper LB chain
/// validation.
fn parse_federation_pin_spec(
    raw: &Option<String>,
) -> anyhow::Result<hermod_transport::pin::PinSpec> {
    use std::str::FromStr;
    let trimmed = raw.as_deref().map(str::trim).filter(|s| !s.is_empty());
    match trimmed {
        Some(s) => hermod_transport::pin::PinSpec::from_str(s).map_err(|e| anyhow::anyhow!("{e}")),
        None => Ok(hermod_transport::pin::PinSpec::Insecure),
    }
}

fn parse_federation_pin_label(spec: &hermod_transport::pin::PinSpec) -> &'static str {
    match spec {
        hermod_transport::pin::PinSpec::Tofu => "tofu",
        hermod_transport::pin::PinSpec::PublicCa => "public-ca",
        hermod_transport::pin::PinSpec::Insecure => "insecure",
        hermod_transport::pin::PinSpec::Fingerprint(_) => "fingerprint",
    }
}

#[cfg(test)]
mod federation_pin_tests {
    use super::*;
    use hermod_transport::pin::PinSpec;

    #[test]
    fn unset_defaults_to_insecure() {
        assert_eq!(parse_federation_pin_spec(&None).unwrap(), PinSpec::Insecure);
        assert_eq!(
            parse_federation_pin_spec(&Some("".into())).unwrap(),
            PinSpec::Insecure,
        );
        assert_eq!(
            parse_federation_pin_spec(&Some("   ".into())).unwrap(),
            PinSpec::Insecure,
        );
    }

    #[test]
    fn keywords_parse() {
        assert_eq!(
            parse_federation_pin_spec(&Some("tofu".into())).unwrap(),
            PinSpec::Tofu,
        );
        assert_eq!(
            parse_federation_pin_spec(&Some("public-ca".into())).unwrap(),
            PinSpec::PublicCa,
        );
        assert_eq!(
            parse_federation_pin_spec(&Some("none".into())).unwrap(),
            PinSpec::Insecure,
        );
    }

    #[test]
    fn fingerprint_parses() {
        let fp = "AB".to_string() + &"00".repeat(31);
        match parse_federation_pin_spec(&Some(fp)).unwrap() {
            PinSpec::Fingerprint(s) => assert!(s.starts_with("ab:00:")),
            other => panic!("expected Fingerprint, got {other:?}"),
        }
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_federation_pin_spec(&Some("nonsense".into())).is_err());
    }
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
