use anyhow::{Context, Result};
use hermod_daemon::config::Config;
use hermod_daemon::home_layout::{HomeFileKind, LayoutError, Presence};
use hermod_daemon::paths;
use std::path::Path;

use crate::client::ClientTarget;

/// Soft cap on the held-confirmation queue. Beyond this we surface a
/// FAIL — operator inbox is being flooded and probably needs a peer
/// trust adjustment.
const SOFT_LIMIT_CONFIRMATIONS: u32 = 100;

/// Schema version the binary expects to find in `schema_meta`. Bump
/// this in lockstep with each migration that changes the live shape.
const EXPECTED_SCHEMA_VERSION: &str = "1";

pub async fn run(home: &Path, target: &ClientTarget) -> Result<()> {
    let mut report = Report::new();
    let cfg_path = home.join("config.toml");

    report.check("$HERMOD_HOME exists and is readable", home.is_dir(), || {
        format!("create it: mkdir -p {} && hermod init", home.display())
    });

    report.check("config.toml present", cfg_path.exists(), || {
        "run `hermod init` to write a default config".into()
    });

    // $HERMOD_HOME mode audit driven by the daemon's single-source-of-truth
    // `home_layout::spec`. Adding a new file there (or in the storage
    // layer's `database_local_files` / `blob_store_local_files`)
    // automatically adds a row here — boot enforcement, doctor output,
    // and chmod hints stay in sync via one declarative list.
    //
    // Audit is backend-aware on both axes: a Postgres-backed daemon
    // has no local database file; a cloud-blob daemon has no local
    // blob root. Resolve the same DSNs the daemon will see at boot.
    let config = Config::load(None, home).context("load config")?;
    let storage_dsn = paths::expand_dsn(&config.storage.dsn, home);
    let blob_dsn = paths::expand_dsn(&config.blob.dsn, home);
    let local_agent_ids: Vec<hermod_core::AgentId> =
        match hermod_daemon::local_agent::scan_disk_ids(home) {
            Ok(ids) => ids,
            Err(e) => {
                report.note(&format!(
                    "could not enumerate $HERMOD_HOME/agents/: {e:#} — \
                     per-agent layout audit skipped"
                ));
                Vec::new()
            }
        };
    for (file, finding) in
        hermod_daemon::home_layout::audit(home, &storage_dsn, &blob_dsn, &local_agent_ids)
    {
        match finding {
            Ok(()) => report.pass(&format!("{} ({:o})", file.label, file.required_mode)),
            Err(LayoutError::Missing { .. }) if file.presence == Presence::Optional => {
                // Optional files (hermod.db-wal/-shm, archive/,
                // blob-store/) are absent in normal pre-write states.
                // Skip silently — first write creates them under the
                // canonical mode (umask 0o077).
            }
            Err(LayoutError::Missing { .. }) => match file.kind {
                HomeFileKind::Secret | HomeFileKind::Directory => {
                    report.fail(&file.label, "run `hermod init` to generate it".into())
                }
                HomeFileKind::Public | HomeFileKind::OperatorManaged => {
                    // Public + operator-managed missing is non-fatal;
                    // surface as a note for visibility.
                    report.note(&format!("{} not present", file.label));
                }
            },
            Err(e) => match file.kind {
                HomeFileKind::Public | HomeFileKind::OperatorManaged => {
                    report.note(&format!("{} ({})", file.label, e))
                }
                HomeFileKind::Secret | HomeFileKind::Directory => {
                    report.fail(&file.label, e.to_string())
                }
            },
        }
    }

    let host_loaded = hermod_daemon::host_identity::load(home).is_ok();
    report.check("host identity loadable", host_loaded, || {
        "regenerate via `hermod init` (move existing $HERMOD_HOME first)".into()
    });

    let local_agent_count = local_agent_ids.len();
    report.check(
        "at least one local agent provisioned",
        local_agent_count > 0,
        || "run `hermod init` to provision the bootstrap local agent".into(),
    );

    if host_loaded {
        let kp = hermod_daemon::host_identity::load(home)?;
        let tls = hermod_daemon::host_identity::ensure_tls(home, &kp);
        report.check(
            "TLS certificate readable / generatable",
            tls.is_ok(),
            || format!(
                "remove $HERMOD_HOME/host/tls.crt + tls.key and restart so they regenerate (was: {})",
                tls.as_ref().err().map(|e| e.to_string()).unwrap_or_default()
            ),
        );
        // Cert expiry surfacing. The federation listener silently
        // starts rejecting peers once `notAfter` passes — the
        // operator-visible signal is "all peers suddenly fail TLS
        // pin", which is the wrong moment to discover the cause.
        // We warn at <30d, fail at expired so a CI cron of
        // `hermod doctor` catches it weeks before the outage.
        if let Ok(material) = tls.as_ref()
            && let Some(not_after_secs) = material.not_after_unix_secs()
        {
            let now_secs = hermod_core::Timestamp::now().unix_ms() / 1000;
            let remaining_secs = not_after_secs - now_secs;
            const DAY: i64 = 24 * 3600;
            if remaining_secs <= 0 {
                report.fail(
                    "TLS certificate validity",
                    format!(
                        "cert expired {} day(s) ago — rotate via the SIGHUP \
                         hot-reload path (see DEPLOY.md §4.3) or remove tls.crt/tls.key \
                         and restart so they regenerate",
                        remaining_secs.abs() / DAY
                    ),
                );
            } else if remaining_secs < 30 * DAY {
                report.note(&format!(
                    "TLS certificate expires in {} day(s) — rotate before \
                     federation peers start failing TLS-pin verification",
                    remaining_secs / DAY
                ));
            } else {
                report.pass(&format!(
                    "TLS certificate valid for {} more day(s)",
                    remaining_secs / DAY
                ));
            }
        }
    }

    // Daemon reachability and audit chain.
    let label = match target {
        ClientTarget::Local(_) => "daemon reachable on Unix socket",
        ClientTarget::Remote { .. } => "remote daemon reachable (WSS+Bearer)",
    };
    let mut client = match target.connect().await {
        Ok(c) => {
            report.pass(label);
            Some(c)
        }
        Err(e) => {
            report.fail(
                label,
                format!("start the daemon (`hermodd` or systemctl --user start hermod): {e}"),
            );
            None
        }
    };

    if let Some(c) = client.as_mut() {
        match c.status().await {
            Ok(s) => {
                report.pass(&format!(
                    "daemon status: agent_id={}, peers={}, pending={}, uptime={}s",
                    s.agent_id, s.peer_count, s.pending_messages, s.uptime_secs
                ));
                if s.schema_version == EXPECTED_SCHEMA_VERSION {
                    report.pass(&format!("schema version {}", s.schema_version));
                } else {
                    report.fail(
                        "schema version",
                        format!(
                            "binary expects v{EXPECTED_SCHEMA_VERSION}, database is v{} — \
                             run the matching migration or roll back the binary",
                            s.schema_version
                        ),
                    );
                }
            }
            Err(e) => report.fail("daemon status RPC", format!("{e}")),
        }

        match c.audit_verify().await {
            Ok(v) => match v {
                hermod_protocol::ipc::methods::AuditVerifyResult::Ok { rows } => {
                    report.pass(&format!("audit chain intact ({rows} rows)"));
                }
                other => report.fail(
                    "audit chain integrity",
                    format!(
                        "verifier reported {other:?} — investigate via `hermod audit query`; \
                         if corruption is real, archive then rotate the database"
                    ),
                ),
            },
            Err(e) => report.fail("audit chain integrity", format!("{e}")),
        }

        match c.peer_list().await {
            Ok(r) => {
                if r.peers.is_empty() {
                    report.note("no federation peers registered (federation features disabled)");
                } else {
                    report.note(&format!("{} federation peer(s) known", r.peers.len()));
                }
            }
            Err(e) => report.fail("peer.list RPC", format!("{e}")),
        }

        match c
            .confirmation_list(hermod_protocol::ipc::methods::ConfirmationListParams {
                limit: Some(SOFT_LIMIT_CONFIRMATIONS),
                after_id: None,
            })
            .await
        {
            Ok(r) if r.confirmations.len() as u32 >= SOFT_LIMIT_CONFIRMATIONS => report.fail(
                "confirmation queue depth",
                format!(
                    "{}+ held — review with `hermod confirm list`. Sustained \
                     growth means a peer is hammering you; consider \
                     `peer trust untrusted` or `peer remove`",
                    r.confirmations.len()
                ),
            ),
            Ok(r) if !r.confirmations.is_empty() => report.note(&format!(
                "{} held confirmation(s) — `hermod confirm list`",
                r.confirmations.len()
            )),
            Ok(_) => {}
            Err(e) => report.fail("confirmation.list RPC", format!("{e}")),
        }

        match c
            .capability_list(hermod_protocol::ipc::methods::CapabilityListParams {
                include_revoked: false,
                include_expired: false,
                limit: Some(1),
                after_id: None,
                direction: None,
            })
            .await
        {
            Ok(r) => {
                if !r.capabilities.is_empty() {
                    report.note("active capability tokens present (use `hermod capability list`)");
                }
            }
            Err(e) => report.fail("capability.list RPC", format!("{e}")),
        }

        // Per-agent block. The daemon-level `status` row above
        // reports counts for the unix-socket caller (the bootstrap
        // agent in single-tenant; unset in multi-tenant). For each
        // additional locally-hosted agent, surface its alias +
        // bearer-file path so operators have one place to find
        // "which agent maps to which project". `local.list` enumerates
        // them via the live registry — no disk re-walk.
        match c.local_list().await {
            Ok(r) if r.agents.is_empty() => {
                report.fail(
                    "local agents",
                    "registry is empty after boot — run `hermod init` to provision a bootstrap"
                        .into(),
                );
            }
            Ok(r) => {
                report.pass(&format!("local agents: {} hosted", r.agents.len()));
                for a in &r.agents {
                    let alias_str = a
                        .alias
                        .as_ref()
                        .map(|al| format!(" alias=@{}", al.as_str()))
                        .unwrap_or_default();
                    report.note(&format!(
                        "  {}{alias_str} bearer={}",
                        a.agent_id, a.bearer_file
                    ));
                }
            }
            Err(e) => report.fail("local.list RPC", format!("{e}")),
        }
    }

    // Claude Code channels integration probe. We can't directly observe
    // whether Claude Code is running with --dangerously-load-development-channels,
    // but we can verify the MCP server is registered.
    match std::process::Command::new("claude")
        .args(["mcp", "list"])
        .output()
    {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            if stdout.contains("hermod:") {
                report.note(
                    "Claude Code MCP integration: hermod registered. \
                     Launch with `claude --dangerously-load-development-channels server:hermod` \
                     for inbox notifications.",
                );
            } else {
                report.note(
                    "Claude Code MCP integration: hermod NOT registered. \
                     Run `claude mcp add hermod hermod mcp --scope user`.",
                );
            }
        }
        Err(_) => {
            report.note(
                "`claude` CLI not on PATH — Claude Code integration check skipped. \
                 If you use Claude Code, register the MCP server with \
                 `claude mcp add hermod hermod mcp --scope user`.",
            );
        }
    }

    report.print();
    if report.failed > 0 {
        std::process::exit(1);
    }
    Ok(())
}

struct Report {
    lines: Vec<String>,
    failed: usize,
}

impl Report {
    fn new() -> Self {
        Self {
            lines: Vec::new(),
            failed: 0,
        }
    }
    fn pass(&mut self, label: &str) {
        self.lines.push(format!("  ok    {label}"));
    }
    fn fail(&mut self, label: &str, hint: String) {
        self.lines
            .push(format!("  FAIL  {label}\n        → {hint}"));
        self.failed += 1;
    }
    fn note(&mut self, label: &str) {
        self.lines.push(format!("  note  {label}"));
    }
    fn check(&mut self, label: &str, ok: bool, hint: impl FnOnce() -> String) {
        if ok {
            self.pass(label);
        } else {
            self.fail(label, hint());
        }
    }
    fn print(&self) {
        println!("hermod doctor:");
        for line in &self.lines {
            println!("{line}");
        }
        println!();
        if self.failed == 0 {
            println!("  → all checks passed");
        } else {
            println!("  → {} check(s) failed", self.failed);
        }
    }
}
