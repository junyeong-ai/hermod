//! Optional HTTP listener for `/healthz` (liveness probe) and `/metrics`
//! (Prometheus text format).
//!
//! The endpoint is intentionally opt-in via `[daemon] metrics_listen`, since
//! the federation port is the only public-facing one — the metrics surface
//! is for the operator's own monitoring stack, typically bound to localhost
//! or a private network interface.
//!
//! Hand-rolled HTTP/1.1 instead of pulling in hyper: this is a single-method,
//! two-route surface and the runtime cost of a dedicated dependency for it
//! would dwarf the actual code.

use hermod_core::Timestamp;
use hermod_storage::{Database, SESSION_TTL_SECS};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

const READ_BUF: usize = 2048;

pub async fn serve(
    addr: SocketAddr,
    db: Arc<dyn Database>,
    started: Instant,
    version: &'static str,
) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!(addr = %listener.local_addr()?, "metrics listener up");
    loop {
        let (sock, peer) = match listener.accept().await {
            Ok(p) => p,
            Err(e) => {
                warn!(error = %e, "metrics accept failed");
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                continue;
            }
        };
        let db = db.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(sock, db, started, version).await {
                debug!(peer = %peer, error = %e, "metrics connection ended");
            }
        });
    }
}

async fn handle(
    mut sock: TcpStream,
    db: Arc<dyn Database>,
    started: Instant,
    version: &'static str,
) -> anyhow::Result<()> {
    let mut buf = vec![0u8; READ_BUF];
    let n = sock.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }
    let head = std::str::from_utf8(&buf[..n]).unwrap_or("");
    let path = parse_request_path(head);

    let response = match path {
        Some("/healthz") => match db.ping().await {
            Ok(()) => format_response(200, "text/plain; charset=utf-8", "ok\n"),
            Err(reason) => {
                let body = format!("unhealthy: {reason}\n");
                format_response(503, "text/plain; charset=utf-8", &body)
            }
        },
        Some("/metrics") => {
            let body = render_metrics(&*db, started, version).await;
            format_response(200, "text/plain; version=0.0.4; charset=utf-8", &body)
        }
        _ => format_response(404, "text/plain; charset=utf-8", "not found\n"),
    };
    sock.write_all(response.as_bytes()).await?;
    sock.shutdown().await.ok();
    Ok(())
}

/// Parse the request line — first whitespace-separated token after `GET `.
fn parse_request_path(req: &str) -> Option<&str> {
    let line = req.lines().next()?;
    let mut parts = line.split_ascii_whitespace();
    let method = parts.next()?;
    if method != "GET" {
        return None;
    }
    parts.next()
}

fn format_response(status: u16, content_type: &str, body: &str) -> String {
    let phrase = match status {
        200 => "OK",
        404 => "Not Found",
        503 => "Service Unavailable",
        _ => "OK",
    };
    format!(
        "HTTP/1.1 {status} {phrase}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        len = body.len()
    )
}

async fn render_metrics(db: &dyn Database, started: Instant, version: &'static str) -> String {
    let uptime_s = started.elapsed().as_secs_f64();
    let now_ms = Timestamp::now().unix_ms();

    // Best-effort: a snapshot failure surfaces as `metric_query_errors` ticking
    // and the gauges going to NaN, which Prometheus tolerates. Distinguishes
    // "scrape errored" from "value is genuinely zero".
    let mut metric_errors = 0u64;
    let snapshot = match db.metrics_snapshot(now_ms).await {
        Ok(s) => Some(s),
        Err(_) => {
            metric_errors = metric_errors.saturating_add(1);
            None
        }
    };
    let mcp_sessions_attached = match db
        .mcp_sessions()
        .count_live(Timestamp::now(), (SESSION_TTL_SECS * 1_000) as i64)
        .await
    {
        Ok(n) => Some(n as i64),
        Err(_) => {
            metric_errors = metric_errors.saturating_add(1);
            None
        }
    };

    let mut out = String::with_capacity(2048);
    out.push_str("# HELP hermod_build_info Daemon build info; constant 1.\n");
    out.push_str("# TYPE hermod_build_info gauge\n");
    out.push_str(&format!("hermod_build_info{{version=\"{version}\"}} 1\n"));

    out.push_str("# HELP hermod_uptime_seconds Time since daemon start.\n");
    out.push_str("# TYPE hermod_uptime_seconds gauge\n");
    out.push_str(&format!("hermod_uptime_seconds {uptime_s}\n"));

    push_gauge(
        &mut out,
        "hermod_messages_pending",
        "Direct messages awaiting delivery.",
        snapshot.as_ref().map(|s| s.messages_pending),
    );
    push_gauge(
        &mut out,
        "hermod_messages_failed",
        "Direct messages that exhausted retries — actionable; investigate peer reachability.",
        snapshot.as_ref().map(|s| s.messages_failed),
    );
    push_gauge(
        &mut out,
        "hermod_peers_total",
        "Known federation peers (agents with WSS endpoint).",
        snapshot.as_ref().map(|s| s.peers_total),
    );
    push_gauge(
        &mut out,
        "hermod_workspaces_total",
        "Workspaces this daemon belongs to.",
        snapshot.as_ref().map(|s| s.workspaces_total),
    );
    push_gauge(
        &mut out,
        "hermod_channels_total",
        "Channels across all workspaces.",
        snapshot.as_ref().map(|s| s.channels_total),
    );
    push_gauge(
        &mut out,
        "hermod_confirmations_pending",
        "Inbound actions held for operator confirmation.",
        snapshot.as_ref().map(|s| s.confirmations_pending),
    );
    push_gauge(
        &mut out,
        "hermod_audit_rows_total",
        "Total audit-log rows. Monotonic; operators rotate the DB to reset.",
        snapshot.as_ref().map(|s| s.audit_rows_total),
    );
    push_gauge(
        &mut out,
        "hermod_discovered_channels_total",
        "Channels learned via ChannelAdvertise.",
        snapshot.as_ref().map(|s| s.discovered_channels_total),
    );
    push_gauge(
        &mut out,
        "hermod_mcp_sessions_attached",
        "MCP stdio sessions currently attached and heartbeating. Self is `live` iff this is positive.",
        mcp_sessions_attached,
    );
    push_gauge(
        &mut out,
        "hermod_rate_buckets_total",
        "Token-bucket rows in storage. Janitor sweeps idle full buckets — sustained growth means a flapping (sender,recipient) pair churning new keys.",
        snapshot.as_ref().map(|s| s.rate_buckets_total),
    );
    push_gauge(
        &mut out,
        "hermod_capabilities_active",
        "Capability rows that are unrevoked and unexpired — i.e. presently authoritative.",
        snapshot.as_ref().map(|s| s.capabilities_active),
    );

    out.push_str("# HELP hermod_metric_query_errors_total Best-effort failure counter for the metric collection itself. Distinguishes \"scrape returned nothing\" from \"a gauge could not be computed\".\n");
    out.push_str("# TYPE hermod_metric_query_errors_total counter\n");
    out.push_str(&format!(
        "hermod_metric_query_errors_total {metric_errors}\n"
    ));

    out
}

fn push_gauge(out: &mut String, name: &str, help: &str, value: Option<i64>) {
    out.push_str(&format!("# HELP {name} {help}\n"));
    out.push_str(&format!("# TYPE {name} gauge\n"));
    match value {
        Some(v) => out.push_str(&format!("{name} {v}\n")),
        None => out.push_str(&format!("{name} NaN\n")),
    }
}
