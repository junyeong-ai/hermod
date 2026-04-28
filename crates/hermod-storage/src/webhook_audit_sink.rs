//! HTTP-push audit sink.
//!
//! POSTs every audit row as a single JSON object to a configurable
//! webhook URL. Composes alongside [`StorageAuditSink`] /
//! [`FileAuditSink`] / `RemoteAuditSink` via [`TeeAuditSink`].
//!
//! Designed for managed log-aggregation endpoints where the operator
//! prefers push over pull:
//!   * **DataDog Logs** — `https://http-intake.logs.datadoghq.com/api/v2/logs`
//!   * **Loki HTTP push** — `https://loki.example/loki/api/v1/push`
//!     (use the loki-push body shape via a sidecar; this sink ships
//!     the canonical Hermod row schema)
//!   * **OpenTelemetry collector OTLP/HTTP-JSON** — same shape, point
//!     at the collector
//!   * **Generic webhook** — any HTTPS endpoint that accepts JSON
//!
//! ## Architecture
//!
//! `record(entry)` is non-blocking: it drops the entry into a bounded
//! [`tokio::sync::mpsc`] channel and returns immediately. A background
//! worker drains the channel and POSTs each row sequentially. This
//! shape protects the audit hot path from network latency and webhook
//! outages — a slow endpoint cannot stall a `workspace.create` call
//! waiting for an HTTP round-trip.
//!
//! ## Best-effort
//!
//! Per `AuditSink` contract, errors don't propagate. Three failure
//! modes, all logged via `tracing::warn`:
//!   * Queue full — the worker fell behind. Drop the entry, warn.
//!   * Network / timeout — the POST failed. Log and discard.
//!   * Non-2xx HTTP status — the endpoint rejected the row. Log and
//!     discard.
//!
//! Operators tracking webhook reliability tail the daemon log for
//! `webhook audit` warnings; the SQLite hash-chain remains the source
//! of truth regardless of webhook health.

use async_trait::async_trait;
use hermod_crypto::SecretString;
use reqwest::Client;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::audit_sink::AuditSink;
use crate::repositories::audit::AuditEntry;

/// Bound on the in-flight queue between `record` and the worker.
/// Sized for short outages: 1024 rows × ~512 bytes ≈ 512 KiB resident
/// memory. A backlog deeper than this almost certainly means the
/// webhook is wedged or the operator misconfigured the endpoint;
/// dropping the oldest is the honest signal.
const DEFAULT_QUEUE_CAPACITY: usize = 1024;

/// Per-POST timeout. Generous enough for cross-region endpoints,
/// short enough that a wedged endpoint doesn't pin the worker.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// One JSON line per POST. Mirrors `FileAuditSink::AuditLine` — same
/// field set so a single dashboard can ingest from either source.
#[derive(serde::Serialize)]
struct WebhookBody<'a> {
    ts: String,
    ts_ms: i64,
    actor: String,
    action: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<&'a serde_json::Value>,
}

#[derive(Clone)]
pub struct WebhookAuditSink {
    /// Sender side of the worker queue. Bounded, non-blocking via
    /// `try_send` so the audit hot path is never throttled.
    tx: mpsc::Sender<AuditEntry>,
    /// URL kept for `Debug` only — the worker has its own copy.
    url: Arc<str>,
}

impl std::fmt::Debug for WebhookAuditSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebhookAuditSink")
            .field("url", &self.url)
            .field("queue_capacity", &self.tx.max_capacity())
            .finish()
    }
}

/// Builder-style construction so future knobs (custom headers,
/// per-endpoint TLS roots, retry policy) slot in without breaking the
/// callsite.
#[derive(Debug, Clone)]
pub struct WebhookAuditSinkConfig {
    pub url: String,
    pub bearer_token: Option<SecretString>,
    pub queue_capacity: usize,
    pub timeout: Duration,
}

impl WebhookAuditSinkConfig {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            bearer_token: None,
            queue_capacity: DEFAULT_QUEUE_CAPACITY,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    pub fn bearer_token(mut self, token: SecretString) -> Self {
        self.bearer_token = Some(token);
        self
    }
}

impl WebhookAuditSink {
    /// Construct + spawn the background worker. Returns immediately;
    /// the worker runs until the daemon shuts down (the sink's
    /// `Sender` keeps the channel alive, and dropping the last sink
    /// closes the channel which terminates the worker loop).
    pub fn spawn(config: WebhookAuditSinkConfig) -> Result<Self, String> {
        let client = Client::builder()
            .timeout(config.timeout)
            .user_agent(concat!("hermod/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| format!("build http client: {e}"))?;

        let (tx, rx) = mpsc::channel(config.queue_capacity);
        let url: Arc<str> = config.url.into();
        let bearer: Option<Arc<SecretString>> = config.bearer_token.map(Arc::new);
        let worker_url = url.clone();
        let worker_bearer = bearer.clone();
        info!(url = %url, capacity = config.queue_capacity, "audit webhook sink spawned");
        tokio::spawn(worker_loop(client, worker_url, worker_bearer, rx));

        Ok(Self { tx, url })
    }
}

#[async_trait]
impl AuditSink for WebhookAuditSink {
    async fn record(&self, entry: AuditEntry) {
        // `try_send` keeps the audit hot path non-blocking. A full
        // queue means the worker is wedged on a slow webhook —
        // dropping is the only honest behaviour (the row stays in the
        // hash-chain regardless).
        if let Err(e) = self.tx.try_send(entry) {
            match e {
                mpsc::error::TrySendError::Full(dropped) => warn!(
                    action = %dropped.action,
                    url = %self.url,
                    "audit webhook queue full; dropping row (best-effort)"
                ),
                mpsc::error::TrySendError::Closed(dropped) => warn!(
                    action = %dropped.action,
                    url = %self.url,
                    "audit webhook worker is gone; dropping row"
                ),
            }
        }
    }
}

/// Drain the queue and POST each row. Sequential delivery preserves
/// audit ordering on the receiver side; if an operator needs higher
/// throughput, run a local sidecar (vector / fluent-bit) tailing the
/// `FileAuditSink` instead.
async fn worker_loop(
    client: Client,
    url: Arc<str>,
    bearer: Option<Arc<SecretString>>,
    mut rx: mpsc::Receiver<AuditEntry>,
) {
    while let Some(entry) = rx.recv().await {
        post_one(&client, &url, bearer.as_deref(), &entry).await;
    }
    debug!(url = %url, "audit webhook worker exited (channel closed)");
}

async fn post_one(client: &Client, url: &str, bearer: Option<&SecretString>, entry: &AuditEntry) {
    let body = WebhookBody {
        ts: entry.ts.to_string(),
        ts_ms: entry.ts.unix_ms(),
        actor: entry.actor.to_string(),
        action: &entry.action,
        target: entry.target.as_deref(),
        details: entry.details.as_ref(),
    };
    let mut req = client.post(url).json(&body);
    if let Some(tok) = bearer {
        req = req.bearer_auth(tok.expose_secret());
    }
    match req.send().await {
        Ok(resp) => {
            let status = resp.status();
            if !status.is_success() {
                // Read a snippet of the body so the operator has a
                // hint at what the endpoint rejected. Cap to keep log
                // lines manageable.
                let snippet = resp
                    .text()
                    .await
                    .unwrap_or_default()
                    .chars()
                    .take(256)
                    .collect::<String>();
                warn!(
                    action = %entry.action,
                    url = %url,
                    status = status.as_u16(),
                    body = %snippet,
                    "audit webhook returned non-2xx (best-effort)"
                );
            }
        }
        Err(e) => warn!(
            action = %entry.action,
            url = %url,
            error = %e,
            "audit webhook POST failed (best-effort)"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hermod_core::{AgentId, Timestamp};
    use std::str::FromStr;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;

    fn fake_actor() -> AgentId {
        AgentId::from_str("abcdefghijklmnopqrstuvwxyz").unwrap()
    }

    fn entry(action: &str) -> AuditEntry {
        AuditEntry {
            id: None,
            ts: Timestamp::now(),
            actor: fake_actor(),
            action: action.into(),
            target: Some("ttt".into()),
            details: Some(serde_json::json!({"k": "v"})),
            federation: crate::AuditFederationPolicy::Default,
        }
    }

    /// Tiny HTTP/1.1 listener that captures the first N requests'
    /// body strings, then 200s. Avoids a `httpmock` dep — we only need
    /// to assert "the POST arrived with this body".
    async fn spawn_capture(want: usize) -> (String, Arc<Mutex<Vec<String>>>, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/v1/logs", listener.local_addr().unwrap());
        let bodies: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let count = Arc::new(AtomicUsize::new(0));
        let bodies_w = bodies.clone();
        let count_w = count.clone();
        tokio::spawn(async move {
            for _ in 0..want {
                let (mut sock, _) = match listener.accept().await {
                    Ok(s) => s,
                    Err(_) => return,
                };
                let body = read_http_body(&mut sock).await.unwrap_or_default();
                bodies_w.lock().unwrap().push(body);
                count_w.fetch_add(1, Ordering::SeqCst);
                let _ = sock
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                    .await;
                let _ = sock.shutdown().await;
            }
        });
        (url, bodies, count)
    }

    /// Minimal HTTP/1.1 body reader. Reads headers, parses
    /// Content-Length, then reads exactly that many bytes. Sufficient
    /// for reqwest POST with an explicit Content-Length, which is what
    /// the JSON encoder emits.
    async fn read_http_body(sock: &mut tokio::net::TcpStream) -> Option<String> {
        let mut br = BufReader::new(sock);
        let mut content_length: usize = 0;
        loop {
            let mut line = String::new();
            br.read_line(&mut line).await.ok()?;
            if line == "\r\n" {
                break;
            }
            if let Some(v) = line
                .strip_prefix("content-length:")
                .or_else(|| line.strip_prefix("Content-Length:"))
            {
                content_length = v.trim().parse().ok()?;
            }
        }
        let mut buf = vec![0u8; content_length];
        br.read_exact(&mut buf).await.ok()?;
        Some(String::from_utf8_lossy(&buf).into_owned())
    }

    #[tokio::test]
    async fn posts_each_row_as_json() {
        let (url, bodies, count) = spawn_capture(2).await;
        let sink = WebhookAuditSink::spawn(WebhookAuditSinkConfig::new(url)).unwrap();

        sink.record(entry("a.b")).await;
        sink.record(entry("c.d")).await;

        // Wait for the worker to drain both rows.
        for _ in 0..200 {
            if count.load(Ordering::SeqCst) >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert_eq!(count.load(Ordering::SeqCst), 2, "both rows should POST");

        let bodies = bodies.lock().unwrap();
        assert_eq!(bodies.len(), 2);
        let first: serde_json::Value = serde_json::from_str(&bodies[0]).unwrap();
        assert_eq!(first["action"], "a.b");
        assert_eq!(first["actor"], fake_actor().to_string());
        assert!(first["ts"].is_string());
        assert!(first["ts_ms"].is_i64());
        let second: serde_json::Value = serde_json::from_str(&bodies[1]).unwrap();
        assert_eq!(second["action"], "c.d");
    }

    #[tokio::test]
    async fn includes_bearer_token_when_set() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let captured: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let captured_w = captured.clone();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut br = BufReader::new(&mut sock);
            let mut auth = None;
            let mut content_length: usize = 0;
            loop {
                let mut line = String::new();
                if br.read_line(&mut line).await.is_err() {
                    return;
                }
                if line == "\r\n" {
                    break;
                }
                if let Some(v) = line.strip_prefix("authorization:") {
                    auth = Some(v.trim().to_string());
                } else if let Some(v) = line.strip_prefix("Authorization:") {
                    auth = Some(v.trim().to_string());
                } else if let Some(v) = line.strip_prefix("content-length:") {
                    content_length = v.trim().parse().unwrap_or(0);
                } else if let Some(v) = line.strip_prefix("Content-Length:") {
                    content_length = v.trim().parse().unwrap_or(0);
                }
            }
            let mut buf = vec![0u8; content_length];
            let _ = br.read_exact(&mut buf).await;
            *captured_w.lock().unwrap() = auth;
            let _ = sock
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await;
            let _ = sock.shutdown().await;
        });

        let sink = WebhookAuditSink::spawn(
            WebhookAuditSinkConfig::new(url).bearer_token(SecretString::new("secret-tok")),
        )
        .unwrap();
        sink.record(entry("auth.test")).await;

        for _ in 0..200 {
            if captured.lock().unwrap().is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        let auth = captured.lock().unwrap().clone();
        assert_eq!(auth.as_deref(), Some("Bearer secret-tok"));
    }

    #[tokio::test]
    async fn full_queue_drops_with_warn_not_panic() {
        // Bind a listener but never accept — every POST stalls,
        // worker hangs on the first send, queue fills.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        // Hold the listener so the OS doesn't ECONNREFUSED.
        let _keep = listener;

        let cfg = WebhookAuditSinkConfig {
            url,
            bearer_token: None,
            queue_capacity: 4,
            timeout: Duration::from_secs(60),
        };
        let sink = WebhookAuditSink::spawn(cfg).unwrap();

        // Drop way more than capacity; must not panic and must return
        // promptly (no blocking on the queue).
        for i in 0..1024 {
            let action = format!("flood.{i}");
            sink.record(entry(&action)).await;
        }
        // If we got here, `record` was non-blocking and overflow was
        // handled gracefully.
    }

    #[tokio::test]
    async fn non_2xx_response_does_not_panic() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut br = BufReader::new(&mut sock);
            let mut content_length: usize = 0;
            loop {
                let mut line = String::new();
                if br.read_line(&mut line).await.is_err() {
                    return;
                }
                if line == "\r\n" {
                    break;
                }
                if let Some(v) = line.strip_prefix("content-length:") {
                    content_length = v.trim().parse().unwrap_or(0);
                } else if let Some(v) = line.strip_prefix("Content-Length:") {
                    content_length = v.trim().parse().unwrap_or(0);
                }
            }
            let mut buf = vec![0u8; content_length];
            let _ = br.read_exact(&mut buf).await;
            let _ = sock
                .write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 4\r\n\r\nbusy")
                .await;
            let _ = sock.shutdown().await;
        });

        let sink = WebhookAuditSink::spawn(WebhookAuditSinkConfig::new(url)).unwrap();
        sink.record(entry("server.error")).await;
        // Give the worker time to receive the 503 and warn-and-continue.
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}
