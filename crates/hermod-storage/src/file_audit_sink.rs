//! Append-only JSONL audit sink.
//!
//! Operators wire this alongside the [`StorageAuditSink`] via
//! [`TeeAuditSink`] when they want every audit row mirrored to a flat
//! file. The file format is one JSON object per line — the format every
//! log-shipping pipeline (promtail / vector / fluent-bit / filebeat)
//! consumes natively. The SQLite hash-chain remains the cryptographic
//! source of truth; this file is the operator-readable forwarding stream.
//!
//! ## Logrotate compatibility
//!
//! Every `record` call opens the path in append mode, writes one line,
//! and closes the handle. That makes the sink robust to external rotation
//! (logrotate `create`, vector's `move + truncate`) without copy-truncate
//! gymnastics — we simply hit the new inode on the next call. No long-
//! lived `File` handle, no sync-write race with the rotator.
//!
//! ## Best-effort
//!
//! [`AuditSink::record`] cannot return an error by contract, so file
//! IO failures (disk full, permission denied, parent dir vanished) are
//! logged via `tracing::warn` and swallowed. The hash-chain has already
//! captured the entry — losing the mirror is recoverable, refusing the
//! action would not be.

use async_trait::async_trait;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tracing::warn;

use crate::audit_sink::AuditSink;
use crate::repositories::audit::AuditEntry;

/// One-line JSON record format. Mirrors the `audit_log` columns the
/// hash-chain stores (minus the chain bookkeeping, which is a SQLite
/// concern). Field names are stable wire — log-shipping pipelines will
/// build dashboards on them.
#[derive(serde::Serialize)]
struct AuditLine<'a> {
    /// RFC 3339 UTC timestamp.
    ts: String,
    /// Unix milliseconds — for shippers that want numeric ordering.
    ts_ms: i64,
    actor: String,
    action: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<&'a serde_json::Value>,
}

#[derive(Clone)]
pub struct FileAuditSink {
    path: PathBuf,
    /// Serialises concurrent writes so two records can't interleave
    /// bytes mid-line. The `OpenOptions::append` flag is atomic at the
    /// kernel level only on POSIX — the Mutex is the portable guarantee.
    write_lock: Arc<Mutex<()>>,
}

impl std::fmt::Debug for FileAuditSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileAuditSink")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl FileAuditSink {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            write_lock: Arc::new(Mutex::new(())),
        }
    }
}

#[async_trait]
impl AuditSink for FileAuditSink {
    async fn record(&self, entry: AuditEntry) {
        let target = entry.target.as_deref();
        let details = entry.details.as_ref();
        let ts_ms = entry.ts.unix_ms();
        let line = AuditLine {
            // `Display` impl on `Timestamp` formats as RFC 3339 UTC.
            ts: entry.ts.to_string(),
            ts_ms,
            actor: entry.actor.to_string(),
            action: &entry.action,
            target,
            details,
        };
        let mut bytes = match serde_json::to_vec(&line) {
            Ok(b) => b,
            Err(e) => {
                warn!(action = %entry.action, error = %e, "audit file: serialize failed");
                return;
            }
        };
        bytes.push(b'\n');

        let _guard = self.write_lock.lock().await;
        let mut file = match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .await
        {
            Ok(f) => f,
            Err(e) => {
                warn!(
                    action = %entry.action,
                    path = %self.path.display(),
                    error = %e,
                    "audit file: open failed"
                );
                return;
            }
        };
        if let Err(e) = file.write_all(&bytes).await {
            warn!(
                action = %entry.action,
                path = %self.path.display(),
                error = %e,
                "audit file: write failed"
            );
            return;
        }
        // `flush` pushes the userspace buffer to the kernel; we don't
        // call `sync_all` because the chain already has durability —
        // this file is for operator visibility, not crash-recovery.
        if let Err(e) = file.flush().await {
            warn!(
                action = %entry.action,
                path = %self.path.display(),
                error = %e,
                "audit file: flush failed"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hermod_core::{AgentId, Timestamp};
    use std::str::FromStr;

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

    #[tokio::test]
    async fn appends_one_line_per_record() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let sink = FileAuditSink::new(path.clone());

        sink.record(entry("a.b")).await;
        sink.record(entry("c.d")).await;

        let contents = tokio::fs::read_to_string(&path).await.unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2);

        let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first["action"], "a.b");
        assert_eq!(first["target"], "ttt");
        assert_eq!(first["details"]["k"], "v");
        assert!(first["ts_ms"].is_i64());
        assert!(first["ts"].is_string());
        assert_eq!(first["actor"], fake_actor().to_string());

        let second: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(second["action"], "c.d");
    }

    #[tokio::test]
    async fn missing_optional_fields_omitted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let sink = FileAuditSink::new(path.clone());

        let mut e = entry("plain");
        e.target = None;
        e.details = None;
        sink.record(e).await;

        let contents = tokio::fs::read_to_string(&path).await.unwrap();
        let v: serde_json::Value = serde_json::from_str(contents.trim()).unwrap();
        assert!(v.get("target").is_none());
        assert!(v.get("details").is_none());
    }

    #[tokio::test]
    async fn open_failure_does_not_panic() {
        // Path under a non-existent parent dir → open fails, we warn-and-continue.
        let sink = FileAuditSink::new(PathBuf::from("/nonexistent/__hermod_audit__.log"));
        sink.record(entry("won't.write")).await; // no panic, no error returned
    }

    #[tokio::test]
    async fn concurrent_writes_do_not_interleave() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let sink = Arc::new(FileAuditSink::new(path.clone()));

        let mut handles = Vec::new();
        for i in 0..32 {
            let s = sink.clone();
            handles.push(tokio::spawn(async move {
                let action = format!("action.{i}");
                s.record(entry(&action)).await;
            }));
        }
        for h in handles {
            h.await.unwrap();
        }

        let contents = tokio::fs::read_to_string(&path).await.unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 32);
        // Every line must parse — proves no byte-interleaving.
        for line in lines {
            let _: serde_json::Value = serde_json::from_str(line).expect("valid JSONL line");
        }
    }
}
