//! Audit-sink stack assembly.
//!
//! The hash-chained `StorageAuditSink` is always present; additional
//! mirror sinks (file, webhook, federation) layer in via `TeeAuditSink`
//! based on the operator's `[audit]` config. Service code stays
//! oblivious — every callsite holds `Arc<dyn AuditSink>` and never
//! names a concrete sink type.
//!
//! Built in two phases. Phase 1 here returns the assembled sink plus
//! the `RemoteAuditSink` handle (Some when audit federation is
//! enabled). The caller wires `RemoteAuditSink::set_messages` after
//! `MessageService::new` returns — the dependency is circular by
//! definition (RemoteAuditSink ships an envelope through MessageService;
//! MessageService consumes the audit_sink it sits inside) and the
//! `OnceLock` post-construction setter is the agreed break-the-cycle
//! pattern.

use anyhow::Result;
use hermod_storage::{AuditSink, Database};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use tracing::info;

use hermod_daemon::config::AuditConfig;

use crate::services::RemoteAuditSink;

/// Output of [`build_audit_sink`].
///
/// `sink` is the unified audit destination injected into every
/// service. `remote` is `Some` iff the operator listed at least one
/// agent under `[audit] aggregators` — the caller threads it forward
/// so it can hand `MessageService` to it post-construction.
pub struct AuditSinkBundle {
    pub sink: Arc<dyn AuditSink>,
    pub remote: Option<RemoteAuditSink>,
}

pub fn build_audit_sink(
    db: Arc<dyn Database>,
    audit_file_path: Option<PathBuf>,
    audit_cfg: &AuditConfig,
) -> Result<AuditSinkBundle> {
    let remote = build_remote_sink(audit_cfg);

    let storage_sink: Arc<dyn AuditSink> = Arc::new(hermod_storage::StorageAuditSink::new(db));
    let mut sinks: Vec<Arc<dyn AuditSink>> = vec![storage_sink];
    if let Some(path) = audit_file_path {
        info!(path = %path.display(), "audit file mirror enabled");
        sinks.push(Arc::new(hermod_storage::FileAuditSink::new(path)));
    }
    if let Some(rs) = &remote {
        sinks.push(Arc::new(rs.clone()));
    }
    if let Some(url) = &audit_cfg.webhook_url {
        let mut cfg = hermod_storage::WebhookAuditSinkConfig::new(url.clone());
        if let Some(tok) = &audit_cfg.webhook_bearer_token {
            cfg = cfg.bearer_token(tok.clone());
        }
        match hermod_storage::WebhookAuditSink::spawn(cfg) {
            Ok(sink) => sinks.push(Arc::new(sink)),
            Err(e) => tracing::warn!(
                url = %url,
                error = %e,
                "audit webhook sink construction failed; skipping (best-effort)"
            ),
        }
    }
    let sink: Arc<dyn AuditSink> = if sinks.len() == 1 {
        sinks.into_iter().next().expect("len == 1")
    } else {
        Arc::new(hermod_storage::TeeAuditSink::new(sinks))
    };
    Ok(AuditSinkBundle { sink, remote })
}

fn build_remote_sink(audit_cfg: &AuditConfig) -> Option<RemoteAuditSink> {
    let mut aggregators = Vec::with_capacity(audit_cfg.aggregators.len());
    for raw in &audit_cfg.aggregators {
        match hermod_core::AgentId::from_str(raw.trim()) {
            Ok(id) => aggregators.push(id),
            Err(e) => tracing::warn!(
                value = %raw,
                error = %e,
                "[audit] aggregators: skipping invalid agent id"
            ),
        }
    }
    if aggregators.is_empty() {
        None
    } else {
        info!(
            count = aggregators.len(),
            aggregators = ?aggregators,
            "audit federation enabled"
        );
        Some(RemoteAuditSink::new(aggregators))
    }
}
