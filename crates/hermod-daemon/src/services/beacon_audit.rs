//! Adapter from the discovery crate's [`BeaconAuditor`] callback shape
//! onto the daemon's hash-chained [`AuditSink`] stack.
//!
//! Why a tiny adapter and not a direct dependency: `hermod-discovery`
//! should not depend on `hermod-storage`. The discovery crate emits
//! sync, fire-and-forget events; this adapter lifts each event onto
//! an `AuditEntry` and dispatches via `tokio::spawn` so the discovery
//! task never blocks on storage.

use hermod_core::{AgentId, Endpoint, Timestamp};
use hermod_discovery::BeaconAuditor;
use hermod_storage::{AuditEntry, AuditFederationPolicy, AuditSink};
use std::sync::Arc;

#[derive(Clone)]
pub struct AuditSinkBeaconAuditor {
    sink: Arc<dyn AuditSink>,
    host_actor: AgentId,
}

impl std::fmt::Debug for AuditSinkBeaconAuditor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditSinkBeaconAuditor")
            .field("self_id", &self.host_actor)
            .finish_non_exhaustive()
    }
}

impl AuditSinkBeaconAuditor {
    pub fn new(sink: Arc<dyn AuditSink>, host_actor: AgentId) -> Self {
        Self { sink, host_actor }
    }

    fn dispatch(&self, entry: AuditEntry) {
        let sink = self.sink.clone();
        tokio::spawn(async move {
            sink.record(entry).await;
        });
    }
}

impl BeaconAuditor for AuditSinkBeaconAuditor {
    fn emitted(&self, port: u16, validity_secs: u32) {
        self.dispatch(AuditEntry {
            id: None,
            ts: Timestamp::now(),
            actor: self.host_actor.clone(),
            action: "mdns.beacon_emitted".into(),
            target: None,
            details: Some(serde_json::json!({
                "port": port,
                "validity_secs": validity_secs,
            })),
            client_ip: None,
            federation: AuditFederationPolicy::Default,
        });
    }

    fn observed(&self, agent_id: &str, endpoint: &Endpoint) {
        self.dispatch(AuditEntry {
            id: None,
            ts: Timestamp::now(),
            actor: self.host_actor.clone(),
            action: "mdns.beacon_observed".into(),
            target: Some(agent_id.to_string()),
            details: Some(serde_json::json!({
                "endpoint": endpoint.to_string(),
            })),
            client_ip: None,
            federation: AuditFederationPolicy::Default,
        });
    }

    fn rejected(&self, agent_id: Option<&str>, reason: &'static str) {
        self.dispatch(AuditEntry {
            id: None,
            ts: Timestamp::now(),
            actor: self.host_actor.clone(),
            action: "mdns.beacon_rejected".into(),
            target: agent_id.map(str::to_string),
            details: Some(serde_json::json!({
                "reason": reason,
            })),
            client_ip: None,
            federation: AuditFederationPolicy::Default,
        });
    }
}
