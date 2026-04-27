//! Permission relay — Claude Code Channels permission_request bridge.
//!
//! ## Why a separate service
//!
//! Claude Code's permission relay (`notifications/claude/channel/
//! permission_request` / `permission`) lets a remote operator approve or
//! deny tool calls (Bash, Write, Edit, …) the host model is about to make.
//! The MCP server receives the inbound prompt over stdio and forwards it
//! here; the daemon parks the request, surfaces it through whatever
//! operator surface is in use (local CLI, federation push, future Slack /
//! Telegram bridge), and replays the verdict back to the MCP server when
//! it arrives.
//!
//! ## Why in-memory
//!
//! Permission prompts are *ephemeral*: the host's terminal dialog stays
//! open in parallel, and whichever side answers first wins. A pending
//! request that survives a daemon restart is meaningless — the host's
//! dialog is gone too, and Claude Code reissues the prompt on the next
//! tool call. Persisting them to SQLite would buy nothing while paying
//! disk I/O on the latency-critical approval path. We use a `Mutex<HashMap>`
//! keyed by short id; the lock is held only across `O(1)` operations.
//!
//! ## TTL
//!
//! [`REQUEST_TTL`] caps how long an open prompt stays live. Past the TTL
//! the request is silently dropped (a `permission.respond` that arrives
//! late returns `matched=false`) and the host's local dialog will time
//! out on its own schedule. The TTL is also enforced lazily on every
//! lookup, so a slow daemon doesn't accumulate ghost entries.
//!
//! ## Idempotency
//!
//! `respond` removes the entry under the lock; a second `respond` with
//! the same id sees nothing and returns `matched=false`. Equivalent
//! semantics to the Channels reference: "whichever side answers first".

use async_trait::async_trait;
use hermod_core::{AgentId, Timestamp};
use hermod_crypto::short_id;
use hermod_protocol::ipc::methods::{
    PermissionBehavior, PermissionListParams, PermissionListResolvedParams,
    PermissionListResolvedResult, PermissionListResult, PermissionOutcome,
    PermissionRequestParams, PermissionRequestResult, PermissionRequestView,
    PermissionResolvedView, PermissionRespondParams, PermissionRespondResult,
};
use hermod_storage::{AuditEntry, AuditSink};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, OnceCell};

use crate::services::{ServiceError, audit_or_warn};

/// Ships a finalised verdict back to the originating peer of a relayed
/// permission prompt. Production uses [`MessageService`] to wrap the
/// verdict in a `PermissionResponse` envelope; tests substitute an
/// in-memory recorder. Wired exactly once at daemon construction via
/// [`PermissionService::set_relay_responder`].
#[async_trait]
pub trait RelayResponder: Send + Sync + 'static {
    async fn respond(
        &self,
        to: AgentId,
        request_id: String,
        behavior: PermissionBehavior,
    ) -> Result<(), ServiceError>;
}

/// Fan-out shape for a freshly-opened local prompt. Returns the count
/// of `permission:respond` delegates the prompt reached so the audit
/// row records the fan-out width. Wired alongside [`RelayResponder`].
#[async_trait]
pub trait PromptForwarder: Send + Sync + 'static {
    async fn forward(&self, payload: PromptForwardPayload) -> Result<u32, ServiceError>;
}

/// Plain-data carrier handed to the [`PromptForwarder`]. Borrowing
/// across the await boundary would require `'static` on every field;
/// cloning the small primitives is the simpler choice.
#[derive(Debug, Clone)]
pub struct PromptForwardPayload {
    pub request_id: String,
    pub tool_name: String,
    pub description: String,
    pub input_preview: String,
    pub expires_at: Timestamp,
}

/// How long an unanswered permission prompt stays live. Five minutes is
/// plenty for a phone-bound operator to glance at the alert and reply;
/// long enough to bridge a handful of context switches, short enough that
/// the live set never grows unbounded under a stuck remote.
pub const REQUEST_TTL: Duration = Duration::from_secs(5 * 60);

/// Hard cap on simultaneously-open requests. Prevents an automated client
/// from filling the table with stale entries before TTL kicks in. The
/// cap is generous — a chatty session might have a handful of tool calls
/// in flight — but defends against pathological loops.
const MAX_OPEN: usize = 1024;

/// Hard cap on the resolved-events ring buffer. The MCP server polls
/// `permission.list_resolved` at sub-second cadence, so this only needs
/// to absorb spikes — a buffer that holds a few thousand entries is
/// more than enough headroom against any realistic operator workflow.
/// Entries beyond the cap are dropped from the front (oldest first), and
/// any cursor that lands inside the dropped range receives an empty
/// batch — Claude Code's terminal dialog absorbs the missed verdict via
/// its own timeout.
const RESOLVED_RING_CAP: usize = 4096;

/// Where this prompt originated. Local prompts go through MCP →
/// daemon → operator → MCP. Relayed prompts came in over the wire
/// from a peer who delegated to us — the operator's verdict travels
/// back as a `PermissionResponse` envelope addressed to `from`.
#[derive(Debug, Clone)]
enum PromptOrigin {
    Local,
    Relayed { from: AgentId },
}

#[derive(Debug, Clone)]
struct OpenRequest {
    request_id: String,
    tool_name: String,
    description: String,
    input_preview: String,
    requested_at: Timestamp,
    expires_at: Timestamp,
    origin: PromptOrigin,
}

impl OpenRequest {
    fn view(&self) -> PermissionRequestView {
        PermissionRequestView {
            request_id: self.request_id.clone(),
            tool_name: self.tool_name.clone(),
            description: self.description.clone(),
            input_preview: self.input_preview.clone(),
            requested_at: self.requested_at,
            expires_at: self.expires_at,
        }
    }
}

#[derive(Debug, Clone)]
struct ResolvedEntry {
    seq: u64,
    request_id: String,
    outcome: PermissionOutcome,
    resolved_at: Timestamp,
}

impl ResolvedEntry {
    fn view(&self) -> PermissionResolvedView {
        PermissionResolvedView {
            seq: self.seq,
            request_id: self.request_id.clone(),
            outcome: self.outcome,
            resolved_at: self.resolved_at,
        }
    }
}

#[derive(Debug, Default)]
struct State {
    by_id: HashMap<String, OpenRequest>,
    resolved: VecDeque<ResolvedEntry>,
    next_seq: u64,
}

impl State {
    /// Drop expired open requests, materialising one resolved-with-
    /// `Expired` entry per drop so the MCP server's verdict cursor can
    /// observe the timeout. Returns the dropped requests so the caller
    /// can emit one audit row per expiration outside the lock —
    /// expirations are first-class events that an operator inspecting
    /// the audit log expects to see, not silent garbage collection.
    fn purge_expired(&mut self, now: Timestamp) -> Vec<OpenRequest> {
        let now_ms = now.unix_ms();
        let mut expired: Vec<OpenRequest> = Vec::new();
        self.by_id.retain(|_, r| {
            if r.expires_at.unix_ms() > now_ms {
                true
            } else {
                expired.push(r.clone());
                false
            }
        });
        for req in &expired {
            self.push_resolved(req.request_id.clone(), PermissionOutcome::Expired, now);
        }
        expired
    }

    fn push_resolved(&mut self, request_id: String, outcome: PermissionOutcome, at: Timestamp) {
        self.next_seq = self.next_seq.saturating_add(1);
        let entry = ResolvedEntry {
            seq: self.next_seq,
            request_id,
            outcome,
            resolved_at: at,
        };
        self.resolved.push_back(entry);
        while self.resolved.len() > RESOLVED_RING_CAP {
            self.resolved.pop_front();
        }
    }
}

#[derive(Clone)]
pub struct PermissionService {
    audit_sink: Arc<dyn AuditSink>,
    self_id: AgentId,
    state: Arc<Mutex<State>>,
    ttl: Duration,
    /// Trait object that ships a `PermissionResponse` envelope back
    /// to a federated originator. `OnceCell` because the responder is
    /// wired exactly once at daemon construction (after both
    /// PermissionService and MessageService exist) and read on every
    /// Relayed-origin verdict.
    relay_responder: Arc<OnceCell<Arc<dyn RelayResponder>>>,
    /// Trait object that fans out a freshly-opened local prompt to
    /// every active `permission:respond` delegate. Mirrors
    /// `relay_responder` — wired once after MessageService exists.
    prompt_forwarder: Arc<OnceCell<Arc<dyn PromptForwarder>>>,
}

impl std::fmt::Debug for PermissionService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PermissionService")
            .field("self_id", &self.self_id)
            .field("ttl", &self.ttl)
            .field("has_relay_responder", &self.relay_responder.get().is_some())
            .field("has_prompt_forwarder", &self.prompt_forwarder.get().is_some())
            .finish()
    }
}

impl PermissionService {
    pub fn new(audit_sink: Arc<dyn AuditSink>, self_id: AgentId) -> Self {
        Self {
            audit_sink,
            self_id,
            state: Arc::new(Mutex::new(State::default())),
            ttl: REQUEST_TTL,
            relay_responder: Arc::new(OnceCell::new()),
            prompt_forwarder: Arc::new(OnceCell::new()),
        }
    }

    /// Wire the federated-relay responder. Called once at daemon
    /// startup. A second call is a no-op (the cell is locked after
    /// the first set) so test harnesses can't accidentally swap it
    /// mid-run.
    pub fn set_relay_responder(&self, responder: Arc<dyn RelayResponder>) {
        let _ = self.relay_responder.set(responder);
    }

    /// Wire the prompt forwarder (invoked from `request` when a fresh
    /// local prompt opens). Same single-shot semantics as
    /// `set_relay_responder`.
    pub fn set_prompt_forwarder(&self, forwarder: Arc<dyn PromptForwarder>) {
        let _ = self.prompt_forwarder.set(forwarder);
    }

    /// Open a fresh permission request and return the operator-visible
    /// short id + expiry. Audited so the operator's history shows every
    /// prompt the host received, not just the verdicts.
    #[tracing::instrument(
        name = "permission.request",
        skip(self, params),
        fields(tool = %params.tool_name)
    )]
    pub async fn request(
        &self,
        params: PermissionRequestParams,
    ) -> Result<PermissionRequestResult, ServiceError> {
        let now = Timestamp::now();
        let expires_at = now.offset_by_ms(self.ttl.as_millis() as i64);

        let (request_id, expired) = {
            let mut state = self.state.lock().await;
            let expired = state.purge_expired(now);
            if state.by_id.len() >= MAX_OPEN {
                drop(state);
                self.audit_expirations(&expired, now).await;
                return Err(ServiceError::InvalidParam(format!(
                    "too many open permission requests ({MAX_OPEN}); refusing new prompts \
                     until existing ones expire or are answered"
                )));
            }
            let mut rng = rand::thread_rng();
            let id = loop {
                let candidate = short_id::generate(&mut rng);
                if !state.by_id.contains_key(&candidate) {
                    break candidate;
                }
            };
            state.by_id.insert(
                id.clone(),
                OpenRequest {
                    request_id: id.clone(),
                    tool_name: params.tool_name.clone(),
                    description: params.description.clone(),
                    input_preview: params.input_preview.clone(),
                    requested_at: now,
                    expires_at,
                    origin: PromptOrigin::Local,
                },
            );
            (id, expired)
        };

        self.audit_expirations(&expired, now).await;

        audit_or_warn(&*self.audit_sink,
            AuditEntry {
                id: None,
                ts: now,
                actor: self.self_id.clone(),
                action: "permission.request".into(),
                target: Some(request_id.clone()),
                details: Some(serde_json::json!({
                    "tool_name": params.tool_name,
                    "description": params.description,
                })),
                federation: hermod_storage::AuditFederationPolicy::Default,
            },
        )
        .await;

        // Federated fan-out: ship the prompt to every active
        // `permission:respond` delegate so a remote operator can
        // answer it. Best-effort — a transport failure to one
        // delegate doesn't block the local prompt from being live.
        if let Some(forwarder) = self.prompt_forwarder.get() {
            let payload = PromptForwardPayload {
                request_id: request_id.clone(),
                tool_name: params.tool_name.clone(),
                description: params.description.clone(),
                input_preview: params.input_preview.clone(),
                expires_at,
            };
            // Always audit the fan-out result, even at reach=0 or on
            // forwarder error: the operator needs visibility into a
            // delegation chain that's silently broken (e.g. the only
            // delegated peer was removed, or every cap expired). Without
            // this, a relayed-permission setup can degrade to "purely
            // local" without any signal.
            match forwarder.forward(payload).await {
                Ok(reach) => {
                    let action = if reach > 0 {
                        "permission.relay"
                    } else {
                        "permission.relay.unreachable"
                    };
                    audit_or_warn(&*self.audit_sink,
                        AuditEntry {
                            id: None,
                            ts: now,
                            actor: self.self_id.clone(),
                            action: action.into(),
                            target: Some(request_id.clone()),
                            details: Some(serde_json::json!({
                                "delegates": reach,
                            })),
                            federation: hermod_storage::AuditFederationPolicy::Default,
                        },
                    )
                    .await;
                }
                Err(e) => {
                    tracing::warn!(
                        request_id = %request_id,
                        error = %e,
                        "permission prompt fan-out failed; local prompt still live"
                    );
                    audit_or_warn(&*self.audit_sink,
                        AuditEntry {
                            id: None,
                            ts: now,
                            actor: self.self_id.clone(),
                            action: "permission.relay.failed".into(),
                            target: Some(request_id.clone()),
                            details: Some(serde_json::json!({
                                "error": e.to_string(),
                            })),
                            federation: hermod_storage::AuditFederationPolicy::Default,
                        },
                    )
                    .await;
                }
            }
        }

        Ok(PermissionRequestResult {
            request_id,
            expires_at,
        })
    }

    /// Apply a verdict that arrived from a federated delegate via a
    /// `PermissionResponse` envelope. Routes through the same state
    /// machine as a local `respond` call — `state.by_id.remove` +
    /// `push_resolved` — so the MCP `permission.list_resolved` cursor
    /// surfaces the verdict to Claude Code identically regardless of
    /// origin (local CLI vs federated delegate). Idempotent: a second
    /// arrival for the same `request_id` (e.g. local CLI already
    /// answered) returns `matched = false` with no resolved-event
    /// duplication.
    pub async fn apply_relayed_verdict(
        &self,
        request_id: String,
        behavior: PermissionBehavior,
        from: AgentId,
    ) -> Result<bool, ServiceError> {
        if !short_id::is_valid(&request_id) {
            return Err(ServiceError::InvalidParam(format!(
                "relayed verdict carries invalid request_id `{request_id}`"
            )));
        }
        let now = Timestamp::now();
        let removed = {
            let mut state = self.state.lock().await;
            let _ = state.purge_expired(now);
            let removed = state.by_id.remove(&request_id);
            if removed.is_some() {
                let outcome = match behavior {
                    PermissionBehavior::Allow => PermissionOutcome::Allow,
                    PermissionBehavior::Deny => PermissionOutcome::Deny,
                };
                state.push_resolved(request_id.clone(), outcome, now);
            }
            removed
        };

        let matched = removed.is_some();
        if matched {
            audit_or_warn(&*self.audit_sink,
                AuditEntry {
                    id: None,
                    ts: now,
                    actor: from,
                    action: behavior.audit_action().into(),
                    target: Some(request_id),
                    details: removed.map(|r| {
                        serde_json::json!({
                            "tool_name": r.tool_name,
                            "description": r.description,
                            "via": "federated_relay",
                        })
                    }),
                    federation: hermod_storage::AuditFederationPolicy::Default,
                },
            )
            .await;
        }
        Ok(matched)
    }

    /// Receive a `PermissionPrompt` envelope forwarded by a peer who
    /// delegated their host's prompts to us. Stored with origin =
    /// Relayed { from } so the operator's verdict (via the same
    /// `respond` CLI flow) routes back as a `PermissionResponse`
    /// envelope addressed to `from`. The originator's `request_id`
    /// is used verbatim — the operator's CLI matches against it
    /// regardless of which side originated the prompt.
    pub async fn receive_relayed(
        &self,
        from: AgentId,
        request_id: String,
        tool_name: String,
        description: String,
        input_preview: String,
        expires_at: Timestamp,
    ) -> Result<(), ServiceError> {
        if !short_id::is_valid(&request_id) {
            return Err(ServiceError::InvalidParam(format!(
                "relayed request_id `{request_id}` is not a valid short id"
            )));
        }
        let now = Timestamp::now();
        let mut state = self.state.lock().await;
        // Avoid clobbering an in-flight local prompt that happens to
        // share the same id (1-in-9.7M chance — but defence in depth
        // costs nothing).
        if state.by_id.contains_key(&request_id) {
            return Err(ServiceError::InvalidParam(format!(
                "request_id `{request_id}` collides with an existing prompt"
            )));
        }
        if state.by_id.len() >= MAX_OPEN {
            return Err(ServiceError::InvalidParam(
                "permission queue full; refusing relayed prompt".into(),
            ));
        }
        state.by_id.insert(
            request_id.clone(),
            OpenRequest {
                request_id,
                tool_name,
                description,
                input_preview,
                requested_at: now,
                expires_at,
                origin: PromptOrigin::Relayed { from },
            },
        );
        Ok(())
    }

    /// Apply a verdict to an open request. Idempotent: a second call with
    /// the same id (or one whose request expired) returns `matched=false`,
    /// never duplicates the audit row, and never resurfaces the prompt.
    #[tracing::instrument(
        name = "permission.respond",
        skip(self, params),
        fields(id = %params.request_id, behavior = %params.behavior.as_str())
    )]
    pub async fn respond(
        &self,
        params: PermissionRespondParams,
    ) -> Result<PermissionRespondResult, ServiceError> {
        if !short_id::is_valid(&params.request_id) {
            return Err(ServiceError::InvalidParam(format!(
                "invalid request_id `{}` — must be {} chars from `[a-km-z]`",
                params.request_id,
                short_id::LEN
            )));
        }

        let now = Timestamp::now();
        let (removed, expired) = {
            let mut state = self.state.lock().await;
            let expired = state.purge_expired(now);
            let removed = state.by_id.remove(&params.request_id);
            if removed.is_some() {
                let outcome = match params.behavior {
                    PermissionBehavior::Allow => PermissionOutcome::Allow,
                    PermissionBehavior::Deny => PermissionOutcome::Deny,
                };
                state.push_resolved(params.request_id.clone(), outcome, now);
            }
            (removed, expired)
        };

        self.audit_expirations(&expired, now).await;

        // Federated relay: if this prompt came from a peer, ship the
        // verdict back as a `PermissionResponse` envelope. Send failure
        // is audited so the operator can see "I answered, but the
        // originator never heard" — the verdict applies locally either
        // way (Claude Code on this side moves on), but the originator's
        // pending prompt is left orphaned and that fact must be visible.
        if let Some(req) = removed.as_ref()
            && let PromptOrigin::Relayed { from } = &req.origin
            && let Some(responder) = self.relay_responder.get()
            && let Err(e) = responder
                .respond(
                    from.clone(),
                    params.request_id.clone(),
                    params.behavior,
                )
                .await
        {
            tracing::warn!(
                request_id = %params.request_id,
                from = %from,
                error = %e,
                "federated permission verdict send failed; verdict still applied locally"
            );
            audit_or_warn(&*self.audit_sink,
                AuditEntry {
                    id: None,
                    ts: now,
                    actor: self.self_id.clone(),
                    action: "permission.relay.send_failed".into(),
                    target: Some(params.request_id.clone()),
                    details: Some(serde_json::json!({
                        "to": from.to_string(),
                        "error": e.to_string(),
                    })),
                    federation: hermod_storage::AuditFederationPolicy::Default,
                },
            )
            .await;
        }

        let matched = removed.is_some();
        if matched {
            audit_or_warn(&*self.audit_sink,
                AuditEntry {
                    id: None,
                    ts: now,
                    actor: self.self_id.clone(),
                    action: params.behavior.audit_action().into(),
                    target: Some(params.request_id),
                    details: removed.map(|r| {
                        serde_json::json!({
                            "tool_name": r.tool_name,
                            "description": r.description,
                        })
                    }),
                    federation: hermod_storage::AuditFederationPolicy::Default,
                },
            )
            .await;
        }

        Ok(PermissionRespondResult { matched })
    }

    /// Cursor-based feed of resolved requests (allow / deny / expired).
    /// Used by the MCP server to drive the verdict notification path back
    /// to Claude Code. Returns entries with `seq > after_seq` in seq
    /// order, capped at `limit` (default 256).
    pub async fn list_resolved(
        &self,
        params: PermissionListResolvedParams,
    ) -> Result<PermissionListResolvedResult, ServiceError> {
        let now = Timestamp::now();
        let after = params.after_seq.unwrap_or(0);
        let cap = params.limit.unwrap_or(256) as usize;

        let (resolved, daemon_next_seq, expired) = {
            let mut state = self.state.lock().await;
            // Materialise expirations first so the cursor sees them in order.
            let expired = state.purge_expired(now);

            let resolved: Vec<PermissionResolvedView> = state
                .resolved
                .iter()
                .filter(|e| e.seq > after)
                .take(cap)
                .map(ResolvedEntry::view)
                .collect();
            // `next_seq` is the value the daemon will hand out on the
            // next resolution — by definition strictly greater than
            // every entry currently in the ring (or 1 if nothing has
            // been pushed yet). Consumers compare against their cursor
            // to detect a daemon restart (monotonic counter going
            // backwards).
            let daemon_next_seq = state.next_seq.saturating_add(1);
            (resolved, daemon_next_seq, expired)
        };

        self.audit_expirations(&expired, now).await;
        Ok(PermissionListResolvedResult {
            resolved,
            daemon_next_seq,
        })
    }

    /// Snapshot of the live (non-expired) request set. Used by operator
    /// surfaces (`hermod permission list`, MCP `permission_list` tool) to
    /// review what the host is currently waiting on.
    pub async fn list(
        &self,
        params: PermissionListParams,
    ) -> Result<PermissionListResult, ServiceError> {
        let now = Timestamp::now();
        let (requests, expired) = {
            let mut state = self.state.lock().await;
            let expired = state.purge_expired(now);
            let mut requests: Vec<PermissionRequestView> =
                state.by_id.values().map(OpenRequest::view).collect();
            // Stable, oldest-first ordering — operators triage in arrival order.
            requests.sort_by_key(|r| r.requested_at.unix_ms());
            if let Some(n) = params.limit {
                requests.truncate(n as usize);
            }
            (requests, expired)
        };
        self.audit_expirations(&expired, now).await;
        Ok(PermissionListResult { requests })
    }

    /// Emit one `permission.expired` audit row per request that timed
    /// out. Called by every public method that could trigger a purge,
    /// outside the state lock so audit storage IO doesn't extend the
    /// critical section.
    async fn audit_expirations(&self, expired: &[OpenRequest], at: Timestamp) {
        for req in expired {
            audit_or_warn(&*self.audit_sink,
                AuditEntry {
                    id: None,
                    ts: at,
                    actor: self.self_id.clone(),
                    action: "permission.expired".into(),
                    target: Some(req.request_id.clone()),
                    details: Some(serde_json::json!({
                        "tool_name": req.tool_name,
                        "description": req.description,
                    })),
                    federation: hermod_storage::AuditFederationPolicy::Default,
                },
            )
            .await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hermod_protocol::ipc::methods::PermissionBehavior;

    async fn make_service() -> (PermissionService, std::sync::Arc<dyn hermod_storage::Database>) {
        let mut p = std::env::temp_dir();
        p.push(format!("hermod-permission-{}.sqlite", ulid::Ulid::new()));
        let keypair = std::sync::Arc::new(hermod_crypto::Keypair::generate());
        let self_id = keypair.agent_id();
        let signer: std::sync::Arc<dyn hermod_crypto::Signer> =
            std::sync::Arc::new(hermod_crypto::LocalKeySigner::new(keypair));
        let url = format!("sqlite://{}", p.display());
        let db = hermod_storage::connect(
            &url,
            signer,
            std::sync::Arc::new(hermod_storage::MemoryBlobStore::new()),
        )
        .await
        .unwrap();
        let audit_sink: std::sync::Arc<dyn hermod_storage::AuditSink> =
            std::sync::Arc::new(hermod_storage::StorageAuditSink::new(db.clone()));
        (PermissionService::new(audit_sink, self_id), db)
    }

    fn req_params(tool: &str) -> PermissionRequestParams {
        PermissionRequestParams {
            tool_name: tool.into(),
            description: format!("run {tool}"),
            input_preview: "{\"command\":\"ls\"}".into(),
        }
    }

    #[tokio::test]
    async fn request_returns_short_id_in_alphabet() {
        let (svc, _db) = make_service().await;
        for _ in 0..50 {
            let r = svc.request(req_params("Bash")).await.unwrap();
            assert!(short_id::is_valid(&r.request_id), "bad id: {}", r.request_id);
        }
    }

    #[tokio::test]
    async fn respond_is_idempotent() {
        let (svc, _db) = make_service().await;
        let r = svc.request(req_params("Write")).await.unwrap();

        let first = svc
            .respond(PermissionRespondParams {
                request_id: r.request_id.clone(),
                behavior: PermissionBehavior::Allow,
            })
            .await
            .unwrap();
        assert!(first.matched);

        let second = svc
            .respond(PermissionRespondParams {
                request_id: r.request_id,
                behavior: PermissionBehavior::Allow,
            })
            .await
            .unwrap();
        assert!(!second.matched, "second respond must be a no-op");
    }

    #[tokio::test]
    async fn respond_unknown_id_is_no_op() {
        let (svc, _db) = make_service().await;
        // Use an id in the alphabet but never issued.
        let res = svc
            .respond(PermissionRespondParams {
                request_id: "abcde".into(),
                behavior: PermissionBehavior::Deny,
            })
            .await
            .unwrap();
        assert!(!res.matched);
    }

    #[tokio::test]
    async fn respond_rejects_invalid_id() {
        let (svc, _db) = make_service().await;
        let err = svc
            .respond(PermissionRespondParams {
                request_id: "ablde".into(), // contains forbidden `l`
                behavior: PermissionBehavior::Allow,
            })
            .await
            .unwrap_err();
        assert!(matches!(err, ServiceError::InvalidParam(_)));
    }

    #[tokio::test]
    async fn list_orders_oldest_first_and_honours_limit() {
        let (svc, _db) = make_service().await;
        let _r1 = svc.request(req_params("Bash")).await.unwrap();
        let _r2 = svc.request(req_params("Write")).await.unwrap();
        let _r3 = svc.request(req_params("Edit")).await.unwrap();

        let res = svc
            .list(PermissionListParams { limit: Some(2) })
            .await
            .unwrap();
        assert_eq!(res.requests.len(), 2);
        // Oldest first.
        assert!(res.requests[0].requested_at.unix_ms() <= res.requests[1].requested_at.unix_ms());
    }

    #[tokio::test]
    async fn cap_blocks_excess_requests() {
        let (svc, _db) = make_service().await;
        // Force the state into the cap and verify a fresh request is refused.
        {
            let mut state = svc.state.lock().await;
            for i in 0..MAX_OPEN {
                let id = format!("{:0>5}", i);
                state.by_id.insert(
                    id.clone(),
                    OpenRequest {
                        request_id: id.clone(),
                        tool_name: "Bash".into(),
                        description: String::new(),
                        input_preview: String::new(),
                        requested_at: Timestamp::now(),
                        expires_at: Timestamp::now().offset_by_ms(60_000),
                        origin: PromptOrigin::Local,
                    },
                );
            }
        }
        let err = svc.request(req_params("Bash")).await.unwrap_err();
        assert!(matches!(err, ServiceError::InvalidParam(_)));
    }

    #[tokio::test]
    async fn list_resolved_emits_allow_then_deny_in_seq_order() {
        use hermod_protocol::ipc::methods::PermissionListResolvedParams;

        let (svc, _db) = make_service().await;
        let r1 = svc.request(req_params("Bash")).await.unwrap();
        let r2 = svc.request(req_params("Write")).await.unwrap();

        svc.respond(PermissionRespondParams {
            request_id: r1.request_id.clone(),
            behavior: PermissionBehavior::Allow,
        })
        .await
        .unwrap();
        svc.respond(PermissionRespondParams {
            request_id: r2.request_id.clone(),
            behavior: PermissionBehavior::Deny,
        })
        .await
        .unwrap();

        let res = svc
            .list_resolved(PermissionListResolvedParams::default())
            .await
            .unwrap();
        assert_eq!(res.resolved.len(), 2);
        assert!(res.resolved[0].seq < res.resolved[1].seq, "monotonic seq");
        assert_eq!(res.resolved[0].outcome, PermissionOutcome::Allow);
        assert_eq!(res.resolved[1].outcome, PermissionOutcome::Deny);

        // Cursor advances correctly.
        let after = res.resolved[0].seq;
        let next = svc
            .list_resolved(PermissionListResolvedParams {
                after_seq: Some(after),
                limit: None,
            })
            .await
            .unwrap();
        assert_eq!(next.resolved.len(), 1);
        assert_eq!(next.resolved[0].outcome, PermissionOutcome::Deny);
    }

    #[tokio::test]
    async fn purge_expired_records_expiry_in_resolved_feed() {
        use hermod_protocol::ipc::methods::PermissionListResolvedParams;

        let (svc, _db) = make_service().await;
        // Inject an entry that's already past its expiry.
        {
            let mut state = svc.state.lock().await;
            let id = "aabba".to_string();
            state.by_id.insert(
                id.clone(),
                OpenRequest {
                    request_id: id,
                    tool_name: "Bash".into(),
                    description: String::new(),
                    input_preview: String::new(),
                    requested_at: Timestamp::now().offset_by_ms(-120_000),
                    expires_at: Timestamp::now().offset_by_ms(-60_000),
                    origin: PromptOrigin::Local,
                },
            );
        }

        // Calling list_resolved triggers purge.
        let res = svc
            .list_resolved(PermissionListResolvedParams::default())
            .await
            .unwrap();
        assert_eq!(res.resolved.len(), 1);
        assert_eq!(res.resolved[0].outcome, PermissionOutcome::Expired);
    }

    /// `list_resolved` reports the daemon's current `next_seq` so a cursor
    /// consumer can detect a monotonic-counter rewind (== daemon
    /// restart, since the in-memory ring is wiped).
    #[tokio::test]
    async fn list_resolved_reports_daemon_next_seq() {
        use hermod_protocol::ipc::methods::PermissionListResolvedParams;

        let (svc, _db) = make_service().await;
        let empty = svc
            .list_resolved(PermissionListResolvedParams::default())
            .await
            .unwrap();
        assert_eq!(empty.daemon_next_seq, 1, "fresh daemon: next_seq = 1");

        let r = svc.request(req_params("Bash")).await.unwrap();
        svc.respond(PermissionRespondParams {
            request_id: r.request_id,
            behavior: PermissionBehavior::Allow,
        })
        .await
        .unwrap();

        let after_one = svc
            .list_resolved(PermissionListResolvedParams::default())
            .await
            .unwrap();
        assert_eq!(after_one.resolved.len(), 1);
        assert_eq!(after_one.resolved[0].seq, 1);
        assert_eq!(
            after_one.daemon_next_seq, 2,
            "next_seq must be strictly greater than every resolved seq"
        );
    }

    /// Audit-log evidence: an expiration must produce one
    /// `permission.expired` row, just like allow/deny produce
    /// `permission.allow` / `permission.deny`. Otherwise operators can't
    /// distinguish "operator stalled" from "request silently timed out".
    #[tokio::test]
    async fn expiration_writes_permission_expired_audit_row() {
        use hermod_protocol::ipc::methods::PermissionListResolvedParams;

        let (svc, _db) = make_service().await;
        // Inject an expired open request.
        {
            let mut state = svc.state.lock().await;
            let id = "aacde".to_string();
            state.by_id.insert(
                id.clone(),
                OpenRequest {
                    request_id: id,
                    tool_name: "Bash".into(),
                    description: "list dir".into(),
                    input_preview: String::new(),
                    requested_at: Timestamp::now().offset_by_ms(-600_000),
                    expires_at: Timestamp::now().offset_by_ms(-1_000),
                    origin: PromptOrigin::Local,
                },
            );
        }

        // Trigger a purge.
        let _ = svc
            .list_resolved(PermissionListResolvedParams::default())
            .await
            .unwrap();

        let entries = _db
            .audit()
            .query(None, Some("permission.expired"), None, 16)
            .await
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].action, "permission.expired");
        assert_eq!(entries[0].target.as_deref(), Some("aacde"));
    }
}
