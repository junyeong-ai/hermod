//! Minimal MCP server speaking JSON-RPC 2.0 over stdio.
//!
//! Implements the Model Context Protocol (2025-03-26) plus three Claude
//! Code Channels capabilities:
//!
//!   * `experimental.claude/channel` — server-push of inbox + held
//!     confirmation events as `<channel kind="...">` blocks.
//!   * `experimental.claude/channel/permission` — bidirectional permission
//!     relay: inbound `permission_request` notifications get parked on the
//!     daemon (5-letter short id minted), surfaced to the operator, then
//!     the operator's verdict is forwarded back to Claude Code as
//!     `notifications/claude/channel/permission`.
//!   * `tools` — request/response surface for Claude (message_send,
//!     agent_list, presence_get, …).
//!
//! ## Concurrent paths sharing stdout
//!
//!   1. **Request/response loop** — `initialize`, `tools/list`, `tools/call`.
//!      Plus inbound notifications (no `id`) routed through
//!      [`route_notification`] for permission relay.
//!   2. **Channel emitter** — polls the daemon for inbox + held confirmations
//!      and emits one notification per new item.
//!   3. **Permission verdict emitter** — polls the daemon's resolved-events
//!      ring buffer and emits one verdict notification per resolved
//!      `(allow|deny)` request.
//!   4. **Session heartbeat** — keeps the daemon's `mcp_sessions` row alive
//!      so peer-side liveness flips correctly when we attach / detach.
//!
//! All writers serialise via a shared `Mutex<Stdout>`; line-delimited
//! framing prevents byte interleaving.

mod channel;
mod initialize;
mod notification;
mod permission;
mod session;
mod tools;

use anyhow::Result;
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Stdout};
use tokio::sync::Mutex;

use crate::client::ClientTarget;

use notification::{PERMISSION_REQUEST_METHOD, channel};
use session::Session;

/// How long we wait for `mcp.session_detach` on stdin EOF before giving up
/// and letting the janitor reap the row via TTL. The detach is best-effort —
/// hanging here on a slow daemon would just leak a few hundred ms of
/// "appears live" time, which the TTL handles anyway.
pub(crate) const DETACH_TIMEOUT: Duration = Duration::from_secs(1);

pub async fn run(target: &ClientTarget) -> Result<()> {
    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin);
    let stdout = Arc::new(Mutex::new(tokio::io::stdout()));
    let target = Arc::new(target.clone());
    let mut session: Option<Session> = None;
    let mut line = String::new();

    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let msg: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(e) => {
                write_json(
                    &stdout,
                    json!({
                        "jsonrpc":"2.0",
                        "id": Value::Null,
                        "error":{"code":-32700,"message":format!("parse error: {e}")}
                    }),
                )
                .await?;
                continue;
            }
        };

        // Route inbound notifications (no `id`) — permission relay lives here.
        if msg.get("id").is_none() {
            route_notification(&msg, target.as_ref(), &stdout).await;
            continue;
        }

        let req: Request = match serde_json::from_value(msg) {
            Ok(r) => r,
            Err(e) => {
                write_json(
                    &stdout,
                    json!({
                        "jsonrpc":"2.0",
                        "id": Value::Null,
                        "error":{"code":-32600,"message":format!("invalid request: {e}")}
                    }),
                )
                .await?;
                continue;
            }
        };

        let is_initialize = req.method == "initialize";
        let client_info = if is_initialize {
            extract_client_info(req.params.as_ref())
        } else {
            None
        };
        let resp = handle(req, target.as_ref()).await;
        write_json(&stdout, resp).await?;

        // Per the MCP spec the server may begin sending server-initiated
        // notifications after replying to `initialize`. Attach the session,
        // start heartbeat + emitters exactly once.
        if is_initialize && session.is_none() {
            session = Some(Session::start(target.clone(), stdout.clone(), client_info).await);
        }
    }

    // stdin closed → Claude Code is shutting us down. Detach + abort the
    // background tasks so the daemon flips us to offline immediately
    // instead of waiting for the heartbeat TTL.
    if let Some(s) = session {
        s.shutdown().await;
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub(crate) struct Request {
    jsonrpc: String,
    id: Value,
    method: String,
    #[serde(default)]
    params: Option<Value>,
}

async fn handle(req: Request, target: &ClientTarget) -> Value {
    match req.method.as_str() {
        "initialize" => initialize::response(req.id, env!("CARGO_PKG_VERSION")),
        "tools/list" => json!({
            "jsonrpc":"2.0",
            "id": req.id,
            "result": { "tools": tools::schemas() }
        }),
        "tools/call" => tools::dispatch(req.id, req.params.unwrap_or(Value::Null), target).await,
        other => json!({
            "jsonrpc":"2.0",
            "id": req.id,
            "error": {
                "code": -32601,
                "message": format!("method not found: {other}"),
            }
        }),
    }
}

/// Dispatch an inbound JSON-RPC notification. Currently the only
/// notification Claude Code sends to us is `permission_request`; anything
/// else (including stdlib MCP `notifications/initialized`) is silently
/// dropped, which matches MCP's "no-id messages have no response"
/// semantic.
async fn route_notification(msg: &Value, target: &ClientTarget, stdout: &Arc<Mutex<Stdout>>) {
    let Some(method) = msg.get("method").and_then(|v| v.as_str()) else {
        return;
    };
    if method == PERMISSION_REQUEST_METHOD {
        handle_permission_request(msg, target, stdout).await;
    }
}

/// Handle `notifications/claude/channel/permission_request`: forward to
/// the daemon, then emit the operator-facing channel event so whoever
/// is on call sees the prompt + the 5-letter short id to type back.
async fn handle_permission_request(
    msg: &Value,
    target: &ClientTarget,
    stdout: &Arc<Mutex<Stdout>>,
) {
    let Some(params) = permission::parse_request_params(msg) else {
        tracing::warn!("dropping malformed permission_request notification");
        return;
    };
    let tool_name = params.tool_name.clone();
    let description = params.description.clone();
    let input_preview = params.input_preview.clone();

    let opened = match permission::forward_request_to_daemon(target, params).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "permission.request failed; dropping prompt");
            return;
        }
    };

    let body = format!(
        "Claude wants to run {tool_name}: {description}\n\n\
         Reply \"yes {id}\" or \"no {id}\".",
        id = opened.request_id
    );
    let meta = json!({
        "kind": "permission",
        "request_id": opened.request_id,
        "tool_name": tool_name,
        "description": description,
        "input_preview": input_preview,
    });
    if let Err(e) = write_json(stdout, channel(body, meta)).await {
        tracing::warn!(error = %e, "failed to emit permission channel event");
    }
}

#[derive(Default, Clone, Debug)]
pub(crate) struct ClientInfo {
    pub name: Option<String>,
    pub version: Option<String>,
}

fn extract_client_info(params: Option<&Value>) -> Option<ClientInfo> {
    let info = params?.get("clientInfo")?;
    Some(ClientInfo {
        name: info
            .get("name")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        version: info
            .get("version")
            .and_then(|v| v.as_str())
            .map(str::to_string),
    })
}

pub(crate) async fn write_json(stdout: &Arc<Mutex<Stdout>>, value: Value) -> Result<()> {
    let mut line = serde_json::to_string(&value)?;
    line.push('\n');
    let mut guard = stdout.lock().await;
    guard.write_all(line.as_bytes()).await?;
    guard.flush().await?;
    Ok(())
}
