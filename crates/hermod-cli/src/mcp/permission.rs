//! Claude Code Channels permission-relay bridge.
//!
//! ## Roles
//!
//! Two flows touch this module:
//!
//! 1. **Inbound prompt** (Claude Code → Hermod). Claude Code sends a
//!    `notifications/claude/channel/permission_request` over stdio when
//!    the host is about to call a tool that needs approval (Bash, Write,
//!    Edit, …). The MCP run loop dispatches it to
//!    [`forward_request_to_daemon`], which calls `permission.request` on
//!    the daemon, receives a 5-letter short id, and emits a
//!    `<channel kind="permission" …>` event so the operator sees what to
//!    approve.
//!
//! 2. **Verdict** (operator → Claude Code). The operator's reply
//!    eventually lands as a `permission.respond` RPC on the daemon. The
//!    daemon's permission service places a resolved-event into a small
//!    in-memory ring buffer; the MCP server polls this ring buffer via
//!    `permission.list_resolved` and emits the corresponding
//!    `notifications/claude/channel/permission` frame back to Claude Code.
//!
//! ## Why a ring-buffer cursor (not OpenSet diff, not long-poll)
//!
//! The daemon already has a single source of truth for resolved events
//! — its in-memory ring buffer with monotonic sequence numbers. Cursor
//! polling is the pattern used by the inbox / confirmation streams in
//! [`super::channel`], so adding a third cursor keeps the design
//! language consistent. Long-polling would deliver lower latency but at
//! the cost of new IPC machinery; we can switch to it if approval
//! latency ever shows up as a real complaint.

use anyhow::Result;
use hermod_protocol::ipc::methods::{
    PermissionListResolvedParams, PermissionRequestParams, PermissionRequestResult,
    PermissionResolvedView,
};
use serde_json::Value;

use crate::client::{ClientTarget, DaemonClient};

/// Parse an inbound `notifications/claude/channel/permission_request` and
/// return the typed params, or `None` if the message isn't shaped right.
/// Unknown extra fields are tolerated — the schema may grow.
pub fn parse_request_params(value: &Value) -> Option<PermissionRequestParams> {
    let params = value.get("params")?;
    Some(PermissionRequestParams {
        tool_name: params.get("tool_name")?.as_str()?.to_string(),
        description: params.get("description")?.as_str()?.to_string(),
        input_preview: params
            .get("input_preview")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
    })
}

/// Forward an inbound permission prompt to the daemon. Returns the daemon's
/// allocated short id + expiry so the caller can emit the operator-facing
/// channel event with those identifiers.
pub async fn forward_request_to_daemon(
    target: &ClientTarget,
    params: PermissionRequestParams,
) -> Result<PermissionRequestResult> {
    let mut client: DaemonClient = target.connect().await?;
    client.permission_request(params).await
}

/// Cursor over the daemon's resolved-events ring buffer. Holds the
/// highest `seq` value seen so far; on the next poll only newer entries
/// are returned. Reset to `None` to receive the full buffer once.
#[derive(Debug, Default, Clone)]
pub struct ResolvedCursor {
    after_seq: Option<u64>,
}

impl ResolvedCursor {
    pub fn new() -> Self {
        Self::default()
    }

    /// Pull the next batch of resolved events from the daemon and advance
    /// the cursor past the largest `seq` returned. Caller decides what to
    /// emit per entry (typically: an `allow` / `deny` verdict frame to
    /// Claude Code; nothing for `expired`).
    ///
    /// Detects daemon restarts: the daemon's monotonic seq counter is
    /// in-memory only, so a process restart resets it to 1. Without
    /// detection, our cursor would point past the (newly-empty) ring's
    /// max forever and silently lose every subsequent verdict. We
    /// reset the cursor to `None` whenever the daemon's reported
    /// `next_seq` is `<=` our own `after_seq` — the next poll then
    /// catches up the full current ring.
    pub async fn poll(
        &mut self,
        target: &ClientTarget,
        limit: u32,
    ) -> Result<Vec<PermissionResolvedView>> {
        let mut client: DaemonClient = target.connect().await?;
        let res = client
            .permission_list_resolved(PermissionListResolvedParams {
                after_seq: self.after_seq,
                limit: Some(limit),
            })
            .await?;

        if let Some(after) = self.after_seq
            && res.daemon_next_seq <= after
        {
            tracing::warn!(
                cursor = after,
                daemon_next_seq = res.daemon_next_seq,
                "permission cursor exceeds daemon next_seq — daemon restarted; resetting cursor"
            );
            self.after_seq = None;
            // Re-poll so the caller sees the now-current ring rather
            // than a misleadingly-empty batch.
            let res = client
                .permission_list_resolved(PermissionListResolvedParams {
                    after_seq: None,
                    limit: Some(limit),
                })
                .await?;
            if let Some(max) = res.resolved.iter().map(|e| e.seq).max() {
                self.after_seq = Some(max);
            }
            return Ok(res.resolved);
        }

        if let Some(max) = res.resolved.iter().map(|e| e.seq).max() {
            self.after_seq = Some(max);
        }
        Ok(res.resolved)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_request_params_happy_path() {
        let n = json!({
            "method": "notifications/claude/channel/permission_request",
            "params": {
                "request_id": "abcde",
                "tool_name": "Bash",
                "description": "list files",
                "input_preview": "{\"command\":\"ls\"}"
            }
        });
        let p = parse_request_params(&n).expect("must parse");
        assert_eq!(p.tool_name, "Bash");
        assert_eq!(p.description, "list files");
        assert!(p.input_preview.contains("ls"));
    }

    #[test]
    fn parse_request_params_tolerates_missing_input_preview() {
        let n = json!({
            "method": "notifications/claude/channel/permission_request",
            "params": {
                "tool_name": "Write",
                "description": "create file"
            }
        });
        let p = parse_request_params(&n).expect("must parse");
        assert_eq!(p.input_preview, "");
    }

    #[test]
    fn parse_request_params_rejects_missing_required_fields() {
        let bad = json!({"params": {"tool_name": "Bash"}});
        assert!(parse_request_params(&bad).is_none());
    }

}
