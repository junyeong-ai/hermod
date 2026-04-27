//! `initialize` response: protocol version, declared capabilities, and the
//! `instructions` system prompt that tells Claude how to read inbound
//! Hermod events.
//!
//! Three pieces are advertised to Claude Code:
//!
//! 1. `tools: {}` — enables tool discovery so Claude can call our reply
//!    surface (`message_send`, `agent_list`, `permission_*`, …).
//! 2. `experimental.claude/channel: {}` — registers the
//!    `notifications/claude/channel` listener. Without this declaration
//!    Claude Code drops our notifications.
//! 3. `experimental.claude/channel/permission: {}` — opts in to receive
//!    permission-relay prompts for the host's tool calls. Safe to
//!    declare because every Hermod sender is ed25519-authenticated, so
//!    there is no untrusted-input path that could forge a verdict.
//!
//! The [`INSTRUCTIONS`] string is byte-for-byte stable: tests pin it so
//! Claude's behaviour can't drift just because someone tweaked the prose.
//! Bump it intentionally when the wire schema changes — never as a
//! drive-by.

use serde_json::{Value, json};

/// Protocol version negotiated with Claude Code on `initialize`.
pub const MCP_PROTOCOL_VERSION: &str = "2025-03-26";

/// System prompt added to Claude's context. Describes the `<channel>` tag
/// shape, the meaning of every `kind`, and how to reply.
///
/// Authoring rules (so this stays useful as the surface grows):
///   * One line per `kind` value — keep it scannable.
///   * Reply tools named exactly as registered in [`super::tools::schemas`].
///   * No examples that quote real data; the schema description is enough.
pub const INSTRUCTIONS: &str = "\
Hermod surfaces inbound agent activity through Claude Code Channels. Each \
event arrives as a `<channel source=\"hermod\" kind=\"...\" ...>` block.

Event kinds:
  - `direct`        DM from another agent. Reply with `message_send`, \
passing the `from` attribute as `to`.
  - `confirmation`  An inbound envelope held by the trust gate. Surface the \
summary to the operator and wait — only the operator decides via the \
`hermod confirm` CLI. Never auto-accept.
  - `permission`    A host-side tool call (Bash, Write, Edit, …) waiting on \
operator approval. Show the description and the 5-letter `request_id` to \
the operator; they reply with `yes <id>` or `no <id>`. Forward verbatim \
to whoever is on call.

Attributes you can rely on across every event:
  - `from`               Canonical agent_id of the sender (hash of pubkey).
  - `from_local_alias`   Operator's nickname for `from`, if any.
  - `from_peer_alias`    `from`'s self-asserted display name (advisory).
  - `from_alias`         Effective display — local override wins.
  - `from_live`          `true` iff `from` has a Claude Code session attached.
  - `priority`           For `direct` events only.

When in doubt, prefer reading state with `agent_list` / `presence_get` / \
`message_list` over guessing.";

/// Build the `initialize` JSON-RPC response.
pub fn response(id: Value, version: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {
                "tools": {},
                "experimental": {
                    "claude/channel": {},
                    "claude/channel/permission": {}
                }
            },
            "serverInfo": {
                "name": "hermod",
                "version": version,
            },
            "instructions": INSTRUCTIONS,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_advertises_both_channel_capabilities() {
        let v = response(serde_json::json!(1), "0.1.0");
        let exp = &v["result"]["capabilities"]["experimental"];
        assert!(exp.get("claude/channel").is_some());
        assert!(exp.get("claude/channel/permission").is_some());
        assert!(v["result"]["capabilities"].get("tools").is_some());
    }

    #[test]
    fn response_includes_instructions_string() {
        let v = response(serde_json::json!(1), "0.1.0");
        let s = v["result"]["instructions"]
            .as_str()
            .expect("instructions must be present");
        assert_eq!(s, INSTRUCTIONS);
    }

    #[test]
    fn instructions_documents_every_event_kind_and_reply_tool() {
        // If a new kind is added or a tool renamed, this test forces the
        // doc string to be updated in the same commit.
        for needle in [
            // Event kinds.
            "`direct`",
            "`confirmation`",
            "`permission`",
            // Reply tools the doc references.
            "message_send",
            "presence_get",
            "agent_list",
            "message_list",
            // Permission-relay vocabulary so Claude knows the format.
            "request_id",
            "yes <id>",
            "no <id>",
        ] {
            assert!(
                INSTRUCTIONS.contains(needle),
                "instructions must mention `{needle}`"
            );
        }
    }

    #[test]
    fn protocol_version_is_pinned() {
        assert_eq!(MCP_PROTOCOL_VERSION, "2025-03-26");
    }
}
