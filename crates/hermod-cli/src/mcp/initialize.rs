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
//! The instructions prelude (event kinds + reply vocabulary) is
//! byte-for-byte stable; tests pin it so Claude's behaviour can't drift
//! just because someone tweaked the prose. The leading identity stanza
//! (agent_id / alias / host) is per-session — it lets Claude know
//! which Hermod agent it is speaking *for* on this stdio.

use hermod_protocol::ipc::methods::IdentityGetResult;
use serde_json::{Value, json};

/// Protocol version negotiated with Claude Code on `initialize`.
pub const MCP_PROTOCOL_VERSION: &str = "2025-03-26";

/// Static prelude — event kinds, attribute reference, and reply
/// vocabulary. Identical across sessions so Claude's behaviour stays
/// stable; the per-session identity stanza is prepended at runtime.
///
/// Authoring rules (so this stays useful as the surface grows):
///   * One line per `kind` value — keep it scannable.
///   * Reply tools named exactly as registered in [`super::tools::schemas`].
///   * No examples that quote real data; the schema description is enough.
pub const INSTRUCTIONS_PRELUDE: &str = "\
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
  - `from_host`          8-char prefix of the sender's host pubkey, for \
cross-host disambiguation when local aliases collide.
  - `from_live`          `true` iff `from` has a Claude Code session attached.
  - `priority`           For `direct` events only.

When in doubt, prefer reading state with `agent_list` / `presence_get` / \
`message_list` over guessing.";

/// Build the per-session instructions string. Prepends an identity
/// stanza so Claude knows which agent it speaks for on this stdio,
/// then concatenates [`INSTRUCTIONS_PRELUDE`] verbatim.
///
/// `identity = None` (daemon unreachable at startup) falls back to
/// the static prelude alone — the supervisor will retry attach and
/// the bridge will keep working; the identity stanza simply doesn't
/// appear that session.
pub fn build_instructions(identity: Option<&IdentityGetResult>) -> String {
    let Some(id) = identity else {
        return INSTRUCTIONS_PRELUDE.to_string();
    };
    let alias_line = match id.alias.as_ref() {
        Some(a) => format!("  - alias:        {}\n", a.as_str()),
        None => String::new(),
    };
    let host_short: String = id.host_pubkey_hex.chars().take(8).collect();
    format!(
        "You are speaking for the Hermod agent on this stdio:\n  \
         - agent_id:     {agent}\n\
         {alias_line}  - fingerprint:  {fp}\n  \
         - host:         {host}\n\n\
         {prelude}",
        agent = id.agent_id,
        fp = id.fingerprint,
        host = host_short,
        prelude = INSTRUCTIONS_PRELUDE,
    )
}

/// Build the `initialize` JSON-RPC response.
pub fn response(id: Value, version: &str, identity: Option<&IdentityGetResult>) -> Value {
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
            "instructions": build_instructions(identity),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hermod_core::{AgentAlias, AgentId};
    use std::str::FromStr;

    fn sample_identity() -> IdentityGetResult {
        IdentityGetResult {
            agent_id: AgentId::from_str("bc57yc7fmoidqeomcxvyszkalo").unwrap(),
            alias: Some(AgentAlias::from_str("projA").unwrap()),
            fingerprint: "ab:cd:ef:01:23:45:67:89".into(),
            host_pubkey_hex: "deadbeefcafebabe1122334455667788\
                              99aabbccddeeff0011223344556677"
                .into(),
        }
    }

    #[test]
    fn response_advertises_both_channel_capabilities() {
        let v = response(serde_json::json!(1), "0.1.0", None);
        let exp = &v["result"]["capabilities"]["experimental"];
        assert!(exp.get("claude/channel").is_some());
        assert!(exp.get("claude/channel/permission").is_some());
        assert!(v["result"]["capabilities"].get("tools").is_some());
    }

    #[test]
    fn instructions_without_identity_match_prelude_verbatim() {
        let v = response(serde_json::json!(1), "0.1.0", None);
        let s = v["result"]["instructions"]
            .as_str()
            .expect("instructions must be present");
        assert_eq!(s, INSTRUCTIONS_PRELUDE);
    }

    #[test]
    fn instructions_with_identity_carry_agent_alias_and_host() {
        let id = sample_identity();
        let s = build_instructions(Some(&id));
        assert!(s.contains("bc57yc7fmoidqeomcxvyszkalo"));
        assert!(s.contains("projA"));
        // 8-char host prefix.
        assert!(s.contains("deadbeef"));
        assert!(!s.contains("ddeeff00"));
        // Prelude still embedded.
        assert!(s.contains("Event kinds:"));
        assert!(s.contains("message_send"));
    }

    #[test]
    fn prelude_documents_every_event_kind_and_reply_tool() {
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
            // Cross-host disambiguation surface.
            "from_host",
        ] {
            assert!(
                INSTRUCTIONS_PRELUDE.contains(needle),
                "instructions prelude must mention `{needle}`"
            );
        }
    }

    #[test]
    fn protocol_version_is_pinned() {
        assert_eq!(MCP_PROTOCOL_VERSION, "2025-03-26");
    }
}
