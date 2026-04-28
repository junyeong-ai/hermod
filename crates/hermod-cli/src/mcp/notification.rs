//! Single source of truth for outbound `notifications/claude/channel*`
//! frames. Every server-push notification flows through this module so
//! the wire shape stays consistent.
//!
//! ## Why `source` is omitted
//!
//! Claude Code derives the `<channel source="…">` attribute automatically
//! from the MCP server's `serverInfo.name`. Including it under `params`
//! is silently dropped (per the Channels reference) — it would only
//! create a misleading "we're stamping the source" impression in logs.
//!
//! ## Meta keys
//!
//! Channel meta keys must be identifiers (`[A-Za-z0-9_]+`); anything else
//! is silently dropped. The [`channel`] builder enforces this with a
//! release-mode `assert!` — a hyphen or dot is a hard programming error,
//! not a silent dropped attribute.
//!
//! ## Verdict ids
//!
//! `permission_verdict` validates the `request_id` against the
//! `[a-km-z]{5}` short-id alphabet and the `behavior` against the
//! [`PermissionBehavior`] enum. Both invariants are enforced at the
//! type system or assert level so a corrupted in-memory id can't
//! escape onto the wire.

use hermod_crypto::short_id;
use hermod_protocol::ipc::methods::PermissionBehavior;
use serde_json::{Map, Value, json};

/// Method name for the channel-event notification.
pub const CHANNEL_METHOD: &str = "notifications/claude/channel";

/// Method name for the inbound permission-request notification.
pub const PERMISSION_REQUEST_METHOD: &str = "notifications/claude/channel/permission_request";

/// Method name for the outbound permission-verdict notification.
pub const PERMISSION_VERDICT_METHOD: &str = "notifications/claude/channel/permission";

/// Build a `notifications/claude/channel` frame.
///
/// `meta` keys must be identifiers; the assert is on by default in
/// release builds because a non-identifier key is a bug — Claude Code
/// silently drops the offending attribute and the channel context Claude
/// sees would be subtly wrong, which is exactly the kind of failure
/// mode that justifies failing loud. `null` values are stripped —
/// Claude Code drops them silently anyway, and the noise breaks log
/// diffs.
pub fn channel(content: String, meta: Value) -> Value {
    let pruned = strip_nulls(meta);
    assert!(
        validate_meta_keys(&pruned),
        "channel notification meta has non-identifier keys: {pruned}"
    );
    json!({
        "jsonrpc": "2.0",
        "method": CHANNEL_METHOD,
        "params": {
            "content": content,
            "meta": pruned,
        }
    })
}

/// Build the verdict notification Claude Code expects when an operator
/// answers a permission prompt. The `request_id` must match the
/// `[a-km-z]{5}` short-id alphabet — a malformed id reaching this point
/// is a daemon-side corruption, not user input, so we assert. `behavior`
/// is taken as the typed enum so any new variant is a compile error
/// here, not a silent JSON typo.
pub fn permission_verdict(request_id: &str, behavior: PermissionBehavior) -> Value {
    assert!(
        short_id::is_valid(request_id),
        "permission verdict received non-alphabet request_id `{request_id}`"
    );
    json!({
        "jsonrpc": "2.0",
        "method": PERMISSION_VERDICT_METHOD,
        "params": {
            "request_id": request_id,
            "behavior": behavior.as_str(),
        }
    })
}

/// Drop entries whose value is `null`. Operates on the meta object only;
/// nested objects are left as-is because the wire schema is flat.
fn strip_nulls(meta: Value) -> Value {
    match meta {
        Value::Object(m) => {
            let kept: Map<String, Value> = m.into_iter().filter(|(_, v)| !v.is_null()).collect();
            Value::Object(kept)
        }
        other => other,
    }
}

/// Verify every key in a `meta` object matches `[A-Za-z0-9_]+`. Returns
/// `true` iff the input is a non-empty object whose keys all qualify.
/// Non-objects return `true` (nothing to check).
pub fn validate_meta_keys(meta: &Value) -> bool {
    let Some(obj) = meta.as_object() else {
        return true;
    };
    obj.keys()
        .all(|k| !k.is_empty() && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_omits_source_field() {
        let v = channel("hi".into(), json!({"kind": "direct"}));
        assert!(
            v["params"].get("source").is_none(),
            "params.source must be omitted; Claude Code derives it from serverInfo.name"
        );
    }

    #[test]
    fn channel_includes_content_and_meta() {
        let v = channel("hi".into(), json!({"kind": "direct", "id": "abc"}));
        assert_eq!(v["jsonrpc"], "2.0");
        assert_eq!(v["method"], CHANNEL_METHOD);
        assert_eq!(v["params"]["content"], "hi");
        assert_eq!(v["params"]["meta"]["kind"], "direct");
    }

    #[test]
    fn channel_strips_null_meta_values() {
        let v = channel(
            "hi".into(),
            json!({"kind": "direct", "from_local_alias": null, "id": "abc"}),
        );
        let meta = &v["params"]["meta"];
        assert!(meta.get("from_local_alias").is_none());
        assert_eq!(meta["kind"], "direct");
    }

    #[test]
    fn permission_verdict_shape() {
        let v = permission_verdict("abcde", PermissionBehavior::Allow);
        assert_eq!(v["method"], PERMISSION_VERDICT_METHOD);
        assert_eq!(v["params"]["request_id"], "abcde");
        assert_eq!(v["params"]["behavior"], "allow");
    }

    #[test]
    fn permission_verdict_serialises_deny() {
        let v = permission_verdict("zwxyk", PermissionBehavior::Deny);
        assert_eq!(v["params"]["behavior"], "deny");
    }

    #[test]
    #[should_panic(expected = "non-alphabet request_id")]
    fn permission_verdict_rejects_non_alphabet_id() {
        // Contains the forbidden `l`.
        let _ = permission_verdict("ablde", PermissionBehavior::Allow);
    }

    #[test]
    fn channel_assert_runs_in_release_too() {
        // In release builds debug_assert! is a no-op; assert! is not.
        // This test guarantees the channel builder catches bad meta in
        // both profiles by triggering a panic on a hyphenated key.
        let res = std::panic::catch_unwind(|| channel("hi".into(), json!({"chat-id": "x"})));
        assert!(
            res.is_err(),
            "hyphenated meta key must panic in any profile"
        );
    }

    #[test]
    fn validate_meta_keys_accepts_identifiers() {
        assert!(validate_meta_keys(&json!({"kind": "x", "from_alias": "y"})));
    }

    #[test]
    fn validate_meta_keys_rejects_hyphen_and_dot() {
        assert!(!validate_meta_keys(&json!({"chat-id": "x"})));
        assert!(!validate_meta_keys(&json!({"chat.id": "x"})));
    }
}
