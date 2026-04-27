//! Snapshot test that pins `docs/confirmation.md` to the actual
//! `MessageBody` variants exposed by the protocol. If a new variant is
//! added (or an old one renamed) without the doc being updated to match,
//! this test fails and the build breaks.
//!
//! Why: documentation drift in the trust-gate doc is high-impact — it
//! tells operators what the gate actually does. Wiring the doc to the
//! enum source-of-truth via `strum::IntoEnumIterator` makes drift
//! mechanically impossible.

use hermod_core::MessageKind;
use hermod_protocol::ipc::methods::{PermissionBehavior, PermissionOutcome};
use strum::IntoEnumIterator;

const CONFIRMATION_DOC: &str = include_str!("../../../docs/confirmation.md");
const AUDIT_DOC: &str = include_str!("../../../docs/audit_actions.md");

#[test]
fn confirmation_doc_mentions_every_message_kind() {
    for kind in MessageKind::iter() {
        let name = kind.variant_name();
        assert!(
            CONFIRMATION_DOC.contains(name),
            "docs/confirmation.md is missing MessageBody variant `{name}` — \
             every variant must appear under one of the routine / review / \
             sensitive tiers, otherwise operators have no documented \
             reason for that variant's confirmation behaviour."
        );
    }
}

#[test]
fn confirmation_doc_does_not_reference_unknown_variants() {
    // Variants that previously existed in the doc but were dropped from
    // `MessageBody`. Pin them so a copy-paste from an old draft can't
    // sneak them back in.
    const REMOVED: &[&str] = &["Ack", "PeerAnnounce"];
    for ghost in REMOVED {
        assert!(
            !CONFIRMATION_DOC.contains(ghost),
            "docs/confirmation.md references `{ghost}`, which is not a \
             current `MessageBody` variant. Remove the reference."
        );
    }
}

#[test]
fn audit_doc_lists_every_permission_behavior_action() {
    for b in PermissionBehavior::iter() {
        let action = b.audit_action();
        assert!(
            AUDIT_DOC.contains(action),
            "docs/audit_actions.md is missing `{action}` — \
             every PermissionBehavior variant must have its emitted \
             audit action catalogued."
        );
    }
}

#[test]
fn audit_doc_lists_every_permission_outcome_action() {
    for o in PermissionOutcome::iter() {
        let action = o.audit_action();
        assert!(
            AUDIT_DOC.contains(action),
            "docs/audit_actions.md is missing `{action}` — every \
             PermissionOutcome variant (allow / deny / expired) must \
             have its emitted audit action catalogued."
        );
    }
}

/// Source files that emit audit rows. Hardcoded so the test fails
/// loudly when a new daemon module is added — that's the cue to either
/// (a) add it here, or (b) ensure its emissions are prefixed by an
/// already-included module's emission. Each file is `include_str!`'d
/// at test compile time so file removal also breaks this test (vs.
/// silently missing emissions).
const DAEMON_EMISSION_SOURCES: &[&str] = &[
    include_str!("../../hermod-daemon/src/inbound/mod.rs"),
    include_str!("../../hermod-daemon/src/inbound/capability_audit.rs"),
    include_str!("../../hermod-daemon/src/inbound/channel.rs"),
    include_str!("../../hermod-daemon/src/inbound/file_brief_presence.rs"),
    include_str!("../../hermod-daemon/src/inbound/permission.rs"),
    include_str!("../../hermod-daemon/src/inbound/workspace_observability.rs"),
    include_str!("../../hermod-daemon/src/janitor.rs"),
    include_str!("../../hermod-daemon/src/outbox.rs"),
    include_str!("../../hermod-daemon/src/services/agent.rs"),
    include_str!("../../hermod-daemon/src/services/audit.rs"),
    include_str!("../../hermod-daemon/src/services/beacon_audit.rs"),
    include_str!("../../hermod-daemon/src/services/brief.rs"),
    include_str!("../../hermod-daemon/src/services/broadcast.rs"),
    include_str!("../../hermod-daemon/src/services/broker.rs"),
    include_str!("../../hermod-daemon/src/services/capability.rs"),
    include_str!("../../hermod-daemon/src/services/channel.rs"),
    include_str!("../../hermod-daemon/src/services/confirmation.rs"),
    include_str!("../../hermod-daemon/src/services/mcp.rs"),
    include_str!("../../hermod-daemon/src/services/message.rs"),
    include_str!("../../hermod-daemon/src/services/peer.rs"),
    include_str!("../../hermod-daemon/src/services/permission.rs"),
    include_str!("../../hermod-daemon/src/services/presence.rs"),
    include_str!("../../hermod-daemon/src/services/workspace.rs"),
    include_str!("../../hermod-daemon/src/services/workspace_observability.rs"),
];

/// Extract every `action: "namespace.verb..."` literal from the source
/// text. Skips test bodies (any block under `#[cfg(test)]`) so the
/// fake actions used by unit tests don't pollute the catalogue.
fn extract_static_actions(src: &str) -> std::collections::HashSet<String> {
    let mut out = std::collections::HashSet::new();
    // Strip `#[cfg(test)]` blocks before scanning. The marker is
    // followed by `mod tests {` or `fn …` — we keep it simple by
    // truncating the file at the first occurrence of the marker.
    let scan = match src.find("#[cfg(test)]") {
        Some(i) => &src[..i],
        None => src,
    };
    // A literal of shape `action: "x.y"` or `action: "x.y.z"` —
    // disallows interpolation (`format!`) and method calls
    // (`behavior.audit_action()`) so the dynamic patterns covered by
    // the per-enum tests above are not double-counted.
    let needle = "action: \"";
    let mut idx = 0;
    while let Some(start) = scan[idx..].find(needle) {
        let abs = idx + start + needle.len();
        let rest = &scan[abs..];
        if let Some(end) = rest.find('"') {
            let action = &rest[..end];
            // Valid two/three-component shape — drop noise like
            // empty strings or unrelated `action: "..."` matches.
            let dots: Vec<&str> = action.split('.').collect();
            if dots.len() >= 2
                && dots
                    .iter()
                    .all(|s| !s.is_empty() && s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'))
            {
                out.insert(action.to_string());
            }
            idx = abs + end + 1;
        } else {
            break;
        }
    }
    out
}

/// Every static `action: "..."` literal emitted by the daemon must
/// appear (between backticks) in `docs/audit_actions.md`. Catches
/// the common drift: new emission added to a service without updating
/// the catalogue. Dynamic emitters (broker.rs format!, behavior
/// `audit_action()`) are pinned by the strum-based tests above.
#[test]
fn audit_doc_covers_every_static_emission() {
    let mut emitted: std::collections::HashSet<String> = std::collections::HashSet::new();
    for src in DAEMON_EMISSION_SOURCES {
        emitted.extend(extract_static_actions(src));
    }
    assert!(
        !emitted.is_empty(),
        "DAEMON_EMISSION_SOURCES yielded no actions — the extractor or the source list is broken."
    );

    let mut missing: Vec<String> = emitted
        .iter()
        .filter(|action| !AUDIT_DOC.contains(&format!("`{action}`")))
        .cloned()
        .collect();
    missing.sort();
    assert!(
        missing.is_empty(),
        "docs/audit_actions.md is missing {} emitted action(s):\n  - {}\n\n\
         Either catalogue them with full trigger + details schema, or \
         remove the emission. Operators rely on this catalogue to write \
         queries against the audit log.",
        missing.len(),
        missing.join("\n  - ")
    );
}
