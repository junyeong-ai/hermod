//! Operator-configured auto-approve overlays.
//!
//! Two surfaces, both **downgrade-only**:
//!
//!   * **`[[auto_approve.confirmation]]`** rides on top of the
//!     `confirmation::decide` matrix. When the gate would surface a
//!     prompt to the operator (`Verdict::Confirm`) and a rule
//!     matches the inbound, the verdict is downgraded to `Accept`
//!     and the audit log records `confirmation.auto_accept` with
//!     the rule name. `Reject` is never crossed — there's no rule
//!     vocabulary that lets an operator turn a rejected envelope
//!     into an accepted one.
//!
//!   * **`[[auto_approve.permission]]`** intercepts a freshly-opened
//!     `permission.request`. When the call's `tool_name` is on the
//!     rule's allowlist *and* the caller's `agent_id` matches the
//!     rule's `origin`, the prompt is auto-resolved with `Allow`
//!     and the audit log records `permission.auto_allow`. The
//!     compile-time `FORBIDDEN_TOOL_NAMES` blocks any rule that
//!     names `Bash` / `Write` / `Edit` / `NotebookEdit` — those
//!     tools modify host state outside the operator's review
//!     budget; auto-allowing them on Hermod's surface would defeat
//!     Claude Code's prompt purpose.
//!
//! ## Heuristic discipline
//!
//! Both surfaces share the [`crate::dispatch::RuleCondition`]
//! vocabulary — operators learn one rule grammar across PR-2
//! (Smart Routing) and PR-3 (auto-approve). No regex matchers, no
//! glob, no `input` field on permission rules. The available
//! primitives are exact set-membership / numeric / case-insensitive
//! substring with bounded keyword length, and every condition is
//! validated at boot.
//!
//! ## Type-system enforcement
//!
//! [`AutoApproveOutcome`] has only `NoOp`, `Accept { rule }`, and
//! `Allow { rule }`. There is no variant that escalates `Reject`,
//! and no caller in the workspace can construct one — exhaustive
//! match in the gate code rules out the case at compile time.
//!
//! [`PermissionRule`] has no `input` / regex / glob field. An LLM
//! crafting messages that match an `input` predicate is a
//! well-understood escape vector for tool-restriction systems;
//! the type just doesn't expose the surface.

use hermod_core::AgentId;
use serde::{Deserialize, Serialize};

use crate::dispatch::{RouteContext, RuleCondition, evaluate as evaluate_condition};

/// Tools the daemon will never auto-allow regardless of operator
/// rules. Compile-time so a `[[auto_approve.permission]]` block
/// that names any of these aborts daemon boot via
/// [`AutoApproveConfig::validate`].
///
/// These four cover the destructive / shell-execution surface in
/// Claude Code's bundled tool set. An operator who genuinely wants
/// hands-off shell access runs a shell, not Claude Code; Hermod's
/// auto-approve surface intentionally has no escape hatch.
pub const FORBIDDEN_TOOL_NAMES: &[&str] = &["Bash", "Write", "Edit", "NotebookEdit"];

/// Confirmation-gate overlay rule. When an inbound matches
/// `condition` AND the underlying gate's verdict is `Confirm`, the
/// gate downgrades to `Accept`. Verbatim audit row records `name`
/// so the operator's review trail shows *which* rule fired.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfirmationRule {
    pub name: String,
    pub condition: RuleCondition,
}

/// Permission-relay overlay rule. When a freshly-opened
/// `permission.request` carries a `tool_name` in `tool_names` AND
/// the caller's `agent_id` equals `origin`, the daemon resolves
/// the prompt with `Allow` immediately.
///
/// **Origin is `AgentId`, not alias.** The agent_id is a
/// self-certifying derivation of the agent's pubkey; aliases are
/// mutable display labels. Pinning the rule to the stable identity
/// rules out alias-rebind attacks where a peer rebinds an alias to
/// a different agent and the auto-allow rule starts firing for
/// the wrong identity.
///
/// **`tool_names` is an allowlist, not a regex.** No glob, no
/// substring, no input matcher — exact equality. An LLM-craftable
/// matcher is the wrong primitive on this trust surface; an
/// operator who wants more flexibility expands the list rather
/// than introducing a predicate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionRule {
    pub name: String,
    pub origin: AgentId,
    pub tool_names: Vec<String>,
}

/// Operator config block. Empty `confirmation` + `permission` ⇒
/// no overlay (default). The daemon constructs an
/// [`AutoApproveOverlay`] from a *validated* config — boot calls
/// [`AutoApproveConfig::validate`] before any service sees it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutoApproveConfig {
    #[serde(default)]
    pub confirmation: Vec<ConfirmationRule>,
    #[serde(default)]
    pub permission: Vec<PermissionRule>,
}

/// Boot-validation errors. Every variant fails-loud — the daemon
/// refuses to start so a typo or forbidden-tool slip never
/// silently weakens the trust floor.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum AutoApproveConfigError {
    #[error("auto_approve.confirmation rule name is empty")]
    EmptyConfirmationName,
    #[error("auto_approve.confirmation rule names duplicate `{0}`")]
    DuplicateConfirmationName(String),
    #[error("auto_approve.permission rule name is empty")]
    EmptyPermissionName,
    #[error("auto_approve.permission rule names duplicate `{0}`")]
    DuplicatePermissionName(String),
    #[error("auto_approve.permission rule `{rule}` has empty tool_names list")]
    EmptyToolNames { rule: String },
    #[error(
        "auto_approve.permission rule `{rule}` names forbidden tool `{tool}` — \
         {tool} is in FORBIDDEN_TOOL_NAMES and cannot be auto-allowed"
    )]
    ForbiddenTool { rule: String, tool: String },
    #[error(transparent)]
    BadCondition(#[from] crate::dispatch::RoutingConfigError),
}

impl AutoApproveConfig {
    /// Boot-time validation. Caller invokes before constructing
    /// the overlay; the daemon refuses to start on any error.
    pub fn validate(&self) -> Result<(), AutoApproveConfigError> {
        let mut seen = std::collections::HashSet::new();
        for rule in &self.confirmation {
            if rule.name.is_empty() {
                return Err(AutoApproveConfigError::EmptyConfirmationName);
            }
            if !seen.insert(rule.name.clone()) {
                return Err(AutoApproveConfigError::DuplicateConfirmationName(
                    rule.name.clone(),
                ));
            }
            // Reuse the dispatch-rule condition validator. Every
            // bound (oversized keyword, duplicate condition,
            // degenerate time window) applies identically here.
            crate::dispatch::validate_condition_public(&rule.name, &rule.condition)?;
        }
        let mut seen = std::collections::HashSet::new();
        for rule in &self.permission {
            if rule.name.is_empty() {
                return Err(AutoApproveConfigError::EmptyPermissionName);
            }
            if !seen.insert(rule.name.clone()) {
                return Err(AutoApproveConfigError::DuplicatePermissionName(
                    rule.name.clone(),
                ));
            }
            if rule.tool_names.is_empty() {
                return Err(AutoApproveConfigError::EmptyToolNames {
                    rule: rule.name.clone(),
                });
            }
            for tool in &rule.tool_names {
                if FORBIDDEN_TOOL_NAMES.contains(&tool.as_str()) {
                    return Err(AutoApproveConfigError::ForbiddenTool {
                        rule: rule.name.clone(),
                        tool: tool.clone(),
                    });
                }
            }
        }
        Ok(())
    }
}

/// Outcome of a single overlay check. **Downgrade-only by
/// construction**: there is no variant that escalates `Reject`,
/// and exhaustive `match` in the gate code makes the absent case
/// a compile-time error. `rule` is the matched rule's name —
/// surfaced verbatim on the audit row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AutoApproveOutcome {
    /// No rule matched. The gate proceeds with its underlying verdict.
    NoOp,
    /// Confirmation overlay matched: downgrade `Confirm` ⇒ `Accept`.
    Accept { rule: String },
    /// Permission overlay matched: resolve `Request` ⇒ `Allow`.
    Allow { rule: String },
}

/// Constructed once at daemon boot from a validated
/// [`AutoApproveConfig`]. The overlay is `Send + Sync` and held
/// behind an `Arc` by services that consult it.
#[derive(Debug, Clone, Default)]
pub struct AutoApproveOverlay {
    confirmation: Vec<ConfirmationRule>,
    permission: Vec<PermissionRule>,
}

impl AutoApproveOverlay {
    /// Construct from a validated config. Caller is expected to
    /// have invoked `cfg.validate()` first — debug builds assert.
    pub fn new(cfg: AutoApproveConfig) -> Self {
        debug_assert!(cfg.validate().is_ok(), "AutoApproveOverlay: invalid config");
        Self {
            confirmation: cfg.confirmation,
            permission: cfg.permission,
        }
    }

    /// Confirmation overlay. **Only invoked when the underlying
    /// gate's verdict is `Confirm`** — the caller's exhaustive
    /// match on the verdict guarantees we never see `Reject` /
    /// `Accept` here. Returns `Accept { rule }` if a rule
    /// matches; `NoOp` otherwise.
    pub fn check_confirmation(&self, ctx: &RouteContext<'_>) -> AutoApproveOutcome {
        for rule in &self.confirmation {
            if evaluate_condition(&rule.condition, ctx, /* utc_offset = */ 0) {
                return AutoApproveOutcome::Accept {
                    rule: rule.name.clone(),
                };
            }
        }
        AutoApproveOutcome::NoOp
    }

    /// Permission overlay. Matches when (caller's `agent_id` ==
    /// rule.origin) AND (`tool_name` ∈ rule.tool_names). Exact
    /// equality on both axes — no regex, no substring.
    pub fn check_permission(&self, caller: &AgentId, tool_name: &str) -> AutoApproveOutcome {
        for rule in &self.permission {
            if rule.origin == *caller && rule.tool_names.iter().any(|t| t == tool_name) {
                return AutoApproveOutcome::Allow {
                    rule: rule.name.clone(),
                };
            }
        }
        AutoApproveOutcome::NoOp
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatch::RuleCondition;
    use hermod_core::{MessageBody, MessageId, MessageKind, MessagePriority, TrustLevel};

    fn agent(b: u8) -> AgentId {
        let mut s = String::with_capacity(26);
        s.push((b'a' + (b % 24)) as char);
        s.push_str(&"a".repeat(25));
        AgentId::from_raw(s)
    }

    fn ctx<'a>(
        kind: MessageKind,
        body: &'a MessageBody,
        from: &'a AgentId,
        to: &'a AgentId,
        trust: TrustLevel,
    ) -> RouteContext<'a> {
        RouteContext {
            message_id: MessageId::new(),
            from,
            recipient: to,
            kind,
            priority: MessagePriority::Normal,
            trust,
            body,
            session_active: true,
            now_unix_ms: 0,
        }
    }

    #[test]
    fn forbidden_tool_aborts_validation() {
        let cfg = AutoApproveConfig {
            confirmation: vec![],
            permission: vec![PermissionRule {
                name: "loud-bash".into(),
                origin: agent(1),
                tool_names: vec!["Bash".into()],
            }],
        };
        let err = cfg.validate().unwrap_err();
        match err {
            AutoApproveConfigError::ForbiddenTool { rule, tool } => {
                assert_eq!(rule, "loud-bash");
                assert_eq!(tool, "Bash");
                // Error message must contain "forbidden" so e2e
                // regex matchers pin the rejection cause without
                // coupling to exact phrasing.
                let msg = AutoApproveConfigError::ForbiddenTool {
                    rule: "loud-bash".into(),
                    tool: "Bash".into(),
                }
                .to_string();
                assert!(msg.contains("forbidden"));
                assert!(msg.contains("Bash"));
            }
            other => panic!("expected ForbiddenTool, got {other:?}"),
        }
    }

    #[test]
    fn every_forbidden_tool_is_rejected() {
        for tool in FORBIDDEN_TOOL_NAMES {
            let cfg = AutoApproveConfig {
                confirmation: vec![],
                permission: vec![PermissionRule {
                    name: "x".into(),
                    origin: agent(1),
                    tool_names: vec![(*tool).into()],
                }],
            };
            assert!(
                matches!(
                    cfg.validate(),
                    Err(AutoApproveConfigError::ForbiddenTool { .. })
                ),
                "tool {tool} must be rejected"
            );
        }
    }

    #[test]
    fn empty_tool_names_is_rejected() {
        let cfg = AutoApproveConfig {
            confirmation: vec![],
            permission: vec![PermissionRule {
                name: "x".into(),
                origin: agent(1),
                tool_names: vec![],
            }],
        };
        assert!(matches!(
            cfg.validate(),
            Err(AutoApproveConfigError::EmptyToolNames { .. })
        ));
    }

    #[test]
    fn duplicate_rule_names_are_rejected() {
        let cfg = AutoApproveConfig {
            confirmation: vec![
                ConfirmationRule {
                    name: "dup".into(),
                    condition: RuleCondition::SessionActive,
                },
                ConfirmationRule {
                    name: "dup".into(),
                    condition: RuleCondition::SessionActive,
                },
            ],
            permission: vec![],
        };
        assert!(matches!(
            cfg.validate(),
            Err(AutoApproveConfigError::DuplicateConfirmationName(_))
        ));
    }

    #[test]
    fn confirmation_overlay_matches_by_condition() {
        let from = agent(1);
        let to = agent(2);
        let body = MessageBody::Direct { text: "hi".into() };
        let cfg = AutoApproveConfig {
            confirmation: vec![ConfirmationRule {
                name: "trust-tofu-direct".into(),
                condition: RuleCondition::All {
                    conditions: vec![
                        RuleCondition::KindIn {
                            kinds: vec![MessageKind::Direct],
                        },
                        RuleCondition::TrustIn {
                            trusts: vec![TrustLevel::Tofu],
                        },
                    ],
                },
            }],
            permission: vec![],
        };
        cfg.validate().unwrap();
        let overlay = AutoApproveOverlay::new(cfg);
        let outcome = overlay.check_confirmation(&ctx(
            MessageKind::Direct,
            &body,
            &from,
            &to,
            TrustLevel::Tofu,
        ));
        assert_eq!(
            outcome,
            AutoApproveOutcome::Accept {
                rule: "trust-tofu-direct".into()
            }
        );
    }

    #[test]
    fn confirmation_overlay_no_match_returns_noop() {
        let from = agent(1);
        let to = agent(2);
        let body = MessageBody::Direct { text: "hi".into() };
        let cfg = AutoApproveConfig {
            confirmation: vec![ConfirmationRule {
                name: "verified-only".into(),
                condition: RuleCondition::TrustIn {
                    trusts: vec![TrustLevel::Verified],
                },
            }],
            permission: vec![],
        };
        cfg.validate().unwrap();
        let overlay = AutoApproveOverlay::new(cfg);
        let outcome = overlay.check_confirmation(&ctx(
            MessageKind::Direct,
            &body,
            &from,
            &to,
            TrustLevel::Tofu, // not Verified
        ));
        assert_eq!(outcome, AutoApproveOutcome::NoOp);
    }

    #[test]
    fn permission_overlay_matches_on_origin_and_allowlist() {
        let alice = agent(1);
        let bob = agent(2);
        let cfg = AutoApproveConfig {
            confirmation: vec![],
            permission: vec![PermissionRule {
                name: "alice-read-only".into(),
                origin: alice.clone(),
                tool_names: vec!["Read".into(), "Glob".into(), "Grep".into()],
            }],
        };
        cfg.validate().unwrap();
        let overlay = AutoApproveOverlay::new(cfg);
        // Origin matches + tool on allowlist ⇒ Allow.
        assert_eq!(
            overlay.check_permission(&alice, "Read"),
            AutoApproveOutcome::Allow {
                rule: "alice-read-only".into()
            }
        );
        // Origin matches but tool not on allowlist ⇒ NoOp.
        assert_eq!(
            overlay.check_permission(&alice, "WebSearch"),
            AutoApproveOutcome::NoOp
        );
        // Origin doesn't match ⇒ NoOp regardless of tool.
        assert_eq!(
            overlay.check_permission(&bob, "Read"),
            AutoApproveOutcome::NoOp
        );
    }

    /// Sanity: the type system rules out a permission rule that
    /// carries an LLM-craftable matcher. This test compiles only
    /// because [`PermissionRule`] has exactly the three fields it
    /// has. If a future commit adds an `input` / `regex` / `glob`
    /// field, the `Default::default()` construction below stops
    /// covering every field — the test won't compile, forcing a
    /// review of the trust-boundary docs.
    #[test]
    fn permission_rule_shape_is_minimal() {
        let r = PermissionRule {
            name: String::new(),
            origin: agent(0),
            tool_names: vec![],
        };
        // Confirms the shape — fields beyond these don't exist.
        let _ = (&r.name, &r.origin, &r.tool_names);
    }

    /// Matrix-exhaustive Reject-floor invariant: regardless of how
    /// the overlay is configured, [`AutoApproveOutcome`] cannot
    /// represent a `Reject → Accept` transition. The exhaustive
    /// match below would fail to compile if a `Reject`/`Escalate`
    /// variant snuck in.
    #[test]
    fn auto_approve_outcome_is_downgrade_only() {
        let outcomes = [
            AutoApproveOutcome::NoOp,
            AutoApproveOutcome::Accept { rule: "x".into() },
            AutoApproveOutcome::Allow { rule: "y".into() },
        ];
        for o in outcomes {
            // Exhaustive match — adding a variant fails to compile here.
            match o {
                AutoApproveOutcome::NoOp => {}
                AutoApproveOutcome::Accept { .. } => {}
                AutoApproveOutcome::Allow { .. } => {}
            }
        }
    }

    /// `origin` typed as `AgentId` (not a string with alias prefix)
    /// rules out alias-rebind drift. This test pins the type
    /// signature.
    #[test]
    fn permission_rule_origin_is_agent_id_not_alias() {
        // If `origin` were `AgentAlias` or a free `String`, this
        // assignment from a function returning `AgentId` would
        // need a conversion call — its absence is the assertion.
        let id: AgentId = agent(7);
        let r = PermissionRule {
            name: "x".into(),
            origin: id,
            tool_names: vec!["Read".into()],
        };
        assert_eq!(r.origin.as_str().len(), 26);
    }
}
