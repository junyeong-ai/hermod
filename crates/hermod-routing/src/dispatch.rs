//! Recipient-side dispatch policy.
//!
//! Decides what happens to an inbound envelope *after* the
//! confirmation gate has accepted it: which delivery surface it
//! reaches (`MessageDisposition::{Push, Silent}`) and whether the
//! operator gets an OS-notification ping
//! (`NotifyPreference::{None, Os}`). A single trait
//! ([`DispatchPolicy`]) hides the rule engine from the inbound
//! pipeline so a future hand-coded / LLM-triaging / streaming-
//! priority policy slots in without touching `hermod-daemon`.
//!
//! ## Design — extension axes that stay open
//!
//! * **`MessageDisposition`** lives in `hermod-core` (it's persisted
//!   on `messages.disposition`). Adding `Digest` etc. is a storage
//!   migration plus a rule-engine arm, not a wire change.
//! * **`NotifyPreference`** is recipient-only — never on the wire,
//!   so a sender can't force the recipient's notification surface.
//!   Future variants (`Slack { webhook }`, `Webhook { url }`) plug
//!   in with no envelope churn.
//! * **`RuleCondition`** is an extensible enum. New conditions land
//!   alongside new fields on `RouteContext`; both `routing.rules`
//!   and `auto_approve.confirmation` (PR-3) reuse the evaluator.
//!
//! ## Heuristic discipline
//!
//! Every condition predicate is exact / set-membership / numeric.
//! No regex, no glob, no LLM-craftable matchers — those would let
//! a capable peer engineer messages that match anything (DoS) or
//! nothing (silent suppression). `BodyContainsAny` is exact
//! case-insensitive substring with bounded keyword lengths.
//! `TimeBetween` interprets in operator-configured `utc_offset_minutes`
//! (no `localtime_r`, no glibc tz races).

use hermod_core::{
    AgentId, MessageBody, MessageDisposition, MessageId, MessageKind, MessagePriority, TrustLevel,
};
use serde::{Deserialize, Serialize};

/// Per-recipient notification preference. Decided at routing time;
/// never persisted on the wire (sender can't force this on us).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NotifyPreference {
    /// No OS notification — the standard path.
    #[default]
    None,
    /// Queue an OS notification on the operator's host. `sound` is
    /// platform-defaulted when `None`; operators set it to a known
    /// system sound name (macOS: `"Glass"`; XDG: file path; Windows:
    /// looked up from `WAVEX`).
    Os {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sound: Option<String>,
    },
}

/// Output of [`DispatchPolicy::decide`]. Two orthogonal axes:
/// where the message lands (`disposition`) and whether the operator
/// gets an external ping (`notify`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DispatchDecision {
    pub disposition: MessageDisposition,
    pub notify: NotifyPreference,
    /// Name of the rule that produced this decision, if any. `None`
    /// for the kind-default fallback. Surfaced on the
    /// `routing.dispositioned` audit row so operators trace how a
    /// message was routed.
    pub matched_rule: Option<String>,
}

impl DispatchDecision {
    /// Kind-default decision: push, no OS notification, no rule
    /// matched. Used as the fallback when no rule matches.
    pub fn kind_default(kind: MessageKind) -> Self {
        let disposition = if kind.has_disposition_column() {
            MessageDisposition::Push
        } else {
            // Kinds without a `disposition` column (Brief, presence,
            // workspace gossip) are inherently `Push` — they reach
            // their dedicated surface (the brief table, presence
            // cache, channel broadcast log). Coercing to `Push` here
            // keeps the audit row truthful: a rule can claim
            // `disposition: silent` but the storage layer drops the
            // value, so the audit must reflect what *actually*
            // happened.
            MessageDisposition::Push
        };
        Self {
            disposition,
            notify: NotifyPreference::None,
            matched_rule: None,
        }
    }
}

/// Read-only view of the inbound envelope plus contextual signals
/// the rule engine matches against. Constructed by the inbound
/// pipeline and handed to [`DispatchPolicy::decide`].
#[derive(Debug, Clone)]
pub struct RouteContext<'a> {
    pub message_id: MessageId,
    pub from: &'a AgentId,
    pub recipient: &'a AgentId,
    pub kind: MessageKind,
    pub priority: MessagePriority,
    pub trust: TrustLevel,
    pub body: &'a MessageBody,
    /// Whether the recipient currently has at least one MCP
    /// session attached. Drives `RuleCondition::SessionActive`.
    pub session_active: bool,
    /// Wall-clock instant the inbound was accepted. The rule engine
    /// passes this into time-window predicates; tests inject a fixed
    /// value so the rule's behaviour is deterministic.
    pub now_unix_ms: i64,
}

/// Gate trait the inbound pipeline calls after `Verdict::Accept`.
/// Implementations are stateless and pure-data — the routing config
/// is captured at construction.
pub trait DispatchPolicy: Send + Sync + std::fmt::Debug {
    fn decide(&self, ctx: &RouteContext<'_>) -> DispatchDecision;
}

/// No-op dispatch — every envelope is `Push` with no OS notification.
/// Default daemon construction uses this when `[routing]` is empty,
/// so unconfigured deployments behave exactly like a pre-routing
/// daemon.
#[derive(Debug, Default, Clone, Copy)]
pub struct PassthroughPolicy;

impl DispatchPolicy for PassthroughPolicy {
    fn decide(&self, ctx: &RouteContext<'_>) -> DispatchDecision {
        DispatchDecision::kind_default(ctx.kind)
    }
}

/// Maximum keyword length accepted by `RuleCondition::BodyContainsAny`.
/// Bounded so a malicious operator config can't blow up the
/// allocator — keywords longer than this fail boot validation.
pub const BODY_KEYWORD_MAX_BYTES: usize = 256;

/// Maximum keyword count per `BodyContainsAny` rule. 32 covers
/// realistic operator workflows ("@mention me", common author names);
/// beyond that the rule is over-fitted to its inputs.
pub const BODY_KEYWORD_MAX_COUNT: usize = 32;

/// Minutes per day — sentinel for `RuleCondition::TimeBetween` parsing.
const MINUTES_PER_DAY: i32 = 24 * 60;

/// Composable rule condition. Predicates are exact / set membership /
/// numeric comparisons / case-insensitive substring. **No** regex,
/// glob, or LLM-craftable matchers — those would let a capable peer
/// engineer messages that match anything or nothing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RuleCondition {
    KindIn {
        kinds: Vec<MessageKind>,
    },
    TrustIn {
        trusts: Vec<TrustLevel>,
    },
    PriorityAtLeast {
        priority: MessagePriority,
    },
    PriorityAtMost {
        priority: MessagePriority,
    },
    SenderIs {
        agent_id: AgentId,
    },
    SessionActive,
    /// Inclusive `[start, end]` minute-of-day window in
    /// operator-configured `utc_offset_minutes` (the rule engine's
    /// outer config). Wrap-around midnight (`start > end`) means the
    /// window straddles 00:00.
    TimeBetween {
        start_minute_of_day: u16,
        end_minute_of_day: u16,
    },
    /// Case-insensitive substring match against
    /// `MessageBody::searchable_text()`. Falls through `false` for
    /// kinds with no searchable text (Brief, Presence, etc.).
    BodyContainsAny {
        keywords: Vec<String>,
    },
    All {
        conditions: Vec<RuleCondition>,
    },
    Any {
        conditions: Vec<RuleCondition>,
    },
    Not {
        condition: Box<RuleCondition>,
    },
}

/// Operator-configured rule. First-match-wins; `name` is unique
/// per `RoutingConfig` (boot-validated) and surfaces on the
/// `routing.dispositioned` audit row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub name: String,
    pub condition: RuleCondition,
    pub disposition: MessageDisposition,
    #[serde(default)]
    pub notify: NotifyPreference,
}

/// Operator config for the routing engine. Carried separately from
/// the daemon's `[routing]` TOML so tests can build it directly.
/// `utc_offset_minutes` is the operator's wall-clock offset — the
/// `TimeBetween` predicate evaluates against it. Range is enforced
/// at boot validation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RoutingConfig {
    #[serde(default)]
    pub rules: Vec<Rule>,
    #[serde(default)]
    pub notification: NotificationConfig,
    /// `[-720, 840]` per ISO 8601 wall-clock offsets (UTC-12 to
    /// UTC+14). Default 0 (UTC). Validated at boot.
    #[serde(default)]
    pub utc_offset_minutes: i32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationConfig {
    /// Master switch. When `false`, [`NotifyPreference::Os`]
    /// decisions are downgraded to `None` at decision time and the
    /// `notification.suppressed` audit row records the policy
    /// choice — the rule isn't quietly broken.
    pub enabled: bool,
    /// Per-recipient cap on `pending` + `failed` rows in
    /// `notifications`. Atomic enqueue at the storage layer fails
    /// without writing the row when the cap is reached, and the
    /// daemon emits `notification.suppressed`.
    pub max_pending: u32,
    /// Days a terminal row (`dispatched`/`failed`/`dismissed`)
    /// stays in `notifications` before janitor reaps it.
    pub retention_days: u32,
}

impl Default for NotificationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_pending: 256,
            retention_days: 7,
        }
    }
}

/// Boot-validation errors. Every variant is fail-loud — a misconfigured
/// `[routing]` block aborts daemon startup so operator typos never
/// silently degrade routing.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum RoutingConfigError {
    #[error("routing.utc_offset_minutes {0} out of range [-720, 840]")]
    UtcOffsetOutOfRange(i32),
    #[error("routing.notification.max_pending = 0 — set to at least 1 or disable notifications")]
    AmbiguousMaxPending,
    #[error("routing rule name is empty")]
    EmptyRuleName,
    #[error("routing rule names duplicate `{0}`")]
    DuplicateRuleName(String),
    #[error("routing rule `{rule}` has degenerate time window {start}..{end}")]
    DegenerateTimeWindow { rule: String, start: u16, end: u16 },
    #[error(
        "routing rule `{rule}` has empty `body_contains_any` keyword list — drop the rule or add keywords"
    )]
    EmptyKeywordList { rule: String },
    #[error(
        "routing rule `{rule}` keyword exceeds {BODY_KEYWORD_MAX_BYTES}-byte limit (got {got_bytes})"
    )]
    OversizedKeyword { rule: String, got_bytes: usize },
    #[error(
        "routing rule `{rule}` has more than {BODY_KEYWORD_MAX_COUNT} keywords (got {got_count})"
    )]
    TooManyKeywords { rule: String, got_count: usize },
    #[error("routing rule `{rule}` time window minute-of-day {minute} exceeds 1439")]
    InvalidMinuteOfDay { rule: String, minute: u16 },
}

impl RoutingConfig {
    /// Boot-time validation. Call before constructing any
    /// [`RuleBasedPolicy`]; the daemon fails-loud on any error.
    pub fn validate(&self) -> Result<(), RoutingConfigError> {
        if !(-720..=840).contains(&self.utc_offset_minutes) {
            return Err(RoutingConfigError::UtcOffsetOutOfRange(
                self.utc_offset_minutes,
            ));
        }
        if self.notification.enabled && self.notification.max_pending == 0 {
            return Err(RoutingConfigError::AmbiguousMaxPending);
        }
        let mut seen = std::collections::HashSet::new();
        for rule in &self.rules {
            if rule.name.is_empty() {
                return Err(RoutingConfigError::EmptyRuleName);
            }
            if !seen.insert(&rule.name) {
                return Err(RoutingConfigError::DuplicateRuleName(rule.name.clone()));
            }
            validate_condition(&rule.name, &rule.condition)?;
        }
        Ok(())
    }
}

/// Re-exported for `auto_approve` so confirmation-overlay rules
/// share the same condition validator as dispatch rules. Crate-
/// internal — operators don't see this; they see
/// `RoutingConfig::validate` and `AutoApproveConfig::validate`.
pub(crate) fn validate_condition_public(
    rule: &str,
    c: &RuleCondition,
) -> Result<(), RoutingConfigError> {
    validate_condition(rule, c)
}

fn validate_condition(rule: &str, c: &RuleCondition) -> Result<(), RoutingConfigError> {
    match c {
        RuleCondition::TimeBetween {
            start_minute_of_day,
            end_minute_of_day,
        } => {
            for &m in &[*start_minute_of_day, *end_minute_of_day] {
                if m as i32 >= MINUTES_PER_DAY {
                    return Err(RoutingConfigError::InvalidMinuteOfDay {
                        rule: rule.to_string(),
                        minute: m,
                    });
                }
            }
            if start_minute_of_day == end_minute_of_day {
                return Err(RoutingConfigError::DegenerateTimeWindow {
                    rule: rule.to_string(),
                    start: *start_minute_of_day,
                    end: *end_minute_of_day,
                });
            }
        }
        RuleCondition::BodyContainsAny { keywords } => {
            if keywords.is_empty() {
                return Err(RoutingConfigError::EmptyKeywordList {
                    rule: rule.to_string(),
                });
            }
            if keywords.len() > BODY_KEYWORD_MAX_COUNT {
                return Err(RoutingConfigError::TooManyKeywords {
                    rule: rule.to_string(),
                    got_count: keywords.len(),
                });
            }
            for kw in keywords {
                if kw.len() > BODY_KEYWORD_MAX_BYTES {
                    return Err(RoutingConfigError::OversizedKeyword {
                        rule: rule.to_string(),
                        got_bytes: kw.len(),
                    });
                }
            }
        }
        RuleCondition::All { conditions } | RuleCondition::Any { conditions } => {
            for c in conditions {
                validate_condition(rule, c)?;
            }
        }
        RuleCondition::Not { condition } => validate_condition(rule, condition)?,
        RuleCondition::KindIn { .. }
        | RuleCondition::TrustIn { .. }
        | RuleCondition::PriorityAtLeast { .. }
        | RuleCondition::PriorityAtMost { .. }
        | RuleCondition::SenderIs { .. }
        | RuleCondition::SessionActive => {}
    }
    Ok(())
}

/// First-match-wins policy. Constructed once at daemon boot from a
/// validated [`RoutingConfig`].
#[derive(Debug, Clone)]
pub struct RuleBasedPolicy {
    rules: Vec<Rule>,
    utc_offset_minutes: i32,
    notifications_enabled: bool,
}

impl RuleBasedPolicy {
    /// Construct from a validated config. Caller is expected to have
    /// already invoked [`RoutingConfig::validate`] — debug builds
    /// assert it on entry.
    pub fn new(cfg: RoutingConfig) -> Self {
        debug_assert!(cfg.validate().is_ok(), "RuleBasedPolicy: invalid config");
        Self {
            rules: cfg.rules,
            utc_offset_minutes: cfg.utc_offset_minutes,
            notifications_enabled: cfg.notification.enabled,
        }
    }
}

impl DispatchPolicy for RuleBasedPolicy {
    fn decide(&self, ctx: &RouteContext<'_>) -> DispatchDecision {
        for rule in &self.rules {
            if evaluate(&rule.condition, ctx, self.utc_offset_minutes) {
                let notify = if self.notifications_enabled {
                    rule.notify.clone()
                } else {
                    NotifyPreference::None
                };
                let disposition = if ctx.kind.has_disposition_column() {
                    rule.disposition
                } else {
                    // Coerce to kind-default for kinds without a
                    // column (audit truthfulness).
                    MessageDisposition::Push
                };
                return DispatchDecision {
                    disposition,
                    notify,
                    matched_rule: Some(rule.name.clone()),
                };
            }
        }
        DispatchDecision::kind_default(ctx.kind)
    }
}

pub(crate) fn evaluate(c: &RuleCondition, ctx: &RouteContext<'_>, utc_offset_minutes: i32) -> bool {
    match c {
        RuleCondition::KindIn { kinds } => kinds.contains(&ctx.kind),
        RuleCondition::TrustIn { trusts } => trusts.contains(&ctx.trust),
        RuleCondition::PriorityAtLeast { priority } => ctx.priority >= *priority,
        RuleCondition::PriorityAtMost { priority } => ctx.priority <= *priority,
        RuleCondition::SenderIs { agent_id } => ctx.from == agent_id,
        RuleCondition::SessionActive => ctx.session_active,
        RuleCondition::TimeBetween {
            start_minute_of_day,
            end_minute_of_day,
        } => {
            let local_minute = ((ctx.now_unix_ms / 60_000) + utc_offset_minutes as i64)
                .rem_euclid(MINUTES_PER_DAY as i64) as u16;
            if start_minute_of_day <= end_minute_of_day {
                local_minute >= *start_minute_of_day && local_minute <= *end_minute_of_day
            } else {
                // Wraps midnight: e.g. 22:00–06:00.
                local_minute >= *start_minute_of_day || local_minute <= *end_minute_of_day
            }
        }
        RuleCondition::BodyContainsAny { keywords } => match ctx.body.searchable_text() {
            Some(text) => {
                let haystack = text.to_lowercase();
                keywords
                    .iter()
                    .any(|k| haystack.contains(&k.to_lowercase()))
            }
            None => false,
        },
        RuleCondition::All { conditions } => conditions
            .iter()
            .all(|c| evaluate(c, ctx, utc_offset_minutes)),
        RuleCondition::Any { conditions } => conditions
            .iter()
            .any(|c| evaluate(c, ctx, utc_offset_minutes)),
        RuleCondition::Not { condition } => !evaluate(condition, ctx, utc_offset_minutes),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hermod_core::{MessageId, MessagePriority, TrustLevel};

    fn ctx<'a>(
        kind: MessageKind,
        body: &'a MessageBody,
        from: &'a AgentId,
        to: &'a AgentId,
    ) -> RouteContext<'a> {
        RouteContext {
            message_id: MessageId::new(),
            from,
            recipient: to,
            kind,
            priority: MessagePriority::Normal,
            trust: TrustLevel::Tofu,
            body,
            session_active: true,
            now_unix_ms: 12 * 60 * 60_000, // 12:00 UTC
        }
    }

    fn agent(b: u8) -> AgentId {
        // Synthetic 26-char base32 id (alphabet a-z2-7). The byte
        // distinguishes test agents; the rest is fixed padding so
        // every produced id parses through the validator.
        let mut s = String::with_capacity(26);
        s.push((b'a' + (b % 24)) as char);
        s.push_str(&"a".repeat(25));
        AgentId::from_raw(s)
    }

    #[test]
    fn passthrough_yields_kind_default() {
        let from = agent(1);
        let to = agent(2);
        let body = MessageBody::Direct { text: "hi".into() };
        let p = PassthroughPolicy;
        let d = p.decide(&ctx(MessageKind::Direct, &body, &from, &to));
        assert_eq!(d.disposition, MessageDisposition::Push);
        assert_eq!(d.notify, NotifyPreference::None);
        assert_eq!(d.matched_rule, None);
    }

    #[test]
    fn first_match_wins_and_audit_carries_rule_name() {
        let from = agent(1);
        let to = agent(2);
        let body = MessageBody::Direct { text: "hi".into() };
        let cfg = RoutingConfig {
            rules: vec![
                Rule {
                    name: "always-silent".into(),
                    condition: RuleCondition::KindIn {
                        kinds: vec![MessageKind::Direct],
                    },
                    disposition: MessageDisposition::Silent,
                    notify: NotifyPreference::None,
                },
                // This second rule would also match but must NOT win.
                Rule {
                    name: "noisy".into(),
                    condition: RuleCondition::PriorityAtLeast {
                        priority: MessagePriority::Low,
                    },
                    disposition: MessageDisposition::Push,
                    notify: NotifyPreference::Os { sound: None },
                },
            ],
            ..Default::default()
        };
        cfg.validate().unwrap();
        let p = RuleBasedPolicy::new(cfg);
        let d = p.decide(&ctx(MessageKind::Direct, &body, &from, &to));
        assert_eq!(d.disposition, MessageDisposition::Silent);
        assert_eq!(d.notify, NotifyPreference::None);
        assert_eq!(d.matched_rule.as_deref(), Some("always-silent"));
    }

    #[test]
    fn brief_kind_coerces_disposition_to_push_for_audit_truthfulness() {
        let from = agent(1);
        let to = agent(2);
        let body = MessageBody::Brief {
            topic: None,
            summary: "x".into(),
        };
        let cfg = RoutingConfig {
            rules: vec![Rule {
                name: "claims-silent".into(),
                condition: RuleCondition::KindIn {
                    kinds: vec![MessageKind::Brief],
                },
                disposition: MessageDisposition::Silent,
                notify: NotifyPreference::None,
            }],
            ..Default::default()
        };
        cfg.validate().unwrap();
        let p = RuleBasedPolicy::new(cfg);
        let d = p.decide(&ctx(MessageKind::Brief, &body, &from, &to));
        assert_eq!(
            d.disposition,
            MessageDisposition::Push,
            "Brief has no disposition column — must coerce to Push"
        );
        // Rule still matched (so audit can record the *intent*),
        // but the actual disposition is the kind-default.
        assert_eq!(d.matched_rule.as_deref(), Some("claims-silent"));
    }

    #[test]
    fn body_contains_any_is_case_insensitive() {
        let from = agent(1);
        let to = agent(2);
        let body = MessageBody::Direct {
            text: "Hey @ALICE check this".into(),
        };
        let c = RuleCondition::BodyContainsAny {
            keywords: vec!["@alice".into()],
        };
        assert!(evaluate(
            &c,
            &ctx(MessageKind::Direct, &body, &from, &to),
            0
        ));
    }

    #[test]
    fn body_contains_any_falls_through_for_no_text_kinds() {
        let from = agent(1);
        let to = agent(2);
        let body = MessageBody::Presence {
            live: true,
            manual_status: None,
        };
        let c = RuleCondition::BodyContainsAny {
            keywords: vec!["x".into()],
        };
        assert!(!evaluate(
            &c,
            &ctx(MessageKind::Presence, &body, &from, &to),
            0
        ));
    }

    #[test]
    fn time_between_handles_wrap_around_midnight() {
        let from = agent(1);
        let to = agent(2);
        let body = MessageBody::Direct { text: "x".into() };
        // 22:00–06:00 window.
        let c = RuleCondition::TimeBetween {
            start_minute_of_day: 22 * 60,
            end_minute_of_day: 6 * 60,
        };
        let mut at_midnight = ctx(MessageKind::Direct, &body, &from, &to);
        at_midnight.now_unix_ms = 0; // 00:00 UTC
        assert!(evaluate(&c, &at_midnight, 0));
        let mut at_noon = ctx(MessageKind::Direct, &body, &from, &to);
        at_noon.now_unix_ms = 12 * 60 * 60_000;
        assert!(!evaluate(&c, &at_noon, 0));
    }

    #[test]
    fn validation_rejects_oversized_keyword() {
        let cfg = RoutingConfig {
            rules: vec![Rule {
                name: "fat".into(),
                condition: RuleCondition::BodyContainsAny {
                    keywords: vec!["x".repeat(BODY_KEYWORD_MAX_BYTES + 1)],
                },
                disposition: MessageDisposition::Silent,
                notify: NotifyPreference::None,
            }],
            ..Default::default()
        };
        assert!(matches!(
            cfg.validate(),
            Err(RoutingConfigError::OversizedKeyword { .. })
        ));
    }

    #[test]
    fn validation_rejects_empty_keyword_list() {
        let cfg = RoutingConfig {
            rules: vec![Rule {
                name: "empty".into(),
                condition: RuleCondition::BodyContainsAny { keywords: vec![] },
                disposition: MessageDisposition::Silent,
                notify: NotifyPreference::None,
            }],
            ..Default::default()
        };
        assert!(matches!(
            cfg.validate(),
            Err(RoutingConfigError::EmptyKeywordList { .. })
        ));
    }

    #[test]
    fn validation_rejects_duplicate_rule_names() {
        let cfg = RoutingConfig {
            rules: vec![
                Rule {
                    name: "a".into(),
                    condition: RuleCondition::SessionActive,
                    disposition: MessageDisposition::Push,
                    notify: NotifyPreference::None,
                },
                Rule {
                    name: "a".into(),
                    condition: RuleCondition::SessionActive,
                    disposition: MessageDisposition::Silent,
                    notify: NotifyPreference::None,
                },
            ],
            ..Default::default()
        };
        assert!(matches!(
            cfg.validate(),
            Err(RoutingConfigError::DuplicateRuleName(_))
        ));
    }

    #[test]
    fn validation_rejects_out_of_range_utc_offset() {
        let cfg = RoutingConfig {
            utc_offset_minutes: 1_000,
            ..Default::default()
        };
        assert!(matches!(
            cfg.validate(),
            Err(RoutingConfigError::UtcOffsetOutOfRange(_))
        ));
    }

    #[test]
    fn notifications_disabled_downgrades_os_to_none() {
        let from = agent(1);
        let to = agent(2);
        let body = MessageBody::Direct { text: "x".into() };
        let cfg = RoutingConfig {
            rules: vec![Rule {
                name: "loud".into(),
                condition: RuleCondition::SessionActive,
                disposition: MessageDisposition::Push,
                notify: NotifyPreference::Os { sound: None },
            }],
            notification: NotificationConfig {
                enabled: false,
                ..Default::default()
            },
            ..Default::default()
        };
        cfg.validate().unwrap();
        let p = RuleBasedPolicy::new(cfg);
        let d = p.decide(&ctx(MessageKind::Direct, &body, &from, &to));
        assert_eq!(d.notify, NotifyPreference::None);
        assert_eq!(d.matched_rule.as_deref(), Some("loud"));
    }
}
