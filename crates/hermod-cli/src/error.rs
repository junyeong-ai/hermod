//! CLI error helpers.
//!
//! All commands surface failures as `anyhow::Error`. The CLI's user-visible
//! convention is `<what>: <reason>` — single line, lowercase first word,
//! colon-separated. These helpers funnel every site through that shape so
//! a typo in one command can't drift from the rest of the surface.

use std::fmt::Display;

/// Shape: `invalid <field> "<value>": <reason>`. Use when a parse fails
/// against operator-supplied input that has both a field name and value.
pub fn invalid<V: Display, E: Display>(field: &str, value: V, e: E) -> anyhow::Error {
    anyhow::anyhow!("invalid {field} \"{value}\": {e}")
}

/// Shape: `<field>: <reason>`. Use when there's no specific operator
/// value to echo back, only an opaque underlying error.
pub fn from_underlying<E: Display>(field: &str, e: E) -> anyhow::Error {
    anyhow::anyhow!("{field}: {e}")
}

/// Shape: `<field> "<value>" not found in <where>`. Use after a directory
/// / table lookup fails for an alias / id supplied by the operator.
pub fn not_found<V: Display>(field: &str, value: V, source: &str) -> anyhow::Error {
    anyhow::anyhow!("{field} \"{value}\" not found in {source}")
}
