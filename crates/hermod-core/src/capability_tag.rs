//! Capability tag — discovery-only metadata.
//!
//! Tags are operator-set strings that label a locally-hosted agent
//! by capability ("language:rust", "framework:tokio", "role:reviewer")
//! and are propagated to peers via `MessageBody::PeerAdvertise`.
//! They drive *discovery*: `hermod agent list --tag-any rust` finds
//! agents matching the operator's interest.
//!
//! ## Trust boundary
//!
//! **Tags are NEVER trust-bearing.** A peer can label themselves
//! `framework:tokio`; that does not grant any access, bypass any
//! confirmation gate, or change any routing decision. The
//! authorization story is the same as without tags — capability
//! tokens, trust levels, confirmation matrix, auto-approve
//! overlays. Tags are a label on a directory entry; that's it.
//!
//! `scripts/check_trust_boundaries.sh` verifies this with a grep
//! contract: `hermod-routing` imports zero `capability_tag`
//! symbols. A future commit that consults a tag inside the
//! routing crate (e.g. an access decision branch on
//! `peer.tags.contains("verified")`) fails CI before review.
//!
//! ## Validation
//!
//! Each tag is `[a-z0-9:_.-]{1,64}`:
//! - lowercase ASCII alphanumerics + four punctuation chars
//! - `:` is the conventional namespace separator (`role:reviewer`)
//! - `.`/`_`/`-` cover normal compound names
//! - no whitespace, no shell metacharacters → safe in CLI / TOML
//! - 64-byte ceiling rules out wire-bloat and accidental dumps of
//!   freeform text into a tag set
//!
//! Per-set bounds: ≤16 entries, deduplicated. Sixteen covers
//! realistic operator workflows (a few namespace prefixes × a
//! few values); beyond that the set is over-fitted to its
//! inputs and the operator should reach for capability tokens
//! instead.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

use crate::error::HermodError;

/// Maximum bytes in one tag.
pub const MAX_TAG_BYTES: usize = 64;

/// Maximum tags per [`CapabilityTagSet`].
pub const MAX_TAGS_PER_SET: usize = 16;

/// One operator-set capability tag. Wire form is a plain string;
/// in-memory form goes through [`CapabilityTag::parse`] which
/// validates `^[a-z0-9:_.-]{1,64}$`.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct CapabilityTag(String);

impl From<CapabilityTag> for String {
    fn from(t: CapabilityTag) -> String {
        t.0
    }
}

impl TryFrom<String> for CapabilityTag {
    type Error = HermodError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl CapabilityTag {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for CapabilityTag {
    type Err = HermodError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() || s.len() > MAX_TAG_BYTES {
            return Err(HermodError::InvalidCapabilityTag(format!(
                "length must be 1..={MAX_TAG_BYTES}, got {}",
                s.len()
            )));
        }
        for c in s.chars() {
            if !(c.is_ascii_lowercase()
                || c.is_ascii_digit()
                || c == ':'
                || c == '.'
                || c == '_'
                || c == '-')
            {
                return Err(HermodError::InvalidCapabilityTag(format!(
                    "invalid char {c:?} (allowed: a-z 0-9 : . _ -)"
                )));
            }
        }
        Ok(Self(s.to_string()))
    }
}

impl fmt::Display for CapabilityTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for CapabilityTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CapabilityTag({})", self.0)
    }
}

/// Bounded, deduplicated set of [`CapabilityTag`]s. Wire form is
/// `Vec<String>` (forward-compat — peers running a future version
/// that adds new validation can introduce stricter rules without
/// breaking older receivers; older receivers just drop the entries
/// that fail their parse). In-memory form goes through
/// [`CapabilityTagSet::from_validated`] which enforces cardinality
/// and dedup.
#[derive(Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CapabilityTagSet(Vec<CapabilityTag>);

impl CapabilityTagSet {
    /// Empty set.
    pub fn empty() -> Self {
        Self(Vec::new())
    }

    /// Construct from already-parsed tags. Deduplicates and refuses
    /// sets above [`MAX_TAGS_PER_SET`].
    pub fn from_validated(mut tags: Vec<CapabilityTag>) -> Result<Self, HermodError> {
        // Order-preserving dedup so the operator's first-write
        // ordering survives storage round-trips. Stable rather
        // than sorting — operators sometimes care about the
        // first-listed tag (display priority).
        let mut seen = std::collections::HashSet::new();
        tags.retain(|t| seen.insert(t.0.clone()));
        if tags.len() > MAX_TAGS_PER_SET {
            return Err(HermodError::InvalidCapabilityTag(format!(
                "tag set has {} entries; max {MAX_TAGS_PER_SET}",
                tags.len()
            )));
        }
        Ok(Self(tags))
    }

    /// Parse a `Vec<String>` from the wire. Per-entry: drop bad
    /// entries (the entry never enters the set), but never reject
    /// the whole set — a peer running a stricter future validator
    /// could otherwise corrupt our entire propagation. Returns
    /// `(set, dropped_count)` so the caller can record the drop in
    /// audit (`peer.advertise.received` carries `dropped_invalid_tags`).
    pub fn parse_lossy(raw: Vec<String>) -> (Self, u32) {
        let mut accepted = Vec::with_capacity(raw.len().min(MAX_TAGS_PER_SET));
        let mut dropped = 0u32;
        for s in raw {
            match s.parse::<CapabilityTag>() {
                Ok(t) => accepted.push(t),
                Err(_) => dropped = dropped.saturating_add(1),
            }
        }
        // Cap on cardinality is also lossy: if a peer ships >16
        // valid tags, we keep the first 16 and drop the rest.
        let kept: Vec<CapabilityTag> = accepted.iter().take(MAX_TAGS_PER_SET).cloned().collect();
        let card_dropped = accepted.len().saturating_sub(kept.len()) as u32;
        let set = match Self::from_validated(kept) {
            Ok(s) => s,
            Err(_) => Self::empty(),
        };
        (set, dropped.saturating_add(card_dropped))
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = &CapabilityTag> {
        self.0.iter()
    }

    pub fn contains(&self, tag: &CapabilityTag) -> bool {
        self.0.contains(tag)
    }

    pub fn as_slice(&self) -> &[CapabilityTag] {
        &self.0
    }

    /// Convert into a `Vec<String>` for wire / TOML serialisation.
    pub fn into_strings(self) -> Vec<String> {
        self.0.into_iter().map(|t| t.0).collect()
    }
}

impl fmt::Debug for CapabilityTagSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.0.iter()).finish()
    }
}

/// Compute the effective tag list for an agent the receiver knows
/// about. The local-set wins over peer-asserted on overlap (the
/// operator's nickname / annotation is sacred); peer-asserted
/// extras concatenate after. Order: local first (operator
/// ordering), then peer-asserted excluding overlaps.
///
/// Single source of truth — `agent.list` and `agent.get` both
/// route through this so a future change to the union semantics
/// can't drift between the two surfaces (memory archive defect 2).
pub fn effective_tags(
    local: &CapabilityTagSet,
    peer_asserted: &CapabilityTagSet,
) -> Vec<CapabilityTag> {
    let mut out = Vec::with_capacity(local.len() + peer_asserted.len());
    let mut seen = std::collections::HashSet::new();
    for t in local.iter() {
        if seen.insert(t.0.clone()) {
            out.push(t.clone());
        }
    }
    for t in peer_asserted.iter() {
        if seen.insert(t.0.clone()) {
            out.push(t.clone());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_accepts_typical_shapes() {
        for s in [
            "rust",
            "language:rust",
            "framework:tokio",
            "role:reviewer",
            "team.platform",
            "agent_v1",
            "a-b-c",
            "01_abc:def",
        ] {
            let t: CapabilityTag = s.parse().unwrap();
            assert_eq!(t.as_str(), s);
        }
    }

    #[test]
    fn parse_rejects_invalid_shapes() {
        for s in [
            "",           // empty
            "Rust",       // uppercase
            "with space", // space
            "a/b",        // slash
            "a@b",        // shell metacharacter
            "a*",         // glob
            "한글",       // non-ASCII
            "a;b",
        ] {
            let r: Result<CapabilityTag, _> = s.parse();
            assert!(r.is_err(), "{s:?} must be rejected");
        }
        // Length boundary.
        let too_long = "x".repeat(MAX_TAG_BYTES + 1);
        assert!(too_long.parse::<CapabilityTag>().is_err());
    }

    #[test]
    fn set_dedupes_and_caps() {
        let tags: Vec<CapabilityTag> = ["rust", "rust", "tokio", "rust"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        let set = CapabilityTagSet::from_validated(tags).unwrap();
        assert_eq!(set.len(), 2);
        assert_eq!(set.as_slice()[0].as_str(), "rust");
        assert_eq!(set.as_slice()[1].as_str(), "tokio");

        // Cardinality cap.
        let many: Vec<CapabilityTag> = (0..MAX_TAGS_PER_SET + 5)
            .map(|i| format!("t{i}").parse().unwrap())
            .collect();
        assert!(CapabilityTagSet::from_validated(many).is_err());
    }

    #[test]
    fn parse_lossy_drops_per_entry_and_records_count() {
        let raw = vec![
            "rust".into(),
            "Bad space".into(), // invalid
            "tokio".into(),
            "한글".into(), // invalid
            "rust".into(), // duplicate
        ];
        let (set, dropped) = CapabilityTagSet::parse_lossy(raw);
        assert_eq!(set.len(), 2); // rust, tokio (after dedup)
        assert_eq!(dropped, 2); // two invalid entries
    }

    #[test]
    fn parse_lossy_caps_cardinality_and_records_drop() {
        let raw: Vec<String> = (0..MAX_TAGS_PER_SET + 3).map(|i| format!("t{i}")).collect();
        let (set, dropped) = CapabilityTagSet::parse_lossy(raw);
        assert_eq!(set.len(), MAX_TAGS_PER_SET);
        assert_eq!(dropped, 3);
    }

    #[test]
    fn effective_tags_merges_local_first_dedup() {
        let local = CapabilityTagSet::from_validated(vec![
            "rust".parse().unwrap(),
            "tokio".parse().unwrap(),
        ])
        .unwrap();
        let peer = CapabilityTagSet::from_validated(vec![
            "tokio".parse().unwrap(), // overlap
            "framework:axum".parse().unwrap(),
        ])
        .unwrap();
        let eff = effective_tags(&local, &peer);
        assert_eq!(eff.len(), 3);
        assert_eq!(eff[0].as_str(), "rust");
        assert_eq!(eff[1].as_str(), "tokio"); // local order kept
        assert_eq!(eff[2].as_str(), "framework:axum");
    }

    #[test]
    fn effective_tags_handles_empty_sides() {
        let empty = CapabilityTagSet::empty();
        let local = CapabilityTagSet::from_validated(vec!["rust".parse().unwrap()]).unwrap();
        assert_eq!(effective_tags(&empty, &empty).len(), 0);
        assert_eq!(effective_tags(&local, &empty)[0].as_str(), "rust");
        assert_eq!(effective_tags(&empty, &local)[0].as_str(), "rust");
    }

    #[test]
    fn round_trip_through_serde() {
        let set = CapabilityTagSet::from_validated(vec![
            "rust".parse().unwrap(),
            "tokio".parse().unwrap(),
        ])
        .unwrap();
        let json = serde_json::to_string(&set).unwrap();
        assert_eq!(json, r#"["rust","tokio"]"#);
        let back: CapabilityTagSet = serde_json::from_str(&json).unwrap();
        assert_eq!(back, set);
    }

    #[test]
    fn serde_rejects_invalid_tag_string() {
        let bad = serde_json::from_str::<CapabilityTagSet>(r#"["BAD UPPERCASE"]"#);
        assert!(bad.is_err());
    }
}
