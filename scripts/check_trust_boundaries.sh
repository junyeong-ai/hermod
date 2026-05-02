#!/usr/bin/env bash
# Mechanical trust-boundary enforcement.
#
# Verifies the contracts that keep PR-3 (auto-approve) + PR-4
# (capability tags, axis 5) safe over time. Each check is a `grep`
# pinned to source — if a future commit breaks the invariant, CI
# fails before review.
#
# Run via:
#   bash scripts/check_trust_boundaries.sh
#
# Add new checks here when introducing a new trust-boundary
# contract; never rely on the social "this should be safe" review
# alone.

set -euo pipefail

cd "$(dirname "$0")/.."

fail=0

# ─────────────────────────────────────────────────────────────────
# 1. Permission auto-approve rule shape: `tool_names` allowlist +
#    `origin: AgentId` ONLY. No `input` / `regex` / `glob` / `pattern`
#    field — those would let an LLM craft messages that match any
#    or no input. The grep targets the struct definition; if a
#    future commit adds such a field, this fails.
# ─────────────────────────────────────────────────────────────────
permission_rule_file="crates/hermod-routing/src/auto_approve.rs"
if ! [ -f "$permission_rule_file" ]; then
    echo "trust-boundaries: missing $permission_rule_file" >&2
    exit 1
fi
# Extract the PermissionRule struct body and grep for forbidden field names.
permission_struct=$(awk '
    /pub struct PermissionRule \{/ { in_struct = 1; print; next }
    in_struct {
        print
        if ($0 ~ /^\}/) exit
    }
' "$permission_rule_file")
for forbidden in "input" "regex" "glob" "pattern" "matcher"; do
    if echo "$permission_struct" | grep -Eq "^[[:space:]]*pub[[:space:]]+${forbidden}[[:space:]]*:"; then
        echo "trust-boundaries: PermissionRule has forbidden field '${forbidden}'" >&2
        echo "  An LLM-craftable matcher is the wrong primitive on this surface." >&2
        echo "  Use the \`tool_names\` allowlist or extend the existing fields instead." >&2
        fail=1
    fi
done

# ─────────────────────────────────────────────────────────────────
# 2. FORBIDDEN_TOOL_NAMES const must list exactly the four
#    destructive / shell-execution tools. Missing one would let
#    an operator config slip through; adding extras silently is
#    OK only if intentional, but should still be reviewed.
# ─────────────────────────────────────────────────────────────────
for tool in "Bash" "Write" "Edit" "NotebookEdit"; do
    if ! grep -Eq "\"${tool}\"" "$permission_rule_file"; then
        echo "trust-boundaries: FORBIDDEN_TOOL_NAMES missing '${tool}'" >&2
        echo "  This tool MUST be in the compile-time forbidden list." >&2
        fail=1
    fi
done

# ─────────────────────────────────────────────────────────────────
# 3. AutoApproveOutcome must have exactly the three downgrade-only
#    variants. Adding a `Reject` / `Escalate` variant would let
#    overlays cross the matrix floor — that's a security
#    regression by definition.
# ─────────────────────────────────────────────────────────────────
outcome_block=$(awk '
    /pub enum AutoApproveOutcome \{/ { in_enum = 1; print; next }
    in_enum {
        print
        if ($0 ~ /^\}/) exit
    }
' "$permission_rule_file")
for forbidden in "Reject" "Deny" "Escalate" "Confirm"; do
    if echo "$outcome_block" | grep -Eq "^[[:space:]]*${forbidden}[ ,{]"; then
        echo "trust-boundaries: AutoApproveOutcome has forbidden variant '${forbidden}'" >&2
        echo "  Auto-approve is downgrade-only by design." >&2
        fail=1
    fi
done

# ─────────────────────────────────────────────────────────────────
# 4. MessageDisposition must NOT derive Default. The codebase
#    treats every storage write as supplying an explicit choice;
#    a global default would let drift accrete silently.
# ─────────────────────────────────────────────────────────────────
disposition_file="crates/hermod-core/src/envelope.rs"
disposition_block=$(awk '
    /pub enum MessageDisposition \{/ { found = 1 }
    found && /^#\[derive/ { print; if (++count >= 1) {} }
    found && /pub enum MessageDisposition/ { exit }
' "$disposition_file" || true)
# Simpler grep: ensure `Default` does not appear inside the derive line(s) for MessageDisposition.
if grep -B1 "pub enum MessageDisposition" "$disposition_file" | grep -E "^#\[derive\(.*Default" >/dev/null; then
    echo "trust-boundaries: MessageDisposition derives Default" >&2
    echo "  No global default — every write picks Push or Silent explicitly." >&2
    fail=1
fi

# ─────────────────────────────────────────────────────────────────
# 5. `auto_approve.rs` rule conditions must reuse `dispatch::RuleCondition`,
#    not introduce a parallel one. (Soft check: the file imports it.)
# ─────────────────────────────────────────────────────────────────
if ! grep -Eq "use[[:space:]]+crate::dispatch::.*RuleCondition" "$permission_rule_file"; then
    echo "trust-boundaries: auto_approve.rs does not reuse dispatch::RuleCondition" >&2
    echo "  Both surfaces should share one rule grammar — see PR-3 design notes." >&2
    fail=1
fi

# ─────────────────────────────────────────────────────────────────
# 6. The confirmation overlay caller must enter the overlay only
#    inside `Verdict::Confirm`. We grep the inbound for the pattern;
#    a future refactor that shifts the call into the `Reject` /
#    `Accept` arm would invert the matrix.
# ─────────────────────────────────────────────────────────────────
inbound_file="crates/hermod-daemon/src/inbound/mod.rs"
if grep -Eq "Verdict::Reject.*check_confirmation|Verdict::Accept.*check_confirmation" "$inbound_file"; then
    echo "trust-boundaries: auto_approve overlay called outside Verdict::Confirm arm" >&2
    echo "  Overlay must run only on Confirm — Reject is the floor." >&2
    fail=1
fi

# ─────────────────────────────────────────────────────────────────
# 7. Capability tags (axis 5) are discovery metadata only — never
#    trust-bearing. The contract: `hermod-routing/src/` imports
#    zero `capability_tag` / `CapabilityTag` symbols. A future
#    commit that consults a tag inside the routing crate (e.g. an
#    access decision branch on `peer.tags.contains("verified")`)
#    fails here before review.
#
#    Exception: this guard is intentional. Tags are propagated via
#    `peer.advertise` and surfaced in `agent.list` / `agent.get`
#    for *discovery* (find me a rust+tokio peer); they have no
#    place in the access-control / confirmation / dispatch /
#    auto-approve decision paths.
# ─────────────────────────────────────────────────────────────────
# Test-only references (constructing `AgentRecord { peer_asserted_tags:
# CapabilityTagSet::empty(), … }` for fixtures) are accepted —
# the gate is that *production* code paths must not consult tag
# semantics. We strip `#[cfg(test)]` mod blocks before scanning;
# inside those, anything goes.
routing_prod_files=$(find crates/hermod-routing/src -name '*.rs' -type f)
violations=0
for f in $routing_prod_files; do
    # Truncate at the first `#[cfg(test)]` marker so test
    # construction sites don't trip the contract. Production
    # references still surface.
    head=$(awk '/#\[cfg\(test\)\]/ { exit } { print }' "$f")
    if echo "$head" | grep -Eq "capability_tag|CapabilityTag"; then
        echo "trust-boundaries: $f references capability_tag in production code" >&2
        echo "$head" | grep -nE "capability_tag|CapabilityTag" | sed "s|^|  $f:|" >&2
        violations=$((violations + 1))
    fi
done
if [ "$violations" -gt 0 ]; then
    echo "  Tags are discovery metadata only — never trust-bearing." >&2
    echo "  Routing/access decisions must NOT branch on a peer's tags." >&2
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "trust-boundaries: ok"
fi
exit "$fail"
