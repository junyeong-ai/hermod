---
description: Workspace lint policy + when to add a test
---

# Lints and tests

## Lint policy lives at the workspace root

`Cargo.toml`'s `[workspace.lints]` is the single source of truth.
Each crate inherits via `[lints] workspace = true`. **Never** add
inner attributes like `#![deny(unsafe_code)]` to a crate's
`lib.rs` / `main.rs` — they duplicate the workspace policy and drift.

Active floor:
- `unsafe_code = "deny"` (rust)
- `clippy::all = "deny"`
- `clippy::todo = "warn"`, `clippy::dbg_macro = "warn"`
- `missing_debug_implementations = "warn"`

Adding a noisy lint requires cleaning the existing warnings first.
Don't enable a lint that produces unactionable noise — that's tech
debt for tech debt's sake. Comment in `Cargo.toml` documents the
rationale.

## When to add a test

Add a unit / integration test when:

- A new typed enum variant is introduced (round-trip + uniqueness +
  shape pin) — see `HeldIntent`'s `intent_tests` module for the
  pattern.
- A new audit action is emitted (doc-coverage test catches the doc
  drift; you don't need to write it manually).
- A new public API on a trait — pin the contract.
- A new defensive guard is added to a pipeline (e.g. hop-count
  rejection, cap-count rejection).

Do **not** add tests for:

- Plumbing that's already covered transitively by an e2e test.
- "Sanity" tests that just call into a function and assert `Ok` —
  those are noise without a behavioral assertion.

## E2E tests need release binaries

`crates/hermod-cli/tests/channels.rs` and `tests/federation.rs` spawn
`target/release/hermod` and `target/release/hermodd`. After any change
to the daemon or CLI binary, rebuild before running the e2e:

```bash
cargo build --release --workspace --bins
cargo test -p hermod-cli --test channels --no-fail-fast
```

CI handles this automatically (release build step before test step).
