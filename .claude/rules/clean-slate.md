---
description: Clean-slate policy — pre-v1, no backwards compat, no migration shims
---

# Clean-slate policy

Hermod is pre-v1. Apply changes in place; do not preserve old shapes.

## Apply to every change

- **No `// renamed from X` / `// previously Y` / "deprecated since"
  comments.** When something is renamed, replace it everywhere in the
  same PR — every callsite, every test, every doc, every config example.
- **No type aliases for old names.** `pub type OldName = NewName;` is
  a maintenance trap; remove the old name entirely.
- **No fallback parsing for old wire formats.** If the wire format
  changes, change every encoder + decoder + test fixture together.
- **No deprecation periods.** A name change lands as one commit, not
  a deprecation cycle.
- **Migrations are up-only.** When a SQL schema field changes, edit
  the existing migration file in place. The daemon's
  `StorageError::SchemaMismatch` handler in `hermod-daemon/src/main.rs`
  tells operators to archive the on-disk DB and re-init — that is the
  documented migration path.

## When the user adds something to docs

If a doc references an action / type / config field that no longer
exists, fix the doc — don't preserve a "previously called" footnote.

## Verification

After a rename, three greps must return zero matches:

```bash
grep -rnE "renamed from|previously called|deprecated since" --include="*.rs" --include="*.md" .
grep -rn "<old-name>" --include="*.rs" --include="*.md" --include="*.sql" --include="*.toml" .
```
