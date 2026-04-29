---
description: Audit row emission rules — typed federation policy, audit_or_warn, doc parity
paths:
  - "crates/hermod-daemon/**"
  - "crates/hermod-storage/src/audit_sink.rs"
  - "crates/hermod-storage/src/file_audit_sink.rs"
  - "crates/hermod-storage/src/webhook_audit_sink.rs"
  - "docs/audit_actions.md"
---

# Audit emission rules

## Always go through `audit_or_warn`

```rust
use crate::services::audit_or_warn;

audit_or_warn(&*self.audit_sink, AuditEntry { ... }).await;
```

Direct `AuditRepository::append(...)` is forbidden by `clippy.toml`
(`disallowed-methods`). The wrapper guarantees that backend errors
become `tracing::warn` rather than failing the action being audited.

## Federation policy is typed

Every `AuditEntry { ... }` literal must specify the `federation`
field:

```rust
federation: hermod_storage::AuditFederationPolicy::Default,  // 거의 모든 사이트
federation: hermod_storage::AuditFederationPolicy::Skip,     // 3개 사이트만
```

`Skip` is reserved for rows that would feed an outbound-federation
feedback loop:

1. `MessageService::send`'s `message.sent` row (the federation
   envelope itself triggers this; without Skip the row would re-fan-out)
2. `accept_audit_federate`'s folded `audit.federate.<original>` row
3. `accept_audit_federate`'s `audit.federate.received` meta-row

Every other emission is `Default`. **Never** add string-prefix
filtering to `RemoteAuditSink::record` — the typed flag is the only
control surface.

## Client IP is ambient

Every `AuditEntry { ... }` literal sets `client_ip: None`. The
`audit_or_warn` helper overlays `audit_context::current_client_ip()`
at append time, picking up the client IP that
`ipc_remote::handshake_and_serve` bound for the duration of the
connection's task tree (after `daemon.trusted_proxies` /
X-Forwarded-For resolution).

This keeps every emission site uniform — sites don't need to know
whether they're running inside a remote-IPC scope or a daemon-
internal one (outbox / janitor / federation accept). Outside any
scope, `current_client_ip()` returns `None` and the row records "no
remote client".

## Naming shape

- `<namespace>.<event>` — primary state events / operator commands.
  Example: `peer.add`, `message.sent`.
- `<namespace>.<event>.<phase>` — observed counterparts and follow-on
  transitions. Example: `channel.advertise.observed`,
  `workspace.invite.accepted`.
- All snake_case within each component.
- Past tense for events the daemon witnessed (`message.delivered`).
  Imperative for operator commands (`peer.add`).

`scripts/check_naming.sh` enforces the regex.

## Doc parity

Every static `action: "..."` literal in
`crates/hermod-daemon/` must appear (between backticks) in
`docs/audit_actions.md`. Pinned by
`crates/hermod-routing/tests/docs_coverage.rs::audit_doc_covers_every_static_emission`.

When you add a new emission site, update the doc in the same PR.
