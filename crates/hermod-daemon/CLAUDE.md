# hermod-daemon — AI agent guide

`hermodd` binary. Owns the federation listener, IPC dispatcher,
service layer, outbox worker, janitor, and observability endpoint.

## Module layout

```
bootstrap/         construction-phase helpers (audit_sink, …)
config.rs          [identity|daemon|storage|blob|federation|policy|audit|broker]
dispatcher.rs      RPC method → service-call routing
federation.rs      WSS+Noise inbound accept loop (Semaphore, per-IP rate limit)
home_layout.rs     single source of truth for $HERMOD_HOME mode policy: spec(), set_secure_umask(), prepare_dirs() (init), ensure_dirs() (boot), enforce(), audit() (doctor)
identity.rs        on-disk seed/cert/bearer helpers (load, save, ensure_tls, ensure_bearer_token)
inbound/           per-MessageKind acceptors (one impl block per file)
ipc_remote.rs      WSS+Bearer remote-IPC server
janitor.rs         periodic sweep (briefs, confirms, sessions, audit archive)
main.rs            entry: load identity → ensure TLS → connect storage → server::serve
observability.rs   /healthz (liveness) + /readyz (readiness) + /metrics (Prometheus, hand-rolled HTTP/1.1)
outbox.rs          retry queue with claim_token + claimed_at backoff
paths.rs           HOME / config / blob root resolution
server.rs          serve() — orchestrates audit sink → transport → services → workers
services/          one *Service per IPC namespace (held by Dispatcher)
services/permission_relay.rs  production trait impls of PromptForwarder + RelayResponder
```

## Inbound pipeline

`InboundProcessor::accept_envelope(source_hop, envelope, hops)` is the
single entry point for every inbound envelope (live federation +
held-confirmation replay take the same path). Order:

1. Hop count guard (`hops > MAX_RELAY_HOPS` ⇒ Invalid)
2. Recipient check (broker fall-through if `to.id != self_id` and broker wired)
3. Cap-count guard (`caps.len() > MAX_CAPS_PER_ENVELOPE` ⇒ Invalid)
4. Replay window
5. `from_pubkey` ↔ `from.id` binding (self-certification)
6. Signature verify
7. Rate limit (per `(from, to)` token bucket)
8. Capability check (strict for kinds in `always_requires_capability`)
9. Confirmation gate (`Verdict::{Accept,Reject,Confirm}`)
10. Apply (per-kind acceptor in `inbound/<kind>.rs`)

`apply_held` (operator-accepts-confirmation path) skips 2–8 — those
gates already cleared at hold time — but re-checks freshness on the
held CBOR.

## Service wiring

`InboundProcessor` is built via the consume-on-wire builder pattern
(`with_permission_service` / `with_workspace_observability` /
`with_broker_service`). Once `Clone`-d into the `Dispatcher`, services
are immutable. Adding a new optional sub-service ⇒ another
`with_*` method that takes `self`.

Two services are post-construction-wired via `OnceLock` to break
circular dependencies with `MessageService`:
- `RemoteAuditSink::set_messages(...)` — audit row → AuditFederate envelope
- `PermissionService::set_relay_responder(...)` / `set_prompt_forwarder(...)`
  — federation-relay verdicts back to originator + fan-out to delegates.
  Backed by trait objects (`MessageRelayResponder`,
  `CapabilityPromptForwarder`) in `services/permission_relay.rs`.

## $HERMOD_HOME layout policy

Every file under `$HERMOD_HOME/` is declared once in
`home_layout::spec(home)` — the single source of truth covering the
home dir itself, `config.toml`, `identity/*`, `hermod.db*`,
`blob-store/`, and `archive/`. Five APIs derive from that one list:

- `home_layout::set_secure_umask()` — process-global `umask 0o077`
  set at the very top of `main()`, mirroring systemd `UMask=0077`.
  Every subsequent file create defaults to 0o600, every dir to 0o700.
- `home_layout::prepare_dirs(home)` — `hermod init` path. Creates +
  chmods `$HERMOD_HOME` and `identity/` to 0o700, repairing existing
  permissive modes. Explicit operator action ⇒ silent repair OK.
- `home_layout::ensure_dirs(home)` — daemon boot path. Strict
  fail-loud — refuses to chmod existing dirs (sshd `StrictModes`).
- `home_layout::enforce(home)` — boot post-init check; refuses to
  start on any `Secret` / `Directory` mode breach. `Public` and
  `OperatorManaged` kinds are reported by `audit` but not enforced.
- `home_layout::audit(home)` — non-fatal per-file report consumed by
  `hermod doctor`.

**No silent repair on the daemon side.** A mode breach is a fail-loud
signal; auto-repair would mask intrusions. Operators chmod manually;
the change lands in shell history. The init path is the one
exception (it's an explicit operator-driven bootstrap).

**Adding a new file under `$HERMOD_HOME`** ⇒ one new `HomeFile` entry
in `spec()`. Boot enforcement, doctor audit, and `chmod` hints all
update automatically. If the daemon writes the file directly, ensure
the writer uses `set_permissions` explicitly so the umask 0o077
doesn't mask `Public`-kind modes (e.g. `tls.crt` at 0o644).

## Broker mode

`BrokerMode { Disabled | RelayOnly | RelayAndWitness }` — single enum,
no impossible bool combinations. `BrokerService::new` only constructed
when `mode != Disabled`. Witness rows go through the same audit sink
as the daemon's own actions.

`RelayWitnessVerb` (strum-iterable) types the audit-action suffix.
Doc-coverage test in this crate pins each variant to
`docs/audit_actions.md`.

## Audit policy at emission

Every `AuditEntry { ... }` literal must specify `federation:
hermod_storage::AuditFederationPolicy::Default` or `Skip`. Default for
nearly every site; Skip only for the 3 federation-feedback paths
documented in the storage-layer guide. Compile error if missing.

## Configuration via env

Every `[section] field` has a matching `HERMOD_<SECTION>_<FIELD>` env
override (see `config.rs::load_env_overrides`). Adding a new config
field requires both: TOML serde default + env-var arm. Operators
running under containers config exclusively via env.

## Common entry points

- New audit action: emit via `audit_or_warn(...)` in the relevant
  service, document in `docs/audit_actions.md`. Doc-coverage test
  catches the drift.
- New IPC method: const in `hermod_protocol::ipc::methods` →
  `Params`/`Result` types → service method → arm in `dispatcher.rs`.
  `scripts/check_naming.sh` enforces shape.
- New envelope kind: `MessageKind` variant in `hermod-core` →
  `MessageBody::*` body type → `inbound/<kind>.rs` acceptor →
  outbound builder in the relevant service → `intent_for` arm in
  `inbound/scope.rs` → `HoldedIntent` variant in `hermod-storage`.
  Compiler walks you through the exhaustiveness.
