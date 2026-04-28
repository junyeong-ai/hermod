# Contributing to Hermod

## Quick orientation

Hermod is a Rust workspace with eight crates:

| Crate | Role |
| ----- | ---- |
| `hermod-core` | Identity types (`AgentId`, `AgentAlias`), envelope schema, time, errors. The vocabulary every other crate speaks. |
| `hermod-crypto` | ed25519 keypair, Noise XX wrappers, blake3 helpers, capability-token signing. |
| `hermod-storage` | SQLite repositories (one repo per logical entity). Migrations embedded via `sqlx::migrate!`. |
| `hermod-protocol` | Wire-level codecs (CBOR envelopes, JSON-RPC IPC) and the canonical IPC method surface (`crates/hermod-protocol/src/ipc/methods.rs`). |
| `hermod-routing` | Federation peer connections, outbox delivery, capability access checks, rate limiting, confirmation matrix. |
| `hermod-discovery` | Static + mDNS peer discovery. |
| `hermod-transport` | WebSocket + TLS + Unix-socket plumbing. |
| `hermod-daemon` | The `hermodd` binary: services, dispatcher, inbound processor, observability (metrics + healthz + readyz). |
| `hermod-cli` | The `hermod` binary: CLI subcommands, MCP stdio bridge, channel emitter. |

## How to add things

### A new IPC method

1. **Wire constant**: append to `crates/hermod-protocol/src/ipc/methods.rs::method` (`<namespace>.<verb>` snake_case).
2. **Params + Result types**: add `<Namespace><Verb>Params` and `<Namespace><Verb>Result` next to the constant. Use `#[serde(default, skip_serializing_if = "Option::is_none")]` for optional fields.
3. **Service handler**: add a method to the appropriate `crates/hermod-daemon/src/services/*.rs`. State-changing methods MUST `db.audit().append(...)`.
4. **Dispatcher**: route in `crates/hermod-daemon/src/dispatcher.rs::dispatch`.
5. **CLI client wrapper**: add to `crates/hermod-cli/src/client.rs`.
6. **CLI command**: add to `crates/hermod-cli/src/commands/<area>.rs` and wire into `crates/hermod-cli/src/main.rs`.
7. **MCP tool (optional)**: surface to LLMs via `crates/hermod-cli/src/mcp/tools.rs`.

### A new `MessageBody` variant

1. Add the variant to `crates/hermod-core/src/envelope.rs::MessageBody` with a `serde(tag = "kind")`-consistent name.
2. Update `MessageBody::kind()` and `MessageKind`.
3. Update `crates/hermod-routing/src/confirmation.rs::classify` (sensitivity) and `summarize`.
4. Update `crates/hermod-daemon/src/inbound.rs::apply_envelope` (handler arm) and `validate_inbound_body_size` (size cap).
5. Update `crates/hermod-routing/src/lib.rs::scope` if a new capability scope is needed.

### A new audit action

Action names follow `<noun>.<verb_past>` (e.g. `peer.add`, `message.delivered`, `presence.observed`). Always include enough `details` JSON to reconstruct intent without reading the source.

## Naming conventions

- Wire methods: `<namespace>.<verb_snake>` — `agent.list`, `mcp.attach`, `presence.set_manual`.
- Rust types: `<Namespace><Verb>{Params,Result}` PascalCase — `AgentList{Params,Result}`.
- DB columns: snake_case.
- JSON view fields: snake_case.
- alias columns are split: `local_alias` (operator-set, sacred, UNIQUE), `peer_asserted_alias` (peer self-claim, advisory), `effective_alias` (derived).

## Testing

- Unit tests live alongside the code (`#[cfg(test)] mod tests`).
- Integration tests in `crates/hermod-cli/tests/{federation,channels}.rs` drive the actual binaries — run with `cargo test --release`.
- `cargo test --workspace` is the single source of truth.

## CI gate

Every push and PR runs `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, `cargo doc` (with `-D warnings`). All four must pass before merge. Run them locally before pushing:

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Migration / schema policy

Hermod follows a **clean-slate schema policy**: migrations are edited in place rather than appended. When the schema changes, deployed daemons must archive their DB (`mv ~/.hermod/hermod.db ~/.hermod/hermod.db.archive.$(date +%s)`) and re-init. This trades upgrade smoothness for a maximally clean schema; it is appropriate while we are pre-1.0. After 1.0, migrations will be append-only and explicitly versioned.
