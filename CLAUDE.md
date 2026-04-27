# Hermod — AI agent guide

Cryptographically-verifiable multi-agent communication layer for Claude
Code. Two binaries: `hermodd` (daemon) and `hermod` (CLI / MCP server).
Pure Rust, edition 2024.

Per-crate detail loads on demand from `crates/<crate>/CLAUDE.md` when
you touch files in that directory. Cross-cutting rules live in
`.claude/rules/`. Operator-facing docs (deployment, threat model,
audit catalogue) live under `DEPLOY.md` and `docs/`.

---

## Crate layer order (strict — never violate)

```
hermod-core   →  hermod-crypto  →  hermod-storage  →  hermod-transport
                                                      ↓
                hermod-protocol ←─────────┐    hermod-routing
                                          │           ↓
                                  hermod-discovery
                                          ↓
                              hermod-daemon  +  hermod-cli
```

A crate may only depend on crates above it in the chain. The boundary
is enforced socially (no cargo lint pins it); flag any inversion in
review.

---

## Build / test / lint

```bash
cargo build --workspace
cargo test  --workspace                            # unit + integration
cargo test  --workspace --features postgres        # adds postgres tests (needs HERMOD_TEST_POSTGRES_URL)
cargo build --release --workspace --bins           # release binaries; e2e tests in crates/hermod-cli/tests/ depend on these
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
bash scripts/check_naming.sh                       # IPC method / dispatcher / audit-action / repo-impl naming
```

Workspace lint floor lives in `[workspace.lints]` in the root
`Cargo.toml`; per-crate `[lints] workspace = true`. **Never** add
`#![deny(...)]` to a crate's `lib.rs` / `main.rs` — it duplicates the
workspace policy and drifts.

The fuzz harness is a separate, workspace-excluded crate at `fuzz/`.
Run campaigns with `cargo install cargo-fuzz` once and then
`cargo fuzz run <target>` (see `fuzz/README.md`).

---

## Naming taxonomy (single source of truth)

Suffix conventions — pick the right one before introducing a new type:

| Suffix | Meaning |
| --- | --- |
| `*Verdict` | Policy gate's judgment. `AccessVerdict`, `confirmation::Verdict`. Variants are `Accept` / `Reject` (+ `Confirm` for the trust gate). |
| `*Outcome` | Operation result with success-path branches. `RelayOutcome`, `DeliveryOutcome`, `MessagePruneOutcome`, `AliasOutcome`, `RepinOutcome`, `DetachOutcome`. |
| `*Result` | RPC response payload. `MessageSendResult`, `WorkspaceRosterResult`. Pairs with `*Params`. |
| `*Response` | Protocol message-pair counterpart inside an envelope body. |
| `*Chunk` | One peer's contribution to an aggregated fan-out. `RosterChunk`, `ChannelsChunk`. |
| `*Repository` | Storage trait per collection. |
| `*Service` | Daemon service (held by `Dispatcher`). |
| `*Sink` | Composable audit destination. `StorageAuditSink`, `FileAuditSink`, `WebhookAuditSink`, `RemoteAuditSink`, `TeeAuditSink`. |
| `*Mode` | Operator-driven enum collapsing previously-conflicting bool combinations. `BrokerMode`. |

RPC method names: `<namespace>.<verb>` (e.g. `message.send`,
`capability.deliver`). Audit actions: `<namespace>.<event>` or
`<namespace>.<event>.<phase>`, all snake_case. Both validated by
`scripts/check_naming.sh` and `crates/hermod-routing/tests/docs_coverage.rs`.

---

## Invariants the codebase relies on

- **Self-certifying identities.** `agent_id = base32(blake3(pubkey))[:26]`.
  Never trust an `agent_id` claimed in metadata — derive it from the
  pubkey on the inbound path.
- **Envelope is application-signed.** Don't add per-hop fields to
  `Envelope`. Hop counters and routing scratch belong to `WireFrame`
  (see `EnvelopeFrame`), not the signed payload.
- **Audit emission goes through `audit_or_warn(&*sink, entry)`.**
  `AuditRepository::append` is forbidden by `clippy.toml`.
- **Federation feedback loop control is typed.** `AuditEntry.federation:
  AuditFederationPolicy { Default | Skip }`. String-prefix heuristics
  are not allowed — the compiler enforces.
- **Held-confirmation intent is typed.** `pending_confirmations.intent`
  column maps to `HoldedIntent` enum at the API boundary, not free
  string.
- **TLS is pinned to 1.3 only.** `hermod_transport::tls::PROTOCOL_VERSIONS`
  is the single source — every rustls config in the workspace uses it.
- **Identity secret zeroizes on drop.** `Keypair` derives
  `ZeroizeOnDrop`; ed25519-dalek's `zeroize` feature is on at the
  workspace level.
- **Hop counter caps mesh cycles.** `wire::MAX_RELAY_HOPS = 4`.
  Brokers increment + reject on overflow; receivers defensively check.

---

## Documentation contracts

- **`docs/audit_actions.md`** is the canonical audit catalogue. Every
  static `action: "..."` literal in the daemon source must appear there
  — pinned by `crates/hermod-routing/tests/docs_coverage.rs`.
- **`docs/threat-model.md`** lists every trust surface. Adding a new
  one (new sink, new transport, new audit federation peer) requires a
  threat entry.
- **`docs/confirmation.md`** is the trust-gate matrix.
  `crates/hermod-routing/tests/docs_coverage.rs` pins it to the
  `MessageKind` enum.
- **Operator-facing docs do not mention internal metrics** (line
  counts, test counts, crate counts). Maintenance cost without behavior
  signal — keep them out of `README.md` / `DEPLOY.md` / `CLAUDE.md`.

---

## Clean-slate policy

Pre-v1: no backwards compatibility, no migration shims, no
"renamed-from" or "deprecated since" comments, no aliases. When a
name / schema / wire-format decision changes, replace it everywhere
in one pass. Migrations are up-only; the schema-mismatch handler in
`hermod-daemon/src/main.rs` tells operators to archive the DB and
re-init rather than offering a downgrade path.

---

## Imports

- `@DEPLOY.md` — operator deployment scenarios (single-user, federation,
  Docker, k8s, Claude Code, broker mode, audit federation, TLS rotate)
- `@docs/threat-model.md` — security spec (trust boundaries, threats
  T1–T22, invariants)
- `@docs/audit_actions.md` — audit-row catalogue
- `@docs/confirmation.md` — trust-gate decision matrix
- `@CONTRIBUTING.md` — contributor workflow
