# Hermod — AI agent guide

Cryptographically-verifiable multi-agent communication layer for Claude
Code. Two binaries: `hermodd` (daemon) and `hermod` (CLI / MCP server).
Pure Rust, edition 2024.

Per-crate detail loads on demand from `crates/<crate>/CLAUDE.md` when
you read files in that directory. Cross-cutting topic rules live under
`.claude/rules/` and load automatically (path-scoped where noted).
Operator and security docs live at `DEPLOY.md`, `CONTRIBUTING.md`, and
`docs/{audit_actions,confirmation,threat-model}.md` — read on demand
when the task touches them.

---

## Crate layer order (strict — never violate)

```
hermod-core
  ↓
hermod-crypto
  ├─→ hermod-storage
  ├─→ hermod-transport
  ├─→ hermod-discovery
  └─→ hermod-protocol     (also depends on transport)
        ↓
        hermod-routing    (also depends on storage + transport)
          ↓
          hermod-daemon   (depends on every crate above)
            ↓
            hermod-cli    (depends on every crate above except discovery)
```

A crate may only depend on crates above it in the chain (verify with
`grep '^hermod-' crates/<crate>/Cargo.toml`). The boundary is
enforced socially (no cargo lint pins it); flag any inversion in
review.

---

## Build / test / lint

```bash
cargo build --workspace
cargo test  --workspace                            # unit + integration
cargo test  --workspace --features postgres        # +postgres tests (needs HERMOD_TEST_POSTGRES_URL)
cargo build --release --workspace --bins           # release bins (e2e tests under crates/hermod-cli/tests/ depend on these)
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
bash scripts/check_naming.sh                       # IPC method / dispatcher / audit-action / repo-impl shapes
```

The fuzz harness is a separate, workspace-excluded crate at `fuzz/`
(`cargo install cargo-fuzz` once, then `cargo fuzz run <target>`).

---

## Invariants the codebase relies on

- **Self-certifying identities.** `agent_id = base32-unpadded-lowercase(blake3(pubkey))[:26]`.
  Never trust an `agent_id` claimed in metadata — derive it from the
  pubkey on the inbound path.
- **Envelope is application-signed.** Don't add per-hop fields to
  `Envelope`. Hop counters and routing scratch belong to `WireFrame`
  (see `EnvelopeFrame`), not the signed payload.
- **Audit emission goes through `audit_or_warn(&*sink, entry)`.**
  `AuditRepository::append` is forbidden by `clippy.toml` (so is
  `tokio::net::UnixListener::bind` — use
  `hermod_transport::UnixIpcListener` for 0o600-from-creation).
- **Federation feedback loop control is typed.** `AuditEntry.federation:
  AuditFederationPolicy { Default | Skip }`. String-prefix heuristics
  forbidden — the compiler enforces.
- **Held-confirmation intent is typed.** `pending_confirmations.intent`
  column maps to `HeldIntent` enum at the API boundary, not free
  string.
- **TLS is pinned to 1.3 only.** `hermod_transport::tls::PROTOCOL_VERSIONS`
  is the single source — every rustls config in the workspace uses it.
- **`$HERMOD_HOME` mode policy is single-source.** Spec lives in
  `hermod_daemon::home_layout::spec(home)`. Boot calls `enforce`
  (fail-loud); doctor calls `audit`. Never chmod files outside that
  module.
- **Identity secret zeroizes on drop.** `Keypair` derives
  `ZeroizeOnDrop`; ed25519-dalek's `zeroize` feature is on at the
  workspace level. Same for `WorkspaceSecret` / `WorkspaceMacKey` /
  `ChannelMacKey` / `SecretString`.
- **Hop counter caps mesh cycles.** `wire::MAX_RELAY_HOPS = 4`.
  Brokers increment + reject on overflow; receivers defensively check.

---

## Documentation contracts

- **`docs/audit_actions.md`** — canonical audit catalogue. Every static
  `action: "..."` literal in the daemon source must appear there.
  Pinned by `crates/hermod-routing/tests/docs_coverage.rs`.
- **`docs/threat-model.md`** — security spec. Adding a new trust
  surface (sink, transport, audit federation peer) requires a threat
  entry.
- **`docs/confirmation.md`** — trust-gate matrix; pinned to the
  `MessageKind` enum by the same doc-coverage test.
- **Operator-facing docs do not mention internal metrics** (line
  counts, test counts, crate counts). Maintenance cost without
  behavior signal — keep them out of `README.md` / `DEPLOY.md` /
  `CLAUDE.md`.
