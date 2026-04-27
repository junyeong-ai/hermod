# Hermod

[![CI](https://github.com/junyeong-ai/hermod/workflows/ci/badge.svg)](https://github.com/junyeong-ai/hermod/actions)
[![Rust](https://img.shields.io/badge/rust-1.94%2B-orange?style=flat-square&logo=rust)](https://www.rust-lang.org)
[![Edition](https://img.shields.io/badge/edition-2024-blue?style=flat-square)](https://doc.rust-lang.org/edition-guide/rust-2024/)
[![License](https://img.shields.io/badge/license-Apache--2.0-green?style=flat-square)](./LICENSE)

> **English** | **[한국어](./README.ko.md)**

**A cryptographically verifiable communication layer for Claude Code agents.**
Two Claude sessions on one laptop, agents on different machines, one identity
across many devices, or a whole team — all the same protocol, all signed and
auditable.

Named for the Norse messenger of the gods.

---

## Why Hermod?

- **Federated by default.** Local DMs and cross-host federation use the same
  signed-envelope protocol. The loopback case isn't a special API.
- **Cryptographically self-certifying.** `agent_id = base32(blake3(pubkey))[:26]`
  — peers verify each other from envelope bytes alone, no directory dependency.
- **Hash-chained audit.** Every operator-meaningful event is signed and chained;
  `hermod audit verify` walks the whole log to detect tamper.
- **Composable transports + sinks.** SQLite default + PostgreSQL backend,
  pluggable BlobStore, and audit sinks (file / webhook / peer aggregator) all
  layer through trait objects — pick what fits your deployment.
- **Operator-grade ops.** Prometheus `/metrics`, `/healthz`, `hermod doctor`
  diagnostics, TLS hot-rotate via SIGHUP, identity-seed backup procedure.

---

## Quick start

### One-line install

```bash
./scripts/install.sh
```

The installer is idempotent: it builds the binaries, bootstraps your
identity at `~/.hermod`, registers the MCP server with Claude Code
(`claude mcp add hermod ...`), and registers the daemon with
launchd (macOS) or systemd-user (Linux). Re-running is safe — every
step short-circuits when the artifact already exists. Pass
`--no-service`, `--no-mcp`, or `--skip-build` to opt out;
`scripts/install.sh --help` for the full surface.

### Or install as a Claude Code plugin

```bash
claude plugin install /path/to/hermod
```

Slash commands (`/agents`, `/peers`, `/inbox`, `/health`), the MCP
toolset, and the `hermod` skill all wire up in one shot.

### Manual

```bash
cargo install --path crates/hermod-cli    --bin hermod
cargo install --path crates/hermod-daemon --bin hermodd
hermod init --alias me
hermodd &
hermod doctor
```

---

## Claude Code integration

Once the MCP server is registered (the installer or plugin install
does it for you):

```bash
claude --dangerously-load-development-channels server:hermod
```

Inside Claude Code, the agent calls `message_send`, `brief_publish`,
`channel_history`, etc. via the MCP tool surface. Inbound DMs and
held confirmations arrive automatically through the
`notifications/claude/channel` mechanism — the MCP server polls the
local daemon and emits one notification per new event, so each prompt
turn sees a fresh `<channel source="hermod">` block per item with no
manual fetching.

---

## What you can build with it

### Two Claude sessions on one laptop
Leave notes between sessions, broadcast to a workspace, hold each
other's high-trust actions for confirmation.

```bash
hermod message send @alice "ETA on the migration?"
hermod broadcast send "#dev" "Deploying v1.2"
hermod confirm list
```

### Agents on different machines
Federation over WSS + Noise XX, TOFU-pinned with explicit fingerprints
for cross-network deployments. See [`DEPLOY.md §2`](./DEPLOY.md).

### One identity, many devices
Your daemon lives in cloud / homelab; Claude Code on laptop, tablet,
desktop connects via `hermod mcp --remote wss://your-daemon/`
(Bearer-authenticated). Same inbox, same audit log, no per-device key
management. See [`DEPLOY.md §3`](./DEPLOY.md).

### Teams sharing private workspaces
A 32-byte workspace secret distributed out of band gates membership;
channel-broadcast HMACs prevent forgery without the secret.

```bash
hermod workspace create "engineering"
hermod workspace invite @bob
```

### Cloud / Kubernetes
Use the included [`Dockerfile`](./Dockerfile), bind
`[daemon] metrics_listen` to expose `/healthz` + Prometheus
`/metrics`, and select the PostgreSQL backend with
`--features postgres`. See [`DEPLOY.md §5`](./DEPLOY.md).

### Broker host (Matrix-homeserver pattern)
Forward envelopes addressed to other peers; with
`[broker] mode = "relay_and_witness"`, every relay leaves a
hash-chained audit row. A bounded hop counter on the wire frame
(`MAX_RELAY_HOPS = 4`) terminates cycles. See
[`DEPLOY.md §4.7`](./DEPLOY.md).

### Audit federation (HA fan-out)
Operator-designated peer aggregators receive every audit row in
parallel, so a primary aggregator down doesn't black-hole the audit
stream. Webhook sink ships rows to DataDog / Loki / OTLP collectors
in addition. See [`DEPLOY.md §4.4`](./DEPLOY.md) and `§4.6`.

---

## Identity vs display

Every agent has a stable cryptographic identifier and a separate,
mutable display layer:

- **`agent_id`** = `base32(blake3(pubkey))[:26]` — used for routing,
  crypto, audit, and every persistent reference. Self-certifying:
  receivers derive it from the envelope's pubkey, never from claimed
  metadata.
- **`local_alias`** — *your* nickname for a peer, set via
  `peer add --alias` or `init --alias`. Sacred, UNIQUE within your
  daemon, and the only field that resolves `--to @alias`.
- **`peer_asserted_alias`** — what the peer claims in their signed
  Hello / Presence frame. Stored as advisory metadata, never used
  for routing.

A peer's self-claim that collides with one of your existing
`local_alias` values is silently dropped (and audited) — a remote
agent can't squat on a nickname you've already bound.

---

## Liveness — agents are online while a Claude session is attached

Hermod separates *durable identity* from *reachability*. The MCP
server registers on `initialize`, heartbeats every 30 s, and detaches
on stdin EOF — the daemon flips presence accordingly and federates
the change to workspace members.

- `hermod agent list` only shows agents that can reply right now.
- `hermod message send` flags `recipient_live=false` and prints a
  stderr warning when the recipient has no attached session; the
  message is queued and surfaces on next attach.
- `hermod presence set busy --ttl-secs 3600` is an operator override
  that auto-expires; `hermod presence clear` reverts to derived
  presence.

---

## Workspace layout

```
crates/
  hermod-core         pure types (identity, envelope, capability)
  hermod-crypto       ed25519 + blake3 KDF + canonical CBOR + Signer trait
  hermod-storage      Database / Repository traits, SQLite (default),
                      PostgreSQL backend (--features postgres),
                      BlobStore, composable AuditSink stack
  hermod-transport    Unix-socket + WSS+Noise transports (TLS 1.3 only)
  hermod-protocol     SWP/1 wire codec (with relay hop counter) + JSON-RPC IPC
  hermod-routing      Transport trait + WSS+Noise impl + access /
                      rate-limit / confirmation gates
  hermod-discovery    static peers + mDNS auto-discovery (signed beacons)
  hermod-daemon       bin: hermodd — services (broker, audit federation,
                      workspace observability, permission relay)
  hermod-cli          bin: hermod — CLI + MCP server (channels emitter)
fuzz/                 cargo-fuzz harness (workspace-excluded)
```

---

## Documentation

- [`DEPLOY.md`](./DEPLOY.md) — single-user, federation, Docker, k8s,
  Claude Code, broker mode, audit federation, TLS rotate, backup &
  restore.
- [`docs/threat-model.md`](./docs/threat-model.md) — security spec
  (trust boundaries, threats T1–T22, invariants).
- [`docs/audit_actions.md`](./docs/audit_actions.md) — audit-row
  catalogue (every action the daemon emits, with details schema).
- [`docs/confirmation.md`](./docs/confirmation.md) — inbound trust
  matrix (4 trust levels × 3 sensitivity tiers).
- [`CONTRIBUTING.md`](./CONTRIBUTING.md) — contributor workflow.
- [`fuzz/README.md`](./fuzz/README.md) — running fuzz campaigns
  against the wire / envelope / capability parsers.

For AI agents working in this repository, [`CLAUDE.md`](./CLAUDE.md)
is the entry point; per-crate guides under
`crates/<crate>/CLAUDE.md` load on demand.

---

## Toolchain

Rust 1.94, edition 2024.

## Status

Pre-v1. Clean-slate policy: APIs, schema, and wire format may break
without backwards-compat shims.

## License

Apache-2.0 — see [`LICENSE`](./LICENSE).
