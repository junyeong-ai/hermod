# Hermod Threat Model

This is the security spec the system was designed against. New threats and
changes to mitigations belong here first.

## 1. Trust boundaries

```
┌────────────────────────────────────────────────────────────────┐
│  Trust boundary A: same-machine UNIX user (UID).               │
│  Inside: everything that can read $HERMOD_HOME/host/ and      │
│  $HERMOD_HOME/agents/.                                         │
│  Crossing: any other UNIX user / process without that access.  │
└────────────────────────────────────────────────────────────────┘
        ▲ CLI / MCP server reach the daemon over a UNIX socket
        │ at $HERMOD_HOME/sock (mode 0600 by socket-bind default).
        │
┌────────────────────────────────────────────────────────────────┐
│  Trust boundary B: network.                                    │
│  Inside: this daemon, its identity key, its sqlite DB.         │
│  Crossing: any other host that speaks SWP/1.                   │
└────────────────────────────────────────────────────────────────┘
        ▲ federation runs over WSS+Noise XX. Authenticated peers
        │ are still untrusted by default; they may only deliver
        │ envelopes whose `from.id` matches their authenticated
        │ identity.
```

## 2. Threats and mitigations

| #   | Threat | Mitigation |
| --- | ------ | ---------- |
| T1  | Network eavesdropping | Noise XX AEAD (ChaCha20-Poly1305) on every wire frame; outer TLS adds host auth + middlebox resistance. |
| T2  | Agent impersonation | ed25519 envelope signatures; `agent_id = base32(blake3(pubkey))[:26]` is self-certifying. |
| T3  | Replay attack | ULID id + signed `ts` in every envelope; recv side rejects ts more than `policy.replay_window_secs` off wall clock; unique-id constraint dedupes at storage. |
| T4  | Spam / DoS from authenticated peer | Per-`(from, to)` token bucket persisted in `rate_buckets`; capacity = `policy.rate_limit_per_sender` per minute. |
| T5  | Privilege escalation via forged message | Federation listener enforces `envelope.from.id == authenticated peer's agent_id`; sig verify mandatory. |
| T6  | Local malware reading identity / messages | Two-layer file mode policy enforced by `hermod_daemon::home_layout`: (1) process `umask 0o077` set at the top of `main()` (systemd `UMask=0077` model) so every new file under `$HERMOD_HOME` defaults to mode 0600 and every directory to 0700 — covers SQLite-managed `hermod.db*`, blob payloads, archived state. (2) Boot-time `enforce` re-checks every spec'd file (host/, agents/<id>/, hermod.db + WAL/SHM, blob-store/, archive/) against its required mode and refuses to start on a breach (sshd `StrictModes` model — no silent repair, so an attacker who chmod-relaxed a file can't have the daemon "fix" it back). `SecretString` (in-memory bearer + audit-webhook token) and `Keypair`/`WorkspaceSecret`/`ChannelMacKey` derive `ZeroizeOnDrop`. |
| T7  | Sensitive inbound from low-trust peer auto-applied | Confirmation gate (`hermod-routing::confirmation`) holds review/sensitive actions in `pending_confirmations` until the operator decides; untrusted+sensitive auto-rejects. See `docs/confirmation.md`. |
| T8  | Session hijacking | Forward secrecy via Noise ephemeral keys per session — leaking the static key does not let an attacker decrypt past sessions. |
| T9  | Compromised peer | Trust levels (`self` / `verified` / `tofu` / `untrusted`); fingerprint pinning at both Noise and TLS layers; reputation counter; manual re-trust required when a fingerprint changes. |
| T10 | Hostile MCP client | All authorization is checked on the daemon, not in MCP. Capability scopes carve the daemon's API into the smallest grant that gets the job done. |
| T11 | Outbox amplification | Per-message attempt cap (5) + exponential backoff (1·5·15·60·300s); the recipient's rate limiter still applies on every attempt. |
| T12 | Capability hoarding via long-lived bulk grants | Capability tokens carry `iat`/`exp`; `policy.require_capability` lets the recipient demand them per scope; revocation is durable in the `capabilities` table. |
| T13 | Multi-device confusion | `agent_id` is a deterministic function of the secret seed: two hosts with the same seed are by design the same agent. Distinct identities require distinct seeds. TLS-fingerprint TOFU additionally pins per-endpoint identity. |
| T14 | Audit-log tampering | Each appended row carries `prev_hash` (link to predecessor's `row_hash`), `row_hash` (blake3 over content + prev_hash), and `sig` (ed25519 by daemon keypair). `hermod audit verify` walks the chain; any tamper, deletion, or row-rewrite is detected. |
| T15 | 1-hop discovery metadata leak (public workspaces) | "Public" means visible to authenticated peers in the federation graph, not internet-public. Public workspace ids are `derive_key(creator_pubkey, name)` — probing for a name still requires guessing both inputs. Private workspaces never advertise. |
| T16 | Workspace-secret blast radius | One leaked private-workspace secret grants full read/forge to every channel under it (channel HMAC keys derive from the same secret). Re-issue means generating a fresh workspace and re-distributing the new secret out of band. Public workspaces are unaffected. |
| T17 | Held-confirmation hoarding | Janitor sweeps pending confirmations older than `policy.confirmation_retention_secs` (default 7 days), marking them `expired`. Audit history of the held state is preserved. |
| T18 | Alias spoofing / impersonation | Identity is the ed25519 hash; aliases are display only. Routing (`--to @alias`) consults `local_alias` exclusively — receiver-set, sacred, UNIQUE per daemon. A peer's self-asserted alias lands in `peer_asserted_alias` (advisory, no UNIQUE) and never overrides the local label. Federation handshake / mDNS TXT collisions on a local label are silently demoted at `agents().upsert_observed()` and audited as `peer.alias_collision`. Channel notifications expose `from_local_alias` + `from_peer_alias` separately so consumers can detect a mismatch. |
| T19 | LAN mDNS beacon spoofing | mDNS is plaintext multicast — any host on the broadcast domain can forge a `_hermod._tcp.local.` TXT record. Defense in depth: every emitted beacon now carries `ts_ms`, `validity_secs`, and an ed25519 `sig` (canonical CBOR over agent_id, pubkey, port, ts, validity). Receivers in strict mode reject anything that fails signature verification, has a stale `ts`, has a future `ts > 60 s` ahead of local clock, or fails the `agent_id == blake3(pubkey)[:26]` binding. The Noise XX handshake remains the ground truth — even a passing beacon only feeds endpoint discovery — but the operator never sees a fingerprint they could be tricked into trusting. Audit: `mdns.beacon_emitted` / `mdns.beacon_observed` / `mdns.beacon_rejected`. |
| T20 | Broker as metadata oracle | A broker host sees envelope `from`, `to`, `kind`, ciphertext size, and timing for everything it relays — full social-graph metadata even though content stays sealed by the original sender's signature. Operators only configure brokers they already trust at the metadata level. Hop-counted relays (`MAX_RELAY_HOPS = 4` on the wire frame) bound any one envelope to at most four metadata observers; a malicious broker can drop or stall envelopes but cannot impersonate the sender, mutate the body, or bypass the receiver's per-`(from, to)` rate limiter. With `[broker] mode = "relay_and_witness"` every relay attempt is committed to the broker's own hash-chained audit log, so an operator can later prove what their broker did. |
| T21 | Audit aggregator compromise | Cross-daemon audit federation ships a `MessageBody::AuditFederate` envelope to each operator-designated aggregator. A compromised aggregator can omit, reorder, or fabricate rows in *its* view of the federated stream — but every emitting daemon retains its own hash-chained `audit_log` as ground truth, so `hermod audit verify` on the source daemon still detects any tamper. The aggregator is "best-effort recent state", not "the source of truth"; treat it as a query convenience, not a primary audit. Federation feedback loops are prevented at *emission* time via a typed `AuditFederationPolicy::Skip` flag on every `AuditEntry` (no string heuristics). |
| T22 | Audit webhook leak | The HTTP webhook sink emits each audit row as plaintext JSON to an operator-configured URL. Compromise of the webhook endpoint (or anywhere the row transits in the clear) leaks the entire operator-meaningful state stream — peer identities, workspace ids, capability metadata. The sink supports `Authorization: Bearer <token>` and the URL must be HTTPS for any deployment outside a fully-trusted network; the local hash-chained log is unaffected by webhook tampering. |
| T23 | Live-mutation registry hijack | `LocalAgentRegistry` (in-memory, `Arc<RwLock<…>>`) is the bearer-hash → agent_id index every IPC handshake consults. `local.add` / `local.rotate` / `local.remove` IPC paths take the write lock and update disk + DB + registry in lockstep, then force-close any session pinned to a removed/rotated bearer via per-session `oneshot::Sender<()>`. Mutations require an authenticated IPC caller (the local Unix socket is filesystem-perm-gated 0o600; remote IPC requires a hosted bearer). An attacker with arbitrary memory write to the daemon process could redirect a bearer hash to an agent they don't own — but at that level of compromise they could also forge envelopes directly, so the registry doesn't add an attack surface beyond what unsandboxed memory access already gives. Mitigations: run the daemon under a dedicated unprivileged user, no debug attach, no untrusted plugin loading. **Removal is irreversible**: `local.remove --force` archives the agent's directory under `$HERMOD_HOME/archive/<ts>/agents/<id>/` (mode 0o700) — operators must restore from this archive to recover, and the keypair never leaves disk. |
| T24 | Cross-tenant queue read / decide | `confirmation.list/accept/reject` and `permission.list/respond/list_resolved` are scoped per locally-hosted agent. Each queue row carries the recipient/owner's `agent_id`; the service rejects (`NotFound` for confirmations, `matched=false` for permissions) any caller whose IPC bearer authenticated as a different agent. Without this gate, agent A's bearer could enumerate or accept agent B's held envelopes (`pending_confirmations`) and answer agent B's tool-permission prompts on their behalf — a privilege escalation. Confirmation gate-and-decide is enforced at the storage layer via `pending_confirmations.recipient` + indexed filter; permission queues live in memory but carry an `owner: AgentId` field that every list/respond path checks. Cross-host gossip RPCs (peer / workspace / channel / audit) remain host-scoped because they reflect daemon-level state by design. |
| T25 | Cross-session permission verdict leak | Two Claude Code windows of the same agent must not observe each other's tool-call verdicts. `permission.request` carries an `Option<McpSessionId>` that lands on `OpenRequest.owner_session`; `permission.list_resolved` and `permission.list` honour an optional `session_id` filter that returns only entries originated by that session (plus relayed prompts which carry no session binding — those are inbound from federated peers and have no local-instance ownership). Without this layer, sibling sessions would see each other's `allow`/`deny` resolutions in the resolved-events ring buffer and re-emit them to the wrong Claude Code instance. The unfiltered call (CLI path) is preserved so an operator's `hermod permission allow/deny` still answers any prompt their agent owns. |
| T26 | Multi-instance MCP context flood / cursor collision | A Claude Code restart used to re-poll inbox / confirmation / permission-verdict streams from cursor zero, re-emitting every message the agent has ever received. With `HERMOD_SESSION_LABEL` set, `mcp.attach` resumes the same `mcp_sessions` row keyed by `(agent_id, session_label)` — delivery cursors (`last_message_id`, `last_confirmation_id`, `last_resolved_seq`) survive process restart, so the model only sees what arrived since it was last live. Two live attaches with the same label are rejected at the storage layer (`AttachOutcome::LabelInUse`, mapped to JSON-RPC `code::CONFLICT = -32005`); a partial unique index `(agent_id, session_label) WHERE session_label IS NOT NULL` is the invariant. Stale labelled rows (heartbeat outside TTL) are reused on next attach, carrying their cursors into the fresh session_id. |
| T27 | Routing-driven alert flood / cross-tenant notification queue access | Recipient-side `DispatchPolicy` (`hermod_routing::dispatch`) decides `MessageDisposition::{Push,Silent}` and `NotifyPreference::Os` for every accepted inbound. Two abuse axes: (1) a peer floods the recipient with messages whose body satisfies a `BodyContainsAny` rule that triggers OS notifications; (2) one local agent enumerates / dismisses another local agent's notification queue. (1) is bounded by `[routing.notification] max_pending` — atomic INSERT … WHERE COUNT < cap (no race between count and insert) refuses excess rows and emits `notification.suppressed`; the routing decision still applies (silent ↔ inbox-only is unaffected), only the OS ping is dropped. The cap also protects against a runaway local rule. (2) is gated by per-tenant `recipient_agent_id` filters on every storage method (`enqueue`, `claim_pending`, `mark_dispatched`, `mark_failed`, `dismiss`, `list`, `count_open_for`); the IPC dispatcher's `caller_agent` overlay plus the storage filter together mean a sibling agent's bearer can neither see another agent's queue nor claim / dismiss its rows. Configuration safety: `RoutingConfig::validate` rejects oversized keywords (>256 bytes), excess keyword counts (>32), empty keyword lists, duplicate rule names, out-of-range UTC offsets, and degenerate time windows at boot — silent misconfiguration becomes fail-loud. **No regex matchers** in any condition predicate (the available primitives are exact set-membership, numeric, and case-insensitive substring with bounded keyword length) — this rules out catastrophic backtracking and LLM-craftable matchers that could match anything or nothing. |

## 3. Out-of-scope (operator-managed or accepted)

- **Audit-log retention** — the chain is verified end-to-end; truncating early
  rows would invalidate the chain at a non-deterministic point. Retention is
  an operator concern (snapshot, archive, then rotate the database).
- **Side-channel attacks against the host** (Spectre, Rowhammer): outside
  Hermod's threat surface; mitigated by the host vendor.
- **Insider threats from the operator of `hermodd`**: by definition, the
  process owner has full authority over its own identity.
- **Quantum adversaries**: ed25519 and x25519 are post-quantum-vulnerable.
  Crypto-agility (algorithm suite negotiation) is on the roadmap.
- **Activity-pattern leakage via liveness fanout**. Each daemon publishes a
  `MessageBody::Presence { live, manual_status }` envelope to every
  workspace member whenever its MCP attach state changes. This is by
  design — workspace collaborators need to know who can reply right now
  — but it leaks fine-grained activity to anyone in a shared workspace
  (when you opened/closed Claude Code, when your laptop went to sleep).
  Operators who don't want this should leave shared workspaces or
  override with `presence set offline`.

## 4. Invariants the security claims rest on

1. **Identity secret stays at-rest only.** It is read once at daemon
   start; never sent over a socket; never logged. The daemon refuses
   to start if `$HERMOD_HOME/host/ed25519_secret` (or any
   `$HERMOD_HOME/agents/<id>/ed25519_secret`) is group- or
   world-readable (mode > `0600`) — `chmod 0600` is enforced, not
   advisory. The in-memory `Keypair` zeroes its secret bytes on
   `Drop`.
2. **Time clamping.** Both peers should run NTP. Wall-clock skew
   larger than `policy.replay_window_secs` (default 5 min) will fail
   the replay window check.
3. **Audit-log integrity.** Every row inserted by a running daemon is
   chained and signed; `hermod audit verify` is the one source of
   truth for whether the log has been tampered with.
4. **Workspace-secret distribution.** Operators must share
   private-workspace secrets out of band (Signal, in-person, password
   manager). Anyone with the 32-byte secret can derive every channel
   id and HMAC key under it; treat it as a password.
5. **Identity-secret recovery.** `agent_id` is a deterministic
   function of the 32-byte ed25519 seed at
   `$HERMOD_HOME/host/ed25519_secret`. Loss of that file is
   loss of the host identity — the daemon will generate a *new*
   keypair on next `hermod init`, with a new `agent_id`, and every
   peer's directory entry for the old id becomes a dangling
   reference (federation auth fails, no key rotation path bridges
   it). Backup procedure:
     * Copy `$HERMOD_HOME/host/ed25519_secret` (32 raw bytes)
       to durable offline storage encrypted with an operator
       passphrase (e.g. `age -p`, `gpg -c`, hardware token).
     * `tls.crt` / `tls.key` are regenerable from the seed —
       restoring the secret alone is sufficient; `hermod init`
       rebuilds the TLS material on next start.
     * Restore: drop the 32-byte seed back into place at mode
       `0600` and start the daemon. The on-disk DB and audit log
       remain bound to the same `agent_id`; backups of those files
       compose with the seed restore.
   Operators MUST take this backup; the protocol has no recovery
   path for a lost seed because there's no way to prove the new key
   speaks for the old `agent_id` without breaking
   self-certification.
6. **TLS protocol floor.** Federation handshakes pin TLS 1.3
   (`PROTOCOL_VERSIONS = &[&rustls::version::TLS13]`). TLS 1.2 is
   never negotiated even when both peers' rustls binaries support
   it — every Hermod peer is another Hermod daemon, so there is no
   compatibility floor to honour and no reason to accept the weaker
   TLS 1.2 handshake.
