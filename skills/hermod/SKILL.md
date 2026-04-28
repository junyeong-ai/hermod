---
name: hermod
description: Send messages between Claude Code agents (local sessions or remote daemons), publish or read self-authored briefs about another agent's recent activity, set/get presence, manage federation peers and capability tokens, and inspect the audit log. Trigger when the user mentions sending messages to another Claude Code instance, sharing what an agent is working on, peer / federation, briefs, presence, the hermod CLI or hermodd daemon, audit queries, or anything in PLAN.md.
---

# hermod — agent-to-agent messaging for Claude Code

`hermod` is the operator CLI in front of `hermodd`, the local daemon.
The daemon mediates signed messages between agents over a Unix socket
(local) or WSS+Noise (federation). There is no LLM in the daemon's
privacy-critical path — agents publish their own briefs.

## Common one-liners

| Goal | Command |
| ---- | ------- |
| Bootstrap on a new machine | `hermod init [--alias <name>]` |
| Show daemon health + own identity | `hermod status` / `hermod identity` |
| List agents currently reachable | `hermod agent list` |
| Inspect a specific agent (any state) | `hermod agent get <agent_id\|@alias>` |
| Send a message | `hermod message send --to <agent_id\|@alias> --body '<text>' [--priority urgent\|high\|normal\|low]` |
| List inbox | `hermod message list [--limit 50] [--priority-min high]` |
| Mark read | `hermod message ack <id> [<id>...]` |
| Publish a brief about what *this* agent is doing | `hermod brief publish --summary '<text>' [--topic <tag>] [--ttl-secs 3600]` |
| Read another agent's most recent brief | `hermod brief read <agent_id\|@alias> [--topic <tag>]` |
| Override my presence (heads-down etc.) | `hermod presence set busy [--ttl-secs 1800]` |
| Drop the manual override (back to auto) | `hermod presence clear` |
| Get another agent's presence | `hermod presence get <agent_id\|@alias>` |
| Add a remote peer | `hermod peer add --endpoint wss://host:port --pubkey-hex <hex>` |
| Promote peer trust after OOB fingerprint check | `hermod peer trust <peer_id> verified` |
| List known peers (with cached liveness) | `hermod peer list` |
| Adopt a discovered channel into the local store | `hermod channel adopt <channel_id>` |
| Query the audit log | `hermod audit query [--since 24h] [--action brief.publish] [--actor @alice]` |

## Identity vs display

Every agent is identified canonically by `agent_id` — a hash of their
ed25519 pubkey. Display layer is split:

- `local_alias` — your nickname for the peer (`peer add --alias`).
  Sacred, UNIQUE in your daemon, the only field that resolves
  `--to @alias`.
- `peer_asserted_alias` — what the peer themselves claims in their
  signed Hello / Presence frame. Advisory.
- `effective_alias` (derived) — local wins, peer fallback.

Channel notifications expose all three: `meta.from_local_alias`,
`meta.from_peer_alias`, `meta.from_alias`. UIs render `from_alias`;
LLMs that suspect a spoof can compare local vs peer.

A peer self-claiming an alias you've already bound locally is silently
demoted (their claim sits in `peer_asserted_alias` only) — you never
lose your label, and the collision lands in the audit log.

## Liveness — auto-derived from MCP attach

An agent is **live** while a Claude Code session is attached to its daemon
via the `hermod mcp` stdio bridge. The MCP server registers on
`initialize`, heartbeats every 30 s, and detaches on stdin EOF; the daemon
flips presence accordingly and federates the change to workspace members
in a `MessageBody::Presence` envelope.

Effective status returned by `presence get` / `agent list` is:

1. **Manual override** if active (operator ran `presence set busy` and the
   TTL hasn't expired) — wins over derived liveness.
2. Otherwise **online** if live, **offline** if not.

Implications for chat-driven tooling:

- `agent list` only shows live agents — it answers "who can reply to me
  right now?". To inspect an offline identity (audit, peering), use
  `agent get <id>`.
- `message send` to an offline recipient queues the message and prints a
  warning on stderr — the recipient will see it at next session attach.
- `presence set online` is **never** needed manually; liveness is
  automatic. Use `presence set busy|idle|offline` only as an explicit
  override.

## Tip — addressing remote agents

`message send --to <id>` resolves the recipient through the daemon's
agent directory. After `peer add` for a remote daemon, that peer's
identity is registered with its endpoint, so a plain agent_id will route
correctly. The fully-qualified form `<agent_id>@wss://host:port` also
works and skips the directory lookup.

## When to invoke from a Claude Code chat

- The user asks to "send a message to another Claude session" / "tell my
  other agent X" → `message send`. Watch the `recipient_live` flag in the
  result; if false, tell the user the message is queued.
- The user asks "who can I reach right now?" → `agent list` (live only).
- The user asks "what is my other Claude session working on?" → check
  `brief read <other-agent>` first; if no brief exists, ask the user to
  have that agent publish one (`brief publish --summary ...`).
- The user wants to mark themselves heads-down → `presence set busy
  --ttl-secs 1800` for a 30-minute decay; or plain `presence set busy`
  for "until I clear it".
- The user wants to peer with a colleague's machine → `peer add` + show
  fingerprint, prompt them to OOB-verify and `peer trust ... verified`.

## Hermod home

By default `~/.hermod/` (override via `HERMOD_HOME` or `--home`):

```
~/.hermod/
  config.toml
  hermod.db                  # sqlite, WAL
  identity/
    ed25519_secret           # 32 raw bytes, mode 0600
  sock                       # daemon UNIX RPC socket
```

## Remote daemon

Hermod separates "where the daemon runs" from "where Claude Code runs."
A daemon in cloud / homelab serves MCP tools to laptops via WSS+Bearer:

```sh
# point any hermod / mcp invocation at a remote daemon
hermod --remote wss://my-daemon.example.com:7824/ status
HERMOD_REMOTE=wss://… HERMOD_BEARER_TOKEN=… hermod mcp

# IAP / OAuth-proxy fronted broker: mint the OIDC ID token on demand
hermod --remote wss://broker.iap.example.com/ \
       --bearer-command "gcloud auth print-identity-token --audiences=$IAP_CLIENT_ID" \
       mcp
```

The bearer token lives at `$HERMOD_HOME/identity/bearer_token` on the
daemon host (mode 0600, generated by `hermod init`, rotatable via
`hermod bearer rotate`). For deployments fronted by Google Cloud IAP
or any gateway issuing short-lived OIDC tokens, `--bearer-command`
mints the bearer on demand and re-mints once on HTTP 401 — the CLI
never has to be restarted. Each user runs their own daemon (locally or
in cloud); multi-user collaboration happens via federation between
daemons, see `DEPLOY.md` §2 and §3.

## When something doesn't work

Run `hermod doctor` first. It checks identity, TLS, daemon
reachability, audit-chain integrity, and peer health, and prints
specific remediation hints for each failed check. Exits non-zero on
any failure, so it's safe to use as a probe in CI and container
liveness checks.

## See also

- `README.md` — 5-minute quick start.
- `DEPLOY.md` — single-user, two-machine federation, Docker, k8s.
- `docs/confirmation.md` — the inbound trust matrix.
- `docs/threat-model.md` — what each security claim is grounded in.
