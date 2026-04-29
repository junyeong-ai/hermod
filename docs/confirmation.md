# Confirmation gate

A small policy layer between **inbound delivery** and **user-visible
application** of a message. Every inbound envelope that has cleared
signature, replay window, and capability checks passes through this gate.
The gate consults two inputs and produces one of three verdicts.

## Inputs

- **Peer trust level**: read from `agents.trust_level` for the authenticated
  sender. Falls back to `Tofu` if the row is missing — the federation
  listener TOFU-upserts on first contact, so the only way the row is missing
  is a delete-then-incoming race.
- **Action sensitivity**: classified from the envelope body kind by
  `hermod_routing::confirmation::classify`. Three tiers:
  - **routine** — `Brief`, `Presence`, `ChannelBroadcast`,
    `ChannelAdvertise`, `PermissionResponse`, `AuditFederate`,
    `WorkspaceRosterRequest`, `WorkspaceRosterResponse`,
    `WorkspaceChannelsRequest`, `WorkspaceChannelsResponse`,
    `PeerAdvertise`. Group MAC + workspace membership already gate
    the channel kinds; `PermissionResponse` is capability-gated
    (the `permission:respond` scope is the real authority check);
    `AuditFederate` is gated by the operator's `[audit]
    accept_federation` opt-in (a daemon that hasn't opted in
    rejects the envelope outright before the confirmation gate
    runs), so per-envelope confirmation prompts on bulk audit
    shipping would be impractical. The `Workspace*` RPC variants
    are gated by the workspace MAC (private) or the receiver's
    `workspace_members` table (public) — membership IS the trust
    gate, so per-envelope confirmation would be infinite friction
    between members. `PeerAdvertise` carries directory upserts;
    the inbound acceptor's self-inclusion proof + host_pubkey
    cross-check IS the trust gate, and per-advertise confirmation
    would defeat the auto-discovery point. (Each advertised agent
    still lands as `TrustLevel::Tofu`, so the *agent's* first
    real envelope still hits the confirmation gate.)
  - **review** — `Direct`, `File`, `PermissionPrompt`. DM bodies land in
    a human-visible inbox feed; `File` payloads are also user-visible
    (and could be opened by a sandbox); a `PermissionPrompt` from an
    unfamiliar peer must be vetted before reaching the operator's
    approval queue.
  - **sensitive** — `WorkspaceInvite`, `CapabilityGrant`. Importing
    either expands the local authority surface (a 32-byte channel secret
    or a fresh capability token) and must always involve operator
    review for unfamiliar peers.

## Decision matrix (4 × 3)

|              | routine | review  | sensitive |
| ------------ | ------- | ------- | --------- |
| Self         | accept  | accept  | accept    |
| Verified     | accept  | accept  | confirm   |
| Tofu         | accept  | confirm | confirm   |
| Untrusted    | accept  | confirm | reject    |

`accept` — apply immediately.<br>
`confirm` — write the original envelope CBOR to `pending_confirmations`; the
operator runs `hermod confirm accept <id>` or `hermod confirm reject <id>`
to decide. Held envelopes do not appear in inboxes / channel feeds.<br>
`reject` — drop. Federation listener returns `unauthorized: trust matrix`,
the audit log records the decision, and the sender is notified via the
rejection ack path.

## Why these cells

- **Routine is always accepted.** Presence pings, broadcasts, and channel
  advertisements are signals, not state mutations; gating them on trust
  would be infinite friction.
- **Review under TOFU asks.** A DM from a brand-new peer is the textbook
  social-engineering vector. Holding it for a glance is cheap.
- **Sensitive under Verified still asks.** Capability grants, peer
  announcements, and workspace invites promote authority. Even verified
  peers shouldn't silently hand us new authority without us seeing the
  grant.
- **Untrusted + sensitive rejects, not confirms.** If an untrusted peer is
  trying to grant capabilities or push a fresh workspace secret, that's
  adversarial; there's no plausible benign reason to even surface it.

## Operator workflow

```sh
# See what's currently held.
hermod confirm list

# Accept a held DM or workspace invite after reviewing the summary.
hermod confirm accept 01HZN0...

# Drop a held capability grant.
hermod confirm reject 01HZN0...
```

On accept, the daemon replays the original envelope CBOR through the
post-gate apply path (`InboundProcessor::apply_held`). Envelope ids dedupe
at the `messages` and `channel_messages` tables, so a confused double-accept
is idempotent.

## Lifetime

Pending confirmations older than `policy.confirmation_retention_secs`
(default 7 days) are auto-marked `expired` by the janitor. The audit row
remains in place; only the `status` column transitions.

## Out of scope

- **Outbound confirmation.** When *we* send something sensitive, the
  operator decides at the call site (CLI / MCP tool). That UX is
  interactive and doesn't need a parking table.

The audit log records `confirmation.held`, `confirmation.accept`, and
`confirmation.reject` for every transition.
