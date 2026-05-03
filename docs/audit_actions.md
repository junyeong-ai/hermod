# Audit actions

Every audit row is a tuple of `(actor, action, target, details)`. This
table documents the canonical set of action strings the daemon writes.

## Conventions

- Shape: `<namespace>.<event>` or `<namespace>.<event>.<phase>`.
- Lowercase, snake_case within each component.
- The two-component form is for operator-driven commands and primary
  state events. The three-component form is reserved for inbound
  observations of an outbound counterpart (`<verb>.observed`) or
  follow-on transitions (`invite.accepted`).
- Past tense (`message.delivered`, `broadcast.delivered`,
  `confirmation.held`, `audit.archived`) for events the daemon
  witnessed. Imperative (`peer.add`, `capability.issue`) for
  operator-issued commands — matches the IPC method name.
- Every row carries an [`AuditFederationPolicy`] flag chosen by the
  emitter. Rows that would otherwise loop through audit federation
  (`message.sent` for the federated envelope itself; the
  aggregator-side `audit.federate.*` echo) are tagged `Skip` and
  filtered by [`RemoteAuditSink`] without touching the action string.

`scripts/check_naming.sh` enforces the two-/three-component shape; CI
runs it on every PR.

## Catalogue

### agent.*
| Action | Trigger | Details |
| --- | --- | --- |
| `agent.register` | `agent.register` IPC call (operator-driven directory entry). Routing — endpoint or broker — is wired up separately via `peer.add`. | `trust_level`, `local_alias` |

### audit.*
| Action | Trigger | Details |
| --- | --- | --- |
| `audit.archived` | Janitor (or operator-triggered `audit.archive_now`) sealed a UTC day-bucket into the BlobStore and deleted the rows from `audit_log`. Single action covers both success and failure; the `details.outcome` field discriminates. | `outcome` (`"success"` \| `"failure"`), and either (`archives`, `rows`) on success, or (`reason`) on failure. |
| `audit.federate.<original_action>` | (Aggregator only.) Inbound `AuditFederate` envelope from an authenticated peer was written into the local hash-chained log. The `<original_action>` suffix mirrors the action the originating daemon emitted. | `envelope_id`, `action`, `target`, `details`, `original_ts_ms` |
| `audit.federate.received` | (Aggregator only.) Receiver-side meta-row paired with each `audit.federate.<original_action>` row, so operators can graph cross-daemon delivery rate independent of which actions were shipped. | `envelope_id`, `original_action` |

### brief.*
| Action | Trigger | Details |
| --- | --- | --- |
| `brief.publish` | `brief.publish` IPC call. | `topic`, `len`, `ttl_secs`, `fanout`, `skipped`, `truncated_at` |
| `brief.observed` | Inbound brief envelope from a peer was applied. | `envelope_id`, `topic`, `len` |

### broadcast.*
| Action | Trigger | Details |
| --- | --- | --- |
| `broadcast.send` | Operator sent a `broadcast.send`. | `channel_id`, `len` |
| `broadcast.delivered` | Inbound `ChannelBroadcast` was applied. | `id`, `workspace_id`, `len` |

### broker.*
| Action | Trigger | Details |
| --- | --- | --- |
| `broker.relay.forwarded` | (Broker host with `mode = "relay_and_witness"`.) An inbound envelope addressed to another peer was successfully relayed via the daemon's outbound pool. | `envelope_id`, `kind`, `from`, `to`, `source_hop` |
| `broker.relay.rejected` | (Broker host with `mode = "relay_and_witness"`.) A relay attempt failed at some pre-delivery step. The `reason` discriminates: `no_route`, `no_endpoint`, `serialize`, `deferred`, `upstream_reject`, `hops_exceeded`, transport error. | `envelope_id`, `kind`, `from`, `to`, `source_hop`, `reason` |

### capability.*
| Action | Trigger | Details |
| --- | --- | --- |
| `capability.issue` | Operator-driven `capability.issue`. | `scope`, `audience`, `scope_target`, `exp` |
| `capability.revoke` | Operator-driven `capability.revoke` (only when the row actually transitioned). | none |
| `capability.deliver` | Issuer envelope-shipped a capability to its audience via `capability.deliver`. | `audience`, `scope`, `jti` |
| `capability.observed` | Inbound `CapabilityGrant` envelope auto-imported into the audience-side `capabilities` table. | `envelope_id`, `scope`, `jti` |

### channel.*
| Action | Trigger | Details |
| --- | --- | --- |
| `channel.create` / `channel.delete` / `channel.mute` / `channel.adopt` | Operator-driven IPC call. | varies |
| `channel.advertise` | Operator advertised a channel they own. | `workspace_id`, `channel_id` |
| `channel.advertise.observed` | Inbound `ChannelAdvertise` envelope from a peer. | `from`, `workspace_id`, `channel_id` |

### confirmation.*
| Action | Trigger | Details |
| --- | --- | --- |
| `confirmation.held` | Inbound envelope failed the trust gate's `Confirm` verdict and was queued for operator review. | `envelope_id`, `sensitivity`, `trust_level` |
| `confirmation.accept` / `confirmation.reject` | Operator decided a held envelope. | `from`, `held_intent` |

### file.*
| Action | Trigger | Details |
| --- | --- | --- |
| `file.delivered` | Inbound `MessageBody::File` was hash-verified, persisted to the BlobStore, and recorded in the inbox. | `id`, `name`, `size`, `location` |

### local_agent.*
| Action | Trigger | Details |
| --- | --- | --- |
| `local_agent.bearer_rotated_on_drift` | Daemon boot detected a divergence between an agent's on-disk `bearer_token` and the `local_agents` row's `bearer_hash` — typically because `hermod bearer rotate` wrote a new file while the daemon was offline — and reconciled the DB to match disk. | `previous_hash_prefix` (first 4 bytes hex), `current_hash_prefix` (first 4 bytes hex) |

### mcp.*
| Action | Trigger | Details |
| --- | --- | --- |
| `mcp.attach` | First IPC `mcp.attach` for a session. | `client_name`, `client_version` |
| `mcp.detach` | IPC `mcp.detach` (clean shutdown of a Claude Code stdio session). | none |

### mdns.*
| Action | Trigger | Details |
| --- | --- | --- |
| `mdns.beacon_emitted` | Daemon registered (or re-signed) its own `_hermod._tcp.local.` beacon. | `port`, `validity_secs` |
| `mdns.beacon_observed` | An inbound beacon passed signature + freshness + identity-binding checks. | `endpoint` |
| `mdns.beacon_rejected` | An inbound beacon failed verification. The `reason` discriminates: `missing_agent_id`, `malformed_fields`, `invalid_sig`, `stale`, `future_ts`. | `reason` |

### message.*
| Action | Trigger | Details |
| --- | --- | --- |
| `message.sent` | Local `message.send` IPC call enqueued / delivered an envelope. Tagged `AuditFederationPolicy::Skip` so it never feeds back through outbound audit federation. `via` carries the broker `agent_id` when `route="brokered"`, `null` otherwise. | `id`, `kind`, `priority`, `status`, `route`, `via` |
| `message.delivered` | Inbound `Direct` envelope applied to local inbox. | `id`, `kind` |
| `message.read` | Operator `message.ack`. | `ids` |
| `message.failed` | Outbox gave up after exhausted retries / remote rejected / corrupt CBOR. | `id`, `reason`, `detail`, `attempts` |

### peer.*
| Action | Trigger | Details |
| --- | --- | --- |
| `peer.add` | Operator `peer.add`. Exactly one of `host_id` / `via_agent` is non-null per the schema CHECK; direct adds populate `host_id` (which joins to the `hosts` table for the dial endpoint), brokered adds populate `via_agent`. | `fingerprint`, `host_id`, `via_agent` |
| `peer.trust` | `peer.trust` (operator promotes / demotes). | `level` |
| `peer.remove` | `peer.remove` (clears endpoint and TLS pin). | none |
| `peer.repin` | `peer.repin` (operator-confirmed cert rotation). | `previous`, `new` |
| `peer.advertise` | Operator pushed a `PeerAdvertise` (or `peer.add` auto-trigger). Per-target wire status reflected in the `delivered` / `failed` counts. | `delivered`, `failed`, `agents` |
| `peer.advertise.received` | Inbound `PeerAdvertise` from a peer. | `agents_advertised`, `agents_upserted`, `rejected_self_cert`, `rejected_host_conflict` |

### routing.*

Dispatch-time misconfiguration signals. Emitted on every send to the
affected target until the operator repairs — same per-event pattern
as wire-level rejections so forensic queries can answer "from when
did messages to X stop routing?".

| Action | Trigger | Details |
| --- | --- | --- |
| `routing.cycle_detected` | `Router::resolve` walked an `agents.via_agent` chain that looped back to a previously-visited agent. `target` is the original recipient; `chain` is the visit order ending at the cycle. | `chain` |
| `routing.via_too_deep` | `Router::resolve` walked `MAX_VIA_DEPTH` hops without reaching a directly-dialable endpoint (no cycle, just depth). `target` is the original recipient; `limit` is `MAX_VIA_DEPTH`. | `limit` |

### local.*

Live-registry mutation. Each row records the operator action; the
on-disk + DB + in-memory registry update happens atomically and any
session pinned to a removed/rotated bearer is force-closed.

| Action | Trigger | Details |
| --- | --- | --- |
| `local.add` | Operator `local add` (IPC). New agent provisioned on disk + DB + registry. | `alias` |
| `local.remove` | Operator `local remove` (IPC). Agent archived from disk + dropped from DB + registry; active sessions force-closed. | `archive` |
| `local.rotate` | Operator `local rotate` (IPC). Bearer regenerated; active sessions on the previous bearer force-closed. | none |
| `local_agent.bearer_rotated_on_drift` | Boot-time `merge_with_db` reconciliation: on-disk bearer hash differs from DB row (e.g. operator wrote a fresh token while the daemon was offline). | `previous_hash_prefix`, `current_hash_prefix` |
| `local.tag_set` | Operator replaced the capability tag set on a local agent via `hermod local tag set`. Tags are discovery metadata only — never trust-bearing (`scripts/check_trust_boundaries.sh` grep contract). | `tags` (the new set, post-validation) |

### permission.*

Audit trail for the Claude Code Channels permission relay
(`hermod-daemon::services::permission`). Every prompt the host sends to
the operator and every verdict (or expiration) the operator returns
leaves one row, so a stalled approval can be distinguished from a
silently-timed-out one in post-incident review.

| Action | Trigger | Details |
| --- | --- | --- |
| `permission.request` | MCP forwarded a `notifications/claude/channel/permission_request` from Claude Code. | `tool_name`, `description` |
| `permission.allow` | Operator answered yes through `hermod permission allow` or a federated path. | `tool_name`, `description`, `via` |
| `permission.deny` | Operator answered no. | `tool_name`, `description`, `via` |
| `permission.expired` | TTL elapsed before any verdict arrived; the host's local terminal dialog absorbs the timeout. | `tool_name`, `description` |
| `permission.relay` | An originating daemon successfully forwarded a prompt to one or more `permission:respond` delegates via `PermissionPrompt` envelopes. | `delegates` |
| `permission.relay.unreachable` | Forwarder ran but reached zero delegates (no active `permission:respond` capabilities). The local prompt is still live; this row exists so a silently-broken delegation chain is observable. | `delegates` (always 0) |
| `permission.relay.failed` | Forwarder closure errored before reaching any delegate. | `error` |
| `permission.relay.send_failed` | Originating daemon's response-to-delegator `PermissionResponse` envelope failed to ship. | `to`, `error` |
| `permission.relay.observed` | Inbound `PermissionPrompt` from a delegating peer landed in the local permission queue. | `envelope_id`, `request_id`, `tool_name`, `description`, `input_preview`, `expires_at` |
| `permission.relay.responded` | Inbound `PermissionResponse` verdict from a delegate was applied (or no-op'd if the prompt was already resolved). | `envelope_id`, `request_id`, `behavior` |
| `permission.auto_allow` | A `[[auto_approve.permission]]` rule matched a freshly-opened request; the daemon resolved it with `Allow` immediately rather than parking. The matched rule's `tool_names` allowlist contained the call's `tool_name` AND the rule's `origin` equalled the calling agent's `agent_id`. **Reject is never crossed by this surface.** | `rule`, `tool_name`, `origin` |
| `confirmation.auto_accept` | A `[[auto_approve.confirmation]]` rule matched an inbound whose verdict was `Confirm`; the daemon downgraded to `Accept` rather than parking. **Reject is never crossed.** | `rule`, `kind`, `sensitivity`, `trust_level` |

### routing.* / inbox.* / notification.*

Recipient-side delivery surface. After the confirmation gate accepts an
inbound (Direct/File), `hermod_routing::DispatchPolicy` chooses
`MessageDisposition::{Push, Silent}` and (optionally)
`NotifyPreference::Os`. The result lands here so an operator can audit
both the routing decision and every life-cycle transition of the
OS-notification queue.

| Action | Trigger | Details |
| --- | --- | --- |
| `routing.dispositioned` | Routing engine made a decision for an accepted inbound (one row per envelope). | `kind`, `disposition`, `rule` (matched rule name or `null` for kind-default), `notify` (`"none"` \| `"os"`) |
| `inbox.promote` | Operator flipped a silent inbox row to push via `inbox.promote`. | `null` (target carries the message id) |
| `notification.queued` | Atomic enqueue succeeded; the dispatcher will pick this row up on its next poll. | `message_id`, `recipient` |
| `notification.suppressed` | Atomic enqueue refused — `[routing.notification] max_pending` cap reached for the recipient. The routing decision still applied; only the OS ping was dropped. | `recipient`, `reason` |
| `notification.dispatched` | Dispatcher invoked the platform notifier successfully and acknowledged via `notification.complete`. | `null` |
| `notification.failed` | Dispatcher's platform notifier returned a terminal error and acknowledged via `notification.fail`. | `reason` |
| `notification.dismissed` | Operator dismissed a live row via `hermod notification dismiss`. | `null` |
| `notification.purged` | Janitor / operator-driven `notification.purge` reaped terminal rows past the retention window. | `rows` |

### presence.*
| Action | Trigger | Details |
| --- | --- | --- |
| `presence.set_manual` / `presence.clear_manual` | Operator set / cleared a manual hint. | `status`, `ttl_secs`, `fanout`, `skipped`, `truncated_at` |
| `presence.observed` | Inbound `Presence` envelope from a peer. | `envelope_id`, `manual_status`, `live` |

### workspace.*
| Action | Trigger | Details |
| --- | --- | --- |
| `workspace.create` / `workspace.delete` / `workspace.mute` / `workspace.invite` / `workspace.join` | Operator-driven IPC call. | varies |
| `workspace.invite.accepted` | Operator accepted an inbound `WorkspaceInvite` (replayed through the apply path). | `envelope_id`, `name` |
| `workspace.roster.request` | Inbound `WorkspaceRosterRequest` from a peer authorised against the workspace MAC (private) or member list (public). | `envelope_id`, `workspace_id` |
| `workspace.channels.request` | Inbound `WorkspaceChannelsRequest` from a peer, same authorisation model as above. | `envelope_id`, `workspace_id` |

## Adding a new action

1. Pick a namespace from the existing table or, for a new domain, follow
   `<resource>.<event>`. Keep the two/three component split.
2. Add an entry to this catalogue with the trigger and details schema.
3. Write the row through `crate::services::audit_or_warn` —
   `AuditRepository::append` is forbidden by `clippy.toml`.
4. Decide the row's `AuditFederationPolicy` at the emission site.
   `Default` is correct for nearly every action; use `Skip` only for
   rows that would otherwise feed audit-federation feedback loops
   (the federation envelope's own `message.sent`, the aggregator-side
   `audit.federate.*` echo).
5. `scripts/check_naming.sh` validates the shape on CI.
