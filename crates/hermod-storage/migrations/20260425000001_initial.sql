-- Hermod schema.

-- Federation hosts — per-daemon identity and dial metadata. A host is
-- a *daemon*, the entity authenticated by the federation Noise XX
-- handshake. It is never an envelope recipient (that role belongs to
-- the agents it carries). Splitting hosts and agents into separate
-- tables encodes that asymmetry once at the schema level so callers
-- (peer enumeration, fan-out, dial pool) never need to filter
-- "is this row a host or an agent?" out of one conflated directory.
--
-- `id = base32(blake3(pubkey))[:26]`, same derivation as agents, so
-- a single AgentId newtype carries either kind of identity through
-- the codebase.
CREATE TABLE hosts (
    id                  TEXT NOT NULL PRIMARY KEY,
    -- ed25519 static key the daemon presents during the federation
    -- Noise XX handshake. UNIQUE so the (id, pubkey) pair stays
    -- self-certifying — `id` is its blake3 prefix.
    pubkey              BLOB NOT NULL UNIQUE,
    -- Network endpoint dialled by the federation pool. NULL when
    -- the host has only ever been observed via inbound TOFU and
    -- the operator hasn't run `peer add --endpoint <wss://>` yet.
    endpoint            TEXT,
    -- SHA-256 of the host's TLS leaf cert DER, captured on first
    -- successful TLS handshake. Pinned per-host (every agent on
    -- this host shares this cert). Lowercase, colon-separated.
    tls_fingerprint     TEXT,
    -- Host-level peer-claimed display name ("alice-laptop").
    -- Distinct from `agents.peer_asserted_alias` (the agent
    -- persona's self-claim). Advisory display only — never used
    -- for routing.
    peer_asserted_alias TEXT,
    first_seen          INTEGER NOT NULL,
    last_seen           INTEGER
);

-- Agents directory — every entity that signs envelopes (local self
-- + every remote agent we've interacted with). One agent lives on
-- exactly one host; the `host_id` FK formalises that.
--
-- Identity / display split (best practice, see Signal / GitHub / PGP):
--   * `id` (ed25519 pubkey hash) — canonical identifier. Routing,
--     crypto, audit, foreign keys all reference this. Immutable.
--   * `local_alias` — operator's nickname. Sacred — once an
--     operator names someone @bob, no peer can take it. UNIQUE
--     within the daemon. Used for `--to @alias` resolution.
--   * `peer_asserted_alias` — peer's self-claim from their last
--     Hello / PeerAdvertise frame. Advisory; never overrides
--     `local_alias`. NOT unique.
CREATE TABLE agents (
    id                  TEXT NOT NULL PRIMARY KEY,
    -- Agent's own ed25519 pubkey — verifies envelope signatures.
    pubkey              BLOB NOT NULL,
    -- The host this agent runs on. ON DELETE SET NULL keeps the
    -- agent row alive when an operator forgets the host (e.g. via
    -- `peer remove`); the agent becomes "directory-only" until a
    -- new host record is observed.
    host_id             TEXT REFERENCES hosts(id) ON DELETE SET NULL,
    -- Indirect routing target. NULL ⇒ envelope addressed to this
    -- agent dials `host_id`'s endpoint directly. `Some(broker_id)`
    -- ⇒ dispatched to the broker's host with `envelope.to.id`
    -- preserved; the broker's `BrokerMode::RelayOnly` fall-through
    -- forwards the second hop. Enables mesh topologies where only
    -- one node has a public endpoint.
    --
    -- Resolution is recursive (broker may itself be brokered),
    -- capped at MAX_RELAY_HOPS at dispatch time. Cycles fail-loud
    -- at dispatch (audit `routing.cycle_detected`) rather than at
    -- row insert — the graph can change atomically across rows so
    -- DB constraints can't catch every cycle.
    --
    -- ON DELETE SET NULL keeps the indirect row around when the
    -- broker is forgotten — operator repair (re-add broker, swap
    -- via_agent) is an explicit step, not a forced cascade.
    via_agent           TEXT REFERENCES agents(id) ON DELETE SET NULL,
    local_alias         TEXT UNIQUE,
    peer_asserted_alias TEXT,
    -- `local` means this agent is hosted by THIS daemon (private
    -- key in `local_agents`). Multi-tenant — multiple `local` rows
    -- are normal.
    trust_level         TEXT NOT NULL
                        CHECK (trust_level IN ('local','verified','tofu','untrusted')),
    reputation          INTEGER NOT NULL DEFAULT 0,
    first_seen          INTEGER NOT NULL,
    last_seen           INTEGER,
    -- Capability tags the *peer* claims about themselves —
    -- propagated via `MessageBody::PeerAdvertise`. Discovery
    -- metadata only (NEVER trust-bearing — see
    -- `hermod_core::capability_tag` module docs and the
    -- `scripts/check_trust_boundaries.sh` grep contract). JSON-
    -- encoded `Vec<String>` validated through
    -- `CapabilityTagSet::parse_lossy` on read; per-entry parse
    -- failures drop the entry, never reject the row.
    peer_asserted_tags  TEXT NOT NULL DEFAULT '[]',
    -- Direct routing (host_id) XOR brokered routing (via_agent),
    -- or both NULL = directory-only / not yet routable.
    CHECK (host_id IS NULL OR via_agent IS NULL)
);
CREATE INDEX idx_agents_host ON agents(host_id) WHERE host_id IS NOT NULL;
CREATE INDEX idx_agents_via  ON agents(via_agent) WHERE via_agent IS NOT NULL;

-- Sub-relation for agents this daemon hosts. Adds the private-key
-- material (kept on disk under `$HERMOD_HOME/agents/<id>/`, not in
-- the DB) and the per-agent IPC bearer credential.
--
-- Foreign-keyed to `agents` so a local agent always has a directory
-- entry (capabilities, briefs, presence, audit references all key by
-- agent_id). `ON DELETE CASCADE` keeps the sub-relation consistent
-- when an operator removes the agent.
CREATE TABLE local_agents (
    agent_id            TEXT NOT NULL PRIMARY KEY
                        REFERENCES agents(id) ON DELETE CASCADE,
    -- blake3 of the bearer token. The raw token is stored in the
    -- filesystem (`$HERMOD_HOME/agents/<id>/bearer_token`, mode
    -- 0600) for the CLI / MCP to read; this hash is the lookup key
    -- IPC handshake compares against.
    bearer_hash         BLOB NOT NULL,
    -- Optional operator-set context. Filesystem path of the project
    -- directory this agent represents — surfaced in MCP `instructions`
    -- so Claude Code knows what this agent is about.
    workspace_root      TEXT,
    created_at          INTEGER NOT NULL,
    -- Capability tags the operator set on this hosted agent.
    -- Discovery metadata only — propagated to peers via
    -- `peer.advertise`; `agent.list --tag-{any,all}` filters on
    -- the union of these and `agents.peer_asserted_tags`.
    -- Bounded by `CapabilityTagSet` (≤16 entries, each
    -- `[a-z0-9:_.-]{1,64}`). JSON-encoded `Vec<String>`.
    tags                TEXT NOT NULL DEFAULT '[]'
);
-- Bearer hash is the auth lookup key — index for O(log n) handshake.
CREATE UNIQUE INDEX idx_local_agents_bearer_hash ON local_agents(bearer_hash);

-- Direct-message event log + outbox columns.
CREATE TABLE messages (
    id              TEXT NOT NULL PRIMARY KEY,
    thread_id       TEXT,
    from_agent      TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    to_agent        TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    kind            TEXT NOT NULL,
    priority        TEXT NOT NULL,
    body_json       TEXT NOT NULL,
    envelope_cbor   BLOB NOT NULL,
    status          TEXT NOT NULL
                    CHECK (status IN ('pending','delivered','read','expired','failed')),
    attempts        INTEGER NOT NULL DEFAULT 0,
    next_attempt_at INTEGER,
    -- Outbox claim ownership. `claim_token` is the worker UUID that
    -- picked this row up; `claimed_at` is the wall-clock instant. Both
    -- NULL means the row is unclaimed and any worker may take it. A
    -- worker whose claim is older than the per-deployment claim TTL is
    -- assumed crashed and the row is reclaimable. See
    -- `MessageRepository::claim_pending_remote`.
    claim_token     TEXT,
    claimed_at      INTEGER,
    created_at      INTEGER NOT NULL,
    delivered_at    INTEGER,
    read_at         INTEGER,
    expires_at      INTEGER,
    -- BlobStore opaque location for File-kind payloads. NULL for any
    -- other kind. The metadata column `body_json` carries only the
    -- File metadata (name / mime / size / hash); the bytes themselves
    -- live in the BlobStore so the messages table doesn't bloat.
    file_blob_location TEXT,
    -- Resolved delivery endpoint, captured at send time by the router.
    -- Decouples the outbox retry path from the live `agents.endpoint`
    -- so brokered envelopes (recipient registered without an endpoint,
    -- delivered via the configured `[federation] upstream_broker`)
    -- and standard remote envelopes share one retry mechanism. NULL
    -- for purely-local destinations (loopback / `local-known`).
    delivery_endpoint TEXT,
    -- Recipient-side delivery disposition. Set immediately after the
    -- confirmation gate accepts an inbound, by the routing engine's
    -- `DispatchPolicy::decide`. `push` = standard channel emit;
    -- `silent` = inbox-only (no AI-agent context pollution). Operators
    -- promote silent rows via `inbox.promote`. The DEFAULT documents
    -- the kind-default for fresh inserts; application code always
    -- supplies an explicit value (no `Default` derive on the Rust enum).
    disposition     TEXT NOT NULL DEFAULT 'push'
                    CHECK (disposition IN ('push','silent'))
);
CREATE INDEX idx_messages_inbox ON messages(to_agent, status, created_at);
-- Channel-emitter hot path: only `push`-dispositioned rows reach the
-- AI-agent stream, so the index keys on the filter the MCP poller
-- applies on every poll.
CREATE INDEX idx_messages_pushed_inbox
    ON messages(to_agent, disposition, status, created_at);
CREATE INDEX idx_messages_thread ON messages(thread_id, created_at);
CREATE INDEX idx_messages_expiry ON messages(expires_at)
    WHERE status IN ('pending','delivered');
CREATE INDEX idx_messages_outbox ON messages(next_attempt_at)
    WHERE status = 'pending' AND delivery_endpoint IS NOT NULL;
-- Janitor sweep of stale claims: stalled workers leave rows owned by a
-- claim_token whose claimed_at is past the TTL.
CREATE INDEX idx_messages_outbox_claim ON messages(claimed_at)
    WHERE status = 'pending' AND claim_token IS NOT NULL;

-- Capability tokens (issuance log; attenuation is client-side).
CREATE TABLE capabilities (
    id            TEXT NOT NULL PRIMARY KEY,
    issuer        TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    audience      TEXT,
    scope         TEXT NOT NULL,
    target        TEXT,
    expires_at    INTEGER,
    revoked_at    INTEGER,
    raw_token     BLOB NOT NULL,
    -- 'issued' rows are tokens this daemon minted; 'received' rows are
    -- tokens delivered to us by another agent (we are the audience),
    -- imported via `capability.deliver` envelopes. Same primary key
    -- (jti) — a token is either ours-to-revoke or ours-to-attach,
    -- never both.
    direction     TEXT NOT NULL DEFAULT 'issued'
                  CHECK (direction IN ('issued','received'))
);

-- Hash-chained signed audit log. Each row's `row_hash` is blake3 over
-- (ts || actor || action || target || details_json || client_ip ||
-- prev_hash) with explicit length prefixes (see
-- hermod_storage::audit::compute_row_hash). `sig` is ed25519 over
-- `row_hash` by the daemon's keypair. `prev_hash` of the first row
-- is 32 zero bytes.
--
-- `client_ip` is the resolved originating IP for events that flow in
-- from a remote IPC connection (after `daemon.trusted_proxies` /
-- X-Forwarded-For resolution). NULL for events that have no remote
-- client (outbox worker, janitor, daemon-internal periodic tasks,
-- local Unix socket IPC).
CREATE TABLE audit_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            INTEGER NOT NULL,
    actor         TEXT NOT NULL,
    action        TEXT NOT NULL,
    target        TEXT,
    details_json  TEXT,
    client_ip     TEXT,
    prev_hash     BLOB NOT NULL,
    row_hash      BLOB NOT NULL,
    sig           BLOB NOT NULL
);
CREATE INDEX idx_audit_actor_ts ON audit_log(actor, ts);
CREATE INDEX idx_audit_ts ON audit_log(ts);

-- Token-bucket rate limiter, keyed by `<sender>|<recipient>`.
CREATE TABLE rate_buckets (
    pair_key      TEXT NOT NULL PRIMARY KEY,
    tokens        REAL NOT NULL,
    updated_at    INTEGER NOT NULL
);

-- Operator-authored briefs. One row per (agent, topic) — newer publishes
-- overwrite older within the same topic. `topic` is nullable; the
-- "default brief" is the row with `topic IS NULL`. SQLite treats NULLs
-- as distinct in UNIQUE constraints, so we use a generated column to
-- collapse NULL → empty string for the uniqueness check while keeping
-- the natural NULL semantics in `topic` itself.
CREATE TABLE briefs (
    agent_id      TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    topic         TEXT,
    summary       TEXT NOT NULL,
    published_at  INTEGER NOT NULL,
    expires_at    INTEGER,
    topic_key     TEXT GENERATED ALWAYS AS (COALESCE(topic, '')) VIRTUAL,
    UNIQUE (agent_id, topic_key)
);
CREATE INDEX idx_briefs_published ON briefs(agent_id, published_at);

-- Per-agent presence state.
--
-- Two facets, kept in one row per agent:
--   1. Manual hint — what the agent (or its operator) explicitly signalled.
--      Optional; expires after `manual_status_expires_at` (null = no expiry).
--   2. Peer liveness cache — for federated peers, the most recent `live` flag
--      they advertised in a Presence envelope. Self liveness is NOT cached
--      here; it's derived live from `mcp_sessions` on every read.
--
-- The wire-level "presence.get" returns an *effective* status computed from
-- both facets: manual override wins if active; otherwise online/offline is
-- derived from liveness.
CREATE TABLE agent_presence (
    agent_id                  TEXT NOT NULL PRIMARY KEY REFERENCES agents(id) ON DELETE CASCADE,
    manual_status             TEXT CHECK (manual_status IN ('online','idle','busy','offline')),
    manual_status_set_at      INTEGER,
    manual_status_expires_at  INTEGER,
    peer_live                 INTEGER CHECK (peer_live IN (0, 1)),
    peer_live_updated_at      INTEGER,
    peer_live_expires_at      INTEGER
);

-- MCP stdio sessions currently attached to this daemon. Liveness for a
-- locally-hosted agent is derived from this table: an agent is "live"
-- iff at least one row has `agent_id = <its id>` AND
-- `last_heartbeat_at > now - SESSION_TTL`. Stale rows are pruned by the
-- janitor; sudden process death therefore decays to offline cleanly
-- without requiring a clean detach.
--
-- `agent_id` binds the session to the locally-hosted agent the
-- bearer authenticated as on `mcp.attach`. References `agents(id)`
-- for FK integrity; cascade-delete fires if the agent is removed
-- via `local rm`.
--
-- `session_label` is an operator-supplied stable nickname (see
-- `HERMOD_SESSION_LABEL`). When a fresh `mcp.attach` arrives with
-- a label that already has a live row for the same agent, the
-- daemon evicts the prior session and reuses its row — preserving
-- the cursors below across MCP process restart. The partial unique
-- index keys this resumption logic.
--
-- The three `last_*` columns are server-side persistence of MCP
-- delivery cursors. The MCP client calls `mcp.cursor_advance` after
-- writing a batch to stdout so the position survives restart and
-- multiple Claude Code windows of the same agent observe distinct
-- cursors:
--   * `last_message_id`        — inbox emitter (Direct/File)
--   * `last_confirmation_id`   — held-confirmation emitter
--   * `last_resolved_seq`      — permission verdict emitter
CREATE TABLE mcp_sessions (
    session_id            TEXT NOT NULL PRIMARY KEY,
    agent_id              TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    session_label         TEXT,
    attached_at           INTEGER NOT NULL,
    last_heartbeat_at     INTEGER NOT NULL,
    client_name           TEXT,
    client_version        TEXT,
    last_message_id       TEXT,
    last_confirmation_id  TEXT,
    last_resolved_seq     INTEGER
);
CREATE INDEX idx_mcp_sessions_heartbeat ON mcp_sessions(last_heartbeat_at);
CREATE INDEX idx_mcp_sessions_agent ON mcp_sessions(agent_id, last_heartbeat_at);
CREATE UNIQUE INDEX idx_mcp_sessions_agent_label
    ON mcp_sessions(agent_id, session_label) WHERE session_label IS NOT NULL;

-- Workspaces: a logical group container. Either:
--   private — secret = 32-byte PSK; workspace_id and channel keys are
--             derived via blake3 KDF (see hermod-crypto::workspace).
--   public  — secret IS NULL; identified by (creator_pubkey, name) at the
--             crypto layer. Broadcasts authenticate by ed25519 signature
--             alone.
-- `created_locally` is true iff this daemon called workspace.create on this
-- row (vs joining/learning about it).
CREATE TABLE workspaces (
    id              TEXT NOT NULL PRIMARY KEY,
    name            TEXT NOT NULL,
    visibility      TEXT NOT NULL
                    CHECK (visibility IN ('public','private')),
    secret          BLOB,
    created_locally INTEGER NOT NULL DEFAULT 0
                    CHECK (created_locally IN (0, 1)),
    muted           INTEGER NOT NULL DEFAULT 0
                    CHECK (muted IN (0, 1)),
    joined_at       INTEGER NOT NULL,
    last_active     INTEGER
);

-- Channels within a workspace. mac_key cached on join to avoid re-deriving
-- on every send/recv. NULL when workspace.visibility = public.
CREATE TABLE channels (
    id            TEXT NOT NULL PRIMARY KEY,
    workspace_id  TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    mac_key       BLOB,
    muted         INTEGER NOT NULL DEFAULT 0
                  CHECK (muted IN (0, 1)),
    joined_at     INTEGER NOT NULL,
    last_active   INTEGER,
    UNIQUE (workspace_id, name)
);
CREATE INDEX idx_channels_workspace ON channels(workspace_id);

-- Members of a workspace we know about. Auto-populated when a valid
-- broadcast / advertise / invite arrives from a previously-unseen sender.
-- Both columns reference parent rows: cascading from the workspace cleans
-- up membership when the workspace is deleted; cascading from the agent
-- prevents dangling membership rows pointing at an identity we no longer
-- have a record of.
CREATE TABLE workspace_members (
    workspace_id  TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    agent_id      TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    first_seen    INTEGER NOT NULL,
    last_seen     INTEGER,
    PRIMARY KEY (workspace_id, agent_id)
);

-- Channel broadcast log. Distinct from `messages` (which holds DMs);
-- broadcasts are group-addressed and don't share status semantics.
CREATE TABLE channel_messages (
    id            TEXT NOT NULL PRIMARY KEY,
    channel_id    TEXT NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
    from_agent    TEXT NOT NULL,
    body_text     TEXT NOT NULL,
    received_at   INTEGER NOT NULL
);
CREATE INDEX idx_channel_messages_channel ON channel_messages(channel_id, received_at);

-- Confirmation gate: inbound actions whose (peer_trust × sensitivity) cell
-- maps to "require confirmation" are parked here until the operator
-- decides. The held bytes are the full original envelope CBOR so accept
-- replays are deterministic. The partial unique index dedupes retries:
-- at most one PENDING row per envelope_id.
CREATE TABLE pending_confirmations (
    id            TEXT NOT NULL PRIMARY KEY,
    envelope_id   TEXT NOT NULL,
    requested_at  INTEGER NOT NULL,
    actor         TEXT NOT NULL,
    -- Locally-hosted agent the held envelope was addressed to
    -- (`envelope.to.id`). Multi-tenant isolation: `confirmation.list`
    -- and `confirmation.{accept,reject}` filter / verify on this so
    -- agent A's IPC bearer can never see or decide on B's queue.
    recipient     TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    intent        TEXT NOT NULL,
    sensitivity   TEXT NOT NULL
                  CHECK (sensitivity IN ('routine','review','sensitive')),
    trust_level   TEXT NOT NULL,
    summary       TEXT NOT NULL,
    envelope_cbor BLOB NOT NULL,
    status        TEXT NOT NULL
                  CHECK (status IN ('pending','accepted','rejected','expired'))
                  DEFAULT 'pending',
    decided_at    INTEGER,
    decided_by    TEXT
);
CREATE INDEX idx_pending_confirmations_status
    ON pending_confirmations(status, requested_at);
CREATE INDEX idx_pending_confirmations_recipient
    ON pending_confirmations(recipient, status, requested_at);
CREATE UNIQUE INDEX idx_pending_confirmations_envelope_pending
    ON pending_confirmations(envelope_id) WHERE status = 'pending';

-- One row per closed audit-archive day-bucket. The actual archive
-- payload (gzip-compressed JSONL) lives in the BlobStore at
-- `blob_location`; this table is the index that lets the operator
-- query "what archives exist?" and `audit verify-archive <epoch>`
-- find the right blob to verify. Chain continuity across archives
-- is checked by ensuring each row's `first_prev_hash` matches the
-- previous archive's `last_row_hash`, and the most recent archive's
-- `last_row_hash` matches the live `audit_log`'s first row's
-- `prev_hash` (or zero if `audit_log` is empty).
CREATE TABLE audit_archive_index (
    epoch_start      INTEGER NOT NULL PRIMARY KEY,  -- UTC day boundary, ms
    epoch_end        INTEGER NOT NULL,              -- exclusive
    first_row_id     INTEGER NOT NULL,
    last_row_id      INTEGER NOT NULL,
    row_count        INTEGER NOT NULL,
    first_prev_hash  BLOB NOT NULL,
    last_row_hash    BLOB NOT NULL,
    blob_location    TEXT NOT NULL,
    file_size        INTEGER NOT NULL,
    archived_at      INTEGER NOT NULL,
    manifest_sig     BLOB NOT NULL                  -- ed25519 over the manifest CBOR
);
CREATE INDEX idx_audit_archive_index_archived
    ON audit_archive_index(archived_at);

-- OS-notification queue for routing decisions whose recipient-side
-- `NotifyPreference` is `Os { sound }`. The MCP-side
-- `NotificationDispatcher` claims rows atomically (claim_token +
-- claimed_at, mirrors messages outbox) and transitions via
-- `notification.complete` / `notification.fail`. Operators dismiss
-- live rows via `notification.dismiss`. `purge_old` reaps dispatched
-- and dismissed rows past the operator-configured retention window.
--
-- `recipient_agent_id` is the per-tenant scope: every IPC method on
-- this table filters by caller_agent so sibling local agents never
-- enumerate or claim each other's queues.
CREATE TABLE notifications (
    id                  TEXT NOT NULL PRIMARY KEY,
    recipient_agent_id  TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    message_id          TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    status              TEXT NOT NULL
                        CHECK (status IN ('pending','dispatched','failed','dismissed')),
    sound               TEXT,
    attempts            INTEGER NOT NULL DEFAULT 0,
    claim_token         TEXT,
    claimed_at          INTEGER,
    dispatched_at       INTEGER,
    failed_reason       TEXT,
    created_at          INTEGER NOT NULL
);
CREATE INDEX idx_notifications_dispatch
    ON notifications(recipient_agent_id, status, created_at);

-- ChannelAdvertise envelopes from workspace members append here. Janitor
-- sweeps stale rows by `last_seen`.
CREATE TABLE discovered_channels (
    workspace_id   TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    channel_id     TEXT NOT NULL,
    channel_name   TEXT NOT NULL,
    advertised_by  TEXT NOT NULL,
    discovered_at  INTEGER NOT NULL,
    last_seen      INTEGER NOT NULL,
    PRIMARY KEY (workspace_id, channel_id)
);
CREATE INDEX idx_discovered_channels_seen ON discovered_channels(last_seen);

-- Schema version marker. Future migrations bump the `value` of the
-- 'version' row. `hermod doctor` reads this to detect schema drift
-- between the binary and the database.
CREATE TABLE schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
INSERT INTO schema_meta (key, value) VALUES ('version', '1');
