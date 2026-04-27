-- Hermod schema.

-- Agents — unified identity directory for local self + every remote agent
-- this daemon has interacted with. `endpoint` is non-null iff the agent
-- speaks federation (i.e. is "a peer"). `tls_fingerprint` is captured on
-- first successful TLS handshake (TOFU-pinned thereafter). `reputation`
-- is operator-managed feedback; positive on clean traffic, negative on
-- protocol violations.
-- agents directory.
--
-- Identity / display split (best practice, see Signal / GitHub / PGP):
--   * `id` (ed25519 pubkey hash) — the canonical identifier. Routing,
--     crypto, audit, foreign keys all reference this. Immutable.
--   * `local_alias` — the operator-set nickname for this peer. Sacred:
--     once an operator has named someone @bob, no peer can take that
--     name from them. UNIQUE within the daemon. Used for `--to @alias`
--     resolution.
--   * `peer_asserted_alias` — the peer's self-claim from their last
--     Hello / Presence frame. Advisory display metadata only — never
--     used for routing, never overrides `local_alias`. NOT unique
--     (multiple peers can claim the same display name; we just store
--     each one's claim).
CREATE TABLE agents (
    id                  TEXT NOT NULL PRIMARY KEY,
    pubkey              BLOB NOT NULL,
    endpoint            TEXT,
    local_alias         TEXT UNIQUE,
    peer_asserted_alias TEXT,
    trust_level         TEXT NOT NULL
                        CHECK (trust_level IN ('self','verified','tofu','untrusted')),
    tls_fingerprint     TEXT,
    reputation          INTEGER NOT NULL DEFAULT 0,
    first_seen          INTEGER NOT NULL,
    last_seen           INTEGER
);
CREATE INDEX idx_agents_with_endpoint ON agents(id) WHERE endpoint IS NOT NULL;

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
    delivery_endpoint TEXT
);
CREATE INDEX idx_messages_inbox ON messages(to_agent, status, created_at);
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
-- (ts || actor || action || target || details_json || prev_hash) with
-- explicit length prefixes (see hermod_storage::audit::compute_row_hash).
-- `sig` is ed25519 over `row_hash` by the daemon's keypair. `prev_hash`
-- of the first row is 32 zero bytes.
CREATE TABLE audit_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            INTEGER NOT NULL,
    actor         TEXT NOT NULL,
    action        TEXT NOT NULL,
    target        TEXT,
    details_json  TEXT,
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

-- MCP stdio sessions currently attached to this daemon. Liveness for SELF
-- is derived from this table: an agent is "live" iff at least one row has
-- `last_heartbeat_at > now - SESSION_TTL`. Stale rows are pruned by the
-- janitor; sudden process death therefore decays to offline cleanly without
-- requiring a clean detach.
CREATE TABLE mcp_sessions (
    session_id          TEXT NOT NULL PRIMARY KEY,
    attached_at         INTEGER NOT NULL,
    last_heartbeat_at   INTEGER NOT NULL,
    client_name         TEXT,
    client_version      TEXT
);
CREATE INDEX idx_mcp_sessions_heartbeat ON mcp_sessions(last_heartbeat_at);

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
