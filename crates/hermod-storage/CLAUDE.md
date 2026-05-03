# hermod-storage — AI agent guide

Pluggable persistence. Daemon depends only on `Arc<dyn Database>` and
the per-collection repository traits — never names a concrete backend.

## Construction

```rust
let blobs = hermod_storage::open_blob_store(blob_dsn).await?;
//   file:///abs/path/blob-store                    // default, always-on
//   memory://                                      // tests, always-on
//   gcs://bucket/prefix                            // --features gcs
//   s3://bucket/prefix                             // --features s3

let db = hermod_storage::open_database(storage_dsn, signer, blobs).await?;
//   sqlite:///abs/path/hermod.db                   // default, always-on
//   postgres://user@host/db?sslmode=require        // --features postgres
```

Two trait families, two parallel DSN-dispatched factories at the
crate root — the symmetry is intentional. Adding a new database
backend = one new arm in `open_database()` + one new module under
`backends/`. Adding a new blob backend = one new arm in
`blobs::open()` + one new module under `blobs/`. Cloud backends
(`gcs`, `s3`) take auth from the SDK's standard env-var chain (ADC,
AWS credential chain) — DSN never carries secrets.

## Backend introspection — symmetric 4-axis

Each layer (Database, BlobStore) exposes the same four axes so
"what does this backend do?" has one answer per question regardless
of layer:

| axis                  | Database                  | BlobStore                  |
| --------------------- | ------------------------- | -------------------------- |
| typed enum            | `DatabaseBackend`         | `BlobStoreBackend`         |
| classify (DSN-static) | `classify_database_dsn`   | `classify_blob_dsn`        |
| local files (DSN-static) | `database_local_files` | `blob_store_local_files`   |
| backend (instance)    | `Database::backend()`     | `BlobStore::backend()`     |

`classify_*_dsn` and `*_local_files` answer before construction and
are used by `home_layout` to derive boot-time enforcement and
`hermod doctor` audit without opening the backend. `*::backend()`
answers after construction so callers (metrics labels, doctor
output, future operator tooling) get a typed identifier without
downcasting.

A new backend declares its on-disk artefacts in its `*_local_files`
arm and self-identifies via `backend()`. Backends with no local
state (Postgres, GCS, S3, in-memory) return an empty `Vec<LocalFile>`
from the static path.

## Trait surface

`Database` (in `database.rs`) hands out `&dyn <Repo>` accessors:

| Accessor | Trait |
| --- | --- |
| `agents()` | `AgentRepository` |
| `audit()` | `AuditRepository` |
| `blobs()` | (returns `Arc<dyn BlobStore>`) |
| `briefs()` | `BriefRepository` |
| `capabilities()` | `CapabilityRepository` |
| `channels()` | `ChannelRepository` |
| `confirmations()` | `ConfirmationRepository` |
| `discovered_channels()` | `DiscoveredChannelRepository` |
| `hosts()` | `HostRepository` |
| `local_agents()` | `LocalAgentRepository` |
| `mcp_sessions()` | `McpSessionRepository` |
| `messages()` | `MessageRepository` |
| `notifications()` | `NotificationRepository` |
| `presences()` | `AgentPresenceRepository` |
| `rate_limits()` | `RateLimitRepository` |
| `workspaces()` | `WorkspaceRepository` |
| `workspace_members()` | `WorkspaceMemberRepository` |

Plus `ping()`, `schema_version()`, `metrics_snapshot()`, `shutdown()`.

## Identity model — host vs agent

Two tables, two concepts, no overlap:

- **`hosts`** — daemons (the entity authenticated by the federation
  Noise XX handshake). Carries `pubkey`, `endpoint`, `tls_fingerprint`,
  `peer_asserted_alias` (host's own claimed name). Hosts are NEVER
  envelope recipients; they're how the dial pool knows where to go.
- **`agents`** — envelope senders / receivers. `agents.host_id` FK
  points at the daemon hosting this agent. Carries `local_alias`,
  `peer_asserted_alias` (persona), `trust_level`, `reputation`,
  `peer_asserted_tags`, `via_agent` (brokered routing).

Routing fields (`host_id` / `via_agent`) are NEVER touched by
`upsert` / `upsert_observed`. Their ownership is encoded in three
explicit methods:

- `set_routing_direct(id, host_id)` — direct dial
- `set_routing_brokered(id, via_agent)` — brokered dial
- `clear_routing(id)` — both NULL (directory-only / not routable)

Each method atomically clears the other slot, so the
`host_id XOR via_agent` CHECK is satisfied without a multi-statement
window. Operator paths (`peer add` direct/via) and the
`peer.advertise` inbound acceptor call these methods after the
identity-shaped upsert.

## Backend parity contract

SQLite and Postgres backends MUST be semantically equivalent. Dialect
differences live in three places only:

- `BEGIN IMMEDIATE` (sqlite) ↔ `pg_advisory_xact_lock(hashtext(...))` (postgres) — for hash-chain serialization
- `INSERT OR IGNORE` (sqlite) ↔ `INSERT ... ON CONFLICT DO NOTHING RETURNING` (postgres)
- `SELECT ... LIMIT n` writer-lock (sqlite) ↔ `FOR UPDATE SKIP LOCKED` (postgres) — for outbox claim atomicity

Any new method added to a repository trait must land in **both**
backends in the same PR. The integration tests in `tests/postgres_*.rs`
gate the postgres parity (run with `--features postgres` +
`HERMOD_TEST_POSTGRES_URL`).

## Audit sink stack

`AuditSink` is composable via `TeeAuditSink`. Production layout:

```
StorageAuditSink (always)            ← hash-chained, signed
  ⊕  FileAuditSink (optional)        ← logrotate-compatible JSONL
  ⊕  WebhookAuditSink (optional)     ← HTTP POST, bounded mpsc
  ⊕  RemoteAuditSink (optional)      ← AuditFederate envelopes
```

Emission discipline (`audit_or_warn`, typed `AuditEntry.federation`,
doc parity with `docs/audit_actions.md`) lives in
`.claude/rules/audit-emission.md` — path-scoped to the daemon and
the audit-sink files, so it loads automatically when relevant.

## Migrations

Up-only, baked at compile time (`sqlx::migrate!("./migrations")`).
Pre-v1 clean-slate: when a column changes, edit the migration file in
place — the daemon's `StorageError::SchemaMismatch` handler
instructs operators to archive the DB and re-init.

`migrations/` (sqlite) and `migrations-postgres/` (postgres) must stay
schema-equivalent. Dialect substitutions only:
- `BLOB` ↔ `BYTEA`
- `INTEGER` ↔ `BIGINT`
- `INTEGER PRIMARY KEY AUTOINCREMENT` ↔ `BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY`
