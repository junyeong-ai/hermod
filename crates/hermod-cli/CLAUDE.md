# hermod-cli — AI agent guide

`hermod` binary. Operator CLI + MCP server for Claude Code Channels.
The CLI subcommand surface and the MCP tool surface are sibling APIs
over the same daemon, not duplicates.

## Module layout

```
client.rs            local Unix-socket IPC client + remote dispatch + RemoteAuth { daemon, proxy }
remote.rs            WSS+Bearer remote-IPC client (TLS pin policy + dual-header + 401/407 retry)
bearer/              BearerProvider trait + 3 implementations
  mod.rs             trait, BearerToken, TokenEpoch, BearerError, BearerArgs,
                     daemon_from_env_and_args (required) / proxy_from_env_and_args (optional) factories
  static_provider.rs HERMOD_BEARER_TOKEN / HERMOD_PROXY_BEARER_TOKEN-backed provider (no refresh)
  file.rs            --bearer-file / --proxy-bearer-file / default $HERMOD_HOME/identity/bearer_token
                     (cold-path read; refresh() re-reads on auth failure)
  command.rs         --bearer-command / --proxy-bearer-command (sh -c, 30s timeout, kill_on_drop, single-flight refresh)
main.rs              clap CLI dispatch
commands/            one file per `hermod <subcommand>` (peer, capability, brief, bearer, …)
mcp/                 MCP server (hand-rolled JSON-RPC over stdio)
  initialize.rs      capabilities + INSTRUCTIONS prompt (pinned by tests)
  notification.rs    `notifications/claude/channel` + `…/permission` frame builder
  permission.rs      Channels permission-relay bridge to the daemon
  session.rs         attach / heartbeat / detach + emitters
  channel.rs         cursor-based polling source (DM, file, confirmation, permission)
  tools.rs           tool schemas (operator-facing tool surface)
```

## BearerProvider abstraction

Every `--remote wss://…` connect goes through one or two
`BearerProvider`s — one for the daemon-layer `Authorization` header,
optionally another for the proxy-layer `Proxy-Authorization` header
when the broker sits behind an SSO reverse proxy (Google Cloud IAP,
oauth2-proxy, Cloudflare Access, ALB+Cognito). Both sides share the
same trait; what differs is the factory and the connect path's
refresh policy.

Trait — two methods, no boolean flags:

- `current()` — return the cached token, minting once on the cold
  path.
- `refresh(stale: TokenEpoch)` — single-flight: re-mints only if the
  cached epoch is `<= stale`, otherwise returns the already-advanced
  cache. The connect path retries exactly once on HTTP 401 / 407; if
  no provider advances its epoch (e.g. all sources are
  `StaticBearerProvider`), the failure escalates to fatal.

Two paired factories enforce source precedence — daemon-bearer is
required, proxy-bearer is optional:

- `bearer::daemon_from_env_and_args(args, env_token, default_path)`
  — exactly one of `--bearer-file`, `--bearer-command`,
  `HERMOD_BEARER_TOKEN` may be set. With none set, the implicit
  fallback is `$HERMOD_HOME/identity/bearer_token` via
  `FileBearerProvider` (the on-host "just works" path).
- `bearer::proxy_from_env_and_args(args, env_token)` — exactly one
  of `--proxy-bearer-file`, `--proxy-bearer-command`,
  `HERMOD_PROXY_BEARER_TOKEN` may be set. Returns `Ok(None)` when
  zero sources are configured (no SSO proxy fronting the broker).

Connect path refresh policy (`remote::connect_remote_with_refresh`):

- HTTP 407 (Proxy-Authentication-Required) → refresh proxy provider
  only, retry once.
- HTTP 401 (Unauthorized) → wire-ambiguous about which layer
  rejected, so refresh both providers concurrently and retry once.
- Two consecutive auth failures → fatal.

`File` and `Command` providers cache for the process lifetime —
the 401/407-trigger is the only refresh signal, no time-based
heuristics.

## MCP surface contract

The MCP server is intentionally hand-rolled (no `rmcp` dep) so the
JSON-RPC framing, capability advertisement, and channel emission stay
pinned by tests. Touching `mcp/` requires running
`crates/hermod-cli/tests/channels.rs` end-to-end — those tests spawn
real `hermodd` + `hermod mcp` subprocesses against a fresh
`tempfile::tempdir()`.

Advertised capabilities (exact strings — pinned by initialize-response
tests):

- `experimental.claude/channel`
- `experimental.claude/channel/permission`

`initialize.rs::INSTRUCTIONS` is the system-prompt fragment Claude
Code injects when the MCP server connects. The string is verbatim
inside the test snapshot — do not edit without updating both.

## Tool naming

MCP tool names mirror IPC method names with `.` → `_`
(`message.send` → `message_send`). The MCP tool surface is
intentionally narrower than the full IPC surface — operator-only
namespaces (`peer.*`, `capability.*`, `audit.*`, `permission.*`,
`mcp.*`) are NOT exposed to the agent. Adding a new tool requires a
clear AI-agent use case; otherwise leave it operator-only.

## CLI subcommand → IPC namespace

Every subcommand maps 1:1 to one IPC namespace; the subcommand verbs
mirror the IPC verbs. Discover the live surface with `hermod --help`
and `hermod <subcommand> --help`. Administrative subcommands without
a 1:1 namespace: `init`, `status`, `identity`, `doctor`, `bearer`
(token rotate / show), `mcp` (run the stdio MCP server).

## hermod doctor

`hermod doctor` is the operator's self-diagnostic. Output is driven by
`hermod_daemon::home_layout::audit(home, storage_dsn, blob_dsn)` —
adding a new daemon-owned file to `home_layout::spec` (or a backend-
local file to the storage layer's `database_local_files` /
`blob_store_local_files`) automatically adds a doctor row. Beyond the
spec-driven file/mode audit, doctor also checks: identity loadable,
TLS cert validity (FAIL on expired, warn under 30 days), daemon
reachability, schema version, audit-chain integrity, peer count,
held-confirmation queue depth, capability presence, and Claude Code
MCP registration. New operator-visible health signals ⇒ a new
`report.check` / `report.note` call in `commands/doctor.rs`.
