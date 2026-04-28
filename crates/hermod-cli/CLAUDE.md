# hermod-cli — AI agent guide

`hermod` binary. Operator CLI + MCP server for Claude Code Channels.
The CLI subcommand surface and the MCP tool surface are sibling APIs
over the same daemon, not duplicates.

## Module layout

```
client.rs            local Unix-socket IPC client + remote dispatch
remote.rs            WSS+Bearer remote-IPC client (TLS pin policy + 401-retry)
bearer/              BearerProvider trait + 3 implementations
  mod.rs             trait, BearerToken, TokenEpoch, BearerError, from_env_and_args factory
  static_provider.rs HERMOD_BEARER_TOKEN-backed provider (no refresh)
  file.rs            --bearer-file / default $HERMOD_HOME/identity/bearer_token (cold-path read; refresh() re-reads on 401)
  command.rs         --bearer-command (sh -c, 30s timeout, kill_on_drop, single-flight refresh)
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

Every `--remote wss://…` connect goes through a `BearerProvider`. Two
methods, no boolean flags:

- `current()` — return the cached token, minting once on the cold
  path.
- `refresh(stale: TokenEpoch)` — single-flight: re-mints only if the
  cached epoch is `<= stale`, otherwise returns the already-advanced
  cache. The connect path retries exactly once on HTTP 401; if
  `refresh` returns the same epoch (provider declines, e.g.
  `StaticBearerProvider`), the failure escalates to fatal.

Source precedence is enforced once in `bearer::from_env_and_args`:
exactly one of `--bearer-file`, `--bearer-command`,
`HERMOD_BEARER_TOKEN` may be set. With none set the implicit fallback
is `$HERMOD_HOME/identity/bearer_token` via `FileBearerProvider`.
`File` and `Command` providers cache for the process lifetime — the
401-trigger is the only refresh signal, no time-based heuristics.

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
`hermod_daemon::home_layout::audit(home)` — adding a new file to
`home_layout::spec` automatically adds a doctor row. Beyond the
spec-driven file/mode audit, doctor also checks: identity loadable,
TLS cert validity (FAIL on expired, warn under 30 days), daemon
reachability, schema version, audit-chain integrity, peer count,
held-confirmation queue depth, capability presence, and Claude Code
MCP registration. New operator-visible health signals ⇒ a new
`report.check` / `report.note` call in `commands/doctor.rs`.
