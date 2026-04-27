# hermod-cli — AI agent guide

`hermod` binary. Operator CLI + MCP server for Claude Code Channels.
The CLI subcommand surface and the MCP tool surface are sibling APIs
over the same daemon, not duplicates.

## Module layout

```
client.rs            local Unix-socket IPC client
remote.rs            WSS+Bearer remote-IPC client (TLS pin policy)
main.rs              clap CLI dispatch
commands/            one file per `hermod <subcommand>` (peer, capability, brief, …)
mcp/                 MCP server (hand-rolled JSON-RPC over stdio)
  initialize.rs      capabilities + INSTRUCTIONS prompt (pinned by tests)
  notification.rs    `notifications/claude/channel` + `…/permission` frame builder
  permission.rs      Channels permission-relay bridge to the daemon
  session.rs         attach / heartbeat / detach + emitters
  channel.rs         cursor-based polling source (DM, file, confirmation, permission)
  tools.rs           tool schemas (operator-facing tool surface)
```

## MCP surface contract

The MCP server is intentionally hand-rolled (no `rmcp` dep) so the
JSON-RPC framing, capability advertisement, and channel emission stay
pinned by tests. Touching `mcp/` requires running
`crates/hermod-cli/tests/channels.rs` end-to-end — those tests spawn
real `hermodd` + `hermod mcp` subprocesses against a fresh
`tempfile::tempdir()`.

The advertised capabilities are exactly:
- `experimental.claude/channel`
- `experimental.claude/channel/permission`

`initialize.rs::INSTRUCTIONS` is the system-prompt fragment Claude
Code injects when the MCP server connects. The string is verbatim
inside the test snapshot — do not edit without updating both.

## Tool naming

MCP tool names mirror IPC method names with `.` → `_`:

| IPC method | MCP tool |
| --- | --- |
| `message.send` | `message_send` |
| `workspace.invite` | `workspace_invite` |
| `confirmation.list` | `confirmation_list` |

Tool surface is intentionally narrower than the full IPC surface —
operator-only actions (`peer.*`, `capability.*`, `audit.*`,
`permission.*`, `mcp.*`) are NOT exposed to the agent. Adding a new
tool requires a clear AI-agent use case; otherwise leave it
operator-only.

## CLI subcommand consistency

Every subcommand maps to one IPC namespace:

```
hermod peer        → peer.*       (add / list / remove / trust / repin)
hermod capability  → capability.* (issue / list / revoke / deliver / request)
hermod confirm     → confirmation.* (list / accept / reject)
hermod permission  → permission.* (list / allow / deny / delegate)
hermod workspace   → workspace.*  (create / list / join / invite / channels / members / mute / delete)
hermod channel     → channel.*    (create / list / history / discover / adopt / advertise / mute / delete)
hermod brief       → brief.*      (publish / read)
hermod presence    → presence.*   (set / clear / get)
hermod broadcast   → broadcast.*  (send)
hermod audit       → audit.*      (query / verify / archive-now / list-archives / verify-archive)
hermod agent       → agent.*      (list / get / register)
hermod message     → message.*    (send / list / ack / send-file)
hermod doctor / status / identity / init / mcp        administrative
```

## Release-binary dependence in tests

`tests/channels.rs` and `tests/federation.rs` spawn the *release*
binaries — they call `release_bin("hermod")` / `release_bin("hermodd")`
which look at `target/release/`. CI runs `cargo build --release
--workspace --bins` before `cargo test` for this reason. After any
change to MCP framing, IPC types, or daemon services, run:

```bash
cargo build --release --workspace --bins
cargo test -p hermod-cli --test channels
cargo test -p hermod-cli --test federation
```

## hermod doctor expectations

`hermod doctor` is the operator's self-diagnostic. It checks identity
file mode (0600), TLS cert validity (with 30-day expiry warning, FAIL
on expired), schema version match, audit-chain integrity, daemon
reachability, peer count, confirmation queue depth, capability
presence, and Claude Code MCP registration. Adding a new operator-
visible health signal ⇒ a new `report.check` / `report.note` call in
`commands/doctor.rs`.
