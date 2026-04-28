#!/usr/bin/env bash
# Hermod installer. Idempotent — safe to re-run.
#
# Steps:
#   1. Build + install `hermod` + `hermodd` binaries (via `cargo install --path`).
#   2. Bootstrap identity at $HERMOD_HOME (default ~/.hermod) if absent.
#   3. Register the hermod MCP server with Claude Code (`claude mcp add`).
#   4. Register this checkout as a Claude Code plugin marketplace + install
#      the `hermod` plugin (slash commands, skill, MCP wiring).
#   5. Set up the daemon as a background service (launchd on macOS, systemd
#      --user on Linux). Skipped when --no-service is passed.
#
# Env / flags:
#   HERMOD_HOME=<path>       — identity + DB location (default ~/.hermod)
#   HERMOD_ALIAS=<name>      — alias to register (default: $USER)
#   --no-service             — skip launchd/systemd registration
#   --no-mcp                 — skip `claude mcp add`
#   --no-plugin              — skip Claude Code plugin marketplace + install
#   --skip-build             — assume hermod/hermodd already on PATH
#   --help                   — show this message
#
# Deployment patterns (compose the flags above):
#
#   1. Local laptop (default — daemon, MCP, and plugin all local):
#         ./scripts/install.sh
#
#   2. Cloud-daemon thin client (laptop ↔ remote daemon over WSS+Bearer):
#         ./scripts/install.sh --no-service --no-mcp
#         # then register MCP that points at the remote daemon:
#         claude mcp add hermod -s user -- hermod mcp \
#           --remote wss://broker.example.com/ \
#           --bearer-file ~/.hermod/remote_bearer
#         # behind an SSO reverse proxy (IAP / oauth2-proxy / Cloudflare
#         # Access)? add --proxy-bearer-command to the MCP entry above.
#         # See DEPLOY.md §3.
#
#   3. Admin only (CLI to operate a remote broker — no daemon, no MCP,
#      no plugin):
#         ./scripts/install.sh --no-service --no-mcp --no-plugin
#         hermod --remote wss://broker.example.com/ \
#                --bearer-file ~/.hermod/remote_bearer status
#
#   4. Broker host (server that relays envelopes for federated peers):
#         ./scripts/install.sh
#         # then enable [broker] in $HERMOD_HOME/config.toml — see
#         # DEPLOY.md §4.7.
#
# After install:
#   hermod status            (should print agent_id + uptime)
#   hermod doctor            (sanity check)
#   /agents /peers /inbox /health    (slash commands from the plugin)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HERMOD_HOME="${HERMOD_HOME:-$HOME/.hermod}"
HERMOD_ALIAS="${HERMOD_ALIAS:-${USER:-me}}"
DO_SERVICE=1
DO_MCP=1
DO_BUILD=1
DO_PLUGIN=1

# ── pretty-printing helpers ──────────────────────────────────────────────
bold() { printf '\033[1m%s\033[0m\n' "$*"; }
ok()   { printf '\033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '\033[33m!\033[0m %s\n' "$*"; }
err()  { printf '\033[31m✗\033[0m %s\n' "$*" >&2; }

usage() {
  sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
  exit 0
}

# ── platform-specific service installers ─────────────────────────────────
install_launchd() {
  local plist="$HOME/Library/LaunchAgents/com.hermod.daemon.plist"
  local hermodd_bin
  hermodd_bin="$(command -v hermodd)"
  if [[ -f "$plist" ]]; then
    ok "launchd plist already installed (skipping)"
    return
  fi
  mkdir -p "$HOME/Library/LaunchAgents"
  cat > "$plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>             <string>com.hermod.daemon</string>
  <key>ProgramArguments</key>  <array><string>$hermodd_bin</string></array>
  <key>EnvironmentVariables</key>
    <dict>
      <key>HERMOD_HOME</key>   <string>$HERMOD_HOME</string>
      <key>RUST_LOG</key>      <string>info</string>
    </dict>
  <key>RunAtLoad</key>         <true/>
  <key>KeepAlive</key>         <true/>
  <key>StandardOutPath</key>   <string>$HERMOD_HOME/hermodd.log</string>
  <key>StandardErrorPath</key> <string>$HERMOD_HOME/hermodd.log</string>
  <key>WorkingDirectory</key>  <string>$HERMOD_HOME</string>
  <key>ProcessType</key>       <string>Background</string>
</dict>
</plist>
PLIST
  launchctl load -w "$plist"
  ok "launchd service registered (com.hermod.daemon)"
}

install_systemd() {
  local unit="$HOME/.config/systemd/user/hermodd.service"
  local hermodd_bin
  hermodd_bin="$(command -v hermodd)"
  if [[ -f "$unit" ]]; then
    ok "systemd unit already installed (skipping)"
    return
  fi
  mkdir -p "$(dirname "$unit")"
  cat > "$unit" <<UNIT
[Unit]
Description=Hermod agent-to-agent messaging daemon
After=network.target
# network-online ensures DNS / outbound TLS is reachable before federation
# tries to dial peers on startup.
Wants=network-online.target

[Service]
Type=simple
ExecStart=$hermodd_bin
WorkingDirectory=$HERMOD_HOME
Environment=HERMOD_HOME=$HERMOD_HOME
Environment=RUST_LOG=info
# Logs go to journalctl (\`journalctl --user -u hermodd -f\`) instead of a
# growing log file under \$HERMOD_HOME — operators get standard rotation +
# query support without bespoke tooling.
StandardOutput=journal
StandardError=journal
# Restart policy: 5s delay so a crash loop can't burn CPU. on-failure
# only — clean exits (SIGTERM from \`systemctl stop\`) don't restart.
Restart=on-failure
RestartSec=5
# Cap restart attempts in a short window to surface persistent crashes
# instead of looping silently.
StartLimitIntervalSec=60
StartLimitBurst=5

[Install]
WantedBy=default.target
UNIT
  systemctl --user daemon-reload
  systemctl --user enable --now hermodd.service
  ok "systemd user service registered (hermodd.service)"
}

# ── arg parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-service) DO_SERVICE=0; shift ;;
    --no-mcp)     DO_MCP=0;     shift ;;
    --no-plugin)  DO_PLUGIN=0;  shift ;;
    --skip-build) DO_BUILD=0;   shift ;;
    --help|-h)    usage ;;
    *) err "unknown flag: $1"; exit 2 ;;
  esac
done

# ── 1. binaries ──────────────────────────────────────────────────────────
if [[ "$DO_BUILD" -eq 1 ]]; then
  bold "[1/5] building + installing binaries (cargo install)"
  if ! command -v cargo >/dev/null 2>&1; then
    err "cargo not found — install Rust from https://rustup.rs first"
    exit 1
  fi
  cargo install --path "$REPO_ROOT/crates/hermod-cli"    --quiet
  cargo install --path "$REPO_ROOT/crates/hermod-daemon" --quiet
  ok "installed hermod + hermodd"
else
  command -v hermod  >/dev/null || { err "hermod not on PATH"; exit 1; }
  command -v hermodd >/dev/null || { err "hermodd not on PATH"; exit 1; }
  ok "hermod + hermodd already on PATH"
fi

# ── 2. identity ──────────────────────────────────────────────────────────
bold "[2/5] bootstrapping identity at $HERMOD_HOME"
if [[ -f "$HERMOD_HOME/identity/ed25519_secret" ]]; then
  ok "identity already present (skipping init)"
else
  HERMOD_HOME="$HERMOD_HOME" hermod init --alias "$HERMOD_ALIAS" >/dev/null
  ok "created identity (alias=$HERMOD_ALIAS)"
fi

# ── 3. Claude Code MCP registration ──────────────────────────────────────
if [[ "$DO_MCP" -eq 1 ]]; then
  bold "[3/5] registering hermod MCP server with Claude Code"
  if ! command -v claude >/dev/null 2>&1; then
    warn "claude CLI not found — skipping MCP registration"
    warn "  install Claude Code, then run: claude mcp add hermod hermod mcp --scope user"
  elif claude mcp list 2>/dev/null | grep -q '^hermod:'; then
    ok "hermod MCP server already registered"
  else
    claude mcp add hermod hermod mcp --scope user >/dev/null
    ok "registered hermod MCP server (--scope user)"
  fi
else
  warn "[3/5] MCP registration skipped (--no-mcp)"
fi

# ── 4. Claude Code plugin (slash commands + skill + auto-MCP) ────────────
#
# `claude plugin install <path>` is unsupported — Claude Code resolves
# every install through a marketplace. We register the local checkout
# itself as a marketplace via `.claude-plugin/marketplace.json`, then
# install the `hermod` plugin from it. The marketplace stays pointed at
# the working tree, so a `git pull` followed by `/plugin marketplace
# update hermod` picks up new commands without re-running this script.
if [[ "$DO_PLUGIN" -eq 1 ]]; then
  bold "[4/5] registering local plugin marketplace + installing hermod plugin"
  if ! command -v claude >/dev/null 2>&1; then
    warn "claude CLI not found — skipping plugin install"
    warn "  install Claude Code, then run:"
    warn "    claude plugin marketplace add $REPO_ROOT"
    warn "    claude plugin install hermod@hermod"
  else
    if claude plugin marketplace list 2>/dev/null | grep -q '^hermod\b'; then
      ok "marketplace 'hermod' already registered"
    else
      claude plugin marketplace add "$REPO_ROOT" >/dev/null
      ok "registered marketplace 'hermod' → $REPO_ROOT"
    fi
    if claude plugin list 2>/dev/null | grep -q '^hermod\b'; then
      ok "plugin 'hermod' already installed"
    else
      claude plugin install hermod@hermod >/dev/null
      ok "installed plugin 'hermod' (slash commands, skill, MCP)"
    fi
  fi
else
  warn "[4/5] plugin install skipped (--no-plugin)"
fi

# ── 5. background service ────────────────────────────────────────────────
if [[ "$DO_SERVICE" -eq 1 ]]; then
  bold "[5/5] setting up background daemon"
  case "$(uname -s)" in
    Darwin) install_launchd ;;
    Linux)  install_systemd ;;
    *)      warn "unsupported OS $(uname -s) — start hermodd manually" ;;
  esac
else
  warn "[5/5] background service skipped (--no-service); run \`hermodd\` manually"
fi

# ── done ─────────────────────────────────────────────────────────────────
bold "next steps"
cat <<EOF

  hermod status                        # confirm daemon is up
  hermod doctor                        # full health check
  /agents  /peers  /inbox  /health     # slash commands (from the plugin)

The local plugin marketplace tracks $REPO_ROOT — after \`git pull\` run
\`/plugin marketplace update hermod\` inside Claude Code to refresh slash
commands without re-running this script.

EOF
