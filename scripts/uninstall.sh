#!/usr/bin/env bash
# Hermod uninstaller.
#
# Tears down what `install.sh` set up. Identity at $HERMOD_HOME is
# preserved by default — pass --purge to also remove it. Identities are
# cryptographic keys; deleting them is irreversible.
#
# Flags:
#   --purge        — also delete $HERMOD_HOME (identity, DB, audit log)
#   --keep-binaries — leave hermod/hermodd installed
#   --help

set -euo pipefail

HERMOD_HOME="${HERMOD_HOME:-$HOME/.hermod}"
DO_PURGE=0
DO_BINARIES=1

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
ok()   { printf '\033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '\033[33m!\033[0m %s\n' "$*"; }

usage() {
  sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --purge)         DO_PURGE=1;    shift ;;
    --keep-binaries) DO_BINARIES=0; shift ;;
    --help|-h)       usage ;;
    *) warn "unknown flag: $1"; shift ;;
  esac
done

bold "stopping background service"
case "$(uname -s)" in
  Darwin)
    plist="$HOME/Library/LaunchAgents/com.hermod.daemon.plist"
    if [[ -f "$plist" ]]; then
      launchctl unload -w "$plist" 2>/dev/null || true
      rm -f "$plist"
      ok "removed launchd plist"
    else
      ok "no launchd plist found"
    fi
    ;;
  Linux)
    if systemctl --user list-unit-files 2>/dev/null | grep -q '^hermodd.service'; then
      systemctl --user disable --now hermodd.service 2>/dev/null || true
      rm -f "$HOME/.config/systemd/user/hermodd.service"
      systemctl --user daemon-reload
      ok "removed systemd user unit"
    else
      ok "no systemd user unit found"
    fi
    ;;
esac

bold "removing MCP registration"
if command -v claude >/dev/null 2>&1; then
  claude mcp remove hermod --scope user >/dev/null 2>&1 || true
  ok "removed hermod MCP server"
else
  warn "claude CLI not on PATH — skipping"
fi

if [[ "$DO_BINARIES" -eq 1 ]]; then
  bold "removing binaries"
  for bin in hermod hermodd; do
    if path="$(command -v "$bin" 2>/dev/null)"; then
      rm -f "$path"
      ok "removed $path"
    fi
  done
fi

if [[ "$DO_PURGE" -eq 1 ]]; then
  bold "purging $HERMOD_HOME"
  if [[ -d "$HERMOD_HOME" ]]; then
    archive="$HERMOD_HOME.uninstalled.$(date +%s)"
    mv "$HERMOD_HOME" "$archive"
    ok "moved to $archive (delete manually if you really mean it)"
  fi
else
  warn "kept identity at $HERMOD_HOME (pass --purge to archive it)"
fi

ok "done"
