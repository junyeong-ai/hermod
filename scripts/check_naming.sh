#!/usr/bin/env bash
# Naming convention enforcement.
#
# Verifies:
#   1. IPC method consts in `hermod-protocol/src/ipc/methods.rs` follow
#      `<NAMESPACE>_<VERB> = "<namespace>.<verb_snake>"` shape.
#   2. Every IPC method const has a matching dispatcher arm.
#   3. Every audit action string in the daemon matches `<ns>.<event>` or
#      `<ns>.<event>.<phase>`, no all-caps or kebab-case.
#   4. Every `pub struct (Sqlite|Postgres)<Domain><Suffix>` under
#      `backends/` ends in `Repository` (or is the canonical
#      `<Backend>Database`), and the domain part matches a
#      `<Domain>Repository` trait declared in `repositories/`.
#
# Portable to bash 3.x (macOS default).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

fail() {
    echo "naming: $*" >&2
    exit 1
}

methods_file="crates/hermod-protocol/src/ipc/methods.rs"
dispatcher_file="crates/hermod-daemon/src/dispatcher.rs"

n_consts=0
while IFS=$'\t' read -r ident value; do
    n_consts=$((n_consts + 1))
    # Build expected wire value from the const name:
    #   IDENT = first segment before `_`; rest joined by `_` becomes the verb.
    head="$(echo "$ident" | cut -d_ -f1 | tr '[:upper:]' '[:lower:]')"
    tail="$(echo "$ident" | cut -d_ -f2- | tr '[:upper:]' '[:lower:]')"
    expected="${head}.${tail}"
    if [ "$value" != "$expected" ]; then
        fail "const $ident = \"$value\" does not match expected \"$expected\""
    fi
    if ! grep -q "method::${ident}\b" "$dispatcher_file"; then
        fail "const $ident has no dispatcher arm in $dispatcher_file"
    fi
done < <(grep -E 'pub const [A-Z_]+: &str = "[a-z_.]+";' "$methods_file" \
    | sed -E 's/.*pub const ([A-Z_]+): &str = "([^"]+)";.*/\1\'$'\t''\2/')

n_actions=0
action_re='^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)?$'
while read -r a; do
    n_actions=$((n_actions + 1))
    if ! [[ "$a" =~ $action_re ]]; then
        fail "audit action \"$a\" does not match <ns>.<event>[.<phase>]"
    fi
done < <(grep -rEho 'action: "[^"]+"' crates/hermod-daemon/src --include="*.rs" \
    | sed -E 's/action: "([^"]+)"/\1/' \
    | sort -u)

# Repository impl naming (R1):
# Every `pub struct Sqlite<X>` / `Postgres<X>` declared in `backends/`
# must either be the backend `Database` aggregator or end in
# `Repository`, and the `<Domain>` part must match a `<Domain>Repository`
# trait in `repositories/`. Catches drift before review.
n_repos=0
trait_file_glob="crates/hermod-storage/src/repositories"
declared_traits="$(grep -hE '^pub trait [A-Z][A-Za-z]*Repository[: ]' \
    "$trait_file_glob"/*.rs \
    | sed -E 's/^pub trait ([A-Z][A-Za-z]*)Repository[: ].*/\1/' \
    | sort -u)"

while IFS=$'\t' read -r file ident; do
    n_repos=$((n_repos + 1))
    case "$ident" in
        SqliteDatabase|PostgresDatabase)
            continue
            ;;
    esac
    case "$ident" in
        SqliteRepository|PostgresRepository)
            fail "$file: \`pub struct $ident\` has no domain segment"
            ;;
    esac
    case "$ident" in
        Sqlite*Repository|Postgres*Repository)
            ;;
        *)
            fail "$file: \`pub struct $ident\` must end in \`Repository\` (R1)"
            ;;
    esac
    domain="$(echo "$ident" \
        | sed -E 's/^(Sqlite|Postgres)([A-Z][A-Za-z]*)Repository$/\2/')"
    if ! echo "$declared_traits" | grep -qx "$domain"; then
        fail "$file: \`$ident\` has no matching \`${domain}Repository\` trait in repositories/"
    fi
done < <(grep -REn '^pub struct (Sqlite|Postgres)[A-Z][A-Za-z]*' \
    crates/hermod-storage/src/backends \
    | sed -E 's@^([^:]+):[0-9]+:pub struct ([A-Z][A-Za-z]*).*@\1\'$'\t''\2@')

echo "naming: ok ($n_consts ipc methods, $n_actions audit actions, $n_repos repo impls)"
