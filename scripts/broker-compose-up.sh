#!/usr/bin/env bash
# Bootstrap a 3-container broker-mode federation:
#
#     bob ──► broker (relay + witness) ──► carol
#
# After this script returns, `bob → carol` DMs route via the broker
# without bob/carol ever doing a `peer add` of each other's endpoint.
# Demonstrates Phase 16.5 client-side `[federation] upstream_broker`
# in real Docker network isolation.
set -euo pipefail
cd "$(dirname "$0")/.."

COMPOSE="docker compose -f docker-compose.broker.yml"

# Compose validates the whole file even on `build` / `run`, so the
# `${BROKER_DESCRIPTOR:?}` reference rejects the call until we've
# generated the broker keypair. Use a syntactically-valid placeholder
# during the bootstrap phase.
export BROKER_DESCRIPTOR="wss://placeholder:7823#$(printf '0%.0s' $(seq 1 64))"

echo "==> build"
$COMPOSE build >/dev/null

echo "==> init three identities"
# Run init via override-entrypoint so the daemon's startup-time identity
# load doesn't fail before the keys exist.
for who in broker bob carol; do
    $COMPOSE run --rm \
        --entrypoint /usr/local/bin/hermod "$who" init --alias "$who" >/dev/null
done

echo "==> capture broker pubkey"
BROKER_PK=$($COMPOSE run --rm \
    --entrypoint /usr/local/bin/hermod broker identity 2>/dev/null \
    | awk '/^pubkey_hex:/ {print $2}')
BROKER_ID=$($COMPOSE run --rm \
    --entrypoint /usr/local/bin/hermod broker identity 2>/dev/null \
    | awk '/^agent_id:/ {print $2}')
[[ -n "$BROKER_PK" ]] || { echo "broker pubkey empty"; exit 1; }
export BROKER_DESCRIPTOR="wss://broker:7823#${BROKER_PK}"

echo "    broker_id  = $BROKER_ID"
echo "    descriptor = $BROKER_DESCRIPTOR"

echo "==> bring up the stack"
$COMPOSE up -d >/dev/null
# Wait for broker healthcheck to pass before declaring success.
for _ in {1..30}; do
    health=$($COMPOSE ps --format json 2>/dev/null | jq -r 'select(.Service=="broker") | .Health' 2>/dev/null || true)
    [[ "$health" == "healthy" ]] && break
    sleep 1
done

echo "==> register peer pubkeys (no endpoints — broker handles routing)"
BOB_PK=$($COMPOSE exec -T bob hermod identity 2>/dev/null | awk '/^pubkey_hex:/ {print $2}')
BOB_ID=$($COMPOSE exec -T bob hermod identity 2>/dev/null | awk '/^agent_id:/ {print $2}')
CAROL_PK=$($COMPOSE exec -T carol hermod identity 2>/dev/null | awk '/^pubkey_hex:/ {print $2}')
CAROL_ID=$($COMPOSE exec -T carol hermod identity 2>/dev/null | awk '/^agent_id:/ {print $2}')

# bob knows carol's pubkey (no endpoint → Router falls back to broker).
$COMPOSE exec -T bob hermod agent register --pubkey-hex "$CAROL_PK" --trust verified >/dev/null
# carol knows bob's pubkey for inbound signature verification.
$COMPOSE exec -T carol hermod agent register --pubkey-hex "$BOB_PK" --trust verified >/dev/null
# Both trust the broker (registered automatically via upstream_broker
# config but stays Tofu by default).
$COMPOSE exec -T bob   hermod peer trust "$BROKER_ID" verified >/dev/null
$COMPOSE exec -T carol hermod peer trust "$BROKER_ID" verified >/dev/null

# The broker registers bob and carol as static peers so the relay path
# can route to either when forwarding. In a production deployment the
# operator would seed these via [federation] peers.
$COMPOSE exec -T broker hermod peer add --endpoint "wss://bob:7823"   --pubkey-hex "$BOB_PK"   >/dev/null
$COMPOSE exec -T broker hermod peer add --endpoint "wss://carol:7823" --pubkey-hex "$CAROL_PK" >/dev/null

echo
echo "Stack ready:"
echo "    BOB_ID=$BOB_ID"
echo "    CAROL_ID=$CAROL_ID"
echo "    BROKER_ID=$BROKER_ID"
echo
echo "Try:"
echo "    docker compose -f docker-compose.broker.yml exec bob \\"
echo "        hermod message send --to $CAROL_ID --body 'hello via docker broker'"
echo "    docker compose -f docker-compose.broker.yml exec carol hermod message list"
