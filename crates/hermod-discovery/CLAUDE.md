# hermod-discovery — AI agent guide

LAN auto-discovery via mDNS. Optional — federation works without
this crate (operators wire peers via `peer add`). Adds a beacon
emitter + observer so peers on the same broadcast domain find each
other without manual config.

## Beacon contract

Beacons are signed by the host keypair. The receiver:
1. Verifies the signature against the claimed `host_pubkey`.
2. Checks freshness against `mdns_beacon_validity_secs`.
3. Verifies that `host_id == base32(blake3(host_pubkey))[:26]`
   (self-certification — the same invariant that gates envelopes).
4. Records via `BeaconAuditor::observed(agent_id, endpoint)` if all
   three pass; rejected beacons go through
   `BeaconAuditor::rejected(agent_id, reason)`.

The daemon's adapter (`services::beacon_audit`) maps these callbacks
to `mdns.beacon_observed` / `mdns.beacon_rejected` audit rows
(`mdns.beacon_emitted` covers the local emit side). Observed
beacons surface as candidate peers; the daemon can auto-register
them on operator opt-in.

## What discovery does NOT do

- It does NOT change trust. A discovered peer lands as
  `TrustLevel::Tofu`, same as `peer add`-then-first-envelope.
- It does NOT bypass the federation handshake. Discovery surfaces
  candidates; the actual Noise XX handshake still runs.
- It does NOT trust the multicast network — beacons are signed
  application-layer, multicast is just transport.

## Optional vs required

`discover_mdns = false` (default) keeps the crate silent — no
emitter, no observer, no socket bind. Enable per-deployment;
production federation usually disables (relies on explicit
`peer add` + `[federation] peers`).
