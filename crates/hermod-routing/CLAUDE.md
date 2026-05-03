# hermod-routing — AI agent guide

The decision layer between "envelope arrived/queued" and "envelope
sent/applied". Every gate that can refuse or hold an envelope lives
here. Concrete federation transport implementation also lives here
behind the `Transport` trait so the daemon depends only on the
trait, not the WSS+Noise concrete.

## Module map

```
transport.rs        Transport / TransportListener / TransportConnection traits — federation backend abstraction
wss_noise.rs        production Transport impl: WSS + Noise XX
peer.rs             PeerConnection — post-handshake send_frame / recv_frame
pool.rs             outbound dial pool (idle sweeper, claim/release)
remote.rs           RemoteDeliverer — service-facing send entry point (handles Loopback / LocalKnown / Remote / Brokered)
router.rs           Router — resolves AgentAddress → RouteOutcome (via_chain walk, MAX_VIA_DEPTH guard)
access.rs           AccessController + AccessVerdict — capability check + scope routing
rate_limit.rs       per-(from,to) token bucket
confirmation.rs     Verdict { Accept, Reject, Confirm } matrix — peer trust × action sensitivity
auto_approve.rs     AutoApproveOverlay — downgrade-only Confirm→Accept rules; Permission auto-allow with FORBIDDEN_TOOL_NAMES floor
dispatch.rs         DispatchPolicy trait + Rule / RoutingConfig — push vs silent disposition (receiver-side; the operator-promote path is in inbox.promote)
```

## Trust matrix invariants

- `confirmation::Verdict { Accept, Reject, Confirm }` is the ONLY
  thing the inbound pipeline accepts at the gate. No other verdict
  shape.
- `AutoApproveOverlay` is **downgrade-only**: it can flip
  `Confirm → Accept`, never `Reject → anything`. Pinned by
  `scripts/check_trust_boundaries.sh`.
- `peer_asserted_tags` (capability tags) are NEVER trust-bearing —
  hermod-routing imports zero `CapabilityTag` symbols. Mechanical
  grep enforced by the same script. Tags are display-and-filter
  only; trust comes from `agents.trust_level`, set by the operator.

## via_chain (brokered routing)

- `agents.via_agent` points at a brokering agent. The router walks
  via_agent→via_agent until it finds a host with a dialable endpoint
  or hits `MAX_VIA_DEPTH` (= `wire::MAX_RELAY_HOPS`).
- Cycle detection: every agent in the walk is added to a `visited`
  set; re-encountering one returns `RoutingError::ViaCycle`.
- Routing intent transitions are atomic via
  `AgentRepository::set_routing_direct / set_routing_brokered /
  clear_routing` — never set `host_id` and `via_agent` in two
  separate writes.

## Adding a federation transport backend

Implement `Transport` + `TransportListener` + `TransportConnection`
in a new module. The daemon constructs `Arc<dyn Transport>` once at
startup; downstream code never names a concrete backend. Hot-rotate
TLS material via `Transport::reload_tls`; backends without TLS
return `Backend("not supported")`.
