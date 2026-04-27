# Hermod fuzz harness

Coverage-guided fuzzing (libFuzzer via `cargo-fuzz`) for the parser
surfaces a malicious peer reaches first:

| Target | Surface | Why |
| --- | --- | --- |
| `wire_decode` | `hermod_protocol::wire::decode` | Top-level `WireFrame` CBOR — the federation listener decodes this *before* signature verify, so a parser panic here is a remotely-triggered abort. |
| `envelope_cbor` | `hermod_protocol::envelope::deserialize_envelope` | Application-level `Envelope` CBOR — same threat model, one layer in. |
| `capability_claim_cbor` | `hermod_crypto::parse_claim_unverified` | Capability-token framing + claim CBOR. Routed through the unverified parser so the fuzzer doesn't short-circuit on every iteration; the verifying path runs the same parser. |

## Run a campaign

```sh
# One-time, on the operator host:
cargo install cargo-fuzz

# Campaign — keep one terminal per target:
cargo fuzz run wire_decode            -- -max_total_time=600
cargo fuzz run envelope_cbor          -- -max_total_time=600
cargo fuzz run capability_claim_cbor  -- -max_total_time=600
```

Crashes land under `fuzz/artifacts/<target>/`. Reduce a crash with
`cargo fuzz tmin <target> <crash-file>`, then file an issue with the
minimised reproducer.

## CI

CI builds every target via `cargo fuzz build` (no campaigns — those
are operator-driven). A regression that breaks one of the parser
surfaces' compile-time invariants fails the PR.
