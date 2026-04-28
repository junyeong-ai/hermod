# hermod-crypto — AI agent guide

Cryptographic primitives. Two boundaries to keep separate:

- **Application-level signing** (`Signer` trait + `LocalKeySigner`) —
  envelopes, capability claims, audit rows, mDNS beacons.
- **Transport-level material** (`Keypair`, `NoiseStaticKey`,
  `TlsMaterial`) — Noise XX handshake, WSS cert generation.

Application code MUST hold `Arc<dyn Signer>`, never `Arc<Keypair>`.
The transport layer is the only place that calls `LocalKeySigner::keypair()`
(for Noise static-key derivation + TLS cert generation).

## Identity and self-certification

`agent_id_from_pubkey(pubkey: &PubkeyBytes) -> AgentId` is the
canonical ID derivation. The invariant
`agent_id == base32_unpadded(blake3(pubkey))[:26]` is what makes peers
self-certifying: receivers verify pubkey ↔ id binding from the
envelope alone, no directory lookup required.

Never add an `agent_id` field that isn't derived this way.

## Capability claim format

Wire layout: `[claim_len: u32 BE][claim_cbor][sig: 64 bytes ed25519]`.
`verify_capability(issuer_pk, token_bytes)` verifies + parses;
`parse_claim_unverified(token_bytes)` parses without sig (used by the
fuzz harness — *never* call from production).

Adding a new capability scope ⇒ const in
`hermod-routing::access::scope` + entry in the capability docs +
inbound use site in the access controller.

## TlsMaterial

Self-signed cert tied to `agent_id` via CN. SHA-256 fingerprint over
DER for TOFU pinning. `not_after_unix_secs()` exposes expiry to
`hermod doctor` — keep this method working when changing rcgen
versions.

`TlsMaterial { cert_pem, key_pem, cert_der, fingerprint }` — DER and
fingerprint are derived once and cached on the struct so callers don't
re-parse.

## Zeroize discipline

Secret types implement `ZeroizeOnDrop`:

- `Keypair` (via ed25519-dalek's `zeroize` feature, enabled at the
  workspace level)
- `WorkspaceSecret`, `WorkspaceMacKey`, `ChannelMacKey`
  (`#[derive(Zeroize, ZeroizeOnDrop)]`)
- `SecretString` — heap-allocated text-shaped secret (IPC bearer,
  audit-webhook bearer, command-minted OIDC tokens). `Display` is
  intentionally not implemented and `PartialEq` is not derived;
  comparison goes through `expose_secret()` + `constant_time_eq`.

Adding a new secret-bearing type ⇒ derive both. No exceptions.

## Constant-time MAC verify

`workspace::constant_time_eq(a: &[u8; 32], b: &[u8; 32])` is the
project's canonical CT comparator. Every `*MacKey::verify(...)` runs
through it. Don't introduce `==` byte comparisons on MAC outputs.

## Canonical envelope bytes

`canonical_envelope_bytes(envelope)` is the single source for "what
gets signed" — order, encoding, and field inclusion are pinned. Adding
a new `Envelope` field requires deciding whether it's signed (include
in canonical) or transport-level (exclude — like `WireFrame.hops`).
