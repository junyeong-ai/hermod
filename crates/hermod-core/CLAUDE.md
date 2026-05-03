# hermod-core — AI agent guide

The vocabulary every other crate speaks. Pure types + canonical
constants. **No I/O, no logging, no async runtime.** If a change
needs `tokio` / `tracing` / a network call, the change belongs in a
higher crate.

## What lives here

- **Identity types**: `AgentId` (26-char base32), `AgentAddress`,
  `AgentAlias`, `PubkeyBytes`, `SignatureBytes`, `FingerprintBytes`.
  These are the canonical wire-and-storage shapes; never re-define
  them in a downstream crate.
- **Envelope schema** (`envelope.rs`): `Envelope`, `MessageBody`,
  `MessageKind`, `MessagePriority`, `MessageStatus`. The signed
  payload — every byte that goes through `canonical_envelope_bytes`
  in hermod-crypto.
- **Capability tags** (`capability_tag.rs`): `CapabilityTagSet`
  (discovery-only, never trust-bearing).
- **Time** (`time.rs`): `Timestamp` (unix-ms i64), the only timestamp
  shape on the wire.
- **Compile-time bounds**: `MAX_FILE_PAYLOAD_BYTES`,
  `MAX_CAPS_PER_ENVELOPE`. Both are pinned by wire-level tests in
  `hermod-protocol`; raising either requires re-running
  `cargo test -p hermod-protocol`.

## Adding a new envelope field

1. Decide: **signed** (include in
   `hermod_crypto::canonical_envelope_bytes`) or **transport-only**
   (lives on `WireFrame`/`EnvelopeFrame` in `hermod-protocol`)?
2. Signed fields cannot change without breaking every existing
   signature on disk. Transport-only fields can evolve freely.
3. Update `Envelope::draft` constructors so call sites stay compact.
4. The compiler's exhaustiveness checker walks every downstream
   match — no manual fan-out doc here.

## What does NOT live here

- Any `async fn` (use a service or repository in a higher crate).
- DB queries (hermod-storage).
- Wire codec (hermod-protocol).
- Crypto operations (hermod-crypto).

If you find yourself reaching for a network call, transactional
state, or `tokio::spawn` from this crate, you're in the wrong place.
