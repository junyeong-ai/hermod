# hermod-protocol — AI agent guide

Wire codec — both the federation `WireFrame` (peer-to-peer over
Noise XX) and the IPC `Request`/`Response` (JSON-RPC over Unix
socket / WSS+Bearer). Hand-rolled CBOR + JSON-RPC, pinned by
roundtrip tests.

## Two surfaces, two shapes

- **`wire.rs`** — federation frames. CBOR-encoded, wrapped in one
  Noise transport message. Frames: `Hello`, `Envelope`,
  `DeliveryAck`, `Ping`, `Pong`, `Close`.
- **`ipc/`** — JSON-RPC IPC. `Request` / `Response` shapes; the
  method catalogue lives in `ipc/methods.rs` (one `pub const` per
  method, paired `*Params`/`*Result` types).

## Signed vs transport-only

- **Inside `Envelope` (signed):** every field reaches
  `canonical_envelope_bytes`. Adding a field here invalidates every
  on-disk signature.
- **Inside `EnvelopeFrame` (transport):** `hops` counter and any
  future per-hop scratch live OUTSIDE the signed payload. Brokers
  rewrite these without re-signing.

`MAX_RELAY_HOPS = 4` is the cycle terminator. Brokers increment and
reject on overflow; receivers defensively check.

## Single Noise frame per WireFrame

Each `WireFrame::Envelope` ships as ONE Noise message. The Noise
transport caps every message at `MAX_NOISE_MESSAGE_LEN = 65,519`
bytes (in `handshake.rs`). The wire test
`max_file_envelope_fits_in_noise_frame` pins that a worst-case File
envelope (using `hermod_core::MAX_FILE_PAYLOAD_BYTES`) plus AEAD tag
fits inside the Noise cap. Bumping either constant past the
headroom cliff trips the test, forcing a chunked-transport design
or a cap rollback.

## Adding a new IPC method

`<namespace>.<verb>` snake_case. Const ident `<NAMESPACE>_<VERB>`.
`scripts/check_naming.sh` enforces both the const-name shape and
the dispatcher arm coverage. Pair every method with `*Params` /
`*Result` types in this same file.

## Connection-scoped methods

Most methods are stateless RPC and live in the dispatcher. The one
exception is `auth.bind_caller`, which modifies per-connection
caller state and is handled directly inside
`hermod-daemon::server::handle_connection`. The dispatcher arm
returns `INVALID_REQUEST` so a remote-IPC client that mistakenly
calls it gets a clear failure (remote IPC has its own bearer
handshake).
