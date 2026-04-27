//! Capability-claim parser under hostile bytes.
//!
//! Skips the signature-verify gate by routing through
//! `parse_claim_unverified` — that gate would short-circuit on every
//! fuzzer-generated input, never exercising the framing /
//! deserialization invariants. The unverified parser walks the same
//! length-prefixed wire shape the verifying path eventually drives,
//! so any panic in the framing or CBOR decode path surfaces here.

#![no_main]

use hermod_crypto::parse_claim_unverified;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = parse_claim_unverified(data);
});
