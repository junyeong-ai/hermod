//! Top-level wire-frame CBOR decode under hostile bytes.
//!
//! Federation listeners decode every inbound `WireFrame` *before*
//! signature verification — the parser is the first code path a
//! malicious peer touches. Any panic, OOB read, or runaway
//! allocation here is a remotely-triggerable DoS or worse, so the
//! contract is: arbitrary bytes → `Result`, never panic.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Result-returning by contract; we ignore the value, the harness
    // only fails on panic / abort / sanitizer trip.
    let _ = hermod_protocol::wire::decode(data);
});
