//! Application-envelope CBOR decode under hostile bytes.
//!
//! `deserialize_envelope` runs once per inbound frame after wire
//! framing strips the outer `WireFrame::Envelope` discriminator —
//! the CBOR parser sees attacker-controlled bytes. Same contract
//! as the top-level wire fuzz target: arbitrary bytes must produce
//! a `Result`, never a panic.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = hermod_protocol::envelope::deserialize_envelope(data);
});
