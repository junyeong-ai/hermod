use hermod_core::{
    AgentAddress, CapabilityToken, Envelope, MessageBody, MessageId, MessageKind, MessagePriority,
    Timestamp,
};
use serde::Serialize;

use crate::error::CryptoError;

/// Borrowed view of `Envelope` excluding `sig`. Canonical signing is performed over
/// this view, guaranteeing that the signature field itself is not part of the input.
///
/// Field order mirrors `Envelope` — canonical bytes are defined by this struct's
/// serialization, so **any future field additions must preserve existing order and
/// bump `PROTOCOL_VERSION`**.
#[derive(Debug, Serialize)]
struct EnvelopeForSigning<'a> {
    v: u16,
    id: &'a MessageId,
    ts: &'a Timestamp,
    from: &'a AgentAddress,
    to: &'a AgentAddress,
    kind: MessageKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    thread: &'a Option<MessageId>,
    priority: MessagePriority,
    ttl_secs: u32,
    body: &'a MessageBody,
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    caps: &'a [CapabilityToken],
}

/// Produce canonical bytes for signing/verification.
///
/// Uses CBOR (binary) serialization. CBOR deterministic encoding rules are not fully
/// enforced here, but our envelope schema has no maps with non-deterministic key
/// ordering; all field ordering is fixed by struct definition.
pub fn canonical_envelope_bytes(env: &Envelope) -> Result<Vec<u8>, CryptoError> {
    let view = EnvelopeForSigning {
        v: env.v,
        id: &env.id,
        ts: &env.ts,
        from: &env.from,
        to: &env.to,
        kind: env.kind,
        thread: &env.thread,
        priority: env.priority,
        ttl_secs: env.ttl_secs,
        body: &env.body,
        caps: &env.caps,
    };
    let mut buf = Vec::with_capacity(256);
    ciborium::into_writer(&view, &mut buf)
        .map_err(|e| CryptoError::Serialization(e.to_string()))?;
    Ok(buf)
}

/// Canonical signing input for an mDNS beacon. The struct order is
/// load-bearing — both ends of the LAN wire reconstruct it identically
/// from the broadcast TXT records, then verify the carried `sig`.
///
/// Field additions must preserve existing order and bump the wire-level
/// version (currently encoded into the `_hermod._tcp.local.` service
/// type so a hard schema change becomes a different mDNS service entry
/// instead of a silently-incompatible peer).
#[derive(Debug, Serialize)]
struct MdnsBeaconForSigning<'a> {
    agent_id: &'a str,
    pubkey: &'a [u8; 32],
    port: u16,
    ts_unix_ms: i64,
    validity_secs: u32,
}

/// Produce canonical bytes a beacon emitter signs and a beacon
/// receiver verifies.
pub fn canonical_mdns_beacon_bytes(
    agent_id: &str,
    pubkey: &[u8; 32],
    port: u16,
    ts_unix_ms: i64,
    validity_secs: u32,
) -> Result<Vec<u8>, CryptoError> {
    let view = MdnsBeaconForSigning {
        agent_id,
        pubkey,
        port,
        ts_unix_ms,
        validity_secs,
    };
    let mut buf = Vec::with_capacity(96);
    ciborium::into_writer(&view, &mut buf)
        .map_err(|e| CryptoError::Serialization(e.to_string()))?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keypair::Keypair;
    use hermod_core::{AgentAddress, Envelope, MessageBody, MessagePriority};

    #[test]
    fn canonical_bytes_are_stable() {
        let kp = Keypair::generate();
        let me = AgentAddress::local(kp.agent_id());
        let env = Envelope::draft(
            me.clone(),
            me,
            MessageBody::Direct {
                text: "hello".into(),
            },
            MessagePriority::Normal,
            60,
        );
        let a = canonical_envelope_bytes(&env).unwrap();
        let b = canonical_envelope_bytes(&env).unwrap();
        assert_eq!(a, b);
        assert!(!a.is_empty());
    }

    #[test]
    fn mdns_beacon_canonical_is_stable() {
        let agent_id = "abcdefghijklmnopqrstuvwxyz";
        let pubkey = [42u8; 32];
        let a = canonical_mdns_beacon_bytes(agent_id, &pubkey, 7823, 1_700_000_000_000, 3600)
            .unwrap();
        let b = canonical_mdns_beacon_bytes(agent_id, &pubkey, 7823, 1_700_000_000_000, 3600)
            .unwrap();
        assert_eq!(a, b);

        // Field-order sensitivity: changing port must change bytes.
        let c =
            canonical_mdns_beacon_bytes(agent_id, &pubkey, 9999, 1_700_000_000_000, 3600).unwrap();
        assert_ne!(a, c);
    }
}
