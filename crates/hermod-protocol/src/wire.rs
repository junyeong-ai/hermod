//! Hermod Wire Protocol (SWP/1) frames.
//!
//! Each frame is CBOR-encoded, then wrapped in one Noise XX transport message,
//! then carried as one WebSocket binary frame.

use hermod_core::{Envelope, MessageId, PROTOCOL_VERSION, PubkeyBytes};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum WireError {
    #[error("cbor encode: {0}")]
    Encode(String),

    #[error("cbor decode: {0}")]
    Decode(String),
}

/// Maximum legal relay hop count. A typical mesh runs 0-1 hops
/// (originator → recipient, optionally through one broker). 4 leaves
/// headroom for unusual topologies while guaranteeing any cycle
/// terminates in finite time. Receivers (and brokers, defensively)
/// reject frames whose `hops` exceeds this bound.
pub const MAX_RELAY_HOPS: u8 = 4;

/// Top-level frame.
///
/// `Hello` is exchanged immediately after Noise handshake completion as
/// connection metadata (`agent_id` derivation source, alias, version).
///
/// `Ping` / `Pong` carry a sender-chosen `nonce` so the initiator can
/// match a response to a specific probe. Application-level liveness check
/// — preferred over TCP keepalive because it traverses every layer of
/// the stack (Noise transport, WS framing, recipient task) and so detects
/// half-open conditions that a kernel-level keepalive cannot see.
///
/// `Envelope` carries an unsigned per-hop `hops` counter alongside the
/// signed application payload. Brokers increment it before forwarding;
/// receivers refuse anything past [`MAX_RELAY_HOPS`]. Keeping the
/// counter outside the signed envelope means relays don't have to
/// re-sign on every hop and a malicious broker can only accelerate the
/// cycle (by inflating the count) — never bypass it.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WireFrame {
    Hello(Hello),
    Envelope(EnvelopeFrame),
    DeliveryAck(DeliveryAck),
    Ping(Ping),
    Pong(Pong),
    Close(Close),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnvelopeFrame {
    /// Brokers this frame has traversed since leaving the originator.
    /// Originator emits 0; each broker increments before forwarding.
    /// `Default` so older test bytes still parse; in practice every
    /// emission site stamps it explicitly.
    #[serde(default)]
    pub hops: u8,
    pub envelope: Box<Envelope>,
}

impl EnvelopeFrame {
    /// Originator-side construction: hops counter starts at 0.
    pub fn origin(envelope: Envelope) -> Self {
        Self {
            hops: 0,
            envelope: Box::new(envelope),
        }
    }

    /// Broker-side construction: bumps the hops counter on the frame
    /// observed inbound. Returns `None` if the bumped count would
    /// exceed [`MAX_RELAY_HOPS`] — the caller must drop the frame
    /// rather than forward it.
    pub fn forwarded(envelope: &Envelope, inbound_hops: u8) -> Option<Self> {
        let next = inbound_hops.checked_add(1)?;
        if next > MAX_RELAY_HOPS {
            return None;
        }
        Some(Self {
            hops: next,
            envelope: Box::new(envelope.clone()),
        })
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct Ping {
    pub nonce: u64,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct Pong {
    pub nonce: u64,
}

/// First application-layer frame sent inside the Noise XX channel by
/// each side of a federation handshake. The Noise handshake itself
/// authenticates the remote's *transport* static key; Hello binds
/// that transport key to the daemon's host identity at the
/// application layer.
///
/// The receiver verifies `derive_noise_static(host_pubkey) ==
/// transport.remote_static_pubkey()` to detect mis-derivation or
/// substitution attempts. The host_pubkey then becomes the row key
/// for TOFU registration in the agents directory.
///
/// Hello carries host-level identity only; per-tenant agents are
/// learned dynamically as their envelopes arrive (see
/// `InboundProcessor`'s envelope-receipt TOFU).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Hello {
    pub protocol_version: u16,
    pub host_pubkey: PubkeyBytes,
}

impl Hello {
    pub fn new(host_pubkey: PubkeyBytes) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            host_pubkey,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeliveryAck {
    pub message_id: MessageId,
    pub status: AckStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AckStatus {
    /// Stored in recipient inbox.
    Delivered,
    /// Recipient refused (visibility, capability, rate limit, signature mismatch, etc).
    Rejected,
    /// Recipient is offline / queue full.
    Deferred,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Close {
    pub code: u16,
    pub reason: String,
}

pub fn encode(frame: &WireFrame) -> Result<Vec<u8>, WireError> {
    let mut buf = Vec::with_capacity(256);
    ciborium::into_writer(frame, &mut buf).map_err(|e| WireError::Encode(e.to_string()))?;
    Ok(buf)
}

pub fn decode(bytes: &[u8]) -> Result<WireFrame, WireError> {
    ciborium::from_reader(bytes).map_err(|e| WireError::Decode(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hermod_core::{AgentAddress, AgentId, MessageBody, MessagePriority, PubkeyBytes};
    use std::str::FromStr;

    #[test]
    fn hello_roundtrip() {
        let h = WireFrame::Hello(Hello {
            protocol_version: 1,
            host_pubkey: PubkeyBytes([7u8; 32]),
        });
        let bytes = encode(&h).unwrap();
        let back = decode(&bytes).unwrap();
        match back {
            WireFrame::Hello(h2) => {
                assert_eq!(h2.protocol_version, 1);
                assert_eq!(h2.host_pubkey.0[0], 7);
            }
            other => panic!("expected Hello, got {other:?}"),
        }
    }

    #[test]
    fn envelope_roundtrip_via_wire() {
        let id = AgentId::from_str("abcdefghijklmnopqrstuvwxyz").unwrap();
        let env = hermod_core::Envelope::draft(
            AgentAddress::local(id.clone()),
            AgentAddress::local(id),
            MessageBody::Direct {
                text: "hi over the wire".into(),
            },
            MessagePriority::Normal,
            60,
        );
        let frame = WireFrame::Envelope(EnvelopeFrame::origin(env.clone()));
        let bytes = encode(&frame).unwrap();
        let back = decode(&bytes).unwrap();
        match back {
            WireFrame::Envelope(f) => {
                assert_eq!(f.hops, 0);
                assert_eq!(*f.envelope, env);
            }
            other => panic!("expected Envelope, got {other:?}"),
        }
    }

    #[test]
    fn envelope_with_capability_roundtrip() {
        use hermod_core::CapabilityToken;
        let id = AgentId::from_str("abcdefghijklmnopqrstuvwxyz").unwrap();
        let mut env = hermod_core::Envelope::draft(
            AgentAddress::local(id.clone()),
            AgentAddress::local(id),
            MessageBody::Direct {
                text: "hi with cap".into(),
            },
            MessagePriority::Normal,
            60,
        );
        env = env.with_capability(CapabilityToken::from_bytes(vec![9u8; 64]));
        let frame = WireFrame::Envelope(EnvelopeFrame::origin(env.clone()));
        let bytes = encode(&frame).unwrap();
        let back = decode(&bytes).unwrap();
        match back {
            WireFrame::Envelope(f) => {
                let e = &f.envelope;
                assert_eq!(e.caps.len(), 1);
                assert_eq!(e.caps[0].as_bytes().len(), 64);
                assert_eq!(**e, env);
            }
            other => panic!("expected Envelope, got {other:?}"),
        }
    }

    #[test]
    fn envelope_channel_broadcast_roundtrip() {
        use serde_bytes::ByteBuf;
        let id = AgentId::from_str("abcdefghijklmnopqrstuvwxyz").unwrap();
        let body = MessageBody::ChannelBroadcast {
            workspace_id: ByteBuf::from(vec![0xAA; 16]),
            channel_id: ByteBuf::from(vec![0xBB; 16]),
            text: "rolling out v2".into(),
            hmac: Some(ByteBuf::from(vec![0xCC; 32])),
        };
        let env = hermod_core::Envelope::draft(
            AgentAddress::local(id.clone()),
            AgentAddress::local(id),
            body.clone(),
            MessagePriority::Normal,
            60,
        );
        let frame = WireFrame::Envelope(EnvelopeFrame::origin(env.clone()));
        let bytes = encode(&frame).unwrap();
        let back = decode(&bytes).unwrap();
        match back {
            WireFrame::Envelope(f) => {
                let e = &f.envelope;
                assert_eq!(**e, env);
                assert_eq!(e.kind, hermod_core::MessageKind::ChannelBroadcast);
                match &e.body {
                    MessageBody::ChannelBroadcast {
                        workspace_id,
                        channel_id,
                        text,
                        hmac,
                    } => {
                        assert_eq!(workspace_id.len(), 16);
                        assert_eq!(channel_id.len(), 16);
                        assert_eq!(text, "rolling out v2");
                        assert_eq!(hmac.as_ref().unwrap().len(), 32);
                    }
                    other => panic!("wrong body: {other:?}"),
                }
            }
            other => panic!("expected Envelope, got {other:?}"),
        }
    }

    #[test]
    fn ack_status_serializes_lower() {
        let f = WireFrame::DeliveryAck(DeliveryAck {
            message_id: hermod_core::MessageId::new(),
            status: AckStatus::Delivered,
            reason: None,
        });
        let bytes = encode(&f).unwrap();
        let back = decode(&bytes).unwrap();
        if let WireFrame::DeliveryAck(a) = back {
            assert_eq!(a.status, AckStatus::Delivered);
        } else {
            panic!()
        }
    }

    #[test]
    fn ping_pong_roundtrip_with_nonce() {
        for &nonce in &[0u64, 1, 42, u64::MAX / 2, u64::MAX] {
            let ping = WireFrame::Ping(Ping { nonce });
            let bytes = encode(&ping).unwrap();
            match decode(&bytes).unwrap() {
                WireFrame::Ping(p) => assert_eq!(p.nonce, nonce, "ping nonce roundtrip"),
                other => panic!("expected Ping, got {other:?}"),
            }
            let pong = WireFrame::Pong(Pong { nonce });
            let bytes = encode(&pong).unwrap();
            match decode(&bytes).unwrap() {
                WireFrame::Pong(p) => assert_eq!(p.nonce, nonce, "pong nonce roundtrip"),
                other => panic!("expected Pong, got {other:?}"),
            }
        }
    }

    #[test]
    fn ping_and_pong_are_distinct_on_the_wire() {
        // Identical nonces but different variants must encode to
        // different bytes — otherwise a peer's correlator could match a
        // Pong against the wrong direction.
        let ping = encode(&WireFrame::Ping(Ping { nonce: 7 })).unwrap();
        let pong = encode(&WireFrame::Pong(Pong { nonce: 7 })).unwrap();
        assert_ne!(ping, pong, "Ping and Pong with same nonce must differ");
    }

    fn fresh_envelope() -> Envelope {
        let id = AgentId::from_str("abcdefghijklmnopqrstuvwxyz").unwrap();
        hermod_core::Envelope::draft(
            AgentAddress::local(id.clone()),
            AgentAddress::local(id),
            MessageBody::Direct {
                text: "relayed".into(),
            },
            MessagePriority::Normal,
            60,
        )
    }

    #[test]
    fn envelope_frame_origin_starts_at_zero() {
        let f = EnvelopeFrame::origin(fresh_envelope());
        assert_eq!(f.hops, 0);
    }

    #[test]
    fn envelope_frame_forwarded_increments() {
        let env = fresh_envelope();
        let f = EnvelopeFrame::forwarded(&env, 0).expect("hops=0 always forwardable");
        assert_eq!(f.hops, 1);
        let f2 = EnvelopeFrame::forwarded(&env, 3).expect("hops=3 yields 4 == MAX");
        assert_eq!(f2.hops, MAX_RELAY_HOPS);
    }

    #[test]
    fn envelope_frame_forwarded_refuses_overflow() {
        let env = fresh_envelope();
        // Walking past MAX must produce None — broker drops the frame.
        assert!(EnvelopeFrame::forwarded(&env, MAX_RELAY_HOPS).is_none());
        assert!(EnvelopeFrame::forwarded(&env, u8::MAX).is_none());
    }

    #[test]
    fn envelope_frame_hops_roundtrips() {
        for hops in [0u8, 1, MAX_RELAY_HOPS] {
            let frame = WireFrame::Envelope(EnvelopeFrame {
                hops,
                envelope: Box::new(fresh_envelope()),
            });
            let bytes = encode(&frame).unwrap();
            match decode(&bytes).unwrap() {
                WireFrame::Envelope(f) => assert_eq!(f.hops, hops),
                other => panic!("expected Envelope, got {other:?}"),
            }
        }
    }
}
