//! Active peer connection: WebSocket + Noise XX transport + Hello exchange.
//!
//! After construction, `PeerConnection` exposes a half-duplex frame API.
//! Outbound paths enforce strict request/ack alternation per send; inbound
//! listeners drive `recv_frame` directly.

use hermod_core::{AgentId, PROTOCOL_VERSION, PubkeyBytes};
use hermod_crypto::agent_id_from_pubkey;
use hermod_protocol::handshake::{NoiseInitiator, NoiseResponder, NoiseTransport};
use hermod_protocol::wire::{AckStatus, DeliveryAck, Hello, WireFrame, decode, encode};
use hermod_transport::WsStream;

use crate::error::{Result, RoutingError};

/// Established federation connection. The remote is identified at the
/// host level: a federation peer is a *daemon*, and the agents it
/// hosts are learned from envelope traffic, not from the handshake.
#[derive(Debug)]
pub struct PeerConnection {
    transport: NoiseTransport,
    ws: WsStream,
    pub remote_host_pubkey: PubkeyBytes,
    pub remote_host_id: AgentId,
}

impl PeerConnection {
    /// Outbound: connect over an already-open `WsStream`, run Noise XX
    /// as initiator, then exchange Hello frames carrying the host
    /// identity.
    pub async fn handshake_outbound(
        ws: WsStream,
        my_noise_secret: &[u8; 32],
        my_host_pubkey: PubkeyBytes,
    ) -> Result<Self> {
        let mut noise = NoiseInitiator::new(my_noise_secret)?;
        let mut ws = ws;

        // Message 1: -> e
        let m1 = noise.write_message(b"")?;
        ws.send_binary(m1).await?;
        // Message 2: <- e, ee, s, es
        let m2 = ws
            .recv_binary()
            .await?
            .ok_or_else(|| RoutingError::Federation("peer closed during handshake".into()))?;
        noise.read_message(&m2)?;
        // Message 3: -> s, se
        let m3 = noise.write_message(b"")?;
        ws.send_binary(m3).await?;

        let mut transport = noise.into_transport()?;

        // Send Hello (initiator first).
        send_wire(
            &mut transport,
            &mut ws,
            &WireFrame::Hello(Hello::new(my_host_pubkey)),
        )
        .await?;

        // Recv remote Hello.
        let remote_hello = match recv_wire(&mut transport, &mut ws).await? {
            Some(WireFrame::Hello(h)) => h,
            Some(other) => {
                return Err(RoutingError::Federation(format!(
                    "expected Hello, got {other:?}"
                )));
            }
            None => return Err(RoutingError::Federation("peer closed before Hello".into())),
        };

        finalise(transport, ws, remote_hello)
    }

    /// Inbound: server side that already accepted a WS, run Noise XX as responder.
    pub async fn handshake_inbound(
        ws: WsStream,
        my_noise_secret: &[u8; 32],
        my_host_pubkey: PubkeyBytes,
    ) -> Result<Self> {
        let mut noise = NoiseResponder::new(my_noise_secret)?;
        let mut ws = ws;

        let m1 = ws
            .recv_binary()
            .await?
            .ok_or_else(|| RoutingError::Federation("peer closed before m1".into()))?;
        noise.read_message(&m1)?;
        let m2 = noise.write_message(b"")?;
        ws.send_binary(m2).await?;
        let m3 = ws
            .recv_binary()
            .await?
            .ok_or_else(|| RoutingError::Federation("peer closed before m3".into()))?;
        noise.read_message(&m3)?;

        let mut transport = noise.into_transport()?;

        // Recv initiator's Hello first.
        let remote_hello = match recv_wire(&mut transport, &mut ws).await? {
            Some(WireFrame::Hello(h)) => h,
            Some(other) => {
                return Err(RoutingError::Federation(format!(
                    "expected Hello, got {other:?}"
                )));
            }
            None => return Err(RoutingError::Federation("peer closed before Hello".into())),
        };

        // Send our Hello.
        send_wire(
            &mut transport,
            &mut ws,
            &WireFrame::Hello(Hello::new(my_host_pubkey)),
        )
        .await?;

        finalise(transport, ws, remote_hello)
    }

    pub async fn send_frame(&mut self, frame: &WireFrame) -> Result<()> {
        send_wire(&mut self.transport, &mut self.ws, frame).await
    }

    pub async fn recv_frame(&mut self) -> Result<Option<WireFrame>> {
        recv_wire(&mut self.transport, &mut self.ws).await
    }

    pub async fn send_ack(
        &mut self,
        message_id: hermod_core::MessageId,
        status: AckStatus,
        reason: Option<String>,
    ) -> Result<()> {
        let f = WireFrame::DeliveryAck(DeliveryAck {
            message_id,
            status,
            reason,
        });
        self.send_frame(&f).await
    }

    pub async fn close(mut self) {
        let _ = self.ws.close().await;
    }
}

fn finalise(transport: NoiseTransport, ws: WsStream, remote: Hello) -> Result<PeerConnection> {
    if remote.protocol_version > PROTOCOL_VERSION {
        return Err(RoutingError::Federation(format!(
            "peer announced protocol_version={} but we support up to {PROTOCOL_VERSION}",
            remote.protocol_version
        )));
    }

    let remote_host_id = agent_id_from_pubkey(&remote.host_pubkey);
    Ok(PeerConnection {
        transport,
        ws,
        remote_host_pubkey: remote.host_pubkey,
        remote_host_id,
    })
}

async fn send_wire(
    transport: &mut NoiseTransport,
    ws: &mut WsStream,
    frame: &WireFrame,
) -> Result<()> {
    let plaintext = encode(frame)?;
    let cipher = transport.write(&plaintext)?;
    ws.send_binary(cipher).await?;
    Ok(())
}

async fn recv_wire(transport: &mut NoiseTransport, ws: &mut WsStream) -> Result<Option<WireFrame>> {
    let cipher = match ws.recv_binary().await? {
        Some(b) => b,
        None => return Ok(None),
    };
    let plaintext = transport.read(&cipher)?;
    let frame = decode(&plaintext)?;
    Ok(Some(frame))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hermod_crypto::Keypair;
    use hermod_transport::ws::{WsListener, connect};

    #[tokio::test]
    async fn full_peer_handshake_loopback() {
        let listener = WsListener::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();

        let server_kp = Keypair::generate();
        let server_noise = server_kp.noise_static_key();
        let server_host_pk = server_kp.to_pubkey_bytes();

        let client_kp = Keypair::generate();
        let client_noise = client_kp.noise_static_key();
        let client_host_pk = client_kp.to_pubkey_bytes();

        let server_secret = *server_noise.private_bytes();
        let server = tokio::spawn(async move {
            let ws = listener.accept().await.unwrap();
            let conn = PeerConnection::handshake_inbound(ws, &server_secret, server_host_pk)
                .await
                .unwrap();
            conn.remote_host_id.clone()
        });

        let client_secret = *client_noise.private_bytes();
        let ws = connect(&addr.ip().to_string(), addr.port()).await.unwrap();
        let conn = PeerConnection::handshake_outbound(ws, &client_secret, client_host_pk)
            .await
            .unwrap();

        assert_eq!(conn.remote_host_pubkey, server_host_pk);
        let observed_client = server.await.unwrap();
        let expected_client = agent_id_from_pubkey(&client_host_pk);
        assert_eq!(observed_client, expected_client);
    }
}
