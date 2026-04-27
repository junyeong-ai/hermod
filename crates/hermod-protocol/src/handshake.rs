//! Noise XX handshake (Noise_XX_25519_ChaChaPoly_BLAKE2s).
//!
//! Three-message handshake delivers:
//! - mutual authentication (each side learns the other's static x25519 pubkey)
//! - forward secrecy (ephemeral keys per session)
//!
//! After completion, both sides are in transport mode and can encrypt/decrypt
//! one-shot messages bounded at `MAX_NOISE_MESSAGE_LEN`.

use thiserror::Error;

pub const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

/// Hard cap per Noise XX message (sneaks under the 65535 limit).
pub const MAX_NOISE_MESSAGE_LEN: usize = 65_519;

#[derive(Debug, Error)]
pub enum HandshakeError {
    #[error("noise: {0}")]
    Noise(String),

    #[error("handshake state mismatch")]
    StateMismatch,

    #[error("handshake not complete")]
    NotComplete,

    #[error("payload too large for noise message ({size} > {max})")]
    PayloadTooLarge { size: usize, max: usize },

    #[error("missing remote static key after handshake")]
    MissingRemoteStatic,
}

impl From<snow::Error> for HandshakeError {
    fn from(e: snow::Error) -> Self {
        HandshakeError::Noise(format!("{e:?}"))
    }
}

/// Initiator state: sends message 1, reads message 2, sends message 3.
pub struct NoiseInitiator {
    inner: snow::HandshakeState,
}

impl std::fmt::Debug for NoiseInitiator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoiseInitiator").finish_non_exhaustive()
    }
}

impl NoiseInitiator {
    pub fn new(static_secret: &[u8; 32]) -> Result<Self, HandshakeError> {
        let builder = snow::Builder::new(NOISE_PATTERN.parse()?);
        let inner = builder
            .local_private_key(static_secret)?
            .build_initiator()?;
        Ok(Self { inner })
    }

    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, HandshakeError> {
        if payload.len() > MAX_NOISE_MESSAGE_LEN {
            return Err(HandshakeError::PayloadTooLarge {
                size: payload.len(),
                max: MAX_NOISE_MESSAGE_LEN,
            });
        }
        let mut buf = vec![0u8; MAX_NOISE_MESSAGE_LEN + 16];
        let n = self.inner.write_message(payload, &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    pub fn read_message(&mut self, message: &[u8]) -> Result<Vec<u8>, HandshakeError> {
        let mut buf = vec![0u8; MAX_NOISE_MESSAGE_LEN + 16];
        let n = self.inner.read_message(message, &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    pub fn is_finished(&self) -> bool {
        self.inner.is_handshake_finished()
    }

    pub fn into_transport(self) -> Result<NoiseTransport, HandshakeError> {
        if !self.inner.is_handshake_finished() {
            return Err(HandshakeError::NotComplete);
        }
        let remote = self
            .inner
            .get_remote_static()
            .ok_or(HandshakeError::MissingRemoteStatic)?
            .to_vec();
        let transport = self.inner.into_transport_mode()?;
        Ok(NoiseTransport::new(transport, remote))
    }
}

/// Responder state: reads message 1, sends message 2, reads message 3.
pub struct NoiseResponder {
    inner: snow::HandshakeState,
}

impl std::fmt::Debug for NoiseResponder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoiseResponder").finish_non_exhaustive()
    }
}

impl NoiseResponder {
    pub fn new(static_secret: &[u8; 32]) -> Result<Self, HandshakeError> {
        let builder = snow::Builder::new(NOISE_PATTERN.parse()?);
        let inner = builder
            .local_private_key(static_secret)?
            .build_responder()?;
        Ok(Self { inner })
    }

    pub fn read_message(&mut self, message: &[u8]) -> Result<Vec<u8>, HandshakeError> {
        let mut buf = vec![0u8; MAX_NOISE_MESSAGE_LEN + 16];
        let n = self.inner.read_message(message, &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, HandshakeError> {
        if payload.len() > MAX_NOISE_MESSAGE_LEN {
            return Err(HandshakeError::PayloadTooLarge {
                size: payload.len(),
                max: MAX_NOISE_MESSAGE_LEN,
            });
        }
        let mut buf = vec![0u8; MAX_NOISE_MESSAGE_LEN + 16];
        let n = self.inner.write_message(payload, &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    pub fn is_finished(&self) -> bool {
        self.inner.is_handshake_finished()
    }

    pub fn into_transport(self) -> Result<NoiseTransport, HandshakeError> {
        if !self.inner.is_handshake_finished() {
            return Err(HandshakeError::NotComplete);
        }
        let remote = self
            .inner
            .get_remote_static()
            .ok_or(HandshakeError::MissingRemoteStatic)?
            .to_vec();
        let transport = self.inner.into_transport_mode()?;
        Ok(NoiseTransport::new(transport, remote))
    }
}

/// Post-handshake encrypt/decrypt API. Each `write` produces one Noise message
/// containing the AEAD-encrypted payload; each `read` consumes one Noise message.
pub struct NoiseTransport {
    inner: snow::TransportState,
    remote_static: Vec<u8>,
}

impl std::fmt::Debug for NoiseTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoiseTransport")
            .field("remote_static_len", &self.remote_static.len())
            .finish_non_exhaustive()
    }
}

impl NoiseTransport {
    fn new(inner: snow::TransportState, remote_static: Vec<u8>) -> Self {
        Self {
            inner,
            remote_static,
        }
    }

    pub fn remote_static_pubkey(&self) -> &[u8] {
        &self.remote_static
    }

    pub fn write(&mut self, payload: &[u8]) -> Result<Vec<u8>, HandshakeError> {
        if payload.len() > MAX_NOISE_MESSAGE_LEN {
            return Err(HandshakeError::PayloadTooLarge {
                size: payload.len(),
                max: MAX_NOISE_MESSAGE_LEN,
            });
        }
        let mut buf = vec![0u8; MAX_NOISE_MESSAGE_LEN + 16];
        let n = self.inner.write_message(payload, &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    pub fn read(&mut self, message: &[u8]) -> Result<Vec<u8>, HandshakeError> {
        let mut buf = vec![0u8; MAX_NOISE_MESSAGE_LEN + 16];
        let n = self.inner.read_message(message, &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xx_handshake_full_roundtrip() {
        let i_secret = [1u8; 32];
        let r_secret = [2u8; 32];

        let mut initiator = NoiseInitiator::new(&i_secret).unwrap();
        let mut responder = NoiseResponder::new(&r_secret).unwrap();

        // 1. -> e
        let m1 = initiator.write_message(b"").unwrap();
        responder.read_message(&m1).unwrap();

        // 2. <- e, ee, s, es
        let m2 = responder.write_message(b"").unwrap();
        initiator.read_message(&m2).unwrap();

        // 3. -> s, se
        let m3 = initiator.write_message(b"").unwrap();
        responder.read_message(&m3).unwrap();

        assert!(initiator.is_finished());
        assert!(responder.is_finished());

        let mut i_t = initiator.into_transport().unwrap();
        let mut r_t = responder.into_transport().unwrap();

        // After handshake, transport mode AEAD round trip.
        let plaintext = b"hello noise";
        let cipher = i_t.write(plaintext).unwrap();
        let decoded = r_t.read(&cipher).unwrap();
        assert_eq!(decoded, plaintext);

        let cipher2 = r_t.write(b"hello back").unwrap();
        let decoded2 = i_t.read(&cipher2).unwrap();
        assert_eq!(decoded2, b"hello back");

        // Initiator learned responder's pubkey and vice versa.
        let i_view_of_r = i_t.remote_static_pubkey();
        let r_view_of_i = r_t.remote_static_pubkey();
        assert_eq!(i_view_of_r.len(), 32);
        assert_eq!(r_view_of_i.len(), 32);
    }
}
