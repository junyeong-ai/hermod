use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("invalid secret key: {0}")]
    InvalidSecretKey(String),

    #[error("invalid signature: {0}")]
    InvalidSignature(String),

    #[error("signature verification failed")]
    SignatureVerificationFailed,

    #[error("canonical serialization error: {0}")]
    Serialization(String),

    #[error("encoding error: {0}")]
    Encoding(String),

    #[error("envelope signer does not match `from` agent id")]
    SignerMismatch,

    #[error(transparent)]
    Core(#[from] hermod_core::HermodError),
}
