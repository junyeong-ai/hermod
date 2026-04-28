//! Static bearer source — value handed in once at process start.
//!
//! Backs `HERMOD_BEARER_TOKEN`. Has no notion of refresh: `refresh` returns
//! the same token and same epoch, so the connect path's
//! "epoch unchanged ⇒ provider declined" rule escalates two consecutive
//! 401s to fatal automatically.

use async_trait::async_trait;
use hermod_crypto::SecretString;

use super::{BearerError, BearerProvider, BearerToken, TokenEpoch};

#[derive(Debug)]
pub struct StaticBearerProvider {
    token: BearerToken,
}

impl StaticBearerProvider {
    pub fn new(secret: SecretString) -> Self {
        Self {
            token: BearerToken::new(secret, TokenEpoch::ZERO),
        }
    }
}

#[async_trait]
impl BearerProvider for StaticBearerProvider {
    async fn current(&self) -> Result<BearerToken, BearerError> {
        Ok(self.token.clone())
    }

    async fn refresh(&self, _stale: TokenEpoch) -> Result<BearerToken, BearerError> {
        Ok(self.token.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn current_and_refresh_return_identical_token() {
        let p = StaticBearerProvider::new(SecretString::new("abc"));
        let a = p.current().await.unwrap();
        let b = p.refresh(a.epoch()).await.unwrap();
        assert_eq!(a.secret().expose_secret(), "abc");
        assert_eq!(a.epoch(), b.epoch());
        assert_eq!(a.epoch(), TokenEpoch::ZERO);
    }
}
