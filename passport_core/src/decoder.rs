use crate::user::ClaimsPrincipal;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DecodeAccessTokenFailure {
    #[error("invalid token")]
    InvalidToken,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("invalid issuer")]
    InvalidIssuer,
    #[error("invalid audience")]
    InvalidAudience,
    #[error("invalid subject")]
    InvalidSubject,
    #[error("unknown decode access token error")]
    Unknown,
}

pub type DecoderResult = Result<Box<dyn ClaimsPrincipal>, DecodeAccessTokenFailure>;
#[async_trait::async_trait]
pub trait DecodeAccessToken {
    async fn decode_access_token(&self, access_token: String) -> DecoderResult;
}
