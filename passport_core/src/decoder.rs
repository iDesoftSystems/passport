use crate::user::UserClaims;

pub enum DecodeAccessTokenFailure {}

pub type DecoderResult = Result<Box<dyn UserClaims>, DecodeAccessTokenFailure>;
#[async_trait::async_trait]
pub trait DecodeAccessToken {
    async fn decode_access_token(&self, access_token: String) -> DecoderResult;
}
