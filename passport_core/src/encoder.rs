use crate::user::UserDetails;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum EncodeUserPrincipalFailure {
    #[error("unknown authentication error")]
    Unknown,
}

pub type EncoderResult = Result<String, EncodeUserPrincipalFailure>;

#[async_trait::async_trait]
pub trait EncodeUserPrincipal: Send + Sync {
    async fn encode_user_principal(&self, user_details: &Box<dyn UserDetails>) -> EncoderResult;
}
