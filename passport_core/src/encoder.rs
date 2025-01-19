use crate::user::UserDetails;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum EncodeUserPrincipalFailure {}

pub type EncoderResult = Result<String, EncodeUserPrincipalFailure>;

#[async_trait::async_trait]
pub trait EncodeUserPrincipal {
    async fn encode_user_principal(&self, user_details: Box<dyn UserDetails>) -> EncoderResult;
}
