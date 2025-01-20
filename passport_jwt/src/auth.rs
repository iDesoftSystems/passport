use crate::{
    AccessToken, TokenUsernamePasswordAuth, TokenUsernamePasswordAuthFailure,
    TokenUsernamePasswordAuthResult,
};
use passport_core::auth::{UsernamePasswordAuthentication, UsernamePasswordAuthenticationFailure};
use passport_core::encoder::EncodeUserPrincipal;
use std::sync::Arc;

pub struct TokenAuthManager {
    authenticator: Arc<dyn UsernamePasswordAuthentication>,
    encoder: Arc<dyn EncodeUserPrincipal>,
}

#[async_trait::async_trait]
impl TokenUsernamePasswordAuth for TokenAuthManager {
    async fn authenticate(
        &self,
        username: String,
        password: String,
    ) -> TokenUsernamePasswordAuthResult {
        let user_principal = self
            .authenticator
            .authenticate(username, password)
            .await
            .map_err(|err| match err {
                UsernamePasswordAuthenticationFailure::BadCredentials => {
                    TokenUsernamePasswordAuthFailure::BadCredentials
                }
                UsernamePasswordAuthenticationFailure::AccessDenied => {
                    TokenUsernamePasswordAuthFailure::AccessDenied
                }
                UsernamePasswordAuthenticationFailure::Unknown => {
                    tracing::error!(?err, "failed to authenticate credentials");
                    TokenUsernamePasswordAuthFailure::Unknown
                }
            })?;

        let access_token = self
            .encoder
            .encode_user_principal(&user_principal)
            .await
            .map_err(|err| {
                tracing::error!(?err, "failed to encode user principal");
                TokenUsernamePasswordAuthFailure::Unknown
            })?;

        Ok(AccessToken::new_bearer(access_token))
    }
}
