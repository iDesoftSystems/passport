use passport_core::auth::{
    AuthenticatorResult, FindByUsername, UsernamePasswordAuthentication,
    UsernamePasswordAuthenticationFailure,
};
use std::sync::Arc;

pub struct UserAuthenticator {
    user_finder: Arc<dyn FindByUsername>,
}

#[async_trait::async_trait]
impl UsernamePasswordAuthentication for UserAuthenticator {
    async fn authenticate(&self, username: String, password: String) -> AuthenticatorResult {
        let user_details = self
            .user_finder
            .find_by_username(username)
            .await
            .map_err(|err| {
                tracing::error!(?err, "failed to find by username");
                UsernamePasswordAuthenticationFailure::Unknown
            })?
            .ok_or(UsernamePasswordAuthenticationFailure::BadCredentials)?;

        bcrypt::verify(password, &user_details.password())
            .map_err(|err| {
                tracing::error!(?err, "failed to verify password");
                UsernamePasswordAuthenticationFailure::Unknown
            })?
            .then_some(())
            .ok_or(UsernamePasswordAuthenticationFailure::BadCredentials)?;

        if !user_details.is_enabled() {
            Err(UsernamePasswordAuthenticationFailure::AccessDenied)?
        }

        Ok(user_details)
    }
}
