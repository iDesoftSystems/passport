use crate::user::UserDetails;

pub enum UsernamePasswordAuthenticationFailure {}

pub type AuthenticatorResult = Result<Box<dyn UserDetails>, UsernamePasswordAuthenticationFailure>;

#[async_trait::async_trait]
pub trait UsernamePasswordAuthentication {
    async fn authenticate(
        &self,
        username: String,
        password: String,
    ) -> Result<Box<dyn UserDetails>, UsernamePasswordAuthenticationFailure>;
}
