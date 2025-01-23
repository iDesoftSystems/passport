use crate::user::UserDetails;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum UsernamePasswordAuthenticationFailure {
    #[error("bad credentials")]
    BadCredentials,
    #[error("access denied")]
    AccessDenied,
    #[error("unknown authentication error")]
    Unknown,
}

pub type AuthenticatorResult = Result<Box<dyn UserDetails>, UsernamePasswordAuthenticationFailure>;

#[async_trait::async_trait]
pub trait UsernamePasswordAuthentication: Send + Sync {
    async fn authenticate(&self, username: String, password: String) -> AuthenticatorResult;
}

#[derive(Error, Debug)]
pub enum FindByUsernameFailure {
    #[error("unknown find by username error")]
    Unknown,
}

pub type FindByUsernameResult = Result<Option<Box<dyn UserDetails>>, FindByUsernameFailure>;

#[async_trait::async_trait]
pub trait FindByUsername: Send + Sync {
    async fn find_by_username(&self, username: String) -> FindByUsernameResult;
}
