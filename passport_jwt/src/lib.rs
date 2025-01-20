use thiserror::Error;

pub mod auth;

#[derive(Error, Debug)]
pub enum TokenUsernamePasswordAuthFailure {
    #[error("bad credentials")]
    BadCredentials,
    #[error("access denied")]
    AccessDenied,
    #[error("unknown authentication error")]
    Unknown,
}

pub struct AccessToken {
    pub access_token: String,
    pub token_type: String,
}

impl AccessToken {
    pub fn new_bearer(access_token: String) -> Self {
        Self {
            access_token,
            token_type: "Bearer".into(),
        }
    }
}

pub type TokenUsernamePasswordAuthResult = Result<AccessToken, TokenUsernamePasswordAuthFailure>;

#[async_trait::async_trait]
pub trait TokenUsernamePasswordAuth {
    async fn authenticate(
        &self,
        username: String,
        password: String,
    ) -> TokenUsernamePasswordAuthResult;
}
