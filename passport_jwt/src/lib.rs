use thiserror::Error;

pub mod auth;
pub mod claims;
pub mod decoder;
pub mod encoder;

#[derive(Error, Debug)]
pub enum TokenUsernamePasswordAuthFailure {
    #[error("bad credentials")]
    BadCredentials,
    #[error("access denied")]
    AccessDenied,
    #[error("unknown authentication error")]
    Unknown,
}

pub struct Authentication {
    pub access_token: String,
    pub token_type: String,
}

impl Authentication {
    pub fn new_bearer(access_token: String) -> Self {
        Self {
            access_token,
            token_type: "Bearer".into(),
        }
    }
}

pub type TokenUsernamePasswordAuthResult = Result<Authentication, TokenUsernamePasswordAuthFailure>;

#[async_trait::async_trait]
pub trait TokenUsernamePasswordAuth {
    async fn authenticate(
        &self,
        username: String,
        password: String,
    ) -> TokenUsernamePasswordAuthResult;
}
