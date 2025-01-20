use chrono::{DateTime, Duration, TimeDelta, Utc};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use passport_core::encoder::{EncodeUserPrincipal, EncodeUserPrincipalFailure, EncoderResult};
use passport_core::user::UserDetails;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct UserClaims {
    pub exp: i64,
    pub iat: i64,
    pub sub: String,
    pub sub_id: i32,
    pub iss: String,
    pub aud: String,
}

impl UserClaims {
    pub fn new(user_details: &Box<dyn UserDetails>, issuer: String, audience: String) -> Self {
        let now: DateTime<Utc> = Utc::now();
        let expire: TimeDelta = Duration::hours(24);

        let exp: i64 = (now + expire).timestamp();
        let iat: i64 = now.timestamp();

        Self {
            exp,
            iat,
            sub: user_details.username(),
            sub_id: user_details.id(),
            iss: issuer.to_owned(),
            aud: audience.to_owned(),
        }
    }
}

pub struct UserEncoder {
    encoding_key: EncodingKey,
    issuer: String,
    audience: String,
}

#[async_trait::async_trait]
impl EncodeUserPrincipal for UserEncoder {
    async fn encode_user_principal(&self, user_details: &Box<dyn UserDetails>) -> EncoderResult {
        let issuer = self.issuer.to_owned();
        let audience = self.audience.to_owned();
        let claims = UserClaims::new(user_details, issuer, audience);

        let access_token =
            jsonwebtoken::encode(&Header::new(Algorithm::RS256), &claims, &self.encoding_key)
                .map_err(|err| {
                    tracing::error!(?err, "failed to encode user principal");
                    EncodeUserPrincipalFailure::Unknown
                })?;

        Ok(access_token)
    }
}
