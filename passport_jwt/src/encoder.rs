use crate::claims::UserClaims;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use passport_core::encoder::{EncodeUserPrincipal, EncodeUserPrincipalFailure, EncoderResult};
use passport_core::user::UserDetails;

pub struct UserEncoder {
    encoding_key: EncodingKey,
    issuer: String,
    audience: String,
}

impl UserEncoder {
    pub fn new(encoding_key: EncodingKey, issuer: String, audience: String) -> Self {
        Self {
            encoding_key,
            issuer,
            audience,
        }
    }
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
