use crate::claims::UserClaims;
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use passport_core::decoder::{DecodeAccessToken, DecodeAccessTokenFailure, DecoderResult};

pub struct AccessTokenDecoder {
    decoding_key: DecodingKey,
    audience: String,
    issuer: String,
}

#[async_trait::async_trait]
impl DecodeAccessToken for AccessTokenDecoder {
    async fn decode_access_token(&self, access_token: String) -> DecoderResult {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[&self.audience]);
        validation.set_issuer(&[&self.issuer]);

        validation.set_required_spec_claims(&["exp", "sub", "sub_id", "aud", "iss"]);

        let result =
            jsonwebtoken::decode::<UserClaims>(&access_token, &self.decoding_key, &validation)
                .map_err(|err| match *err.kind() {
                    ErrorKind::InvalidToken => DecodeAccessTokenFailure::InvalidToken,
                    ErrorKind::InvalidSignature => DecodeAccessTokenFailure::InvalidSignature,
                    ErrorKind::MissingRequiredClaim(_) => DecodeAccessTokenFailure::InvalidToken,
                    ErrorKind::InvalidIssuer => DecodeAccessTokenFailure::InvalidIssuer,
                    ErrorKind::InvalidAudience => DecodeAccessTokenFailure::InvalidAudience,
                    ErrorKind::InvalidSubject => DecodeAccessTokenFailure::InvalidSubject,
                    _ => {
                        tracing::error!(?err, "failed to decode access token");
                        DecodeAccessTokenFailure::Unknown
                    }
                })?;

        Ok(Box::new(result.claims))
    }
}
