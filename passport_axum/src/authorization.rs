use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::{http, Json};
use passport_core::decoder::DecodeAccessToken;
use serde_json::json;
use std::sync::Arc;

pub struct AuthError {
    message: String,
    status_code: StatusCode,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let body = Json(json!({
            "message": self.message
        }));

        (self.status_code, body).into_response()
    }
}

pub async fn authorization_middleware(
    mut req: Request,
    next: Next,
    decoder: Arc<dyn DecodeAccessToken>,
) -> Result<Response, AuthError> {
    let header_value = req.headers_mut().get(http::header::AUTHORIZATION);

    let auth_header = match header_value {
        None => Err(AuthError {
            message: "Please add the JWT token to the header".into(),
            status_code: StatusCode::FORBIDDEN,
        }),
        Some(header) => header.to_str().map_err(|_| AuthError {
            message: "Empty header is not allowed".into(),
            status_code: StatusCode::FORBIDDEN,
        }),
    }?;

    let mut header = auth_header.split_whitespace();

    let (_, token) = (header.next(), header.next());

    let claims_principal = match decoder.decode_access_token(token.unwrap().into()).await {
        Ok(authentication) => authentication,
        Err(err) => Err(AuthError {
            message: err.to_string(),
            status_code: StatusCode::FORBIDDEN,
        })?,
    };

    req.extensions_mut().insert(claims_principal);

    Ok(next.run(req).await)
}
