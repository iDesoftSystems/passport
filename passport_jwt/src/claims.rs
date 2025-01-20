use chrono::{DateTime, Duration, TimeDelta, Utc};
use passport_core::user::{ClaimsPrincipal, UserDetails};
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

impl ClaimsPrincipal for UserClaims {
    fn exp(self) -> i64 {
        self.exp
    }

    fn iat(self) -> i64 {
        self.iat
    }

    fn sub(self) -> String {
        self.sub
    }

    fn sub_id(self) -> i32 {
        self.sub_id
    }

    fn iss(self) -> String {
        self.iss
    }

    fn aud(self) -> String {
        self.aud
    }
}
