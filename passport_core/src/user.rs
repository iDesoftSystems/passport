pub trait UserClaims: Send + Sync {
    fn exp(&self) -> i64;
    fn iat(&self) -> i64;
    fn sub(&self) -> String;
    fn sub_id(&self) -> i32;
    fn iss(&self) -> String;
    fn aud(&self) -> String;
}

pub trait UserDetails: Send + Sync {
    fn id(&self) -> i32;
    fn username(&self) -> String;
    fn password(&self) -> String;
    fn is_enabled(&self) -> bool;
    fn authorities(&self) -> Vec<Box<dyn GrantedAuthority>>;
}

pub trait GrantedAuthority {
    fn authority(&self) -> String;
}
