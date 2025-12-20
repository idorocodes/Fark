use hmac::{Hmac, Mac};
use jwt::{SignWithKey, VerifyWithKey};
use sha2::Sha256;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;

mod error;
use error::*;

#[derive(Debug)]
pub struct Identity {
    pub user_id: String,
    pub data: serde_json::Value,
}

impl Identity {
    pub fn data(&self) -> &serde_json::Value {
        &self.data
    }
}


#[derive(Debug)]
pub enum AuthInput {
    Local { data: HashMap<String, String> },
    Oauth { token: String },
}

pub type Strategy = Box<
    dyn Fn(AuthInput) -> Pin<Box<dyn Future<Output = Result<Identity, AuthError>> + Send>>
        + Send
        + Sync,
>;

fn now() -> Result<u64, TimeError> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| TimeError::TimeGenError)?;

    Ok(time.as_secs())
}
pub struct Fark {
    strategies: HashMap<String, Strategy>,
    secret: String,
}

impl Fark {
    pub fn new() -> Self {
        Self {
            strategies: HashMap::new(),
            secret: String::new(),
        }
    }

    pub fn with_local<F, Fut>(mut self, f: F) -> Self
    where
        F: Fn(HashMap<String, String>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Identity, AuthError>> + Send + 'static,
    {
        self.strategies.insert(
            "local".into(),
            Box::new(move |input: AuthInput| match input {
                AuthInput::Local { data } => Box::pin(f(data)),
                _ => Box::pin(async { Err(AuthError::InvalidInput) }),
            }),
        );

        self
    }

    pub fn with_jwt(&mut self, secret: String) {
        self.secret = secret;
    }

    pub async fn authenticate(&self, name: &str, input: AuthInput) -> Result<Identity, AuthError> {
        let strategy = self
            .strategies
            .get(name)
            .ok_or(AuthError::StrategyNotFound)?;

        strategy(input).await
    }

    pub fn issue_jwt(&self, identity: Identity, ttl_secs: u64) -> Result<String, AuthError> {
        let user_id = identity.user_id;
        let secret = self.secret.clone();
        let issued_at = now().map_err(|_| AuthError::InternalError)?;
        let expires_at = issued_at + ttl_secs;

        let serialized_data =
            serde_json::to_string(&identity.data).map_err(|_| AuthError::TokenError)?;

        if secret.is_empty() {
            return Err(AuthError::SecretNotFound);
        }

        let key: Hmac<Sha256> =
            Hmac::new_from_slice(secret.as_bytes()).map_err(|_| AuthError::TokenError)?;

        let mut claims = BTreeMap::new();
        claims.insert("sub", user_id);
        claims.insert("iat", issued_at.to_string());
        claims.insert("exp", expires_at.to_string());
        claims.insert("claims", serialized_data);

        let token = claims
            .sign_with_key(&key)
            .map_err(|_| AuthError::TokenError)?;

        Ok(token)
    }

    pub fn verify_jwt(&self, token: String) -> Result<Identity, AuthError> {
        let secret = self.secret.clone();

        if secret.is_empty() {
            return Err(AuthError::SecretNotFound);
        }

        let key: Hmac<Sha256> =
            Hmac::new_from_slice(secret.as_bytes()).map_err(|_| AuthError::TokenError)?;

        let claims: BTreeMap<String, String> = token
            .verify_with_key(&key)
            .map_err(|_| AuthError::InvalidToken)?;

        let user_id = claims
            .get("sub")
            .ok_or(AuthError::InvalidToken)?
            .to_string();

        let exp: u64 = claims
            .get("exp")
            .ok_or(AuthError::InvalidToken)?
            .parse()
            .map_err(|_| AuthError::InvalidToken)?;

        let issued_at: u64 = claims
            .get("iat")
            .ok_or(AuthError::InvalidToken)?
            .parse()
            .map_err(|_| AuthError::InvalidToken)?;

        let allowed_skew: u64 = 30;

        if exp <= now().map_err(|_| AuthError::InvalidToken)? + allowed_skew {
            return Err(AuthError::InvalidToken);
        }

        if issued_at > now().map_err(|_| AuthError::InvalidToken)? + allowed_skew {
            return Err(AuthError::InvalidToken);
        }

        let data_str = claims.get("claims").ok_or(AuthError::InvalidToken)?;

        let data: serde_json::Value =
            serde_json::from_str(data_str).map_err(|_| AuthError::InvalidToken)?;

        Ok(Identity { user_id, data })
    }
}
