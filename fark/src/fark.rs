use crate::AuthError; 
use crate::identity::Identity;
use crate::input::AuthInput;
use crate::strategy::Strategy;
use std::collections::HashMap;

pub struct Fark {
    pub(crate) strategies: HashMap<String, Strategy>,
    pub(crate) secret: String,
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

    pub fn with_google<F, Fut>(mut self, f: F) -> Self
    where
        F: Fn(String, String, String, Vec<String>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Identity, AuthError>> + Send + 'static,
    {
        self.strategies.insert(
            "google".into(),
            Box::new(move |input: AuthInput| match input {
                AuthInput::Google {
                    client_id,
                    client_secret,
                    callback_url,
                    scope,
                } => Box::pin(f(client_id, client_secret, callback_url, scope)),
                _ => Box::pin(async { Err(AuthError::InvalidInput) }),
            }),
        );
        self
    }

    pub fn with_pin<F, Fut>(mut self, f: F) -> Self
    where
        F: Fn(i32) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Identity, AuthError>> + Send + 'static,
    {
        self.strategies.insert(
            "pin".into(),
            Box::new(move |input: AuthInput| match input {
                AuthInput::Pin { pin_code } => Box::pin(f(pin_code)),
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
}
