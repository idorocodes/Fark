use thiserror::*;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Invaid Input supplied!")]
    InvalidInput,
    #[error("User Error!")]
    UserError,
    #[error("Strategy provided not found!")]
    StrategyNotFound,
    #[error("Wrong password, check and try again!")]
    PasswordMismatch,
    #[error("Sorry, internal error!")]
    InternalError,
    #[error("Token generation error!")]
    TokenError,
    #[error("secret not supplied! ")]
    SecretNotFound,
    #[error("invalid token provided")]
    InvalidToken,
}

#[derive(Debug)]
pub enum TimeError {
    TimeGenError,
}
