use thiserror::*;
#[cfg(feature = "actix")]
use actix_web::{HttpResponse, ResponseError, http::StatusCode};
use serde::Serialize;


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
    #[error("invalid pin")]
    PinMisMatch,
}

#[derive(Debug)]
pub enum TimeError {
    TimeGenError,
}

#[derive(Debug)]
pub enum CoreError {
    ParseError,
}

#[derive(Serialize)]
struct ErrorResponse {
    message: String,
}

#[cfg(feature = "actix")]
impl ResponseError for AuthError {
    fn status_code(&self) -> StatusCode {
        match self {
            AuthError::InvalidInput => StatusCode::UNAUTHORIZED,
            AuthError::StrategyNotFound => StatusCode::INTERNAL_SERVER_ERROR,
            AuthError::SecretNotFound => StatusCode::INTERNAL_SERVER_ERROR,
            AuthError::TokenError | AuthError::InvalidToken => StatusCode::UNAUTHORIZED,
            _ => StatusCode::BAD_REQUEST,
        }
    }

    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code()).json(ErrorResponse {
            message: self.to_string(),
        })
    }
}
