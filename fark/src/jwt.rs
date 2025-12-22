use crate::error::AuthError;
use crate::identity::Identity;
use crate::time::now;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    #[serde(skip_serializing_if = "Option::is_none")]
    aud: Option<String>, // Optional. Audience
    exp: u64, // Required (validate_exp defaults to true in validation). Expiration time (as UTC timestamp)
    iat: u64, // Optional. Issued at (as UTC timestamp)
    #[serde(skip_serializing_if = "Option::is_none")]
    iss: Option<String>, // Optional. Issuer
    sub: String,
    extra: Value,
}
impl super::fark::Fark {
    pub fn issue_jwt(&self, identity: Identity, ttl_secs: u64) -> Result<String, AuthError> {
        let secret = self.secret.clone();

        if secret.is_empty() {
            return Err(AuthError::SecretNotFound);
        }

        let issued_at = now().map_err(|_| AuthError::InternalError)?;
        let expires_at = issued_at + ttl_secs;

        let my_claims = Claims {
            sub: identity.user_id,
            iat: issued_at,
            exp: expires_at,
            aud: None,
            iss: None,
            extra: identity.data,
        };

        let token = encode(
            &Header::new(Algorithm::HS256),
            &my_claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .map_err(|_| AuthError::InternalError)?;

        Ok(token)
    }

    pub fn verify_jwt(&self, token: String) -> Result<Identity, AuthError> {
        let secret = self.secret.clone();
        if secret.is_empty() {
            return Err(AuthError::SecretNotFound);
        }

        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;
        validation.leeway = 30;

        let token_data = decode::<Claims>(
            &token,
            &DecodingKey::from_secret(secret.as_bytes()),
            &validation,
        )
        .map_err(|_| AuthError::InvalidToken)?;

        let claims = token_data.claims;

        Ok(Identity {
            user_id: claims.sub,
            data: claims.extra,
        })
    }
}
