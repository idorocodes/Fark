use fark::{AuthError, AuthInput, Fark, Identity};
use serde_json::json;
use std::collections::HashMap;

#[tokio::test]
async fn test_local_strategy_success() {
    // Happy: Successful local authentication
    let fark = Fark::new().with_local(|data: HashMap<String, String>| async move {
        if data.get("username") == Some(&"user".to_string())
            && data.get("password") == Some(&"pass".to_string())
        {
            Ok(Identity {
                user_id: "123".to_string(),
                data: json!({ "role": "user" }),
            })
        } else {
            Err(AuthError::InvalidInput)
        }
    });

    let mut input = HashMap::new();
    input.insert("username".to_string(), "user".to_string());
    input.insert("password".to_string(), "pass".to_string());

    let identity = fark
        .authenticate("local", AuthInput::Local { data: input })
        .await
        .unwrap();
    assert_eq!(identity.user_id, "123");
    assert_eq!(identity.data["role"], "user");
}

#[tokio::test]
async fn test_issue_and_verify_jwt_valid() {
    // Happy: Issue and successfully verify a JWT
    let mut fark = Fark::new();
    fark.with_jwt("test-secret".to_string());

    let identity = Identity {
        user_id: "user123".to_string(),
        data: json!({ "role": "admin", "verified": true }),
    };

    let token = fark.issue_jwt(identity.clone(), 3600).unwrap();
    let verified = fark.verify_jwt(token).unwrap();

    assert_eq!(verified.user_id, identity.user_id);
    assert_eq!(verified.data, identity.data);
}

#[tokio::test]
async fn test_multiple_strategies_coexist() {
    // Happy: Register multiple strategies and use independently
    let fark = Fark::new()
        .with_local(|_: HashMap<String, String>| async move {
            Ok(Identity {
                user_id: "local_user".to_string(),
                data: json!({}),
            })
        })
        .with_pin(|pin: i32| async move {
            if pin == 1234 {
                Ok(Identity {
                    user_id: "pin_user".to_string(),
                    data: json!({}),
                })
            } else {
                Err(AuthError::InvalidInput)
            }
        });

    let local_identity = fark
        .authenticate(
            "local",
            AuthInput::Local {
                data: HashMap::new(),
            },
        )
        .await
        .unwrap();
    assert_eq!(local_identity.user_id, "local_user");

    let pin_identity = fark
        .authenticate("pin", AuthInput::Pin { pin_code: 1234 })
        .await
        .unwrap();
    assert_eq!(pin_identity.user_id, "pin_user");
}

#[tokio::test]
async fn test_jwt_with_custom_data() {
    // Happy: Complex custom data round-trips correctly
    let mut fark = Fark::new();
    fark.with_jwt("secret".to_string());

    let original = Identity {
        user_id: "abc".to_string(),
        data: json!({
            "permissions": ["read", "write", "delete"],
            "active": true,
            "metadata": { "theme": "dark" }
        }),
    };

    let token = fark.issue_jwt(original.clone(), 1800).unwrap();
    let verified = fark.verify_jwt(token).unwrap();

    assert_eq!(verified.user_id, original.user_id);
    assert_eq!(verified.data, original.data);
}

#[tokio::test]
async fn test_google_strategy_invocation() {
    // Happy: Google strategy receives correct parameters
    let fark = Fark::new().with_google(
        |client_id, _client_secret, _callback_url, scope| async move {
            assert_eq!(client_id, "test-client");
            assert_eq!(scope, vec!["email", "profile"]);
            Ok(Identity {
                user_id: "google_user".to_string(),
                data: json!({}),
            })
        },
    );

    let identity = fark
        .authenticate(
            "google",
            AuthInput::Google {
                client_id: "test-client".to_string(),
                client_secret: "ignored".to_string(),
                callback_url: "ignored".to_string(),
                scope: vec!["email".to_string(), "profile".to_string()],
            },
        )
        .await
        .unwrap();

    assert_eq!(identity.user_id, "google_user");
}

#[tokio::test]
async fn test_unknown_strategy() {
    // Unhappy: Attempt to authenticate with unregistered strategy
    let fark = Fark::new();
    let result = fark
        .authenticate(
            "unknown",
            AuthInput::Local {
                data: HashMap::new(),
            },
        )
        .await;
    assert!(matches!(result, Err(AuthError::StrategyNotFound)));
}

#[tokio::test]
async fn test_strategy_invalid_input() {
    // Unhappy: Strategy receives mismatched input variant
    let fark = Fark::new().with_local(|_: HashMap<String, String>| async move { unreachable!() });

    let result = fark
        .authenticate("local", AuthInput::Pin { pin_code: 9999 })
        .await;
    assert!(matches!(result, Err(AuthError::InvalidInput)));
}

#[tokio::test]
async fn test_jwt_no_secret_configured() {
    // Unhappy: Issue/verify JWT without setting secret
    let fark = Fark::new(); // No with_jwt call

    let identity = Identity {
        user_id: "123".to_string(),
        data: json!({}),
    };

    assert!(matches!(
        fark.issue_jwt(identity.clone(), 3600),
        Err(AuthError::SecretNotFound)
    ));
    assert!(matches!(
        fark.verify_jwt("any.token.here".to_string()),
        Err(AuthError::SecretNotFound)
    ));
}

#[tokio::test]
async fn test_jwt_expired_token() {
    // Unhappy: Verify an expired token (generated with past exp)
    let mut fark = Fark::new();
    fark.with_jwt("test-secret".to_string());

    // Create a token with expiration in the past (1 second TTL, but issued "now")
    let past_identity = Identity {
        user_id: "old".to_string(),
        data: json!({}),
    };
    let token = fark.issue_jwt(past_identity, 1).unwrap();

    // Sleep briefly to ensure expiration
    tokio::time::sleep(std::time::Duration::from_secs(40)).await;

    let result = fark.verify_jwt(token);
    assert!(matches!(result, Err(AuthError::InvalidToken)));
}

#[tokio::test]
async fn test_jwt_invalid_signature() {
    // Unhappy: Tampered or wrong-secret token
    let mut fark = Fark::new();
    fark.with_jwt("test-secret".to_string());

    // Valid token with different secret
    let mut wrong_fark = Fark::new();
    wrong_fark.with_jwt("wrong-secret".to_string());
    let token = wrong_fark
        .issue_jwt(
            Identity {
                user_id: "user".to_string(),
                data: json!({}),
            },
            3600,
        )
        .unwrap();

    let result = fark.verify_jwt(token);
    assert!(matches!(result, Err(AuthError::InvalidToken)));
}

#[tokio::test]
async fn test_jwt_malformed_token() {
    // Unhappy: Completely malformed token string
    let mut fark = Fark::new();
    fark.with_jwt("secret".to_string());

    let result = fark.verify_jwt("not.a.valid.jwt".to_string());
    assert!(matches!(result, Err(AuthError::InvalidToken)));
}

#[tokio::test]
async fn test_pin_strategy_failure() {
    // Unhappy: PIN strategy rejects wrong code
    let fark = Fark::new().with_pin(|pin: i32| async move {
        if pin == 0000 {
            Ok(Identity {
                user_id: "valid".to_string(),
                data: json!({}),
            })
        } else {
            Err(AuthError::InvalidInput)
        }
    });

    let result = fark
        .authenticate("pin", AuthInput::Pin { pin_code: 9999 })
        .await;
    assert!(matches!(result, Err(AuthError::InvalidInput)));
}

#[tokio::test]
async fn test_jwt_missing_required_claims() {
    // Unhappy: Token missing required claims (sub or exp)
    let mut fark = Fark::new();
    fark.with_jwt("test-secret".to_string());

    let invalid_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3MzQ1Njc4OTB9.c7r7t5vI4u4e3q2v5X8Y9Z0a1b2c3d4e5f6g7h8i9j0";

    let result = fark.verify_jwt(invalid_token.to_string());
    assert!(matches!(result, Err(AuthError::InvalidToken)));
}
