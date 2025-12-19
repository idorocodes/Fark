# fark

**Framework-agnostic Authentication Kernel for Rust**

`fark` is a unified, strategy-based authentication library for Rust. It provides a clean core API for identity verification and strategy orchestration, with adapters for major web frameworks like Actix, Axum, and Rocket.

> Build once. Use everywhere. No framework coupling.

## 🚀 Features

- Email + Password authentication
- OAuth2 Social login (Google, GitHub, etc.)
- JWT and session support
- Framework-agnostic core
- Adapters for Actix, Axum, Rocket
- Policy-based authorization
- Extensible strategy plugin system

## 📦 Installation

```bash
cargo add fark
# and for Actix adapter
cargo add fark-actix
```

## ✨ Quick Start (Actix Web)

### Local (email/password) Sign-In

```rust
    use std::collections::HashMap;
    use serde_json::json;
    use fark::*;

    #[tokio::test]
    async fn test() {
        let secret = "test_secret".to_string();

        // db query logic
        let mut fark = Fark::new().with_local(|data: HashMap<String, String>| async move {
            if data.get("username") == Some(&"admin".to_string())
                && data.get("password") == Some(&"pass".to_string())
            {
                Ok(Identity {
                    user_id: "123".to_string(),
                    data: json!({"role": "admin"}),
                })
            } else {
                Err(AuthError::PasswordMismatch)
            }
        });
        // add jwt
        fark.with_jwt(secret.clone());

        // init query and authenticate
        let mut input_data = HashMap::new();
        input_data.insert("username".to_string(), "admin".to_string());
        input_data.insert("password".to_string(), "pass".to_string());

        // initialize the autn input struct with the local strategy and the data that should be retuned after the query
        let input = AuthInput::Local { data: input_data };

            // authenticate user with the data provided in the request
        match fark.authenticate("local", input).await {
            Ok(identity) => {
                println!("Authenticated: user_id = {}", identity.user_id);
                println!("Custom data: {}", identity.data());


                     // issue jwt token
                let token = fark.issue_jwt(identity, 3600).unwrap();
                println!("Issued JWT: {}", token);

                // verify jwt token
                match fark.verify_jwt(token) {
                    Ok(verified) => {
                        println!("Verified: user_id = {}", verified.user_id);
                        println!("Verified data: {}", verified.data());
                    }
                    Err(e) => println!("Verification failed: {:?}", e),
                }
            }
            Err(e) => println!("Authentication failed: {:?}", e),
        }
    }
}

```

### Google OAuth Login

```rust
let fark = Fark::new()
    .with_google("GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET");

#[post("/auth/google")]
async fn google_login(auth: Auth, body: JwtToken) -> impl Responder {
    let identity = auth.authenticate("google", body.id_token).await?;
    HttpResponse::Ok().json(identity)
}
```

## 🧠 Core Concepts

- **Strategy**  
  A pluggable auth method — email/password, OAuth2 provider, JWT, WebAuthn, etc.

- **Identity**  
  The authenticated user object returned by strategies.

- **Adapter**  
  Framework-specific helpers that bind `fark` into your HTTP stack.

## 🔌 Adapters

| Framework | Crate       |
| --------- | ----------- |
| Actix Web | fark-actix  |
| Axum      | fark-axum   |
| Rocket    | fark-rocket |

## 🛠️ Philosophy

- **No framework lock-in**  
  Core is pure Rust logic.

- **Composable strategies**  
  Add or customize providers easily.

- **Security-first defaults**  
  Safe defaults; opt-in behaviors.

## 📄 License

MIT

---

### Context and Motivation

No mature, ecosystem-agnostic equivalent to Passport.js exists in Rust today. Existing solutions either lack a unified core or are tightly coupled to specific frameworks, requiring developers to implement JWT, OAuth, and session handling manually. `fark` addresses this gap and aims to establish a standard for authentication in the Rust ecosystem.
