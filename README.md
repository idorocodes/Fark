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
cargo add fark -F actix
```

## ✨ Quick Start For Actix Framework

### Local (email/password) Sign-In

```rust
    use actix_service::{Service, Transform};
use actix_web::{
    App, Error, HttpResponse, HttpServer, Responder,
    dev::ServiceRequest,
    get, post,
    web::{self, Data, Json},
};
use fark::{AuthError, AuthInput, Fark, Identity};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::HashMap,
    future::{Ready, ready},
    pin::Pin,
};

#[derive(Deserialize)]
struct UserRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct AuthSuccessResponse {
    token: String,
    message: String,
}
struct AuthMiddleware;

pub struct AuthMiddlewareService<S> {
    service: S,
}

impl<S, B> Transform<S, ServiceRequest> for AuthMiddleware
where
    S: Service<ServiceRequest, Response = actix_web::dev::ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = actix_web::dev::ServiceResponse<B>;

    type Future = Ready<Result<Self::Transform, Self::InitError>>;
    type Error = Error;
    type Transform = AuthMiddlewareService<S>;
    type InitError = ();

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AuthMiddlewareService { service }))
    }
}

impl<S, B> Service<ServiceRequest> for AuthMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = actix_web::dev::ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = actix_web::dev::ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(
        &self,
        ctx: &mut core::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.service.poll_ready(ctx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let fark = req.app_data::<Data<Fark>>().cloned();

        let auth_header = req.headers().get("Authorization");
        if let Some(fark) = fark {
            if let Some(header) = auth_header {
                if let Ok(header_str) = header.to_str() {
                    if header_str.starts_with("Bearer ") {
                        let token = header_str[7..].to_string();
                        let verifyjwt = fark.verify_jwt(token.into());

                        if verifyjwt.is_ok() {
                            let fut = self.service.call(req);
                            return Box::pin(async move { fut.await });
                        }
                    }
                }
            }
        }
        Box::pin(async move {
            Err(actix_web::error::ErrorUnauthorized(
                "Missing or invalid authorization",
            ))
        })
    }
}

async fn protected_path() -> impl Responder {
    "This is a protected route, you are authenticated! "
}
#[get("/")]
async fn hellopath() -> impl Responder {
    HttpResponse::Ok().body("Working perfectly")
}

#[post("/user")]
async fn user(
    payload: Json<UserRequest>,
    fark: web::Data<Fark>,
) -> Result<HttpResponse, AuthError> {
    let mut input = HashMap::new();
    input.insert("username".to_string(), payload.username.clone());
    input.insert("password".to_string(), payload.password.clone());

    let identity = fark
        .authenticate("local", AuthInput::Local { data: input })
        .await?;

    // Issue JWT with 1-hour TTL
    let token = fark.issue_jwt(identity, 10)?;

    Ok(HttpResponse::Ok().json(AuthSuccessResponse {
        token,
        message: "Authentication successful".to_string(),
    }))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("debug"));
    // Configure Fark once and share as app data
    let mut fark = Fark::new().with_local(|data: HashMap<String, String>| async move {
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
    fark.with_jwt("your-secure-secret-key-here".to_string());

    let fark_data = Data::new(fark);
    println!("Server started on http://0.0.0.0:3000");
    HttpServer::new(move || {
        App::new()
            .app_data(fark_data.clone())
            .service(
                web::scope("/api")
                    .wrap(AuthMiddleware)
                    .route("/protected", web::get().to(protected_path)),
            )
            .service(hellopath)
            .service(user)
    })
    .bind("0.0.0.0:3000")?
    .run()
    .await
}


```

### More Auth Strategy Coming Soon


## 🧠 Core Concepts

- **Strategy**  
  A pluggable auth method — email/password, OAuth2 provider, JWT, WebAuthn, etc.

- **Identity**  
  The authenticated user object returned by strategies.




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
