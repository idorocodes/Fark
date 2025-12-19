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
use fark::Fark;
use fark_actix::Auth;

let fark = Fark::new()
    .with_local(|email, password| async move {
        verify_user(email, password).await
    });

#[post("/auth/login")]
async fn login(auth: Auth, body: LoginRequest) -> impl Responder {
    let identity = auth.authenticate("local", (body.email, body.password)).await?;
    HttpResponse::Ok().json(identity)
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

| Framework  | Crate          |
|------------|----------------|
| Actix Web  | fark-actix     |
| Axum       | fark-axum      |
| Rocket     | fark-rocket    |

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
