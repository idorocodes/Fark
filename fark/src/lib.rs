//! Fark — A lightweight, pluggable authentication library for Rust.
//!
//! Provides strategy-based authentication and HMAC-SHA256 JWT support.

pub mod error;
pub mod fark;
pub mod identity;
pub mod input;
pub mod jwt;
pub mod strategy;
pub mod time;

pub use error::*;
pub use fark::Fark;
pub use identity::Identity;
pub use input::AuthInput;

pub use strategy::*;
