
use crate::input::AuthInput;
use crate::error::{AuthError};
use crate::identity::Identity;
use std::future::Future;
use std::pin::Pin;
  
pub type Strategy = Box<
    dyn Fn(AuthInput) -> Pin<Box<dyn Future<Output = Result<Identity, AuthError>> + Send>>
        + Send
        + Sync,
>;