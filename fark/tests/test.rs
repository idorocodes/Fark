#[cfg(test)]
mod tests {
    use fark::*;
    use serde_json::json;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test() {
        let secret = "test_secret".to_string();

        let mut fark = Fark::new().with_local(|data: HashMap<String, String>| async move {
            if data.get("username") == Some(&"admin".to_string())
                && data.get("password") == Some(&"pass".to_string())
            {
                Ok(Identity {
                    user_id: "123".to_string(),
                    data: json!({
                        "role": "admin",
                        "new_user":true,
                        "gender": "male"}),
                })
            } else {
                Err(AuthError::PasswordMismatch)
            }
        });

        fark.with_jwt(secret.clone());

        let mut input_data = HashMap::new();
        input_data.insert("username".to_string(), "admin".to_string());
        input_data.insert("password".to_string(), "pass".to_string());

        let input = AuthInput::Local { data: input_data };

        match fark.authenticate("local", input).await {
            Ok(identity) => {
                println!("Authenticated: user_id = {}", identity.user_id);
                println!("Custom data: {}", identity.data());

                let token = fark.issue_jwt(identity, 3600).unwrap();
                println!("Issued JWT: {}", token);

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
