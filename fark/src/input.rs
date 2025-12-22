use std::collections::HashMap;

#[derive(Debug)]
pub enum AuthInput {
    Local {
        data: HashMap<String, String>,
    },
    Google {
        client_id: String,
        client_secret: String,
        callback_url: String,
        scope: Vec<String>,
    },
    Pin {
        pin_code: i32,
    },
}