
use serde_json::Value;

#[derive(Debug, Clone)]
pub struct Identity {
    pub user_id: String,
    pub data: Value,
}

impl Identity {
    pub fn data(&self) -> &Value {
        &self.data
    }
}