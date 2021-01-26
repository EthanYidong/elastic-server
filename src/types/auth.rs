use serde::{Serialize, Deserialize};

#[derive(Deserialize)]
pub struct LoginRequest {
    pub token: String
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub token: String
}
