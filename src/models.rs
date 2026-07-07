use serde::{Deserialize, Serialize};
#[derive(sqlx::FromRow)]
pub struct User {
    pub id: i32,
    pub email: String,
    pub password_hash: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}
