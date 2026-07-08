use chrono::{DateTime, Utc};
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

#[derive(Deserialize)]
pub struct EndpointRequest {
    pub name: String,
    pub url: String,
    pub check_interval_seconds: Option<i32>,
    pub expected_status_code: Option<i32>,
    pub is_active: Option<bool>,
}

#[derive(sqlx::FromRow, Serialize)]
pub struct Endpoint {
    pub id: i32,
    pub user_id: i32,
    pub name: String,
    pub url: String,
    pub check_interval_seconds: i32,
    pub created_at: DateTime<Utc>,
    pub expected_status_code: i32,
    pub is_active: bool,
    pub last_health_status: Option<String>,
}

#[derive(Deserialize)]
pub struct UpdateEndpointRequest {
    pub name: Option<String>,
    pub url: Option<String>,
    pub check_interval_seconds: Option<i32>,
    pub expected_status_code: Option<i32>,
    pub is_active: Option<bool>,
}

#[derive(sqlx::FromRow, Serialize)]
pub struct HealthCheck {
    pub id: i32,
    pub endpoint_id: i32,
    pub latency: Option<i32>,
    pub status_code: Option<i32>,
    pub health_status: String,
    pub checked_at: DateTime<Utc>,
    pub error_message: Option<String>,
}

#[derive(Deserialize)]
pub struct WebHookRequest {
    pub target_url: String,
    pub is_active: Option<bool>,
}

#[derive(sqlx::FromRow, Serialize)]
pub struct WebHook {
    pub id: i32,
    pub user_id: i32,
    pub target_url: String,
    pub created_at: DateTime<Utc>,
    pub is_active: bool,
}

#[derive(Deserialize)]
pub struct UpdateWebHookRequest {
    pub target_url: Option<String>,
    pub is_active: Option<bool>,
}
