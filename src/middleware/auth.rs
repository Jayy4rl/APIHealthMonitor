use crate::AppState;
use crate::models::Claims;
use axum::{Json, extract::FromRequestParts, http::StatusCode, http::request::Parts};
use jsonwebtoken::{Validation, decode};
use serde_json::json;
use std::sync::Arc;

impl FromRequestParts<Arc<AppState>> for Claims {
    type Rejection = (StatusCode, Json<serde_json::Value>);
    async fn from_request_parts(
        parts: &mut Parts,
        _state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or_else(|| {
                (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"error": "Missing token"})),
                )
            })?;

        let token_data = decode::<Claims>(auth_header, &_state.decode_key, &Validation::default())
            .map_err(|_| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error":"Invalid token"})),
                )
            })?;

        Ok(token_data.claims)
    }
}
