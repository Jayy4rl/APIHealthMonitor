use crate::models::Claims;
use axum::{
    Json, extract::State, http::StatusCode
};
use bcrypt::{DEFAULT_COST, hash, verify};
use chrono::Utc;
use jsonwebtoken::{Header, encode};
use serde_json::json;
use std::sync::Arc;

use crate::{AppState, ApiResult};
use crate::models;
use crate::AuthRequest;

pub async fn register(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<AuthRequest>,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    if payload.email.trim().is_empty() || payload.password.len() < 8 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid Email Or Password"})),
        ));
    }
    let hashed = hash(payload.password, DEFAULT_COST).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Invalid Email Or Password"})),
        )
    })?;

    let result = sqlx::query("INSERT INTO users (email, password_hash) VALUES ($1, $2)")
        .bind(payload.email)
        .bind(hashed)
        .execute(&state.db)
        .await;
    match result {
        Ok(_) => {
            return Ok((
                StatusCode::CREATED,
                Json(json!({"message": "User Created"})),
            ));
        }
        Err(e) => {
            if let sqlx::Error::Database(db_err) = e {
                if db_err.is_unique_violation() {
                    return Err((
                        StatusCode::CONFLICT,
                        Json(json!({"error":"Email already exists"})),
                    ));
                }
            }
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error":"Something went wrong"})),
            ))
        }
    }
}

pub async fn login(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<AuthRequest>,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    if payload.email.trim().is_empty() || payload.password.len() < 8 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid email or password"})),
        ));
    }
    let user = sqlx::query_as::<_, models::User>(
        "SELECT id, email, password_hash FROM users WHERE email = $1",
    )
    .bind(payload.email)
    .fetch_one(&state.db)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "Invalid Email Or Password"})),
        ),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Invalid Email Or Password"})),
        ),
    })?;

    let is_valid = verify(payload.password, &user.password_hash).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Invalid Email Or Password"})),
        )
    })?;
    if !is_valid {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"Invalid Email or Password"})),
        ));
    }

    let time = (Utc::now().timestamp() + 3600) as usize;
    let claims = Claims {
        sub: (user.id).to_string(),
        exp: time,
    };

    let the_token_variable =
        encode(&Header::default(), &claims, &state.encode_key).map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "not found"})),
            )
        })?;

    Ok((StatusCode::OK, Json(json!({"token": the_token_variable}))))
}
