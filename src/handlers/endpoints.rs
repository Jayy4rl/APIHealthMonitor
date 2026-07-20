use crate::models::Claims;
use axum::{
    Json, extract::Path, extract::State, http::StatusCode
};
use serde_json::json;
use std::sync::Arc;

use crate::{AppState, ApiResult};
use crate::models;


pub async fn create_endpoint(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<models::EndpointRequest>,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    let user_id = claims.sub.parse::<i32>().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":"not found"})),
        )
    })?;
    if payload.name.is_empty() || payload.url.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid input"})),
        ));
    }

    let interval = payload.check_interval_seconds.unwrap_or(60);
    let status_code = payload.expected_status_code.unwrap_or(200);
    let active = payload.is_active.unwrap_or(true);

    let result = sqlx::query(
        "INSERT INTO endpoints (user_id, name, url, check_interval_seconds, expected_status_code, is_active) VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(user_id)
    .bind(payload.name)
    .bind(payload.url)
    .bind(interval)
    .bind(status_code)
    .bind(active)
    .execute(&state.db)
    .await;
    match result {
        Ok(_) => {
            return Ok((
                StatusCode::CREATED,
                Json(json!({"message": "Endpoint Created"})),
            ));
        }
        Err(e) => {
            if let sqlx::Error::Database(db_err) = e {
                if db_err.is_unique_violation() {
                    return Err((
                        StatusCode::CONFLICT,
                        Json(json!({"error":"Endpoint already exists"})),
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

pub async fn get_endpoints(
    claims: Claims,
    State(state): State<Arc<AppState>>,
) -> ApiResult<(StatusCode, Json<Vec<models::Endpoint>>)> {
    let user_id = claims.sub.parse::<i32>().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "not found"})),
        )
    })?;
    let endpoints =
        sqlx::query_as::<_, models::Endpoint>("SELECT * FROM endpoints WHERE user_id = $1")
            .bind(user_id)
            .fetch_all(&state.db)
            .await
            .map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error":"Something went wrong"})),
                )
            })?;
    Ok((StatusCode::OK, Json(endpoints)))
}

pub async fn get_endpoint_by_id(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(id): Path<i32>,
) -> ApiResult<(StatusCode, Json<models::Endpoint>)> {
    let user_id = claims.sub.parse::<i32>().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":"Not Found"})),
        )
    })?;
    let endpoint = sqlx::query_as::<_, models::Endpoint>(
        "SELECT * FROM endpoints WHERE id = $1 AND user_id = $2",
    )
    .bind(id)
    .bind(user_id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Endpoint not found"})),
        ),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Something went wrong"})),
        ),
    })?;
    Ok((StatusCode::OK, Json(endpoint)))
}

pub async fn update_endpoint(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(id): Path<i32>,
    Json(payload): Json<models::UpdateEndpointRequest>,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    let user_id = claims.sub.parse::<i32>().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":"not found"})),
        )
    })?;

    let name = payload.name;
    let url = payload.url;
    let interval = payload.check_interval_seconds;
    let status = payload.expected_status_code;
    let active = payload.is_active;
    let result = sqlx::query(
        "UPDATE endpoints SET name = COALESCE($1, name), url = COALESCE($2, url), check_interval_seconds = COALESCE($3, check_interval_seconds), expected_status_code = COALESCE($4, expected_status_code), is_active = COALESCE($5, is_active) WHERE id = $6 AND user_id = $7 ",
    )
    .bind(name)
    .bind(url)
    .bind(interval)
    .bind(status)
    .bind(active)
    .bind(id)
    .bind(user_id)
    .execute(&state.db)
    .await
    .map_err(|_| {(
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": "Something went wrong"}))
    )})?;

    if result.rows_affected() == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error":"Endpoint not found"})),
        ));
    }

    Ok((StatusCode::OK, Json(json!({"message":"Endpoint updated"}))))
}

pub async fn delete_endpoint(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(id): Path<i32>,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    let user_id = claims.sub.parse::<i32>().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":"not found"})),
        )
    })?;
    let result = sqlx::query("DELETE FROM endpoints WHERE id = $1 AND user_id = $2")
        .bind(id)
        .bind(user_id)
        .execute(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::NOT_FOUND,
                Json(json!({"error":"Endpoint not found"})),
            )
        })?;
    Ok((StatusCode::OK, Json(json!({"message":"Endpoint deleted"}))))
}
