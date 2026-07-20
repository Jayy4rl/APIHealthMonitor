use crate::models::Claims;
use axum::{
    Json, extract::Path, extract::State, http::StatusCode
};
use serde_json::json;
use std::sync::Arc;

use crate::{AppState, ApiResult};
use crate::models;


pub async fn get_health_check_history(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(endpoint_id): Path<i32>,
) -> ApiResult<(StatusCode, Json<Vec<models::HealthCheck>>)> {
    let user_id = claims.sub.parse::<i32>().map_err(|_| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({"error":"user not found"})),
        )
    })?;

    let result = sqlx::query_as::<_, models::HealthCheck>(
        "SELECT hc.* FROM health_check
    hc JOIN endpoints e ON hc.endpoint_id = e.id
    WHERE hc.endpoint_id =$1 AND e.user_id = $2",
    )
    .bind(endpoint_id)
    .bind(user_id)
    .fetch_all(&state.db)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":"Something went wrong"})),
        )
    })?;
    Ok((StatusCode::OK, Json(result)))
}