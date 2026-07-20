use crate::models::Claims;
use axum::{
    Json, extract::Path, extract::State, http::StatusCode
};
use serde_json::json;
use std::sync::Arc;

use crate::{AppState, ApiResult};
use crate::models;


pub async fn create_webhook(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<models::WebHookRequest>,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    let user_id = claims.sub.parse::<i32>().map_err(|_| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({"error":"User Not Found"})),
        )
    })?;
    let active = payload.is_active.unwrap_or(true);
    let result =
        sqlx::query("INSERT INTO webhook (user_id, target_url, is_active) VALUES ($1, $2, $3)")
            .bind(user_id)
            .bind(payload.target_url)
            .bind(active)
            .execute(&state.db)
            .await
            .map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error":"Something went wrong"})),
                )
            })?;
    Ok((StatusCode::OK, Json(json!({"message": "WebHook Created"}))))
}

pub async fn get_webhooks(
    claims: Claims,
    State(state): State<Arc<AppState>>,
) -> ApiResult<(StatusCode, Json<Vec<models::WebHook>>)> {
    let user_id = claims.sub.parse::<i32>().map_err(|_| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "User Not Found"})),
        )
    })?;
    let result = sqlx::query_as::<_, models::WebHook>("SELECT * FROM webhook WHERE user_id = $1")
        .bind(user_id)
        .fetch_all(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error":"Something Went Wrong"})),
            )
        })?;
    Ok((StatusCode::OK, Json(result)))
}

pub async fn get_webhook_by_id(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(id): Path<i32>,
) -> ApiResult<(StatusCode, Json<models::WebHook>)> {
    let user_id = claims.sub.parse::<i32>().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":"Not Found"})),
        )
    })?;
    let webhook = sqlx::query_as::<_, models::WebHook>(
        "SELECT * FROM webhook WHERE  id = $1 AND  user_id= $2",
    )
    .bind(id)
    .bind(user_id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Webhook not found"})),
        ),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Something went wrong"})),
        ),
    })?;
    Ok((StatusCode::OK, Json(webhook)))
}

pub async fn update_webhook(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(id): Path<i32>,
    Json(payload): Json<models::UpdateWebHookRequest>,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    let user_id = claims.sub.parse::<i32>().map_err(|_| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({"error":"User Not Found"})),
        )
    })?;
    let result = sqlx::query("UPDATE webhook SET target_url = COALESCE($1, target_url), is_active = COALESCE($2, is_active) WHERE id = $3 AND user_id = $4 ")
    .bind(payload.target_url)
    .bind(payload.is_active)
    .bind(id)
    .bind(user_id)
    .execute(&state.db)
    .await
    .map_err(|_| {(
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error":"Something Went Wrong"}))
    )})?;

    if result.rows_affected() == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error":"WebHook not found"})),
        ));
    }
    Ok((
        StatusCode::OK,
        Json(json!({"message":"WebHook Updated Successfully"})),
    ))
}

pub async fn delete_webhook(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(id): Path<i32>,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    let user_id = claims.sub.parse::<i32>().map_err(|_| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({"error":"User Not Found"})),
        )
    })?;
    let result = sqlx::query("DELETE FROM webhook WHERE id = $1 AND user_id = $2")
        .bind(id)
        .bind(user_id)
        .execute(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::NOT_FOUND,
                Json(json!({"error":"WebHook not found"})),
            )
        })?;
    if result.rows_affected() == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error":"WebHook not found"})),
        ));
    }
    Ok((StatusCode::OK, Json(json!({"message":"WebHook deleted"}))))
}
