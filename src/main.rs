use crate::models::Claims;
use anyhow::Result;
use axum::{
    Json, Router, extract::Path, extract::State, http::StatusCode, routing::get, routing::post,
};
use bcrypt::{DEFAULT_COST, hash, verify};
use chrono::Utc;
use dotenvy::dotenv;
use futures_util::StreamExt;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, encode};
use serde::Deserialize;
use serde_json::json;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use std::env;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;
use tokio::time::interval;
use tokio_stream::{self as stream};
use tracing::error;

mod middleware;
mod models;

#[derive(Deserialize)]
struct AuthRequest {
    email: String,
    password: String,
}
struct AppState {
    db: PgPool,
    encode_key: EncodingKey,
    decode_key: DecodingKey,
}

type ApiResult<T> = Result<T, (StatusCode, Json<serde_json::Value>)>;

async fn database_connection() -> Result<PgPool> {
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL Must be set in .env");
    let connect = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;

    println!("Database connection successful");
    Ok(connect)
}

async fn register(
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

async fn login(
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

async fn create_endpoint(
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

async fn get_endpoints(
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

async fn get_endpoint_by_id(
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

async fn update_endpoint(
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

async fn delete_endpoint(
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

async fn get_health_check_history(
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

async fn create_webhook(
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

async fn get_webhooks(
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

async fn get_webhook_by_id(
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

async fn update_webhook(
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

async fn delete_webhook(
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

async fn scheduler(state: Arc<AppState>) {
    let mut loop_interval = interval(Duration::from_secs(5));
    loop {
        let value = state.clone();
        loop_interval.tick().await;
        let db_check = sqlx::query_as::<_, models::Endpoint>(
        "
    SELECT e.*
    FROM endpoints e
    LEFT JOIN LATERAL (
        SELECT checked_at
        FROM health_check
        WHERE endpoint_id = e.id
        ORDER BY checked_at DESC
        LIMIT 1
        ) hc ON true
        WHERE is_active = true AND ( hc.checked_at + e.check_interval_seconds * INTERVAL '1 second'  <= now()
        OR hc.checked_at IS NULL);
    ",
    )
    .fetch_all(&value.db)
    .await;
        let due_checks = match db_check {
            Ok(data) => data,
            Err(e) => {
                error!("Scheduler query failed: {}", e);
                continue;
            }
        };

        tokio::spawn(async move {
            let http_stream = stream::iter(due_checks);
            http_stream.for_each_concurrent(5, |endpoint| {
                let value = value.clone();
                let timer = Instant::now();
                async move{
                let (status, health_status, error_message)= match reqwest::get(&endpoint.url).await{
                    Ok(response) => {
                        let status = response.status();
                        let code = status.as_u16() as i32;
                        if status.is_success(){
                            (code, "Healthy", None)
                        } else {
                            (code, "Unhealthy", Some(format!("Returned error code: {}", status)))
                        }
                    }
                    Err(e) => {
                        (0, "Down", Some(format!("Unreachable: {}", e)))
                    }
                };
                let latency = (timer.elapsed()).as_millis() as i32;
                let result = sqlx::query(
                    "INSERT INTO health_check(endpoint_id, latency, status_code, health_status, error_message) VALUES ($1, $2, $3, $4, $5)"
                )
            .bind(&endpoint.id)
            .bind(latency)
            .bind(status)
            .bind(health_status)
            .bind(error_message)
            .execute(&value.db)
            .await;
            match result {
                Ok(_) => {},
                Err(e) => {
                    error!("Database query failed: {}", e);
                    return;
                }
            }

        }}).await;
        });
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();
    let pool = database_connection().await?;
    let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    let encode_key = EncodingKey::from_secret(jwt_secret.as_bytes());
    let decode_key = DecodingKey::from_secret(jwt_secret.as_bytes());
    let state = Arc::new(AppState {
        db: pool,
        encode_key: encode_key,
        decode_key: decode_key,
    });

    tokio::spawn(scheduler(state.clone()));
    let app: Router = Router::new()
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/endpoints", post(create_endpoint).get(get_endpoints))
        .route(
            "/endpoints/{id}",
            get(get_endpoint_by_id)
                .put(update_endpoint)
                .delete(delete_endpoint),
        )
        .route("/endpoints/{id}/history", get(get_health_check_history))
        .route("/webhooks", post(create_webhook).get(get_webhooks))
        .route(
            "/webhooks/{id}",
            get(get_webhook_by_id)
                .put(update_webhook)
                .delete(delete_webhook),
        )
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app).await?;

    Ok(())
}
