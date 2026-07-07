use crate::models::Claims;
use anyhow::Result;
use axum::{
    Json, Router, extract::Path, extract::State, http::StatusCode, routing::get, routing::post,
};
use bcrypt::{DEFAULT_COST, hash, verify};
use chrono::Utc;
use dotenvy::dotenv;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, encode};
use serde::Deserialize;
use serde_json::json;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use std::env;
use std::sync::Arc;

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
    Ok((
        StatusCode::OK,
        Json(result)
    ))
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

    let app: Router = Router::new()
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/endpoints", post(create_endpoint).get(get_endpoints))
        .route(
            "/endpoints/:id",
            get(get_endpoint_by_id)
                .put(update_endpoint)
                .delete(delete_endpoint),
        )
        .route("/endpoints/:id/history", get(get_health_check_history))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app).await?;

    Ok(())
}
