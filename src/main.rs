use anyhow::Result;
use axum::{Json, Router, extract::State, http::StatusCode, response::IntoResponse, routing::post};
use bcrypt::{DEFAULT_COST, hash, verify};
use dotenvy::dotenv;
use jsonwebtoken::{encode, decode, Header, Algorithm, Validation, DecodingKey, EncodingKey};
use serde::{Serialize, Deserialize};
use serde_json::json;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use std::env;
use std::sync::Arc;
use chrono::Utc;

mod models;

#[derive(Debug, Serialize, Deserialize)]
struct Claims{
    sub: String,
    exp: usize,
}

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
    let claims = Claims{
        sub: (user.id).to_string(),
        exp: time,
    };

    let the_token_variable = encode(&Header::default(), &claims, &state.encode_key).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "not found"})),
        )
    })?;

    Ok((
        StatusCode::OK,
        Json(json!({"token": the_token_variable}))
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
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app).await?;

    Ok(())
}
