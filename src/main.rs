use anyhow::Result;
use axum::{Json, Router, extract::State, http::StatusCode, response::IntoResponse, routing::post};
use dotenvy::dotenv;
use jsonwebtoken::{DecodingKey, EncodingKey};
use serde::Deserialize;
use serde_json::json;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use std::env;
use std::sync::Arc;

#[derive(Deserialize)]
struct RegisterRequest {
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
    Json(payload): Json<RegisterRequest>,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    if payload.email.trim().is_empty(){
        return Err((StatusCode::BAD_REQUEST, Json(json!({"error": "Invalid Email Address"}))));
    }
    if payload.password.len() < 8{
        return Err((StatusCode::BAD_REQUEST, Json(json!({"error": "Password Must Be Up To 8 Characters"}))));
    }

    Ok(StatusCode::CREATED);

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
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app).await?;

    Ok(())
}
