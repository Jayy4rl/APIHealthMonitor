use handlers::endpoints::{create_endpoint, get_endpoints, get_endpoint_by_id, update_endpoint, delete_endpoint};
use handlers::webhooks::{create_webhook, get_webhooks, get_webhook_by_id, update_webhook, delete_webhook};
use handlers::auth::{register, login};
use handlers::scheduler::scheduler;
use handlers::health_check::get_health_check_history;
use anyhow::Result;
use axum::{
    Json, Router, http::StatusCode, routing::get, routing::post,
};
use dotenvy::dotenv;
use jsonwebtoken::{DecodingKey, EncodingKey};
use serde::Deserialize;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use std::env;
use std::sync::Arc;

mod middleware;
mod models;
mod handlers;

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

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();
    tracing_subscriber::fmt::init();
    rustls::crypto::aws_lc_rs::default_provider().install_default().ok();
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
