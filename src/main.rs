use anyhow::Result;
use dotenvy::dotenv;
use futures::future::join_all;
use serde::Serialize;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use std::env;
use std::fs;
use std::io::Read;
use std::time::Duration;
use tokio::time::sleep;

#[derive(Serialize)]
struct Status {
    link: String,
    status: String,
}

async fn database_connection() -> Result<PgPool> {
    dotenv().ok();
    let supabase_url = env::var("DATABASE_URL").expect("DATABASE_URL Must be set in .env");
    let connect = PgPoolOptions::new()
        .max_connections(5)
        .connect(&supabase_url)
        .await?;

    println!("Supabase connection successful");
    Ok(connect)
}

async fn check_url(
    client: reqwest::Client,
    pool: PgPool,
    url: String,
) -> Result<(), anyhow::Error> {
    let client = client.clone();
    let pool = pool.clone();
    let res = client.get(&url).send().await?;
    println!("Status for {}: {}", url.clone(), res.status());

    let url_status = Status {
        link: url.clone(),
        status: res.status().to_string(),
    };
    println!("updated struct");

    println!("updating database");
    sqlx::query("INSERT INTO links (link, status) VALUES ($1, $2)")
        .bind(&url_status.link)
        .bind(&url_status.status)
        .execute(&pool)
        .await?;
    println!("Write {} to database", url);
    Ok::<_, anyhow::Error>(())
}

async fn health_checker() -> Result<()> {
    let pool = database_connection().await?;

    let data = fs::read_to_string("urls.json")?;
    let urls: Vec<String> = serde_json::from_str(&data)?;

    println!("deserialized");
    let client = reqwest::Client::new();
    println!("initialized client");
    loop {
        let handles: Vec<_> = urls
            .iter()
            .map(|url| tokio::spawn(check_url(client.clone(), pool.clone(), url.clone())))
            .collect();

        for handle in handles {
            if let Err(e) = handle.await? {
                eprintln!("Error checking URL: {}", e)
            }
        }
        sleep(Duration::from_secs(5)).await;
        println!("function successfully run");
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    health_checker().await?;
    Ok(())
}
