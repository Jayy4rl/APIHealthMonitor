use futures_util::StreamExt;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;
use tokio::time::interval;
use tokio_stream::{self as stream};
use tracing::error;

use crate::{AppState};
use crate::models;


pub async fn scheduler(state: Arc<AppState>) {
    let mut loop_interval = interval(Duration::from_secs(5));
    let client = reqwest::Client::new();
    loop {
        let value = state.clone();
        let client = client.clone();
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
                    let client = client.clone();
                    let timer = Instant::now();
                    async move{
                    let (status, health_status, error_message)= match client.get(&endpoint.url).send().await{
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
                    .bind(&error_message)
                    .execute(&value.db)
                    .await;
                    match result {
                        Ok(_) => {},
                        Err(e) => {
                            error!("Database query failed: {}", e);
                            return;
                        }
                    }
                    if endpoint.last_health_status.as_deref() != Some(health_status) {
                        let result = match sqlx::query("
                        UPDATE endpoints SET last_health_status = $1 WHERE id = $2
                        ")
                        .bind(health_status)
                        .bind(&endpoint.id)
                        .execute(&value.db)
                        .await{
                            Ok(_) => {},
                            Err(e) => {
                                error!("Something unexpected occurred: {}", e)
                            }
                        };
                        let target_urls = match sqlx::query_scalar::<_, String>("
                        SELECT target_url from webhook WHERE is_active = true AND user_id = $1
                        ")
                        .bind(&endpoint.user_id)
                        .fetch_all(&value.db)
                        .await{
                            Ok(data) => data,
                            Err(e) =>{
                                error!("Something went wrong: {}", e);
                                return;
                            }
                        };

                        let payload = models::WebHookPayload{
                            url: endpoint.url,
                            name: endpoint.name,
                            status,
                            health_status: health_status.to_string(),
                            error_message
                        };
                        for target_url in target_urls {let webhook_post = client.post(target_url).json(&payload).send().await;}
                    }
            }}).await;
        });
    }
}
