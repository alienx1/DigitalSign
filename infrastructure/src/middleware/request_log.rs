use actix_web::body::MessageBody;
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::middleware::Next;
use actix_web::Error;
use std::time::Instant;

/// One structured line per request — method, path, status, latency — so a
/// production incident can be pinpointed from the access log alone, without
/// turning on verbose per-layer tracing. Severity follows the status class:
/// 5xx as `error`, 4xx (bad input, failed auth) as `warn`, everything else
/// `info`. Never logs headers/bodies — those may carry API keys or PDF/key
/// material.
pub async fn request_log<B: MessageBody>(
    req: ServiceRequest,
    next: Next<B>,
) -> Result<ServiceResponse<B>, Error> {
    let method = req.method().clone();
    let path = req.path().to_string();
    let started = Instant::now();

    let result = next.call(req).await;
    let elapsed_ms = started.elapsed().as_millis();

    match &result {
        Ok(res) => {
            let status = res.status();
            if status.is_server_error() {
                tracing::error!(%method, %path, %status, elapsed_ms, "request failed");
            } else if status.is_client_error() {
                tracing::warn!(%method, %path, %status, elapsed_ms, "request rejected");
            } else {
                tracing::info!(%method, %path, %status, elapsed_ms, "request handled");
            }
        }
        Err(e) => {
            tracing::error!(%method, %path, error = %e, elapsed_ms, "request errored");
        }
    }

    result
}
