use std::{net::SocketAddr, sync::Arc, time::Instant};

use axum::{Router, extract::Request, middleware::Next, response::Response, routing::get};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};
use miette::Result;
use tokio::net::TcpListener;
use tracing::info;

use crate::config::Config;

/// Initialise the Prometheus metrics exporter
///
/// # Errors
/// Returns an error if the Prometheus builder configuration fails or metrics recorder installation fails
pub fn setup_metrics_recorder() -> Result<PrometheusHandle> {
    const EXPONENTIAL_SECONDS: &[f64] = &[
        0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
    ];

    let handle = PrometheusBuilder::new()
        .set_buckets_for_metric(
            Matcher::Full("http_request_duration_seconds".to_string()),
            EXPONENTIAL_SECONDS,
        )
        .map_err(|e| miette::miette!("Failed to configure Prometheus builder: {e}"))?
        .install_recorder()
        .map_err(|e| miette::miette!("Failed to install metrics recorder: {e}"))?;

    Ok(handle)
}

/// Start the metrics server
///
/// # Errors
/// Returns an error if the metrics server fails to bind to the address or encounters runtime errors
pub async fn start(
    config: Arc<Config>,
    handle: PrometheusHandle,
    mut shutdown_rx: tokio::sync::mpsc::Receiver<()>,
) -> Result<()> {
    if !config.web.metrics_enabled {
        info!("Metrics server disabled");
        return Ok(());
    }

    let metrics_addr: SocketAddr = config
        .web
        .metrics_addr
        .parse()
        .map_err(|e| miette::miette!("Invalid metrics address: {e}"))?;

    let app = Router::new().route("/metrics", get(move || async move { handle.render() }));

    let listener = TcpListener::bind(metrics_addr)
        .await
        .map_err(|e| miette::miette!("Failed to bind metrics server on {metrics_addr}: {e}"))?;

    info!("Metrics server listening on {metrics_addr}");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        let _ = shutdown_rx.recv().await;
        info!("Metrics server received shutdown signal");
    })
    .await
    .map_err(|e| miette::miette!("Metrics server error: {e}"))?;

    Ok(())
}

/// Middleware to collect HTTP metrics with domain separation
pub async fn metrics_middleware(request: Request, next: Next) -> Response {
    let start = Instant::now();
    let method = request.method().to_string();

    let domain = request
        .headers()
        .get("host")
        .and_then(|h| h.to_str().ok())
        .map_or("unknown", |h| h.split(':').next().unwrap_or(h))
        .to_string();

    let response = next.run(request).await;

    let status = response.status().as_u16();
    let duration = start.elapsed().as_secs_f64();

    metrics::counter!("http_requests_total", "method" => method.clone(), "domain" => domain.clone(), "status" => status.to_string()).increment(1);
    metrics::histogram!("http_request_duration_seconds", "method" => method, "domain" => domain.clone(), "status" => status.to_string()).record(duration);

    // track cache effectiveness (if ETag header is present)
    if response.headers().contains_key("etag") {
        let cache_status = if status == 304 { "hit" } else { "miss" };
        metrics::counter!("http_cache_requests_total", "domain" => domain, "cache_status" => cache_status).increment(1);
    }

    response
}
