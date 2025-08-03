use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use axum::{
    Router,
    extract::{Path, State},
    response::Json,
    routing::post,
};
use miette::Result;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tower_http::services::ServeDir;
use tracing::{info, warn};

use crate::config::Config;

pub mod reconcile;
pub mod watcher;

/// Global file watcher pause state
static WATCHER_PAUSED: AtomicBool = AtomicBool::new(false);

/// Check if the file watcher is currently paused
pub fn is_watcher_paused() -> bool {
    WATCHER_PAUSED.load(Ordering::Relaxed)
}

/// Set the file watcher pause state
pub fn set_watcher_paused(paused: bool) {
    WATCHER_PAUSED.store(paused, Ordering::Relaxed);
}

/// Start the internal file sync HTTP server
///
/// # Errors
/// Returns an error if the server fails to bind or encounters runtime errors
pub async fn start(
    config: Arc<Config>,
    mut shutdown_rx: tokio::sync::mpsc::Receiver<()>,
) -> Result<()> {
    let app = Router::new()
        .nest_service("/files", ServeDir::new(config.fs.storage_dir.as_std_path()))
        .route("/scan/{domain}", post(handle_domain_scan))
        .route("/watcher/pause", post(handle_pause_watcher))
        .route("/watcher/resume", post(handle_resume_watcher))
        .with_state(config.clone());

    let addr: SocketAddr = config
        .fs
        .addr
        .as_deref()
        .map_or_else(
            || format!("{}:8282", config.wireguard.address).parse(),
            str::parse,
        )
        .map_err(|e| miette::miette!("Invalid file sync address: {e}"))?;

    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| miette::miette!("Failed to bind file sync server on {addr}: {e}"))?;

    info!("File sync server listening on {addr}");

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = shutdown_rx.recv().await;
            info!("File sync server received shutdown signal");
        })
        .await
        .map_err(|e| miette::miette!("File sync server error: {e}"))?;

    Ok(())
}

/// Handle domain scan requests
async fn handle_domain_scan(
    State(config): State<Arc<Config>>,
    Path(domain): Path<String>,
) -> Json<Value> {
    info!("Manual scan requested for domain: {domain}");

    let domain_dir = config.web.static_dir.as_std_path().join(&domain);
    if !domain_dir.exists() {
        warn!("Domain directory does not exist: {}", domain_dir.display());
        return Json(json!({
            "success": false,
            "error": "Domain directory not found"
        }));
    }

    match reconcile::domain::scan(&config, &domain).await {
        Ok((added, removed)) => {
            info!(
                "Manual scan completed for {domain}: {added} files added, {removed} files removed",
            );
            Json(json!({
                "success": true,
                "files_added": added,
                "files_removed": removed,
                "domain": domain
            }))
        }
        Err(e) => {
            warn!("Manual scan failed for {domain}: {e}");
            Json(json!({
                "success": false,
                "error": format!("Scan failed: {e}")
            }))
        }
    }
}

/// Handle file watcher pause requests
async fn handle_pause_watcher() -> Json<Value> {
    set_watcher_paused(true);
    info!("File watcher paused");
    Json(json!({
        "success": true,
        "message": "File watcher paused"
    }))
}

/// Handle file watcher resume requests
async fn handle_resume_watcher() -> Json<Value> {
    set_watcher_paused(false);
    info!("File watcher resumed");
    Json(json!({
        "success": true,
        "message": "File watcher resumed"
    }))
}
