use std::{net::SocketAddr, sync::Arc};

use axum::Router;
use miette::Result;
use tokio::net::TcpListener;
use tower_http::services::ServeDir;
use tracing::info;

use crate::config::Config;

pub mod reconcile;
pub mod watcher;

/// Start the internal file sync HTTP server
///
/// # Errors
/// Returns an error if the server fails to bind or encounters runtime errors
pub async fn start(
    config: Arc<Config>,
    mut shutdown_rx: tokio::sync::mpsc::Receiver<()>,
) -> Result<()> {
    let app =
        Router::new().nest_service("/files", ServeDir::new(config.fs.storage_dir.as_std_path()));

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
