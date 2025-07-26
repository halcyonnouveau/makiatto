use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use miette::Result;
use tower::ServiceExt;
use tower_http::services::ServeDir;
use tracing::{error, info};

use crate::{
    config::Config,
    service::{BasicServiceCommand, ServiceManager},
};

pub type WebManager = ServiceManager<BasicServiceCommand>;

#[derive(Clone)]
struct WebState {
    static_dir: Arc<PathBuf>,
}

async fn handle_request(
    State(state): State<WebState>,
    headers: HeaderMap,
    request: Request<Body>,
) -> Response<Body> {
    let hostname = headers
        .get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost");

    let domain = hostname.split(':').next().unwrap_or(hostname);
    let domain_path = state.static_dir.join(domain);

    tracing::info!(
        "Web request: hostname={}, domain={}, domain_path={:?}, exists={}",
        hostname,
        domain,
        domain_path,
        domain_path.exists()
    );

    if !domain_path.exists() {
        return Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from(format!("Domain '{domain}' not found")))
            .unwrap();
    }

    let serve_dir = ServeDir::new(&domain_path);
    match serve_dir.oneshot(request).await {
        Ok(response) => response.map(Body::new),
        Err(_) => Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::from("Error serving file"))
            .unwrap(),
    }
}

/// Start a web server instance and return a handle to control it
///
/// # Errors
/// Returns an error if the web server fails to bind to HTTP/HTTPS addresses or encounters runtime errors
#[allow(clippy::similar_names)]
pub async fn start(config: Arc<Config>, tripwire: tripwire::Tripwire) -> Result<()> {
    let state = WebState {
        static_dir: Arc::new(config.web.static_dir.as_std_path().to_path_buf()),
    };

    let app = Router::new().fallback(handle_request).with_state(state);

    let http_addr: SocketAddr = config
        .web
        .http_addr
        .parse()
        .map_err(|e| miette::miette!("Invalid HTTP address: {e}"))?;

    let https_addr: SocketAddr = config
        .web
        .https_addr
        .parse()
        .map_err(|e| miette::miette!("Invalid HTTPS address: {e}"))?;

    let http_app = app.clone();
    let http_tripwire = tripwire.clone();
    let http_server = tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(http_addr)
            .await
            .map_err(|e| miette::miette!("Failed to bind HTTP socket: {e}"))?;

        info!("HTTP server listening on {http_addr}");

        axum::serve(listener, http_app)
            .with_graceful_shutdown(http_tripwire)
            .await
            .map_err(|e| miette::miette!("HTTP server error: {e}"))?;

        Ok::<(), miette::Error>(())
    });

    // For now, HTTPS will just return a placeholder
    // TODO: Integrate with certificate management
    let mut https_tripwire = tripwire.clone();
    let https_server = tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(https_addr)
            .await
            .map_err(|e| miette::miette!("Failed to bind HTTPS socket: {e}"))?;

        info!(
            "HTTPS server listening on {} (TLS not yet implemented)",
            https_addr
        );

        loop {
            tokio::select! {
                _ = listener.accept() => {
                }
                () = &mut https_tripwire => {
                    break;
                }
            }
        }

        Ok::<(), miette::Error>(())
    });

    tokio::select! {
        result = http_server => {
            match result {
                Ok(Ok(())) => {},
                Ok(Err(e)) => error!("HTTP server error: {e}"),
                Err(e) => error!("HTTP server task failed: {e}"),
            }
        }
        result = https_server => {
            match result {
                Ok(Ok(())) => {},
                Ok(Err(e)) => error!("HTTPS server error: {e}"),
                Err(e) => error!("HTTPS server task failed: {e}"),
            }
        }
        () = tripwire.clone() => {
            info!("Web server received shutdown signal");
        }
    }

    Ok(())
}
