use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, StatusCode, Uri},
    response::{Redirect, Response},
};
use futures_util::pin_mut;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use miette::Result;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tower::{Service, ServiceExt};
use tower_http::services::ServeDir;
use tracing::{error, info, warn};

use crate::{
    config::Config,
    service::{BasicServiceCommand, ServiceManager},
    web::certificate::CertificateManager,
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
pub async fn start(
    config: Arc<Config>,
    mut shutdown_rx: tokio::sync::mpsc::Receiver<()>,
) -> Result<()> {
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

    let cert_manager = CertificateManager::new(config.corrosion.db.path.clone());

    if let Err(e) = cert_manager.load_certificates_from_db().await {
        warn!("Failed to load certificates from database: {e}");
    }

    let (https_server, https_active) = if let Ok(tls_config) = cert_manager.build_tls_config().await
    {
        let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));
        let (https_shutdown_tx, https_shutdown_rx) = tokio::sync::mpsc::channel(1);
        (
            Some((
                tokio::spawn(https_server(
                    app.clone(),
                    https_addr,
                    tls_acceptor,
                    https_shutdown_rx,
                )),
                https_shutdown_tx,
            )),
            true,
        )
    } else {
        warn!("No certificates available, HTTPS server disabled");
        (None, false)
    };

    let http_app = if https_active {
        Router::new().fallback(https_redirect)
    } else {
        app.clone()
    };

    let (http_shutdown_tx, mut http_shutdown_rx) = tokio::sync::mpsc::channel(1);
    let http_server = tokio::spawn(async move {
        let listener = TcpListener::bind(http_addr)
            .await
            .map_err(|e| miette::miette!("Failed to bind HTTP socket on {http_addr}: {e}"))?;

        info!("HTTP server listening on {http_addr}");

        axum::serve(listener, http_app)
            .with_graceful_shutdown(async move {
                let _ = http_shutdown_rx.recv().await;
            })
            .await
            .map_err(|e| miette::miette!("HTTP server error: {e}"))?;

        Ok::<(), miette::Error>(())
    });

    if let Some((https_handle, https_shutdown_tx)) = https_server {
        tokio::select! {
            result = http_server => {
                match result {
                    Ok(Ok(())) => {},
                    Ok(Err(e)) => error!("HTTP server error: {e}"),
                    Err(e) => error!("HTTP server task failed: {e}"),
                }
            }
            result = https_handle => {
                match result {
                    Ok(Ok(())) => {},
                    Ok(Err(e)) => error!("HTTPS server error: {e}"),
                    Err(e) => error!("HTTPS server task failed: {e}"),
                }
            }
            _ = shutdown_rx.recv() => {
                info!("Web server received shutdown signal");
                let _ = http_shutdown_tx.send(()).await;
                let _ = https_shutdown_tx.send(()).await;
            }
        }
    } else {
        tokio::select! {
            result = http_server => {
                match result {
                    Ok(Ok(())) => {},
                    Ok(Err(e)) => error!("HTTP server error: {e}"),
                    Err(e) => error!("HTTP server task failed: {e}"),
                }
            }
            _ = shutdown_rx.recv() => {
                info!("Web server received shutdown signal");
                let _ = http_shutdown_tx.send(()).await;
            }
        }
    }

    Ok(())
}

async fn https_redirect(headers: HeaderMap, uri: Uri) -> Redirect {
    let host = headers
        .get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost");

    let https_uri = format!(
        "https://{host}{}",
        uri.path_and_query()
            .map_or("/", axum::http::uri::PathAndQuery::as_str)
    );
    Redirect::permanent(&https_uri)
}

async fn https_server(
    app: Router,
    addr: SocketAddr,
    tls_acceptor: TlsAcceptor,
    mut shutdown_rx: tokio::sync::mpsc::Receiver<()>,
) -> Result<()> {
    let tcp_listener = TcpListener::bind(addr)
        .await
        .map_err(|e| miette::miette!("Failed to bind HTTPS socket on {addr}: {e}"))?;

    info!("HTTPS server listening on {addr}");

    let mut make_service = app.into_make_service_with_connect_info::<SocketAddr>();

    pin_mut!(tcp_listener);
    loop {
        tokio::select! {
            result = tcp_listener.accept() => {
                let (cnx, addr) = match result {
                    Ok(conn) => conn,
                    Err(e) => {
                        error!("Failed to accept connection: {e}");
                        continue;
                    }
                };

                let service = match make_service.call(addr).await {
                    Ok(service) => service,
                    Err(e) => {
                        error!("Failed to create service: {e}");
                        continue;
                    }
                };

                let tls_acceptor = tls_acceptor.clone();

                tokio::spawn(async move {
                    let stream = match tls_acceptor.accept(cnx).await {
                        Ok(stream) => stream,
                        Err(e) => {
                            warn!("TLS handshake failed for connection from {addr}: {e}");
                            return;
                        }
                    };

                    let hyper_service = hyper::service::service_fn(move |request: hyper::Request<Incoming>| {
                        service.clone().oneshot(request)
                    });

                    let ret = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                        .serve_connection_with_upgrades(TokioIo::new(stream), hyper_service)
                        .await;

                    if let Err(err) = ret {
                        warn!("Error serving connection from {addr}: {err}");
                    }
                });
            }
            _ = shutdown_rx.recv() => {
                info!("HTTPS server received shutdown signal");
                break;
            }
        }
    }

    Ok(())
}
