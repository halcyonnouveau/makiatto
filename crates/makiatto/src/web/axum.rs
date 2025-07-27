use std::path::Path;
use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::{
        HeaderMap, HeaderValue, StatusCode, Uri,
        header::{CACHE_CONTROL, ETAG, IF_NONE_MATCH},
    },
    middleware::{self, Next},
    response::{IntoResponse, Redirect, Response},
};
use futures_util::pin_mut;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use miette::Result;
use opentelemetry::{KeyValue, global};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tower::{Service, ServiceExt};
use tower_http::services::ServeDir;
use tracing::{error, info, instrument, warn};

use crate::{config::Config, web::certificate::CertificateManager};

#[derive(Clone)]
struct WebState {
    static_dir: Arc<PathBuf>,
}

#[instrument(skip(state, headers, request), fields(hostname = tracing::field::Empty, method = %request.method(), uri = %request.uri()))]
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

    tracing::Span::current().record("hostname", hostname);

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
#[allow(clippy::similar_names, clippy::too_many_lines)]
pub async fn start(
    config: Arc<Config>,
    mut shutdown_rx: tokio::sync::mpsc::Receiver<()>,
) -> Result<()> {
    let state = WebState {
        static_dir: Arc::new(config.web.static_dir.as_std_path().to_path_buf()),
    };

    let app = Router::new()
        .fallback(handle_request)
        .layer(middleware::from_fn(metrics_middleware))
        .layer(middleware::from_fn(caching_middleware))
        .with_state(state);

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

    if let Err(e) = cert_manager.load_certificates().await {
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

/// Generate `ETag` using CRC32 hash of content
fn generate_etag(content: &[u8]) -> String {
    let checksum = crc32fast::hash(content);
    format!("\"{checksum}\"")
}

/// Get cache control header based on file extension
/// With `ETags` providing content validation, we can use longer cache times safely
fn get_cache_control(path: &str) -> HeaderValue {
    let extension = Path::new(path)
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("");

    #[allow(clippy::match_same_arms)]
    match extension {
        // Static assets (images, fonts) - rarely change, expensive to download
        "png" | "jpg" | "jpeg" | "webp" | "avif" | "gif" | "ico" | "svg" | "woff" | "woff2"
        | "ttf" | "otf" | "eot" => {
            HeaderValue::from_static("public, max-age=2592000") // 30 days
        }
        // CSS/JS - might change but ETag protects us
        "css" | "js" => {
            HeaderValue::from_static("public, max-age=86400") // 1 day
        }
        // Videos/media - larger files, less frequent updates
        "mp4" | "webm" | "mov" | "avi" => {
            HeaderValue::from_static("public, max-age=2592000") // 30 days
        }
        // Documents
        "pdf" | "doc" | "docx" => {
            HeaderValue::from_static("public, max-age=3600") // 1 hour
        }
        // Feeds - should be checked frequently but ETag avoids unnecessary transfers
        "xml" | "rss" | "atom" => {
            HeaderValue::from_static("public, max-age=1800") // 30 minutes
        }
        // Everything else including HTML
        _ => HeaderValue::from_static("public, max-age=3600"), // 1 hour
    }
}

/// Middleware to add caching headers and `ETag` validation
async fn caching_middleware(request: Request, next: Next) -> impl IntoResponse {
    let path = request.uri().path().to_string();
    let if_none_match = request.headers().get(IF_NONE_MATCH).cloned();

    let response = next.run(request).await;

    // Only apply caching to successful responses
    if response.status() != StatusCode::OK {
        return response;
    }

    let (mut parts, body) = response.into_parts();

    let Ok(body_bytes) = axum::body::to_bytes(body, usize::MAX).await else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to read response body",
        )
            .into_response();
    };

    let etag = generate_etag(&body_bytes);

    if let Some(client_etag) = if_none_match
        && client_etag.to_str().unwrap_or("") == etag
    {
        parts
            .headers
            .insert(ETAG, HeaderValue::from_str(&etag).unwrap());
        return (StatusCode::NOT_MODIFIED, parts).into_response();
    }

    parts
        .headers
        .insert(ETAG, HeaderValue::from_str(&etag).unwrap());
    parts
        .headers
        .insert(CACHE_CONTROL, get_cache_control(&path));

    (parts, Body::from(body_bytes)).into_response()
}

/// Middleware to collect HTTP metrics with domain separation
async fn metrics_middleware(request: Request, next: Next) -> Response {
    use std::time::Instant;

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

    let meter = global::meter("makiatto.web");

    let attributes = vec![
        KeyValue::new("method", method.clone()),
        KeyValue::new("domain", domain.clone()),
        KeyValue::new("status", status.to_string()),
    ];

    // Record request count
    let counter = meter
        .u64_counter("http.server.request.count")
        .with_description("Total number of HTTP requests")
        .build();
    counter.add(1, &attributes);

    // Record request duration
    let histogram = meter
        .f64_histogram("http.server.request.duration")
        .with_unit("s")
        .with_description("HTTP request duration in seconds")
        .build();
    histogram.record(duration, &attributes);

    // Track cache effectiveness (if ETag header is present)
    if response.headers().contains_key("etag") {
        let cache_status = if status == 304 { "hit" } else { "miss" };
        let cache_attributes = vec![
            KeyValue::new("domain", domain),
            KeyValue::new("cache_status", cache_status),
        ];

        let cache_counter = meter
            .u64_counter("http.server.cache.requests")
            .with_description("Cache requests by status")
            .build();
        cache_counter.add(1, &cache_attributes);
    }

    response
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
