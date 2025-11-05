use std::{
    collections::HashMap,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use axum::{
    Router,
    body::Body,
    extract::{Path as ExtractPath, Request, State},
    http::{
        HeaderMap, HeaderValue, StatusCode, Uri,
        header::{CACHE_CONTROL, CONTENT_TYPE, ETAG, IF_NONE_MATCH},
    },
    middleware::{self, Next},
    response::{IntoResponse, Redirect, Response},
    routing::get,
};
use axum_extra::extract::Host;
use futures_util::pin_mut;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use miette::Result;
use opentelemetry::{KeyValue, global};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tower::{Service, ServiceExt};
use tower_http::{
    compression::{
        CompressionLayer, Predicate,
        predicate::{NotForContentType, SizeAbove},
    },
    services::ServeDir,
};
use tracing::{debug, error, info, instrument, warn};

use crate::{
    config::Config,
    corrosion::{self, schema::AcmeChallenge},
    web::{
        certificate::CertificateStore,
        image::ImageProcessor,
        wasm::{WasmRuntime, wasm_function_middleware, wasm_transform_middleware},
    },
};

#[derive(Clone)]
pub(crate) struct WebState {
    pub(crate) config: Arc<Config>,
    pub(crate) static_dir: Arc<PathBuf>,
    pub(crate) cname_map: Arc<HashMap<String, String>>,
    pub(crate) image_processor: Option<Arc<ImageProcessor>>,
    pub(crate) wasm_runtime: Option<Arc<WasmRuntime>>,
}

#[instrument(
    name = "http_request",
    skip(state, request),
    fields(method, uri, error, slow)
)]
async fn handle_request(
    State(state): State<WebState>,
    Host(host): Host,
    request: Request<Body>,
) -> Response<Body> {
    let start_time = std::time::Instant::now();
    let method = request.method().to_string();
    let uri = request.uri().to_string();

    let span = tracing::Span::current();
    span.record("method", &method);
    span.record("uri", &uri);

    let (hostname, _port) = host
        .split_once(':')
        .map_or((host.as_str(), 80u16), |(hostname, port_str)| {
            (hostname.as_str(), port_str.parse::<u16>().unwrap())
        });

    // resolve domain alias if exists
    let resolved_domain = resolve_cname(&state.cname_map, hostname);
    let domain_path = state.static_dir.join(&resolved_domain);

    if !domain_path.exists() {
        span.record("error", format!("Domain '{resolved_domain}' not found"));

        return Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from(format!("'{hostname:?}' not found")))
            .unwrap();
    }

    let uri_path = request.uri().path().to_string();

    let final_request = {
        let requested_file = domain_path.join(uri_path.trim_start_matches('/'));

        if requested_file.exists() && requested_file.is_file() {
            // original path exists, use as-is
            request
        } else {
            // try fallback paths
            let fallback_paths = generate_fallback_paths(&uri_path);
            let mut found_fallback = None;

            for fallback_path in &fallback_paths {
                let fallback_file = domain_path.join(fallback_path.trim_start_matches('/'));
                if fallback_file.exists() && fallback_file.is_file() {
                    debug!("Using fallback: {} -> {}", uri_path, fallback_path);
                    found_fallback = Some(fallback_path);
                    break;
                }
            }

            if let Some(fallback_path) = found_fallback {
                let fallback_uri = fallback_path
                    .parse::<Uri>()
                    .unwrap_or_else(|_| Uri::from_static("/"));
                Request::builder()
                    .method(request.method())
                    .uri(fallback_uri)
                    .body(Body::empty())
                    .unwrap()
            } else {
                // no fallback found, use original request
                request
            }
        }
    };

    let serve_dir = ServeDir::new(&domain_path);
    match serve_dir.oneshot(final_request).await {
        Ok(response) => {
            let status = response.status();
            let duration = start_time.elapsed();

            if status.is_client_error() || status.is_server_error() {
                span.record("error", format!("HTTP {}", status.as_u16()));
                error!("HTTP error: {method} {uri} -> {status}");
            } else if duration > Duration::from_secs(1) {
                span.record("slow", duration.as_millis());
                warn!(
                    "Slow HTTP request: {method} {uri} took {}ms",
                    duration.as_millis()
                );
            }

            response.map(Body::new)
        }
        Err(e) => {
            span.record("error", e.to_string());
            error!("Failed to serve file: {e}");

            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("Error serving file"))
                .unwrap()
        }
    }
}

#[instrument(
    name = "image_processing",
    skip(state, request, next),
    fields(path, has_params, processed, error)
)]
async fn image_middleware(
    State(state): State<WebState>,
    Host(host): Host,
    request: Request<Body>,
    next: Next,
) -> Response<Body> {
    let span = tracing::Span::current();

    let Some(ref processor) = state.image_processor else {
        return next.run(request).await;
    };

    let query = request.uri().query().unwrap_or("");
    if query.is_empty() || !ImageProcessor::has_transform_params(query) {
        return next.run(request).await;
    }

    span.record("has_params", true);

    let (hostname, _port) = host
        .split_once(':')
        .map_or((host.as_str(), 80u16), |(hostname, port_str)| {
            (hostname, port_str.parse::<u16>().unwrap_or(80))
        });

    let resolved_domain = resolve_cname(&state.cname_map, hostname);
    let domain_path = state.static_dir.join(&resolved_domain);

    if !domain_path.exists() {
        return next.run(request).await;
    }

    let uri_path = request.uri().path();
    let file_path = domain_path.join(uri_path.trim_start_matches('/'));

    span.record("path", uri_path);

    if !file_path.exists() || !file_path.is_file() {
        return next.run(request).await;
    }

    let ext = file_path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_lowercase);

    let is_image = matches!(
        ext.as_deref(),
        Some("jpg" | "jpeg" | "png" | "webp" | "avif" | "gif")
    );

    if !is_image {
        return next.run(request).await;
    }

    // parse query parameters
    let params: crate::web::image::ImageParams = match serde_urlencoded::from_str(query) {
        Ok(p) => p,
        Err(e) => {
            span.record("error", format!("Failed to parse params: {e}"));
            return next.run(request).await;
        }
    };

    match processor.process_image(&file_path, params).await {
        Ok((image_data, content_type)) => {
            span.record("processed", true);
            debug!("Processed image: {} ({} bytes)", uri_path, image_data.len());

            Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, content_type)
                .body(Body::from(image_data))
                .unwrap()
        }
        Err(e) => {
            span.record("error", e.to_string());
            error!("Failed to process image: {e}");
            // Fall back to serving original file
            next.run(request).await
        }
    }
}

#[instrument(
    name = "acme_challenge",
    skip(_state),
    fields(token, found, expired, error, slow)
)]
async fn handle_acme_challenge(
    State(_state): State<WebState>,
    ExtractPath(token): ExtractPath<String>,
) -> impl IntoResponse {
    let start_time = std::time::Instant::now();
    let span = tracing::Span::current();
    span.record("token", &token);

    let token_clone = token.clone();

    let challenge_result: Result<Option<AcmeChallenge>, miette::Report> = async move {
        let pool = corrosion::get_pool().await?;

        let row = sqlx::query!(
            "SELECT token, key_authorisation, created_at, expires_at FROM acme_challenges WHERE token = ?1",
            token_clone
        )
        .fetch_optional(pool)
        .await
        .map_err(|e| miette::miette!("Failed to query challenge: {e}"))?;

        match row {
            Some(row) => Ok(Some(AcmeChallenge {
                token: row.token.into(),
                key_authorisation: row.key_authorisation.into(),
                created_at: row.created_at,
                expires_at: row.expires_at,
            })),
            None => Ok(None),
        }
    }.await;

    let duration = start_time.elapsed();
    let response = match challenge_result {
        Ok(Some(challenge)) => {
            #[allow(clippy::cast_possible_wrap)]
            let current_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;

            if challenge.expires_at < current_time {
                span.record("found", true);
                span.record("expired", true);
                info!("ACME challenge token '{token}' has expired");
                (StatusCode::NOT_FOUND, "Challenge expired").into_response()
            } else {
                span.record("found", true);
                span.record("expired", false);
                info!("Serving ACME challenge for token '{token}'");
                (StatusCode::OK, challenge.key_authorisation.to_string()).into_response()
            }
        }
        Ok(None) => {
            span.record("found", false);
            info!("ACME challenge token '{token}' not found");
            (StatusCode::NOT_FOUND, "Challenge not found").into_response()
        }
        Err(e) => {
            span.record("error", e.to_string());
            error!("Failed to query ACME challenge: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response()
        }
    };

    if duration > Duration::from_millis(100) {
        span.record("slow", duration.as_millis());
        warn!(
            "Slow ACME challenge lookup for token '{token}' took {}ms",
            duration.as_millis()
        );
    }

    response
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
    let mut cname_cache = HashMap::new();

    // load initial domain aliases
    let pool = corrosion::get_pool().await?;
    let rows = sqlx::query!("SELECT alias, target FROM domain_aliases")
        .fetch_all(pool)
        .await
        .map_err(|e| miette::miette!("Failed to query domain aliases: {e}"))?;

    for row in rows {
        cname_cache.insert(row.alias, row.target);
    }

    let image_processor = if config.images.enabled {
        Some(Arc::new(ImageProcessor::new(config.images.clone())))
    } else {
        None
    };

    let wasm_runtime = if config.wasm.enabled {
        match WasmRuntime::new(config.wasm) {
            Ok(runtime) => Some(Arc::new(runtime)),
            Err(e) => {
                warn!("Failed to initialise WASM runtime: {e}");
                None
            }
        }
    } else {
        None
    };

    let state = WebState {
        config: config.clone(),
        static_dir: Arc::new(config.web.static_dir.as_std_path().to_path_buf()),
        cname_map: Arc::new(cname_cache),
        image_processor,
        wasm_runtime,
    };

    let compression_predicate = SizeAbove::new(1024)
        .and(NotForContentType::GRPC)
        .and(NotForContentType::IMAGES)
        .and(NotForContentType::SSE)
        .and(NotForContentType::const_new("application/pdf"))
        .and(NotForContentType::const_new("application/zip"))
        .and(NotForContentType::const_new("application/octet-stream"))
        .and(NotForContentType::const_new("audio/"))
        .and(NotForContentType::const_new("video/"));

    let app = Router::new()
        .route(
            "/.well-known/acme-challenge/{token}",
            get(handle_acme_challenge),
        )
        .fallback(handle_request)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            wasm_function_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            wasm_transform_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            image_middleware,
        ))
        .layer(middleware::from_fn(metrics_middleware))
        .layer(middleware::from_fn(caching_middleware))
        .layer(CompressionLayer::new().compress_when(compression_predicate))
        .with_state(state.clone());

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

    let cert_store = CertificateStore::new();

    if let Err(e) = cert_store.load_certificates().await {
        warn!("Failed to load certificates from database: {e}");
    }

    let (https_server, https_active) = if let Ok(tls_config) = cert_store.build_tls_config().await {
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
        Router::new()
            .route(
                "/.well-known/acme-challenge/{token}",
                get(handle_acme_challenge),
            )
            .fallback(https_redirect)
            .with_state(state.clone())
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
        "pdf" | "doc" | "docx" => {
            HeaderValue::from_static("public, max-age=3600") // 1 hour
        }
        "xml" | "rss" | "atom" => {
            HeaderValue::from_static("public, max-age=1800") // 30 minutes
        }
        _ => HeaderValue::from_static("public, max-age=3600"), // 1 hour
    }
}

async fn caching_middleware(request: Request, next: Next) -> impl IntoResponse {
    let path = request.uri().path().to_string();
    let if_none_match = request.headers().get(IF_NONE_MATCH).cloned();

    let response = next.run(request).await;

    // only apply caching to successful responses
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

    let etag = format!("\"{}\"", crc32fast::hash(&body_bytes));

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
    let duration = start.elapsed().as_millis_f64();

    let meter = global::meter("axum");

    let attributes = vec![
        KeyValue::new("method", method.clone()),
        KeyValue::new("domain", domain.clone()),
        KeyValue::new("status", status.to_string()),
    ];

    let counter = meter
        .u64_counter("server.request.count")
        .with_description("Total number of HTTP requests")
        .build();

    counter.add(1, &attributes);

    let histogram = meter
        .f64_histogram("server.request.duration")
        .with_unit("s")
        .with_description("HTTP request duration in milliseconds")
        .build();

    histogram.record(duration, &attributes);

    if response.headers().contains_key("etag") {
        let cache_status = if status == 304 { "hit" } else { "miss" };
        let cache_attributes = vec![
            KeyValue::new("domain", domain),
            KeyValue::new("cache_status", cache_status),
        ];

        let cache_counter = meter
            .u64_counter("server.cache.requests")
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

/// Generate fallback paths for a given URI path
fn generate_fallback_paths(uri_path: &str) -> Vec<String> {
    let mut fallbacks = Vec::new();
    let clean_path = uri_path.trim_end_matches('/');

    if !clean_path.is_empty() && clean_path != "/" {
        // html fallbacks if the path doesn't have an extension
        let path_obj = std::path::Path::new(clean_path);
        if path_obj.extension().is_none() {
            // path.html (e.g., /about -> /about.html)
            fallbacks.push(format!("{clean_path}.html"));
            // path/index.html (e.g., /about -> /about/index.html)
            fallbacks.push(format!("{clean_path}/index.html"));
        }
    }

    fallbacks
}

/// Resolve a domain through alias chains
pub(crate) fn resolve_cname(cache: &HashMap<String, String>, domain: &str) -> String {
    let mut current = domain;
    let mut seen = std::collections::HashSet::new();

    // follow alias chain with loop detection
    while let Some(target) = cache.get(current) {
        if !seen.insert(current) {
            warn!("Alias loop detected for domain: {domain}");
            return domain.to_string();
        }
        current = target;
    }

    if current != domain {
        debug!("Resolved alias: {domain} -> {current}");
    }

    current.to_string()
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
                    let Ok(stream) = tls_acceptor.accept(cnx).await else { return; };

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
