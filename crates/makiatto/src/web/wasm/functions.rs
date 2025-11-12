use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use axum::{
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, Method, StatusCode},
    middleware::Next,
    response::Response,
};
use axum_extra::extract::Host;
use miette::{Result, miette};
use wasmtime::Store;
use wasmtime::component::Linker;

use super::{
    WasmRuntime, create_store_data, http_bindings,
    http_bindings::exports::makiatto::http::handler::{
        Method as WitMethod, NodeContext as WitNodeContext, Request as WitRequest,
    },
};

pub struct DomainFunction {
    pub env: HashMap<String, String>,
    pub timeout_ms: Option<u64>,
    pub max_memory_mb: Option<u64>,
}

/// Convert Axum Method to WIT Method enum
fn convert_method(method: &Method) -> WitMethod {
    match *method {
        Method::POST => WitMethod::Post,
        Method::PUT => WitMethod::Put,
        Method::DELETE => WitMethod::Delete,
        Method::PATCH => WitMethod::Patch,
        Method::HEAD => WitMethod::Head,
        Method::OPTIONS => WitMethod::Options,
        _ => WitMethod::Get, // Default fallback for GET and other methods
    }
}

/// Convert Axum headers to WIT header list
fn convert_headers(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|v| (name.to_string(), v.to_string()))
        })
        .collect()
}

/// Execute WASM function for HTTP request
pub async fn execute_function(
    runtime: &WasmRuntime,
    function: &DomainFunction,
    wasm_path: &Path,
    domain_dir: &Path,
    request: Request<Body>,
) -> Result<Response<Body>> {
    let (parts, body) = request.into_parts();
    let method = convert_method(&parts.method);
    let path = parts.uri.path().to_string();
    let query = parts.uri.query().map(std::string::ToString::to_string);
    let headers = convert_headers(&parts.headers);

    let body_bytes = axum::body::to_bytes(body, usize::MAX)
        .await
        .map_err(|e| miette!("Failed to read request body: {e}"))?;
    let body_vec = if body_bytes.is_empty() {
        None
    } else {
        Some(body_bytes.to_vec())
    };

    let wit_request = WitRequest {
        method,
        path,
        query,
        headers,
        body: body_vec,
    };

    let timeout = runtime.effective_timeout(function.timeout_ms);
    let timeout_duration = Duration::from_millis(timeout);

    let wit_response = tokio::time::timeout(timeout_duration, async {
        let component = runtime.get_component(wasm_path).await?;
        let memory_limit = runtime.effective_memory_limit(function.max_memory_mb);
        let memory_bytes = (memory_limit * 1024 * 1024) as usize;

        let store_data = create_store_data(function.env.clone(), memory_bytes, Some(domain_dir));
        let mut store = Store::new(component.engine(), store_data);
        store.limiter(|data| &mut data.limits);

        let mut linker = Linker::<super::StoreData>::new(component.engine());
        wasmtime_wasi::p2::add_to_linker_async(&mut linker)
            .map_err(|e| miette!("Failed to add WASI to linker: {e}"))?;

        let instance = http_bindings::Http::instantiate_async(&mut store, &component, &linker)
            .await
            .map_err(|e| miette!("Failed to instantiate component: {e}"))?;

        let node_context = WitNodeContext {
            name: runtime.node_context.name.clone(),
            latitude: runtime.node_context.latitude,
            longitude: runtime.node_context.longitude,
        };

        let handler = instance.makiatto_http_handler();
        handler
            .call_handle_request(&mut store, &node_context, &wit_request)
            .await
            .map_err(|e| miette!("Failed to execute WASM function: {e}"))
    })
    .await
    .map_err(|_| miette!("WASM function execution timed out after {}ms", timeout))??;

    // Convert WIT response back to Axum response
    let status =
        StatusCode::from_u16(wit_response.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

    let mut response = Response::builder().status(status);

    for (name, value) in wit_response.headers {
        response = response.header(name, value);
    }

    let body = wit_response.body.map_or_else(Body::empty, Body::from);

    Ok(response.body(body).unwrap())
}

/// Middleware to execute WASM functions for matching routes
pub(crate) async fn wasm_function_middleware(
    State(state): State<crate::web::axum::WebState>,
    Host(host): Host,
    request: Request<Body>,
    next: Next,
) -> Response {
    if !state.config.wasm.enabled {
        return next.run(request).await;
    }

    let Some(ref wasm_runtime) = state.wasm_runtime else {
        return next.run(request).await;
    };

    let (hostname, _port) = host
        .split_once(':')
        .map_or((host.as_str(), 80u16), |(hostname, port_str)| {
            (hostname, port_str.parse::<u16>().unwrap_or(80))
        });

    let resolved_domain = crate::web::axum::resolve_cname(&state.cname_map, hostname);

    let request_path = request.uri().path();
    let method = request.method().clone();

    let pool = match crate::corrosion::get_pool().await {
        Ok(pool) => pool,
        Err(e) => {
            tracing::error!("Failed to get database pool: {e}");
            return next.run(request).await;
        }
    };

    let row = match sqlx::query!(
        "SELECT path, methods, env, timeout_ms, max_memory_mb FROM domain_functions WHERE domain = ? AND id = ?",
        resolved_domain,
        format!("{}:{}", resolved_domain, request_path)
    )
    .fetch_optional(pool)
    .await
    {
        Ok(Some(row)) => row,
        Ok(None) => return next.run(request).await,
        Err(e) => {
            tracing::error!("Failed to query domain_functions: {e}");
            return next.run(request).await;
        }
    };

    let methods: Option<Vec<String>> = row
        .methods
        .as_ref()
        .and_then(|m| serde_json::from_str(m).ok());

    // Check if request method is allowed
    if let Some(ref allowed_methods) = methods {
        let method_str = method.as_str();
        if !allowed_methods
            .iter()
            .any(|m| m.eq_ignore_ascii_case(method_str))
        {
            return next.run(request).await;
        }
    }

    let env: HashMap<String, String> = serde_json::from_str(&row.env).unwrap_or_default();
    let function = DomainFunction {
        env,
        timeout_ms: row.timeout_ms.map(i64::cast_unsigned),
        max_memory_mb: row.max_memory_mb.map(i64::cast_unsigned),
    };

    let domain_dir = state.static_dir.join(&resolved_domain);
    let wasm_path = domain_dir.join(&row.path);

    match execute_function(wasm_runtime, &function, &wasm_path, &domain_dir, request).await {
        Ok(response) => response,
        Err(e) => {
            let error_msg = e.to_string();
            let is_timeout = error_msg.contains("timed out");

            if is_timeout {
                tracing::warn!("WASM function execution timed out: {e}");
                Response::builder()
                    .status(StatusCode::GATEWAY_TIMEOUT)
                    .body(Body::from(format!("WASM execution error: {e}")))
                    .unwrap()
            } else {
                tracing::error!("WASM function execution failed: {e}");
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::from(format!("WASM execution error: {e}")))
                    .unwrap()
            }
        }
    }
}
