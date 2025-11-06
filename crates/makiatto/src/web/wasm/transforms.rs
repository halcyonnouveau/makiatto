use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use axum::{
    body::{Body, Bytes},
    extract::{Request, State},
    http::HeaderValue,
    middleware::Next,
    response::{IntoResponse, Response},
};
use axum_extra::extract::Host;
use globset::Glob;
use miette::{Result, miette};
use wasmtime::Store;
use wasmtime::component::Linker;

use super::{
    StoreData, WasmRuntime, create_store_data, transformer_bindings,
    transformer_bindings::exports::makiatto::transform::transformer::NodeContext as WitNodeContext,
};

pub struct DomainTransform {
    pub path: String,
    pub env: HashMap<String, String>,
    pub timeout_ms: Option<u64>,
    pub max_memory_mb: Option<u64>,
    pub max_file_size_kb: Option<u64>,
}

/// Execute WASM transform on file content
pub async fn execute_transform(
    runtime: &WasmRuntime,
    transform: &DomainTransform,
    content: Bytes,
    file_path: &str,
    mime_type: Option<String>,
) -> Result<Bytes> {
    // Check file size limit
    #[allow(clippy::cast_possible_truncation)]
    if let Some(max_kb) = transform.max_file_size_kb
        && content.len() > (max_kb as usize * 1024)
    {
        return Ok(content);
    }

    let timeout = runtime.effective_timeout(transform.timeout_ms);
    let timeout_duration = Duration::from_millis(timeout);

    // Clone content for use in error cases
    let content_clone = content.clone();

    let result = tokio::time::timeout(timeout_duration, async {
        let wasm_path = Path::new(&transform.path);
        let component = runtime.get_component(wasm_path).await?;

        let memory_limit = runtime.effective_memory_limit(transform.max_memory_mb);
        #[allow(clippy::cast_possible_truncation)]
        let memory_bytes = (memory_limit * 1024 * 1024) as usize;
        let store_data = create_store_data(transform.env.clone(), memory_bytes);

        let mut store = Store::new(component.engine(), store_data);
        store.limiter(|data| &mut data.limits);

        let mut linker = Linker::<StoreData>::new(component.engine());
        wasmtime_wasi::p2::add_to_linker_async(&mut linker)
            .map_err(|e| miette!("Failed to add WASI to linker: {e}"))?;

        let instance =
            transformer_bindings::Transform::instantiate_async(&mut store, &component, &linker)
                .await
                .map_err(|e| miette!("Failed to instantiate transformer component: {e}"))?;

        let node_context = WitNodeContext {
            name: runtime.node_context.name.clone(),
            latitude: runtime.node_context.latitude,
            longitude: runtime.node_context.longitude,
        };

        let file_info = transformer_bindings::exports::makiatto::transform::transformer::FileInfo {
            path: file_path.to_string(),
            mime_type: mime_type.unwrap_or_else(|| "application/octet-stream".to_string()),
            size: content.len() as u64,
        };

        let transformer_interface = instance.makiatto_transform_transformer();
        let result = transformer_interface
            .call_transform(&mut store, &node_context, &file_info, &content)
            .await
            .map_err(|e| miette!("Transform execution failed: {e}"))?;

        Ok::<_, miette::Error>(result.map(|r| Bytes::from(r.content)).unwrap_or(content))
    })
    .await;

    match result {
        Ok(Ok(transformed)) => Ok(transformed),
        Ok(Err(e)) => {
            tracing::error!("Transform execution error: {e}");
            Ok(content_clone) // Return original content on error
        }
        Err(_) => {
            tracing::error!("Transform timed out after {timeout}ms");
            Ok(content_clone) // Return original content on timeout
        }
    }
}

/// Middleware to apply WASM transforms to response content
#[allow(clippy::too_many_lines)]
pub(crate) async fn wasm_transform_middleware(
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

    let hostname = host
        .split_once(':')
        .map_or(host.as_str(), |(hostname, _)| hostname);
    let resolved_domain = crate::web::axum::resolve_cname(&state.cname_map, hostname);

    let request_path = request.uri().path().to_string();

    let response = next.run(request).await;

    let pool = match crate::corrosion::get_pool().await {
        Ok(pool) => pool,
        Err(e) => {
            tracing::error!("Failed to get database pool: {e}");
            return response;
        }
    };

    let rows = match sqlx::query!(
        "SELECT path, files_pattern, env, timeout_ms, max_memory_mb, max_file_size_kb
         FROM domain_transforms
         WHERE domain = ?
         ORDER BY execution_order ASC",
        resolved_domain
    )
    .fetch_all(pool)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!("Failed to query domain_transforms: {e}");
            return response;
        }
    };

    if rows.is_empty() {
        return response;
    }

    let mut matching_transforms = Vec::new();
    for row in rows {
        let glob = match Glob::new(&row.files_pattern) {
            Ok(g) => g.compile_matcher(),
            Err(e) => {
                tracing::error!(
                    "Invalid glob pattern '{}' for domain {}: {e}",
                    row.files_pattern,
                    resolved_domain
                );
                continue;
            }
        };

        let path_to_match = request_path.trim_start_matches('/');
        if glob.is_match(path_to_match) {
            let env: HashMap<String, String> = serde_json::from_str(&row.env).unwrap_or_default();

            let transform = DomainTransform {
                path: row.path,
                env,
                timeout_ms: row.timeout_ms.map(i64::cast_unsigned),
                max_memory_mb: row.max_memory_mb.map(i64::cast_unsigned),
                max_file_size_kb: row.max_file_size_kb.map(i64::cast_unsigned),
            };

            matching_transforms.push(transform);
        }
    }

    if matching_transforms.is_empty() {
        return response;
    }

    let (mut parts, body) = response.into_parts();

    let body_bytes = match axum::body::to_bytes(body, usize::MAX).await {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::error!("Failed to read response body: {e}");
            return (parts, Body::empty()).into_response();
        }
    };

    let mime_type = parts
        .headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    // Apply each transform in sequence
    let original_len = body_bytes.len();
    let mut current_content = body_bytes;
    for transform in matching_transforms {
        let wasm_path = state
            .static_dir
            .join(&resolved_domain)
            .join(&transform.path);

        let transform_with_path = DomainTransform {
            path: wasm_path.to_string_lossy().to_string(),
            ..transform
        };

        match execute_transform(
            wasm_runtime,
            &transform_with_path,
            current_content.clone(),
            &request_path,
            mime_type.clone(),
        )
        .await
        {
            Ok(transformed) => {
                current_content = transformed;
            }
            Err(e) => {
                tracing::error!("Transform failed for {}: {e}", transform_with_path.path);
            }
        }
    }

    // Update content-length header if it changed
    if current_content.len() != original_len {
        parts.headers.insert(
            axum::http::header::CONTENT_LENGTH,
            HeaderValue::from_str(&current_content.len().to_string())
                .unwrap_or_else(|_| HeaderValue::from_static("0")),
        );
    }

    (parts, Body::from(current_content)).into_response()
}
