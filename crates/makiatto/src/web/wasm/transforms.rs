use std::collections::HashMap;

use axum::{
    body::{Body, Bytes},
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use miette::Result;

use super::WasmRuntime;

pub struct DomainTransform {
    pub path: String,
    pub files_pattern: String,
    pub env: HashMap<String, String>,
    pub timeout_ms: Option<u64>,
    pub max_memory_mb: Option<u64>,
    pub max_file_size_kb: Option<u64>,
}

/// Execute WASM transform on file content
pub async fn execute_transform(
    _runtime: &WasmRuntime,
    transform: &DomainTransform,
    content: Bytes,
    _file_path: &str,
) -> Result<Bytes> {
    // Check file size limit
    if let Some(max_kb) = transform.max_file_size_kb {
        if content.len() > (max_kb as usize * 1024) {
            return Ok(content); // Skip transform for large files
        }
    }

    // TODO: Implement transform execution
    // 1. Load WASM module from transform.path
    // 2. Create WASI context with transform.env
    // 3. Create Store with timeout and memory limits
    // 4. Instantiate module
    // 5. Call exported transform function with content and file_path
    // 6. Return transformed bytes

    todo!("Transform execution not yet implemented")
}

/// Middleware to apply WASM transforms to response content
pub(crate) async fn wasm_transform_middleware(
    State(state): State<crate::web::axum::WebState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    // Check if WASM is enabled
    if !state.config.wasm.enabled {
        return next.run(request).await;
    }

    let Some(ref _wasm_runtime) = state.wasm_runtime else {
        return next.run(request).await;
    };

    // Let request pass through to get response
    let response = next.run(request).await;

    // TODO: Implement middleware
    // 1. Extract hostname from request
    // 2. Extract response path
    // 3. Query database for transforms matching domain + glob pattern
    // 4. For each matching transform (ordered by execution_order):
    //    a. Extract response body as bytes
    //    b. Execute WASM transform
    //    c. Replace response body with transformed content
    // 5. Return transformed response

    response
}
