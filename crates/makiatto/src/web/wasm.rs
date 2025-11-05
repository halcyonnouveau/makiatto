mod functions;
mod transforms;

use std::path::Path;

use dashmap::DashMap;
pub(crate) use functions::wasm_function_middleware;
use miette::{Context, IntoDiagnostic, Result, miette};
pub(crate) use transforms::wasm_transform_middleware;
use wasmtime::component::{Component, ResourceTable};
use wasmtime::*;
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

use crate::config::WasmConfig;

pub mod http_handler_bindings {
    wasmtime::component::bindgen!({
        world: "http-handler",
        path: "wit/http/http-handler.wit",
        imports: {
            default: async,
        },
        exports: {
            default: async,
        },
    });
}

pub mod transformer_bindings {
    wasmtime::component::bindgen!({
        world: "file-transformer",
        path: "wit/transform/transform.wit",
        imports: {
            default: async,
        },
    });
}

/// Global WASM engine shared across all requests
pub struct WasmRuntime {
    engine: Engine,
    components: DashMap<String, Component>,
    config: WasmConfig,
}

impl WasmRuntime {
    pub fn new(config: WasmConfig) -> Result<Self> {
        let mut engine_config = Config::new();
        engine_config.async_support(true);
        engine_config.wasm_component_model(true);
        engine_config.max_wasm_stack(1024 * 1024); // 1MB stack

        let engine = Engine::new(&engine_config)
            .map_err(|e| miette!("Failed to create WASM engine: {e}"))?;

        Ok(Self {
            engine,
            components: DashMap::new(),
            config,
        })
    }

    /// Get the effective memory limit for a function/transform
    /// Returns the requested limit, capped at the global max
    pub fn effective_memory_limit(&self, requested_mb: Option<u64>) -> u64 {
        let limit = requested_mb.unwrap_or(self.config.default_max_memory_mb);
        limit.min(self.config.max_memory_mb)
    }

    /// Get the effective timeout for a function/transform
    /// Returns the requested timeout, capped at the global max
    pub fn effective_timeout(&self, requested_ms: Option<u64>) -> u64 {
        let timeout = requested_ms.unwrap_or(self.config.default_timeout_ms);
        timeout.min(self.config.max_timeout_ms)
    }

    /// Load or get cached component
    pub async fn get_component(&self, path: &Path) -> Result<Component> {
        let path_str = path.to_string_lossy().to_string();

        if self.config.cache_modules {
            if let Some(component) = self.components.get(&path_str) {
                return Ok(component.clone());
            }
        }

        let component_bytes = tokio::fs::read(path)
            .await
            .into_diagnostic()
            .with_context(|| format!("Failed to read WASM component: {}", path.display()))?;

        let component = Component::new(&self.engine, &component_bytes)
            .map_err(|e| miette!("Failed to compile WASM component {}: {e}", path.display()))?;

        if self.config.cache_modules {
            self.components.insert(path_str, component.clone());
        }

        Ok(component)
    }
}

/// Store data for WASI p2 Component Model
pub struct StoreData {
    pub wasi: WasiCtx,
    pub table: ResourceTable,
    pub limits: wasmtime::StoreLimits,
}

impl WasiView for StoreData {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
    }
}

/// Create store data with WASI context, resource table, and limits
pub(crate) fn create_store_data(
    env: std::collections::HashMap<String, String>,
    memory_bytes: usize,
) -> Result<StoreData> {
    let mut builder = WasiCtxBuilder::new();

    for (key, value) in env {
        builder.env(&key, &value);
    }

    builder.inherit_network();

    let wasi = builder.build();
    let table = ResourceTable::new();
    let limits = wasmtime::StoreLimitsBuilder::new()
        .memory_size(memory_bytes)
        .build();

    Ok(StoreData {
        wasi,
        table,
        limits,
    })
}
